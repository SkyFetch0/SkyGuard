package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/skyguard/skyguard/internal/config"
	"github.com/skyguard/skyguard/internal/dashboard"
	"github.com/skyguard/skyguard/internal/server"
	"github.com/skyguard/skyguard/internal/storage"
	"github.com/skyguard/skyguard/internal/update"
)

// Injected at build time: -ldflags "-X main.Version=x.y.z -X main.Commit=… -X main.BuildDate=…".
var (
	Version   = "dev"
	Commit    = ""
	BuildDate = ""
)

const defaultConfigPath = "/etc/skyguard/skyguard.yaml"

func main() {
	configPath := flag.String("config", defaultConfigPath, "config file path (env SKYGUARD_CONFIG is used when the flag is not given)")
	checkOnly := flag.Bool("check-config", false, "validate the config file and exit")
	healthcheck := flag.Bool("healthcheck", false, "probe the running instance's dashboard /healthz and exit 0/1 (for Docker HEALTHCHECK)")
	showVersion := flag.Bool("version", false, "print version and exit")
	mcpStdio := flag.Bool("mcp-stdio", false, "relay MCP over stdin/stdout to the running instance's /mcp endpoint (token from SKYGUARD_MCP_TOKEN or -mcp-token-file)")
	mcpTokenFile := flag.String("mcp-token-file", "", "file holding the MCP token, for -mcp-stdio")
	keygen := flag.Bool("update-keygen", false, "make a release signing key pair and print it (the private key goes into the repository's SKYGUARD_SIGNING_KEY secret)")
	signFile := flag.String("update-sign", "", "sign a release's SHA256SUMS with the key in SKYGUARD_SIGNING_KEY and print the signature")
	flag.Parse()

	if *showVersion {
		fmt.Println("skyguard", Version, Commit, BuildDate)
		return
	}
	if *keygen {
		os.Exit(runKeygen())
	}
	if *signFile != "" {
		os.Exit(runSign(*signFile))
	}

	// An explicit -config flag wins; otherwise SKYGUARD_CONFIG overrides the default.
	flagSet := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "config" {
			flagSet = true
		}
	})
	if envPath := os.Getenv("SKYGUARD_CONFIG"); envPath != "" && !flagSet {
		*configPath = envPath
	}

	// The bridge needs no valid config (it only reads the dashboard address
	// from it) and must keep stdout free of anything but protocol messages.
	if *mcpStdio {
		os.Exit(runMCPBridge(*configPath, *mcpTokenFile))
	}

	logger := setupLogger("info")
	build := update.Build{Version: Version, Commit: Commit, Date: BuildDate}

	// The binary the service starts hands over to an update applied from the
	// dashboard, and takes over again if that one keeps failing. This runs
	// before the config is validated: a newer release may accept settings
	// this build does not know.
	self, _ := os.Executable()
	if p, err := filepath.EvalSymlinks(self); err == nil {
		self = p
	}
	base, slot := os.Getenv(update.EnvBase), os.Getenv(update.EnvSlot)
	if base == "" {
		base = self
		if !*healthcheck && !*checkOnly {
			if path := update.Launch(config.DataDirOf(*configPath), self, build, logger); path != "" && path != self {
				v := filepath.Base(filepath.Dir(path))
				logger.Info("starting the applied update", "version", v, "installed", Version)
				if err := update.Exec(path, self, v); err != nil {
					logger.Error("could not start the applied update; going on with the installed version", "error", err)
				}
			}
		}
	}

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		logger.Error("invalid configuration", "path", *configPath, "error", err)
		os.Exit(1)
	}

	if *healthcheck {
		os.Exit(runHealthcheck(cfg))
	}
	if *checkOnly {
		fmt.Printf("config %s is valid\n", *configPath)
		return
	}

	logger = setupLogger(cfg.General.LogLevel)
	dashboard.Version = Version
	logger.Info("SkyGuard starting", "version", Version, "commit", Commit, "config", *configPath, "update", slot != "")

	db, err := storage.New(cfg.Logging.DBPath)
	if err != nil {
		logger.Error("failed to open database", "path", cfg.Logging.DBPath, "error", err)
		os.Exit(1)
	}
	defer db.Close()

	srv, err := server.New(cfg, db, logger)
	if err != nil {
		logger.Error("failed to create server", "error", err)
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	restart := make(chan struct{}, 1)
	if base != "test" {
		upd := update.NewManager(update.Options{
			DataDir: cfg.General.DataDir, ConfigPath: *configPath, Base: base, Build: build, Slot: slot,
			Source:  &update.GitHub{API: cfg.Update.APIURL, Repo: cfg.Update.Repo, Token: cfg.Update.Token},
			Channel: cfg.Update.Channel, Check: cfg.Update.Checks(), ExtraKeys: []string{cfg.Update.PublicKey},
			Backup: db.BackupTo, DBSize: db.Size, Precheck: srv.UpdatePrecheck,
			Restart: func() {
				select {
				case restart <- struct{}{}:
				default:
				}
			},
			Logger: logger.With("component", "update"),
		})
		srv.SetUpdater(upd)
		go upd.Run(ctx)
	}

	if err := srv.Start(ctx); err != nil {
		logger.Error("server failed to start", "error", err)
		_ = srv.Stop()
		db.Close()
		os.Exit(1)
	}
	logger.Info("SkyGuard running")

	restarting := false
	select {
	case <-ctx.Done():
		logger.Info("shutting down gracefully...")
	case <-restart:
		restarting = true
		logger.Info("restarting for the update...")
	}
	if err := srv.Stop(); err != nil {
		logger.Error("shutdown error", "error", err)
	}
	if restarting {
		db.Close()
		// Same process, same PID: systemd and Docker see no restart at all.
		err := update.Restart(base)
		logger.Error("could not restart in place; exiting so the service manager restarts SkyGuard", "error", err)
		os.Exit(75)
	}
	logger.Info("shutdown complete")
}

func runKeygen() int {
	pub, priv, err := update.GenerateKey()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Println("public key (commit it into internal/update/verify.go TrustedKeys, or set update.public_key):")
	fmt.Println("  " + pub)
	fmt.Println("private key (the repository secret SKYGUARD_SIGNING_KEY; keep no other copy online):")
	fmt.Println("  " + priv)
	return 0
}

func runSign(path string) int {
	key := os.Getenv("SKYGUARD_SIGNING_KEY")
	if key == "" {
		fmt.Fprintln(os.Stderr, "SKYGUARD_SIGNING_KEY is not set")
		return 1
	}
	b, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	sig, err := update.Sign(key, b)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Println(sig)
	return 0
}

// runHealthcheck returns 0 when the dashboard answers /healthz. With the
// dashboard disabled there is nothing to probe without generating fake
// honeypot traffic, so it reports healthy.
func runHealthcheck(cfg *config.Config) int {
	if !cfg.Dashboard.Enabled {
		return 0
	}
	host, port, err := net.SplitHostPort(cfg.Dashboard.Listen)
	if err != nil {
		return 1
	}
	if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
		host = "127.0.0.1"
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://" + net.JoinHostPort(host, port) + "/healthz")
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck:", err)
		return 1
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "healthcheck: status", resp.StatusCode)
		return 1
	}
	return 0
}

// setupLogger constructs a JSON structured logger at the requested level.
func setupLogger(level string) *slog.Logger {
	var l slog.Level
	switch strings.ToLower(level) {
	case "debug":
		l = slog.LevelDebug
	case "warn", "warning":
		l = slog.LevelWarn
	case "error":
		l = slog.LevelError
	default:
		l = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: l}))
}
