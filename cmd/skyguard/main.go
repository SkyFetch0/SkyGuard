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
	"strings"
	"syscall"
	"time"

	"github.com/skyguard/skyguard/internal/config"
	"github.com/skyguard/skyguard/internal/dashboard"
	"github.com/skyguard/skyguard/internal/server"
	"github.com/skyguard/skyguard/internal/storage"
)

// Version is injected at build time via -ldflags "-X main.Version=x.y.z".
var Version = "dev"

const defaultConfigPath = "/etc/skyguard/skyguard.yaml"

func main() {
	configPath := flag.String("config", defaultConfigPath, "config file path (env SKYGUARD_CONFIG is used when the flag is not given)")
	checkOnly := flag.Bool("check-config", false, "validate the config file and exit")
	healthcheck := flag.Bool("healthcheck", false, "probe the running instance's dashboard /healthz and exit 0/1 (for Docker HEALTHCHECK)")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("skyguard", Version)
		return
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

	logger := setupLogger("info")

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
	logger.Info("SkyGuard starting", "version", Version, "config", *configPath)

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

	if err := srv.Start(ctx); err != nil {
		logger.Error("server failed to start", "error", err)
		_ = srv.Stop()
		db.Close()
		os.Exit(1)
	}
	logger.Info("SkyGuard running")

	<-ctx.Done()
	logger.Info("shutting down gracefully...")
	if err := srv.Stop(); err != nil {
		logger.Error("shutdown error", "error", err)
	}
	logger.Info("shutdown complete")
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
