package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/skyguard/skyguard/internal/config"
	"github.com/skyguard/skyguard/internal/server"
	"github.com/skyguard/skyguard/internal/storage"
)

// Version is injected at build time via -ldflags "-X main.Version=x.y.z".
var Version = "dev"

func main() {
	configPath := flag.String("config", "/etc/skyguard/skyguard.yaml", "config file path")
	flag.Parse()

	// Environment variable overrides the flag.
	if envPath := os.Getenv("SKYGUARD_CONFIG"); envPath != "" {
		configPath = &envPath
	}

	// Bootstrap with a default logger until we know the configured level.
	logger := setupLogger("info")
	logger.Info("SkyGuard starting", "version", Version)

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		logger.Error("failed to load config", "path", *configPath, "error", err)
		os.Exit(1)
	}

	// Recreate logger with the level from config.
	logger = setupLogger(cfg.General.LogLevel)

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
		os.Exit(1)
	}

	logger.Info("SkyGuard running – press Ctrl+C to stop")

	<-ctx.Done()

	logger.Info("shutting down gracefully...")
	if err := srv.Stop(); err != nil {
		logger.Error("shutdown error", "error", err)
	}
	logger.Info("shutdown complete")
}

// setupLogger constructs a JSON structured logger at the requested level.
func setupLogger(level string) *slog.Logger {
	var l slog.Level
	switch level {
	case "debug":
		l = slog.LevelDebug
	case "warn":
		l = slog.LevelWarn
	case "error":
		l = slog.LevelError
	default:
		l = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: l}))
}