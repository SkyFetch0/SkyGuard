package dashboard

import (
	"context"
	"crypto/subtle"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/skyguard/skyguard/internal/config"
	"github.com/skyguard/skyguard/internal/firewall"
	"github.com/skyguard/skyguard/internal/storage"
)

// Dashboard serves a lightweight HTTP management interface.
type Dashboard struct {
	cfg    config.DashboardConfig
	db     *storage.DB
	fw     firewall.Firewall
	logger *slog.Logger
	server *http.Server
}

// New creates a Dashboard instance. Call Start to begin serving.
func New(cfg config.DashboardConfig, db *storage.DB, fw firewall.Firewall, logger *slog.Logger) *Dashboard {
	return &Dashboard{
		cfg:    cfg,
		db:     db,
		fw:     fw,
		logger: logger,
	}
}

// Start registers routes and launches the HTTP server in a background goroutine.
// It returns once the server is listening (or immediately on error).
func (d *Dashboard) Start(ctx context.Context) error {
	d.server = &http.Server{
		Addr:         d.cfg.Listen,
		Handler:      d.routes(),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Listen first so we can return an error if the address is already in use.
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", d.cfg.Listen)
	if err != nil {
		return err
	}

	d.logger.Info("dashboard started", "addr", d.cfg.Listen)

	go func() {
		if err := d.server.Serve(ln); err != nil && err != http.ErrServerClosed {
			d.logger.Error("dashboard server error", "error", err)
		}
	}()

	return nil
}

// Stop gracefully shuts down the HTTP server with a 5-second deadline.
func (d *Dashboard) Stop() error {
	if d.server == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return d.server.Shutdown(ctx)
}

// routes builds and returns the HTTP mux with all dashboard endpoints.
func (d *Dashboard) routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/", d.handleIndex)
	mux.HandleFunc("/api/stats", d.handleStats)
	mux.HandleFunc("/api/connections", d.handleConnections)
	mux.HandleFunc("/api/banned", d.handleBanned)
	mux.HandleFunc("/api/attackers", d.handleAttackers)
	mux.HandleFunc("/api/credentials", d.handleCredentials)
	mux.HandleFunc("/api/firewall", d.handleFirewall)
	mux.HandleFunc("/api/ban", d.handleBan)
	mux.HandleFunc("/api/unban", d.handleUnban)

	if d.cfg.Auth.Username != "" && d.cfg.Auth.Password != "" {
		return basicAuthMiddleware(d.cfg.Auth.Username, d.cfg.Auth.Password, mux)
	}
	d.logger.Warn("dashboard authentication is DISABLED (no username/password configured) — anyone who can reach the listen address has full access")
	return mux
}

// basicAuthMiddleware wraps next with HTTP Basic Authentication.
// Uses constant-time comparison to prevent timing-based credential enumeration.
func basicAuthMiddleware(username, password string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		// Always perform both comparisons to avoid short-circuit timing leaks.
		userMatch := subtle.ConstantTimeCompare([]byte(u), []byte(username))
		passMatch := subtle.ConstantTimeCompare([]byte(p), []byte(password))
		if !ok || userMatch != 1 || passMatch != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="SkyGuard"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}