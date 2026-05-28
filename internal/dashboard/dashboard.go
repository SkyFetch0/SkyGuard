package dashboard

import (
	"context"
	"crypto/subtle"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/skyguard/skyguard/internal/config"
	"github.com/skyguard/skyguard/internal/firewall"
	"github.com/skyguard/skyguard/internal/storage"
)

// Dashboard serves a lightweight HTTP management interface.
type Dashboard struct {
	cfg      config.DashboardConfig
	db       *storage.DB
	fw       firewall.Firewall
	settings *storage.Settings
	logger   *slog.Logger
	server   *http.Server
}

// New creates a Dashboard instance. Call Start to begin serving.
func New(cfg config.DashboardConfig, db *storage.DB, fw firewall.Firewall, settings *storage.Settings, logger *slog.Logger) *Dashboard {
	return &Dashboard{
		cfg:      cfg,
		db:       db,
		fw:       fw,
		settings: settings,
		logger:   logger,
	}
}

// Start registers routes and launches the HTTP server in a background goroutine.
// It returns once the server is listening (or immediately on error).
func (d *Dashboard) Start(ctx context.Context) error {
	d.warnInsecureExposure()

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

// warnInsecureExposure logs loud warnings for risky configurations.
func (d *Dashboard) warnInsecureExposure() {
	host, _, err := net.SplitHostPort(d.cfg.Listen)
	if err != nil {
		host = d.cfg.Listen
	}
	ip := net.ParseIP(strings.TrimSpace(host))
	loopback := ip != nil && ip.IsLoopback()

	authSet := d.cfg.Auth.Username != "" && d.cfg.Auth.Password != ""

	if !loopback {
		d.logger.Warn("dashboard is NOT bound to loopback — it may be reachable from the network; prefer 127.0.0.1 + SSH tunnel",
			"listen", d.cfg.Listen)
	}
	if !authSet {
		d.logger.Warn("dashboard authentication is DISABLED — set dashboard.auth.username/password")
	}
	if authSet && (d.cfg.Auth.Password == "CHANGE_ME_NOW" || len(d.cfg.Auth.Password) < 8) {
		d.logger.Warn("dashboard password is weak or default — set a strong password in dashboard.auth.password")
	}
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
	mux.HandleFunc("/api/settings", d.handleSettings)

	var handler http.Handler = mux
	if d.cfg.Auth.Username != "" && d.cfg.Auth.Password != "" {
		handler = newAuthGuard(d.cfg.Auth.Username, d.cfg.Auth.Password, d.logger).wrap(handler)
	}
	// Security headers are applied to every response, including auth failures.
	return securityHeaders(handler)
}

// securityHeaders adds defensive HTTP headers (clickjacking, MIME sniffing,
// referrer leakage, and a CSP that limits resource origins).
func securityHeaders(next http.Handler) http.Handler {
	const csp = "default-src 'self'; script-src 'self' 'unsafe-inline'; " +
		"style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; " +
		"base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", csp)
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// authGuard performs HTTP Basic Auth with constant-time comparison, logs failed
// attempts, slows each failure down, and throttles sustained brute-force bursts.
type authGuard struct {
	username, password string
	logger             *slog.Logger
	mu                 sync.Mutex
	failures           []time.Time
}

const (
	authFailWindow    = time.Minute
	authFailThreshold = 15 // failures within the window before we hard-throttle
	authFailDelay     = 500 * time.Millisecond
)

func newAuthGuard(username, password string, logger *slog.Logger) *authGuard {
	return &authGuard{username: username, password: password, logger: logger}
}

func (a *authGuard) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Hard throttle if too many recent failures (brute-force burst).
		if a.tooManyFailures() {
			w.Header().Set("Retry-After", "60")
			http.Error(w, "too many authentication failures, slow down", http.StatusTooManyRequests)
			return
		}

		u, p, ok := r.BasicAuth()
		userMatch := subtle.ConstantTimeCompare([]byte(u), []byte(a.username))
		passMatch := subtle.ConstantTimeCompare([]byte(p), []byte(a.password))
		if !ok || userMatch != 1 || passMatch != 1 {
			a.recordFailure()
			a.logger.Warn("dashboard auth failed", "remote", clientIP(r), "user", u)
			time.Sleep(authFailDelay) // slow down brute force
			w.Header().Set("WWW-Authenticate", `Basic realm="SkyGuard"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *authGuard) recordFailure() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.failures = append(a.failures, time.Now())
}

func (a *authGuard) tooManyFailures() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	cutoff := time.Now().Add(-authFailWindow)
	kept := a.failures[:0]
	for _, t := range a.failures {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	a.failures = kept
	return len(a.failures) >= authFailThreshold
}

// clientIP extracts the remote IP for logging.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
