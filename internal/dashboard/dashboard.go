package dashboard

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/skyguard/skyguard/internal/config"
	"github.com/skyguard/skyguard/internal/containers"
	"github.com/skyguard/skyguard/internal/firewall"
	"github.com/skyguard/skyguard/internal/netutil"
	"github.com/skyguard/skyguard/internal/portrules"
	"github.com/skyguard/skyguard/internal/storage"
	"github.com/skyguard/skyguard/internal/update"
)

//go:embed static
var staticFiles embed.FS

// BanManager applies and lifts bans consistently (database, firewall, score
// reset, whitelist protection). It is implemented by the server.
type BanManager interface {
	BanIP(ip, reason string, duration time.Duration, permanent bool) error
	UnbanIP(ip string) error
	IsWhitelisted(ip string) bool
}

// ServiceStatus describes one configured listener for the services screen.
type ServiceStatus struct {
	Name          string `json:"name"`
	Kind          string `json:"kind"` // honeypot, stealth, passthrough
	Type          string `json:"type"` // ssh, ftp, mysql, http for honeypots
	Port          int    `json:"port"`
	Target        string `json:"target,omitempty"`
	Enabled       bool   `json:"enabled"`
	ConfigEnabled bool   `json:"config_enabled"`
	Running       bool   `json:"running"`
	Toggleable    bool   `json:"toggleable"`
	Active        int    `json:"active_connections"`
	Error         string `json:"error,omitempty"`
}

// Controller is what the dashboard needs from the running server.
type Controller interface {
	BanManager
	Services() []ServiceStatus
	SetServiceEnabled(name string, enabled bool) error
}

// Dashboard serves a lightweight HTTP management interface.
type Dashboard struct {
	cfg      config.DashboardConfig
	db       *storage.DB
	fw       firewall.Firewall
	settings *storage.Settings
	bans     Controller
	ctr      *containers.Manager // nil unless the config enables an engine
	ports    *portrules.Manager  // nil until the server sets it
	upd      *update.Manager     // nil until main sets it
	mcp      *mcpService
	logger   *slog.Logger
	server   *http.Server

	portListeners func(context.Context) []portrules.Listener
}

// New creates a Dashboard instance. Call Start to begin serving.
func New(cfg config.DashboardConfig, db *storage.DB, fw firewall.Firewall, settings *storage.Settings, ctl Controller, logger *slog.Logger) *Dashboard {
	d := &Dashboard{cfg: cfg, db: db, fw: fw, settings: settings, bans: ctl, logger: logger}
	d.mcp = newMCPService(d)
	return d
}

// Start launches the HTTP server in a background goroutine. It returns an
// error if the address cannot be bound or the configuration is unsafe.
func (d *Dashboard) Start(ctx context.Context) error {
	if err := d.checkExposure(); err != nil {
		return err
	}

	d.server = &http.Server{
		Addr:              d.cfg.Listen,
		Handler:           d.routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      60 * time.Second, // CSV exports can be large
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}

	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", d.cfg.Listen)
	if err != nil {
		return err
	}
	d.logger.Info("dashboard started", "addr", d.cfg.Listen)

	go func() {
		if err := d.server.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			d.logger.Error("dashboard server error", "error", err)
		}
	}()
	return nil
}

// checkExposure refuses to expose an unauthenticated (or default-password)
// admin panel beyond loopback, and warns about weaker setups.
func (d *Dashboard) checkExposure() error {
	host, _, err := net.SplitHostPort(d.cfg.Listen)
	if err != nil {
		host = d.cfg.Listen
	}
	ip := net.ParseIP(strings.TrimSpace(host))
	loopback := ip != nil && ip.IsLoopback()
	if host == "localhost" {
		loopback = true
	}

	authSet := d.cfg.Auth.Username != "" && d.cfg.Auth.Password != ""
	weak := authSet && (d.cfg.Auth.Password == "CHANGE_ME_NOW" || len(d.cfg.Auth.Password) < 8)

	if !loopback {
		if !authSet {
			return fmt.Errorf("refusing to serve the dashboard on %s without authentication; set dashboard.auth or bind to 127.0.0.1", d.cfg.Listen)
		}
		if weak {
			return fmt.Errorf("refusing to serve the dashboard on %s with a weak/default password; set a strong dashboard.auth.password", d.cfg.Listen)
		}
		d.logger.Warn("dashboard is NOT bound to loopback; prefer 127.0.0.1 + SSH tunnel", "listen", d.cfg.Listen)
	}
	if !authSet {
		d.logger.Warn("dashboard authentication is DISABLED — set dashboard.auth.username/password")
	} else if weak {
		d.logger.Warn("dashboard password is weak or the example default — change dashboard.auth.password")
	}
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

// routes builds the HTTP handler with all dashboard endpoints.
func (d *Dashboard) routes() http.Handler {
	api := http.NewServeMux()
	api.HandleFunc("GET /{$}", d.handleStatic("static/index.html", "text/html; charset=utf-8"))
	assets, _ := fs.Sub(staticFiles, "static/assets")
	api.Handle("GET /assets/", http.StripPrefix("/assets/", http.FileServerFS(assets)))
	api.HandleFunc("GET /api/stats", d.handleStats)
	api.HandleFunc("GET /api/info", d.handleInfo)
	api.HandleFunc("GET /api/summary", d.handleSummary)
	api.HandleFunc("GET /api/series", d.handleSeries)
	api.HandleFunc("GET /api/credentials/breakdown", d.handleCredentialBreakdown)
	api.HandleFunc("GET /api/services", d.handleServices)
	api.HandleFunc("POST /api/services", d.csrf(d.handleSetService))
	api.HandleFunc("GET /api/timeline", d.handleTimeline)
	api.HandleFunc("GET /api/connections", d.handleConnections)
	api.HandleFunc("GET /api/search", d.handleConnections) // backward-compatible alias
	api.HandleFunc("GET /api/export", d.handleExport)
	api.HandleFunc("GET /api/banned", d.handleBanned)
	api.HandleFunc("GET /api/attackers", d.handleAttackers)
	api.HandleFunc("GET /api/credentials", d.handleCredentials)
	api.HandleFunc("GET /api/ip", d.handleIPDetail)
	api.HandleFunc("GET /api/firewall", d.handleFirewall)
	api.HandleFunc("GET /api/settings", d.handleGetSettings)
	api.HandleFunc("POST /api/settings", d.csrf(d.handlePostSettings))
	api.HandleFunc("POST /api/ban", d.csrf(d.handleBan))
	api.HandleFunc("POST /api/unban", d.csrf(d.handleUnban))
	d.containerRoutes(api)
	d.portRoutes(api)
	d.updateRoutes(api)
	d.mcpRoutes(api)

	var protected http.Handler = api
	if d.cfg.Auth.Username != "" && d.cfg.Auth.Password != "" {
		protected = newAuthGuard(d.cfg.Auth.Username, d.cfg.Auth.Password, d.logger).wrap(api)
	}

	root := http.NewServeMux()
	// Unauthenticated liveness probe for Docker / systemd health checks, so
	// the password never has to be embedded in a compose file.
	root.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok\n"))
	})
	// The MCP endpoint has its own bearer token (an AI client cannot do the
	// browser's Basic Auth dance) and is off until switched on in Settings.
	root.Handle("/mcp", d.mcp)
	root.Handle("/", protected)
	return securityHeaders(root)
}

func (d *Dashboard) handleStatic(name, contentType string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		b, err := staticFiles.ReadFile(name)
		if err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", contentType)
		_, _ = w.Write(b)
	}
}

// securityHeaders adds defensive HTTP headers. All JavaScript lives in
// /assets, so scripts are restricted to 'self' (no inline script execution).
func securityHeaders(next http.Handler) http.Handler {
	const csp = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; " +
		"img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
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

// csrf protects state-changing endpoints. Browsers cannot attach a custom
// header to a cross-site request without a CORS preflight, which we never
// approve, so requiring it blocks CSRF even though Basic Auth credentials are
// sent automatically. Request bodies are capped as well.
func (d *Dashboard) csrf(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-SkyGuard-Request") == "" {
			writeError(w, http.StatusForbidden, "missing X-SkyGuard-Request header")
			return
		}
		if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
			writeError(w, http.StatusForbidden, "cross-site request rejected")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		next(w, r)
	}
}

// authGuard performs HTTP Basic Auth with constant-time comparison and
// throttles brute force per client IP (a global counter would let any
// attacker lock the real admin out).
type authGuard struct {
	userHash, passHash [32]byte
	logger             *slog.Logger

	mu       sync.Mutex
	failures map[string][]time.Time
}

const (
	authFailWindow    = 5 * time.Minute
	authFailThreshold = 10
	authFailDelay     = 500 * time.Millisecond
)

func newAuthGuard(username, password string, logger *slog.Logger) *authGuard {
	return &authGuard{
		userHash: sha256.Sum256([]byte(username)),
		passHash: sha256.Sum256([]byte(password)),
		logger:   logger,
		failures: make(map[string][]time.Time),
	}
}

func (a *authGuard) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := netutil.HostIP(r.RemoteAddr)
		if a.tooManyFailures(ip) {
			w.Header().Set("Retry-After", "300")
			http.Error(w, "too many authentication failures, try again later", http.StatusTooManyRequests)
			return
		}

		u, p, ok := r.BasicAuth()
		// Hashing first makes the comparison constant-time regardless of length.
		uh, ph := sha256.Sum256([]byte(u)), sha256.Sum256([]byte(p))
		userOK := subtle.ConstantTimeCompare(uh[:], a.userHash[:]) == 1
		passOK := subtle.ConstantTimeCompare(ph[:], a.passHash[:]) == 1
		if !ok || !userOK || !passOK {
			if ok { // a browser's first credential-less probe is not a failure
				a.recordFailure(ip)
				a.logger.Warn("dashboard auth failed", "remote", ip, "user", u)
				time.Sleep(authFailDelay)
			}
			w.Header().Set("WWW-Authenticate", `Basic realm="SkyGuard", charset="UTF-8"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		a.clearFailures(ip)
		next.ServeHTTP(w, r)
	})
}

func (a *authGuard) recordFailure(ip string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.failures[ip] = append(a.failures[ip], time.Now())
	if len(a.failures) > 10000 { // bound memory under a distributed attack
		a.pruneLocked()
	}
}

func (a *authGuard) clearFailures(ip string) {
	a.mu.Lock()
	delete(a.failures, ip)
	a.mu.Unlock()
}

func (a *authGuard) tooManyFailures(ip string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	cutoff := time.Now().Add(-authFailWindow)
	kept := a.failures[ip][:0]
	for _, t := range a.failures[ip] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) == 0 {
		delete(a.failures, ip)
		return false
	}
	a.failures[ip] = kept
	return len(kept) >= authFailThreshold
}

func (a *authGuard) pruneLocked() {
	cutoff := time.Now().Add(-authFailWindow)
	for ip, ts := range a.failures {
		if len(ts) == 0 || ts[len(ts)-1].Before(cutoff) {
			delete(a.failures, ip)
		}
	}
}
