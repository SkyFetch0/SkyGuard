package server

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/skyguard/skyguard/internal/analysis"
	"github.com/skyguard/skyguard/internal/config"
	"github.com/skyguard/skyguard/internal/dashboard"
	"github.com/skyguard/skyguard/internal/firewall"
	"github.com/skyguard/skyguard/internal/honeypot"
	"github.com/skyguard/skyguard/internal/proxy"
	"github.com/skyguard/skyguard/internal/stealth"
	"github.com/skyguard/skyguard/internal/storage"
)

// maxConcurrentConns is the global cap on simultaneously handled connections.
// Prevents goroutine explosion under mass-connection DoS attacks.
const maxConcurrentConns = 4096

// Server manages all TCP listeners and dispatches incoming connections to the
// appropriate handler (stealth, honeypot, or passthrough).
type Server struct {
	cfg       *config.Config
	db        *storage.DB
	geoip     *analysis.GeoIPService
	limiter   *analysis.RateLimiter
	scorer    *analysis.Scorer
	detector  *analysis.Detector
	firewall  firewall.Firewall
	proxy     *proxy.Proxy
	dash      *dashboard.Dashboard
	logger    *slog.Logger
	listeners []net.Listener
	mu        sync.Mutex
	wg        sync.WaitGroup
	// sem throttles the number of concurrently handled connections.
	sem chan struct{}
}

// New initialises all sub-systems and returns a ready-to-start Server.
func New(cfg *config.Config, db *storage.DB, logger *slog.Logger) (*Server, error) {
	geoip, err := analysis.NewGeoIPService(
		cfg.Analysis.GeoIP.DBPath,
		cfg.Analysis.GeoIP.Enabled,
	)
	if err != nil {
		return nil, fmt.Errorf("geoip: %w", err)
	}

	limiter := analysis.NewRateLimiter(
		cfg.Analysis.RateLimit.MaxPerMinute,
		cfg.Analysis.RateLimit.MaxPerHour,
	)

	scorer := analysis.NewScorer(db, cfg.Analysis.AutoBan)

	// Zero values fall back to safe defaults (60s window, 5 ports) inside NewDetector.
	detector := analysis.NewDetector(cfg.Analysis.PortScan.Window, cfg.Analysis.PortScan.Threshold)

	fw, err := firewall.New(cfg.Analysis.AutoBan.Method, logger)
	if err != nil {
		return nil, fmt.Errorf("firewall: %w", err)
	}

	prx := proxy.New(logger)

	s := &Server{
		cfg:      cfg,
		db:       db,
		geoip:    geoip,
		limiter:  limiter,
		scorer:   scorer,
		detector: detector,
		firewall: fw,
		proxy:    prx,
		logger:   logger,
		sem:      make(chan struct{}, maxConcurrentConns),
	}

	if cfg.Dashboard.Enabled {
		s.dash = dashboard.New(cfg.Dashboard, db, fw, logger)
	}

	return s, nil
}

// Start opens all configured listeners and begins accepting connections.
// It blocks until ctx is cancelled.
func (s *Server) Start(ctx context.Context) error {
	eventLogger := honeypot.NewEventLogger(s.db, s.logger)
	// Score captured credentials and apply auto-ban on failed-credential events.
	eventLogger.OnCredential(func(sourceIP string) {
		_, _ = s.scorer.Record(sourceIP, "", analysis.EventFailedCredential, 0)
		s.shouldBanAndBan(sourceIP, "failed_credential")
	})

	// Stealth services.
	for _, svc := range s.cfg.Stealth {
		svc := svc
		if !svc.IsEnabled() {
			s.logger.Info("stealth service disabled, skipping", "name", svc.Name)
			continue
		}
		if len(svc.AllowedCountries) > 0 && !s.cfg.Analysis.GeoIP.Enabled {
			s.logger.Warn("stealth service has allowed_countries but GeoIP is disabled; country filter will not be enforced",
				"service", svc.Name)
		}
		addr := fmt.Sprintf("0.0.0.0:%d", svc.ListenPort)
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("stealth %q: listen %s: %w", svc.Name, addr, err)
		}
		s.addListener(ln)

		h := stealth.NewHandler(svc, s.proxy, s.db, s.logger.With("service", svc.Name))
		s.logger.Info("stealth listener started", "name", svc.Name, "addr", addr)

		s.wg.Add(1)
		go s.acceptLoop(ctx, ln, func(conn net.Conn) {
			s.handleConnection(conn, "stealth", h)
		})
	}

	// Honeypot services.
	for _, svc := range s.cfg.Honeypots {
		svc := svc
		if !svc.IsEnabled() {
			s.logger.Info("honeypot service disabled, skipping", "name", svc.Name)
			continue
		}
		addr := fmt.Sprintf("0.0.0.0:%d", svc.Port)
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("honeypot %q: listen %s: %w", svc.Name, addr, err)
		}
		s.addListener(ln)

		h, err := honeypot.NewHandler(svc, eventLogger)
		if err != nil {
			return fmt.Errorf("honeypot %q: %w", svc.Name, err)
		}
		s.logger.Info("honeypot listener started", "name", svc.Name, "type", svc.Type, "addr", addr)

		s.wg.Add(1)
		go s.acceptLoop(ctx, ln, func(conn net.Conn) {
			s.handleConnection(conn, "honeypot", h)
		})
	}

	// Passthrough services.
	for _, svc := range s.cfg.Passthrough {
		svc := svc
		addr := fmt.Sprintf("0.0.0.0:%d", svc.ListenPort)
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("passthrough %q: listen %s: %w", svc.Name, addr, err)
		}
		s.addListener(ln)

		s.logger.Info("passthrough listener started", "name", svc.Name, "addr", addr, "target", svc.RealTarget)

		target := svc.RealTarget
		s.wg.Add(1)
		go s.acceptLoop(ctx, ln, func(conn net.Conn) {
			s.handleConnection(conn, "passthrough", target)
		})
	}

	// Dashboard.
	if s.dash != nil {
		if err := s.dash.Start(ctx); err != nil {
			return fmt.Errorf("dashboard: %w", err)
		}
	}

	// Periodic maintenance: clean up expired bans once per hour.
	s.wg.Add(1)
	go s.cleanupLoop(ctx)

	return nil
}

// Stop closes all listeners and waits for in-flight goroutines to finish.
func (s *Server) Stop() error {
	s.mu.Lock()
	for _, ln := range s.listeners {
		ln.Close()
	}
	s.listeners = nil
	s.mu.Unlock()

	s.wg.Wait()

	// Release background analysis goroutines and the GeoIP reader.
	s.detector.Stop()
	s.limiter.Stop()
	s.geoip.Close()

	if s.dash != nil {
		return s.dash.Stop()
	}
	return nil
}

// addListener registers a listener under the server's mutex.
func (s *Server) addListener(ln net.Listener) {
	s.mu.Lock()
	s.listeners = append(s.listeners, ln)
	s.mu.Unlock()
}

// cleanupLoop runs once a minute. It lifts firewall rules for bans that have
// expired (so a temporary ban is actually released at the kernel level, not
// just removed from the DB), purges the expired ban rows, and enforces data
// retention. The 1-minute cadence keeps ban expiry reasonably prompt.
func (s *Server) cleanupLoop(ctx context.Context) {
	defer s.wg.Done()
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.releaseExpiredBans()

			// Enforce data retention so the database does not grow unbounded.
			if days := s.cfg.Logging.RetentionDays; days > 0 {
				if err := s.db.CleanOldConnections(days); err != nil {
					s.logger.Error("failed to clean old connections", "error", err)
				}
				if err := s.db.CleanOldCredentials(days); err != nil {
					s.logger.Error("failed to clean old credentials", "error", err)
				}
			}
		}
	}
}

// releaseExpiredBans removes the firewall rule for every expired ban before
// deleting the rows, so the actual block is lifted when the ban duration ends.
func (s *Server) releaseExpiredBans() {
	expired, err := s.db.GetExpiredBans()
	if err != nil {
		s.logger.Error("failed to list expired bans", "error", err)
		return
	}
	for _, ip := range expired {
		if err := s.firewall.UnbanIP(ip); err != nil {
			s.logger.Warn("failed to remove firewall rule for expired ban", "ip", ip, "error", err)
			continue
		}
		s.logger.Info("expired ban lifted from firewall", "ip", ip)
	}
	if err := s.db.CleanExpiredBans(); err != nil {
		s.logger.Error("failed to clean expired bans", "error", err)
	}
}

// acceptLoop accepts new TCP connections and dispatches each to handler in its
// own goroutine. It exits when the listener is closed or ctx is done.
// Transient errors (e.g. "too many open files") are logged and retried;
// only listener-closed errors cause a clean exit.
func (s *Server) acceptLoop(ctx context.Context, ln net.Listener, handler func(net.Conn)) {
	defer s.wg.Done()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				if strings.Contains(err.Error(), "use of closed network connection") {
					return
				}
				// Transient errors (EMFILE, ENFILE, temporary resource limits):
				// log and continue accepting rather than killing the listener.
				if isTemporaryError(err) {
					s.logger.Warn("transient accept error, retrying", "error", err)
					time.Sleep(5 * time.Millisecond)
					continue
				}
				s.logger.Error("accept error", "error", err)
				return
			}
		}

		// Acquire semaphore slot; drop the connection if at capacity.
		select {
		case s.sem <- struct{}{}:
		default:
			s.logger.Warn("connection limit reached, dropping connection",
				"remote", conn.RemoteAddr(), "limit", maxConcurrentConns)
			conn.Close()
			continue
		}

		s.wg.Add(1)
		go func(c net.Conn) {
			defer s.wg.Done()
			defer func() { <-s.sem }()
			handler(c)
		}(conn)
	}
}

// isTemporaryError reports whether err is a transient network error that
// the accept loop should retry rather than terminate on.
func isTemporaryError(err error) bool {
	type temporary interface{ Temporary() bool }
	if t, ok := err.(temporary); ok {
		return t.Temporary()
	}
	// Heuristic: "too many open files" is a well-known transient OS error.
	return strings.Contains(err.Error(), "too many open files")
}

// handleConnection applies shared security checks before routing the
// connection to the appropriate handler. portHandler must be one of:
//   - *stealth.Handler  (portType "stealth")
//   - honeypot.Handler  (portType "honeypot")
//   - string            (portType "passthrough" – the target address)
func (s *Server) handleConnection(conn net.Conn, portType string, portHandler interface{}) {
	defer func() {
		// Safety net: individual handlers are responsible for closing conn, but
		// we close here too so a panic or early return never leaks a fd.
		conn.Close()
	}()

	remoteAddr := conn.RemoteAddr().String()
	sourceIP, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		sourceIP = remoteAddr
	}
	// Normalize to canonical IP string so that IPv4-mapped IPv6 addresses
	// (e.g. "::ffff:1.2.3.4") compare equal to their plain IPv4 form.
	if parsed := net.ParseIP(sourceIP); parsed != nil {
		if v4 := parsed.To4(); v4 != nil {
			sourceIP = v4.String()
		} else {
			sourceIP = parsed.String()
		}
	}

	_, destPort, _ := net.SplitHostPort(conn.LocalAddr().String())

	// 1. Whitelist – always allow.
	for _, wIP := range s.cfg.Whitelist.IPs {
		// Normalize whitelist entry for comparison.
		if normalizeIP(wIP) == sourceIP {
			s.routeConnection(conn, portType, portHandler, sourceIP)
			return
		}
	}

	// 2. Blacklist / ban check.
	banned, err := s.db.IsBanned(sourceIP)
	if err != nil {
		s.logger.Error("ban check error", "ip", sourceIP, "error", err)
	}
	if banned {
		s.logger.Debug("dropping banned IP", "ip", sourceIP)
		_ = s.firewall.BanIP(sourceIP, s.cfg.Analysis.AutoBan.BanDuration)
		s.logConn(sourceIP, destPort, "", "", portType, "dropped", "banned")
		return
	}

	// 3. Manual blacklist IPs.
	for _, blIP := range s.cfg.Blacklist.IPs {
		if normalizeIP(blIP) == sourceIP {
			s.logConn(sourceIP, destPort, "", "", portType, "dropped", "blacklisted_ip")
			return
		}
	}

	// 4. GeoIP lookup.
	geo := s.geoip.Lookup(sourceIP)
	country := geo.CountryCode
	city := geo.City

	// 4a. Stealth service allowed_countries enforcement.
	if portType == "stealth" {
		if h, ok := portHandler.(*stealth.Handler); ok {
			if !h.IsCountryAllowed(country) {
				s.logger.Info("stealth: country not in allowed list, dropping",
					"ip", sourceIP, "country", country, "service", h.Name())
				s.logConn(sourceIP, destPort, country, city, portType, "dropped", "country_not_allowed")
				return
			}
		}
	}

	// Whitelist countries – pass immediately.
	for _, wc := range s.cfg.Whitelist.Countries {
		if strings.EqualFold(wc, country) {
			s.logConn(sourceIP, destPort, country, city, portType, "forwarded", "whitelisted_country")
			s.routeConnection(conn, portType, portHandler, sourceIP)
			return
		}
	}

	// Blacklisted countries.
	for _, bc := range s.cfg.Blacklist.Countries {
		if strings.EqualFold(bc, country) {
			s.logger.Info("dropping blacklisted country", "ip", sourceIP, "country", country)
			_, _ = s.scorer.Record(sourceIP, country, analysis.EventBlacklistedCountry, 0)
			s.shouldBanAndBan(sourceIP, "blacklisted_country")
			s.logConn(sourceIP, destPort, country, city, portType, "dropped", "blacklisted_country")
			return
		}
	}

	// Steps 5-7 (rate-limit, port-scan, behavioural scoring) drive auto-ban.
	// Passthrough forwards real production traffic (e.g. a website), where many
	// connections per client are normal — applying these here would ban real
	// users. Passthrough therefore only honours the explicit deny lists above
	// (manual ban, blacklist IP/country) and skips the heuristic ban triggers.
	if portType != "passthrough" {
		// 5. Rate limit.
		if !s.limiter.Check(sourceIP) {
			s.logger.Info("rate limit exceeded", "ip", sourceIP)
			_, _ = s.scorer.Record(sourceIP, country, analysis.EventRateLimitExceeded, 0)
			s.shouldBanAndBan(sourceIP, "rate_limit_exceeded")
			s.logConn(sourceIP, destPort, country, city, portType, "dropped", "rate_limited")
			return
		}

		// 6. Port-scan detection.
		port := parsePort(destPort)
		if s.detector.RecordPort(sourceIP, port) {
			s.logger.Info("port scan detected", "ip", sourceIP)
			_, _ = s.scorer.Record(sourceIP, country, analysis.EventPortScan, port)
			s.shouldBanAndBan(sourceIP, "port_scan")
			s.logConn(sourceIP, destPort, country, city, portType, "dropped", "port_scan")
			return
		}

		// 7. Scoring for honeypot connections.
		if portType == "honeypot" {
			_, _ = s.scorer.Record(sourceIP, country, analysis.EventHoneypotConnection, port)
			s.shouldBanAndBan(sourceIP, "honeypot_threshold")
		}
	}

	// 8. Connection log. Honeypot handlers write their own richer connection
	//    record (with captured banner/path/data), so we skip here to avoid
	//    double-counting honeypot hits in the stats.
	if portType != "honeypot" {
		s.logConn(sourceIP, destPort, country, city, portType, portType, "")
	}

	// 9. Route to appropriate handler.
	s.routeConnection(conn, portType, portHandler, sourceIP)
}

// normalizeIP parses and normalizes an IP string, converting IPv4-mapped
// IPv6 addresses to their plain IPv4 form. Returns the original string on error.
func normalizeIP(s string) string {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil {
		return s
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}

// routeConnection dispatches conn to the correct handler type.
func (s *Server) routeConnection(conn net.Conn, portType string, portHandler interface{}, sourceIP string) {
	switch portType {
	case "stealth":
		h := portHandler.(*stealth.Handler)
		if err := h.Handle(conn, sourceIP); err != nil {
			s.logger.Debug("stealth handler error", "ip", sourceIP, "error", err)
		}

	case "honeypot":
		h := portHandler.(honeypot.Handler)
		if err := h.Handle(conn, sourceIP); err != nil {
			s.logger.Debug("honeypot handler error", "ip", sourceIP, "error", err)
		}

	case "passthrough":
		target := portHandler.(string)
		if err := s.proxy.Forward(conn, target); err != nil {
			s.logger.Debug("passthrough error", "ip", sourceIP, "target", target, "error", err)
		}
	}
}

// shouldBanAndBan checks the current score for ip and applies a ban if the
// auto-ban threshold has been reached.
func (s *Server) shouldBanAndBan(ip, reason string) {
	if !s.cfg.Analysis.AutoBan.Enabled {
		return
	}
	should, err := s.scorer.ShouldBan(ip)
	if err != nil {
		s.logger.Error("scorer error", "ip", ip, "error", err)
		return
	}
	if !should {
		return
	}

	dur := s.cfg.Analysis.AutoBan.BanDuration
	if err := s.db.BanIP(ip, reason, dur, false); err != nil {
		s.logger.Error("db ban error", "ip", ip, "error", err)
	}
	if err := s.firewall.BanIP(ip, dur); err != nil {
		s.logger.Error("firewall ban error", "ip", ip, "error", err)
	}
	s.logger.Info("auto-ban applied", "ip", ip, "reason", reason, "duration", dur)
}

// logConn is a convenience wrapper around db.LogConnection.
func (s *Server) logConn(sourceIP, destPort, country, city, serviceType, action, data string) {
	port := parsePort(destPort)
	if err := s.db.LogConnection(&storage.Connection{
		SourceIP:    sourceIP,
		DestPort:    port,
		Country:     country,
		City:        city,
		ServiceType: serviceType,
		Action:      action,
		Data:        data,
	}); err != nil {
		s.logger.Error("log connection error", "error", err)
	}
}

// parsePort converts a port string to int, returning 0 on error.
func parsePort(s string) int {
	var p int
	fmt.Sscanf(s, "%d", &p)
	return p
}
