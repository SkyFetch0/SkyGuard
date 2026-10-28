package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/skyguard/skyguard/internal/analysis"
	"github.com/skyguard/skyguard/internal/config"
	"github.com/skyguard/skyguard/internal/containers"
	"github.com/skyguard/skyguard/internal/dashboard"
	"github.com/skyguard/skyguard/internal/firewall"
	"github.com/skyguard/skyguard/internal/honeypot"
	"github.com/skyguard/skyguard/internal/netutil"
	"github.com/skyguard/skyguard/internal/portrules"
	"github.com/skyguard/skyguard/internal/proxy"
	"github.com/skyguard/skyguard/internal/stealth"
	"github.com/skyguard/skyguard/internal/storage"
)

// maxConcurrentConns is the global cap on simultaneously handled connections.
// Prevents goroutine explosion under mass-connection DoS attacks.
const maxConcurrentConns = 4096

// Service kinds.
const (
	kindStealth     = "stealth"
	kindHoneypot    = "honeypot"
	kindPassthrough = "passthrough"
)

// service is one configured listener and the handler behind it.
type service struct {
	kind     string
	name     string
	port     int
	stealth  *stealth.Handler
	honeypot honeypot.Handler
	target   string // passthrough backend
}

// label is the service_type stored with connection rows: the honeypot
// protocol ("ssh", "ftp", ...) or the service kind.
func (svc service) label() string {
	if svc.kind == kindHoneypot && svc.honeypot != nil {
		return svc.honeypot.Type()
	}
	return svc.kind
}

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
	settings  *storage.Settings
	logger    *slog.Logger
	whitelist *netutil.IPSet
	blacklist *netutil.IPSet
	ports     *portrules.Manager
	portGuard *firewall.PortGuard // nil without a usable iptables
	ctr       *containers.Manager // nil without the dashboard

	eventLogger *honeypot.EventLogger

	mu       sync.Mutex
	services []*svcRuntime
	conns    map[net.Conn]struct{}
	stopping bool

	wg     sync.WaitGroup
	sem    chan struct{}
	ctx    context.Context
	cancel context.CancelFunc
}

// New initialises all sub-systems and returns a ready-to-start Server.
func New(cfg *config.Config, db *storage.DB, logger *slog.Logger) (*Server, error) {
	geoip, err := analysis.NewGeoIPService(cfg.Analysis.GeoIP.DBPath, cfg.Analysis.GeoIP.Enabled)
	if err != nil {
		logger.Warn("GeoIP database could not be opened; country features are disabled",
			"path", cfg.Analysis.GeoIP.DBPath, "error", err)
	}

	fw, err := firewall.New(cfg.Analysis.AutoBan.Method,
		firewall.Options{IPTablesBackend: cfg.Analysis.AutoBan.IPTablesBackend}, logger)
	if err != nil {
		geoip.Close()
		return nil, fmt.Errorf("firewall: %w", err)
	}

	// Runtime settings: the dashboard can change auto-ban params without a
	// restart; editing the config file takes precedence again.
	settings, err := db.LoadSettings(storage.AutoBanSettings{
		Enabled:        cfg.Analysis.AutoBan.Enabled,
		ScoreThreshold: cfg.Analysis.AutoBan.ScoreThreshold,
		BanDuration:    cfg.Analysis.AutoBan.BanDuration,
	})
	if err != nil {
		geoip.Close()
		return nil, fmt.Errorf("loading settings: %w", err)
	}

	s := &Server{
		cfg:      cfg,
		db:       db,
		geoip:    geoip,
		limiter:  analysis.NewRateLimiter(cfg.Analysis.RateLimit.MaxPerMinute, cfg.Analysis.RateLimit.MaxPerHour),
		scorer:   analysis.NewScorer(db, cfg.Analysis.AutoBan.Scoring),
		detector: analysis.NewDetector(cfg.Analysis.PortScan.Window, cfg.Analysis.PortScan.Threshold),
		firewall: fw,
		proxy:    proxy.New(logger),
		settings: settings,
		logger:   logger,
		// Loopback is always trusted: SkyGuard's own health checks and the
		// stealth proxy's backend connections must never be scored or banned.
		whitelist: netutil.NewIPSet(append([]string{"127.0.0.0/8", "::1"}, cfg.Whitelist.IPs...)),
		blacklist: netutil.NewIPSet(cfg.Blacklist.IPs),
		conns:     make(map[net.Conn]struct{}),
		sem:       make(chan struct{}, maxConcurrentConns),
	}

	s.ports = s.portRules()
	if cfg.Dashboard.Enabled {
		s.dash = dashboard.New(cfg.Dashboard, db, fw, settings, s, logger)
		s.ctr = s.containerManager()
		s.dash.SetContainers(s.ctr)
		s.dash.SetPortRules(s.ports, s.PortListeners)
	}
	s.warnRiskyConfig()
	return s, nil
}

func (s *Server) warnRiskyConfig() {
	ownIPs := 0
	for _, e := range s.cfg.Whitelist.IPs {
		if set := netutil.NewIPSet([]string{e}); !set.Contains("127.0.0.1") && !set.Contains("::1") {
			ownIPs++
		}
	}
	if s.settings.AutoBan().Enabled && ownIPs == 0 {
		s.logger.Warn("auto-ban is enabled but the whitelist only holds loopback addresses; " +
			"add your own IP to whitelist.ips so you cannot lock yourself out")
	}
	if !s.geoip.Enabled() {
		if len(s.cfg.Blacklist.Countries) > 0 || len(s.cfg.Whitelist.Countries) > 0 {
			s.logger.Warn("country white/blacklists are configured but GeoIP is disabled; they will not match anything")
		}
		for _, svc := range s.cfg.Stealth {
			if svc.IsEnabled() && len(svc.AllowedCountries) > 0 {
				s.logger.Warn("stealth service has allowed_countries but GeoIP is disabled; the country filter is NOT enforced",
					"service", svc.Name)
			}
		}
	}
}

// Start opens all configured listeners and begins accepting connections.
// It returns once everything is listening; call Stop to shut down.
func (s *Server) Start(ctx context.Context) error {
	ctx, s.cancel = context.WithCancel(ctx)

	eventLogger := honeypot.NewEventLogger(s.db, s.logger, s.cfg.Logging.LogFirstBytes)
	eventLogger.OnCredential(func(sess honeypot.Session) {
		if s.IsWhitelisted(sess.IP) {
			return
		}
		score, err := s.scorer.Record(sess.IP, sess.Country, analysis.EventFailedCredential, sess.Port)
		if err != nil {
			s.logger.Error("scoring failed", "ip", sess.IP, "error", err)
			return
		}
		s.maybeAutoBan(sess.IP, score, "failed_credential")
	})

	s.eventLogger = eventLogger
	s.ctx = ctx

	if err := s.buildServices(); err != nil {
		return err
	}
	s.mu.Lock()
	for _, rt := range s.services {
		if !rt.enabled {
			s.logger.Info("service disabled, skipping", "kind", rt.kind, "name", rt.name)
			continue
		}
		if err := s.startListenerLocked(ctx, rt); err != nil {
			if rt.cfgEnabled {
				s.mu.Unlock()
				return err
			}
			// Switched on from the dashboard only: report it there instead
			// of refusing to start the whole server.
			s.logger.Error("honeypot enabled from the dashboard could not start", "name", rt.name, "error", err)
		}
	}
	s.mu.Unlock()

	// Re-apply bans that are still active: firewall rules do not survive a
	// reboot (or a container restart without persistence), the database does.
	s.syncBans()
	// A rule set the firewall refuses is reported, not fatal: the honeypots
	// and the dashboard (where it can be fixed) still start.
	if err := s.ports.Start(); err != nil {
		s.logger.Error("port access rules are not in force", "error", err)
	}

	if s.dash != nil {
		if err := s.dash.Start(ctx); err != nil {
			return fmt.Errorf("dashboard: %w", err)
		}
	}

	s.wg.Add(1)
	go s.maintenanceLoop(ctx)
	return nil
}

// listenHint turns the two most common listen failures into actionable advice.
func listenHint(err error, port int) string {
	switch {
	case errors.Is(err, syscall.EADDRINUSE):
		if port == 22 {
			return " (port 22 is still used by the real sshd — move sshd first, see scripts/enable-ssh-honeypot.sh)"
		}
		return " (another process already listens on this port; check with: ss -tlnp)"
	case errors.Is(err, syscall.EACCES):
		return " (ports below 1024 need root or CAP_NET_BIND_SERVICE)"
	}
	return ""
}

// Stop closes all listeners and active connections, then waits for every
// goroutine to finish. Long-lived proxied sessions are closed rather than
// waited for, so shutdown cannot hang.
func (s *Server) Stop() error {
	s.mu.Lock()
	s.stopping = true
	for _, rt := range s.services {
		if rt.ln != nil {
			rt.ln.Close()
			rt.ln = nil
		}
	}
	for c := range s.conns {
		c.Close()
	}
	s.mu.Unlock()

	if s.cancel != nil {
		s.cancel()
	}

	var dashErr error
	if s.dash != nil {
		dashErr = s.dash.Stop()
	}

	s.wg.Wait()
	s.detector.Stop()
	s.limiter.Stop()
	s.geoip.Close()
	return dashErr
}

// track registers conn for forced close on shutdown; it returns false when
// the server is already stopping.
func (s *Server) track(conn net.Conn, rt *svcRuntime) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopping {
		return false
	}
	s.conns[conn] = struct{}{}
	if rt.conns != nil {
		rt.conns[conn] = struct{}{}
	}
	return true
}

func (s *Server) untrack(conn net.Conn, rt *svcRuntime) {
	s.mu.Lock()
	delete(s.conns, conn)
	delete(rt.conns, conn)
	s.mu.Unlock()
}

// maintenanceLoop lifts expired bans and re-checks the port rules every
// minute, and enforces data retention every hour.
func (s *Server) maintenanceLoop(ctx context.Context) {
	defer s.wg.Done()

	s.releaseExpiredBans()
	s.enforceRetention()

	banTicker := time.NewTicker(time.Minute)
	defer banTicker.Stop()
	retentionTicker := time.NewTicker(time.Hour)
	defer retentionTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-banTicker.C:
			s.releaseExpiredBans()
			s.ports.Maintain()
		case <-retentionTicker.C:
			s.enforceRetention()
		}
	}
}

func (s *Server) enforceRetention() {
	days := s.cfg.Logging.RetentionDays
	if days <= 0 {
		return
	}
	if n, err := s.db.CleanOldConnections(days); err != nil {
		s.logger.Error("failed to clean old connections", "error", err)
	} else if n > 0 {
		s.logger.Info("retention: deleted old connections", "rows", n)
	}
	if n, err := s.db.CleanOldCredentials(days); err != nil {
		s.logger.Error("failed to clean old credentials", "error", err)
	} else if n > 0 {
		s.logger.Info("retention: deleted old credentials", "rows", n)
	}
}

// releaseExpiredBans removes the firewall rule for every expired ban before
// deleting its row, so a temporary ban is actually lifted at the kernel level.
// If the firewall call fails the row is kept and retried next minute;
// deleting it anyway would silently turn the ban into a permanent one.
func (s *Server) releaseExpiredBans() {
	expired, err := s.db.GetExpiredBans()
	if err != nil {
		s.logger.Error("failed to list expired bans", "error", err)
		return
	}
	for _, ip := range expired {
		if err := s.firewall.Unban(ip); err != nil {
			s.logger.Warn("failed to remove firewall rule for expired ban; will retry", "ip", ip, "error", err)
			continue
		}
		if err := s.db.DeleteExpiredBan(ip); err != nil {
			s.logger.Error("failed to delete expired ban", "ip", ip, "error", err)
			continue
		}
		// Start from a clean slate; otherwise the first event after expiry
		// would immediately re-ban because the old score is still above the
		// threshold.
		if err := s.db.ResetScore(ip); err != nil {
			s.logger.Error("failed to reset score", "ip", ip, "error", err)
		}
		s.logger.Info("expired ban lifted", "ip", ip)
	}
}

// syncBans re-applies every active ban to the firewall and drops bans that
// target whitelisted addresses.
func (s *Server) syncBans() {
	bans, err := s.db.GetActiveBans()
	if err != nil {
		s.logger.Error("failed to load active bans", "error", err)
		return
	}
	applied := 0
	for _, b := range bans {
		if s.IsWhitelisted(b.IP) {
			s.logger.Warn("removing ban on whitelisted IP", "ip", b.IP)
			_ = s.UnbanIP(b.IP)
			continue
		}
		if err := s.firewall.Ban(b.IP); err != nil {
			s.logger.Error("failed to re-apply ban", "ip", b.IP, "error", err)
			continue
		}
		applied++
	}
	if len(bans) > 0 {
		s.logger.Info("active bans re-applied to firewall", "count", applied, "method", s.firewall.Method())
	}
}

// acceptLoop accepts new TCP connections and dispatches each to handler in its
// own goroutine. It exits when the listener is closed.
func (s *Server) acceptLoop(rt *svcRuntime, ln net.Listener, handler func(net.Conn)) {
	defer s.wg.Done()

	backoff := 5 * time.Millisecond
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			// Transient errors (EMFILE, ENFILE, ECONNABORTED): back off and retry
			// rather than killing the listener.
			s.logger.Warn("accept error, retrying", "addr", ln.Addr(), "error", err, "backoff", backoff)
			time.Sleep(backoff)
			if backoff < time.Second {
				backoff *= 2
			}
			continue
		}
		backoff = 5 * time.Millisecond

		select {
		case s.sem <- struct{}{}:
		default:
			s.logger.Warn("connection limit reached, dropping connection",
				"remote", conn.RemoteAddr(), "limit", maxConcurrentConns)
			conn.Close()
			continue
		}
		if !s.track(conn, rt) {
			<-s.sem
			conn.Close()
			return
		}

		s.wg.Add(1)
		go func(c net.Conn) {
			defer s.wg.Done()
			defer func() { <-s.sem }()
			defer s.untrack(c, rt)
			defer c.Close()
			defer func() {
				if r := recover(); r != nil {
					s.logger.Error("panic in connection handler", "remote", c.RemoteAddr(), "panic", r)
				}
			}()
			handler(c)
		}(conn)
	}
}

// connInfo carries per-connection facts used for logging.
type connInfo struct {
	ip       string
	srcPort  int
	destPort int
	country  string
	city     string
	svc      service
}

func (s *Server) logConn(ci *connInfo, action, data string) {
	if err := s.db.LogConnection(&storage.Connection{
		SourceIP:    ci.ip,
		SourcePort:  ci.srcPort,
		DestPort:    ci.destPort,
		Country:     ci.country,
		City:        ci.city,
		ServiceType: ci.svc.label(),
		Action:      action,
		Data:        data,
	}); err != nil {
		s.logger.Error("log connection error", "error", err)
	}
}

// handleConnection applies the shared security checks and routes the
// connection. Order: whitelist → active ban → IP blacklist → GeoIP-based
// rules → heuristics (rate limit, port scan, honeypot scoring) → handler.
func (s *Server) handleConnection(conn net.Conn, svc service) {
	ci := &connInfo{
		ip:       netutil.HostIP(conn.RemoteAddr().String()),
		srcPort:  addrPort(conn.RemoteAddr()),
		destPort: addrPort(conn.LocalAddr()),
		svc:      svc,
	}
	if ci.destPort == 0 {
		ci.destPort = svc.port
	}

	// 1. Whitelist: skip every check (the honeypot credential hook also
	// ignores whitelisted IPs, so they can never be scored or banned).
	if s.IsWhitelisted(ci.ip) {
		geo := s.geoip.Lookup(ci.ip)
		ci.country, ci.city = geo.CountryCode, geo.City
		s.route(conn, ci, "whitelisted")
		return
	}

	// 2. Active ban. Normally the kernel drops these packets; seeing one here
	// means the firewall rule is missing (method=none, restart, manual flush),
	// so re-assert it.
	banned, err := s.db.IsBanned(ci.ip)
	if err != nil {
		s.logger.Error("ban check error", "ip", ci.ip, "error", err)
	}
	if banned {
		if err := s.firewall.Ban(ci.ip); err != nil {
			s.logger.Debug("re-applying firewall ban failed", "ip", ci.ip, "error", err)
		}
		s.logConn(ci, storage.ActionDropped, "banned")
		return
	}

	// 3. Manual IP blacklist.
	if s.blacklist.Contains(ci.ip) {
		s.logConn(ci, storage.ActionDropped, "blacklisted_ip")
		return
	}

	// 4. GeoIP.
	geo := s.geoip.Lookup(ci.ip)
	ci.country, ci.city = geo.CountryCode, geo.City

	if svc.kind == kindStealth && svc.stealth.RestrictsCountries() && s.geoip.Enabled() {
		// Private/LAN addresses have no country; never lock them out.
		if !(ci.country == "" && netutil.IsPrivateOrLocal(ci.ip)) && !svc.stealth.IsCountryAllowed(ci.country) {
			s.logger.Info("stealth: country not allowed, dropping",
				"ip", ci.ip, "country", ci.country, "service", svc.name)
			s.logConn(ci, storage.ActionDropped, "country_not_allowed")
			return
		}
	}

	if ci.country != "" {
		for _, wc := range s.cfg.Whitelist.Countries {
			if strings.EqualFold(wc, ci.country) {
				s.route(conn, ci, "whitelisted_country")
				return
			}
		}
		for _, bc := range s.cfg.Blacklist.Countries {
			if strings.EqualFold(bc, ci.country) {
				s.logger.Info("dropping blacklisted country", "ip", ci.ip, "country", ci.country)
				s.recordAndMaybeBan(ci, analysis.EventBlacklistedCountry, "blacklisted_country")
				s.logConn(ci, storage.ActionDropped, "blacklisted_country")
				return
			}
		}
	}

	// 5-7. Heuristic ban triggers. Passthrough forwards real production
	// traffic (e.g. a website) where many connections per client are normal,
	// so it only honours the explicit deny lists above.
	if svc.kind != kindPassthrough {
		if !s.limiter.Check(ci.ip) {
			s.logger.Info("rate limit exceeded", "ip", ci.ip)
			s.recordAndMaybeBan(ci, analysis.EventRateLimitExceeded, "rate_limit_exceeded")
			s.logConn(ci, storage.ActionDropped, "rate_limited")
			return
		}

		if scanning, first := s.detector.RecordPort(ci.ip, ci.destPort); scanning {
			if first {
				s.logger.Info("port scan detected", "ip", ci.ip)
				s.recordAndMaybeBan(ci, analysis.EventPortScan, "port_scan")
			}
			s.logConn(ci, storage.ActionDropped, "port_scan")
			return
		}

		if svc.kind == kindHoneypot {
			if s.recordAndMaybeBan(ci, analysis.EventHoneypotConnection, "honeypot_threshold") {
				s.logConn(ci, storage.ActionDropped, "banned")
				return
			}
		}
	}

	s.route(conn, ci, "")
}

// route hands conn to its handler. Each path writes exactly one connection
// row: the stealth recorder, the honeypot handler, or the passthrough log.
func (s *Server) route(conn net.Conn, ci *connInfo, note string) {
	switch ci.svc.kind {
	case kindStealth:
		record := func(action, data string) {
			if note != "" {
				data = note + "; " + data
			}
			s.logConn(ci, action, data)
		}
		if err := ci.svc.stealth.Handle(conn, ci.ip, record); err != nil {
			s.logger.Debug("stealth handler error", "ip", ci.ip, "error", err)
		}

	case kindHoneypot:
		sess := honeypot.Session{IP: ci.ip, Port: ci.destPort, Country: ci.country, City: ci.city}
		if err := ci.svc.honeypot.Handle(conn, sess); err != nil {
			s.logger.Debug("honeypot handler error", "ip", ci.ip, "error", err)
		}

	case kindPassthrough:
		s.logConn(ci, storage.ActionForwarded, note)
		if err := s.proxy.Forward(conn, ci.svc.target); err != nil {
			s.logger.Warn("passthrough error", "ip", ci.ip, "target", ci.svc.target, "error", err)
		}
	}
}

// recordAndMaybeBan scores event for the connection's IP and applies an
// auto-ban when the threshold is reached. It reports whether the IP is now banned.
func (s *Server) recordAndMaybeBan(ci *connInfo, event analysis.ScoreEvent, reason string) bool {
	score, err := s.scorer.Record(ci.ip, ci.country, event, ci.destPort)
	if err != nil {
		s.logger.Error("scoring failed", "ip", ci.ip, "error", err)
		return false
	}
	return s.maybeAutoBan(ci.ip, score, reason)
}

// maybeAutoBan bans ip when auto-ban is enabled and score has reached the
// (runtime-adjustable) threshold. Whitelisted IPs are never banned.
func (s *Server) maybeAutoBan(ip string, score int, reason string) bool {
	ab := s.settings.AutoBan()
	if !ab.Enabled || score < ab.ScoreThreshold || s.IsWhitelisted(ip) {
		return false
	}
	if banned, _ := s.db.IsBanned(ip); banned {
		return true
	}
	if err := s.BanIP(ip, reason, ab.BanDuration, ab.BanDuration == 0); err != nil {
		s.logger.Error("auto-ban failed", "ip", ip, "error", err)
		return false
	}
	s.logger.Info("auto-ban applied", "ip", ip, "reason", reason, "score", score, "duration", ab.BanDuration)
	return true
}

// IsWhitelisted reports whether ip is covered by whitelist.ips (or loopback).
func (s *Server) IsWhitelisted(ip string) bool {
	return s.whitelist.Contains(ip)
}

// BanIP records a ban and applies it to the firewall. It implements
// dashboard.BanManager. A firewall error is returned after the ban is stored;
// SkyGuard's own listeners still drop the IP.
func (s *Server) BanIP(ip, reason string, duration time.Duration, permanent bool) error {
	ip = netutil.NormalizeIP(ip)
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid IP %q", ip)
	}
	if s.IsWhitelisted(ip) {
		return fmt.Errorf("%s is whitelisted; remove it from whitelist.ips first", ip)
	}
	if err := s.db.BanIP(ip, reason, duration, permanent); err != nil {
		return err
	}
	if err := s.firewall.Ban(ip); err != nil {
		return fmt.Errorf("ban stored but firewall rule failed: %w", err)
	}
	return nil
}

// UnbanIP lifts a ban everywhere and resets the IP's score. It implements
// dashboard.BanManager.
func (s *Server) UnbanIP(ip string) error {
	ip = netutil.NormalizeIP(ip)
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid IP %q", ip)
	}
	if err := s.db.UnbanIP(ip); err != nil {
		return err
	}
	if err := s.db.ResetScore(ip); err != nil {
		s.logger.Warn("failed to reset score after unban", "ip", ip, "error", err)
	}
	if err := s.firewall.Unban(ip); err != nil {
		return fmt.Errorf("ban removed but firewall rule removal failed: %w", err)
	}
	return nil
}

func addrPort(a net.Addr) int {
	if tcp, ok := a.(*net.TCPAddr); ok {
		return tcp.Port
	}
	_, p, err := net.SplitHostPort(a.String())
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(p)
	return n
}
