package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	General     GeneralConfig        `yaml:"general"`
	Stealth     []StealthService     `yaml:"stealth_services"`
	Honeypots   []HoneypotService    `yaml:"honeypot_services"`
	Passthrough []PassthroughService `yaml:"passthrough_services"`
	Analysis    AnalysisConfig       `yaml:"analysis"`
	Whitelist   WhitelistConfig      `yaml:"whitelist"`
	Blacklist   BlacklistConfig      `yaml:"blacklist"`
	Dashboard   DashboardConfig      `yaml:"dashboard"`
	Logging     LoggingConfig        `yaml:"logging"`
}

type GeneralConfig struct {
	LogLevel string `yaml:"log_level"`
	DataDir  string `yaml:"data_dir"`
}

type StealthService struct {
	Name              string        `yaml:"name"`
	Enabled           *bool         `yaml:"enabled"` // nil = true
	ListenPort        int           `yaml:"listen_port"`
	RealTarget        string        `yaml:"real_target"`
	ProtocolSignature string        `yaml:"protocol_signature"`
	Timeout           time.Duration `yaml:"-"`
	TimeoutRaw        string        `yaml:"timeout"`
	AllowedCountries  []string      `yaml:"allowed_countries"`
}

// IsEnabled returns true if the stealth service is active (default: true when omitted).
func (s *StealthService) IsEnabled() bool {
	return s.Enabled == nil || *s.Enabled
}

type HoneypotService struct {
	Name            string `yaml:"name"`
	Enabled         *bool  `yaml:"enabled"` // nil = true (default on)
	Port            int    `yaml:"port"`
	Type            string `yaml:"type"`
	Banner          string `yaml:"banner"`
	MaxAuthAttempts int    `yaml:"max_auth_attempts"`
	// FakeShell is accepted for backward compatibility but not implemented;
	// the SSH honeypot never grants a session.
	FakeShell    bool   `yaml:"fake_shell"`
	ServerHeader string `yaml:"server_header"`
}

// IsEnabled returns true if the honeypot is active (default: true when omitted).
func (h *HoneypotService) IsEnabled() bool {
	return h.Enabled == nil || *h.Enabled
}

type PassthroughService struct {
	Name       string `yaml:"name"`
	Enabled    *bool  `yaml:"enabled"` // nil = true
	ListenPort int    `yaml:"listen_port"`
	RealTarget string `yaml:"real_target"`
}

// IsEnabled returns true if the passthrough service is active (default: true when omitted).
func (p *PassthroughService) IsEnabled() bool {
	return p.Enabled == nil || *p.Enabled
}

type AnalysisConfig struct {
	GeoIP     GeoIPConfig     `yaml:"geoip"`
	RateLimit RateLimitConfig `yaml:"rate_limit"`
	AutoBan   AutoBanConfig   `yaml:"auto_ban"`
	PortScan  PortScanConfig  `yaml:"port_scan"`
}

// PortScanConfig controls port-scan detection. A source IP that touches
// Threshold distinct ports within Window is flagged as scanning.
type PortScanConfig struct {
	Window    time.Duration `yaml:"-"`
	WindowRaw string        `yaml:"window"`    // e.g. "60s"
	Threshold int           `yaml:"threshold"` // distinct ports
}

type GeoIPConfig struct {
	Enabled bool   `yaml:"enabled"`
	DBPath  string `yaml:"db_path"`
}

type RateLimitConfig struct {
	MaxPerMinute int `yaml:"max_per_minute"`
	MaxPerHour   int `yaml:"max_per_hour"`
}

type AutoBanConfig struct {
	Enabled        bool          `yaml:"enabled"`
	ScoreThreshold int           `yaml:"score_threshold"`
	BanDuration    time.Duration `yaml:"-"`
	BanDurationRaw string        `yaml:"ban_duration"`
	Method         string        `yaml:"method"`
	// IPTablesBackend selects the iptables flavour: "auto" (default) picks
	// whichever of iptables-legacy / iptables-nft the host already uses.
	IPTablesBackend string        `yaml:"iptables_backend"`
	Scoring         ScoringConfig `yaml:"scoring"`
}

type ScoringConfig struct {
	HoneypotConnection int `yaml:"honeypot_connection"`
	FailedCredential   int `yaml:"failed_credential"`
	PortScanDetected   int `yaml:"port_scan_detected"`
	BlacklistedCountry int `yaml:"blacklisted_country"`
	RateLimitExceeded  int `yaml:"rate_limit_exceeded"`
}

// WhitelistConfig entries may be single IPs or CIDR ranges.
type WhitelistConfig struct {
	IPs       []string `yaml:"ips"`
	Countries []string `yaml:"countries"`
}

// BlacklistConfig entries may be single IPs or CIDR ranges.
type BlacklistConfig struct {
	Countries []string `yaml:"countries"`
	IPs       []string `yaml:"ips"`
}

type DashboardConfig struct {
	Enabled bool          `yaml:"enabled"`
	Listen  string        `yaml:"listen"`
	Auth    DashboardAuth `yaml:"auth"`
}

type DashboardAuth struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type LoggingConfig struct {
	Database      string `yaml:"database"`
	DBPath        string `yaml:"db_path"`
	RetentionDays int    `yaml:"retention_days"`
	LogFirstBytes int    `yaml:"log_first_bytes"`
}

// DefaultDashboardListen is used when dashboard.listen is omitted.
const DefaultDashboardListen = "127.0.0.1:9090"

// LoadConfig reads the YAML config file at path, applies defaults and
// validates the result. Duration fields accept Go syntax ("90s", "24h") plus a
// "d" suffix for days ("7d").
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}
	return Parse(data)
}

// Parse decodes, defaults and validates a YAML config document.
func Parse(data []byte) (*Config, error) {
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	for i := range cfg.Stealth {
		if cfg.Stealth[i].TimeoutRaw != "" {
			d, err := ParseDuration(cfg.Stealth[i].TimeoutRaw)
			if err != nil {
				return nil, fmt.Errorf("stealth service %q: invalid timeout %q: %w",
					cfg.Stealth[i].Name, cfg.Stealth[i].TimeoutRaw, err)
			}
			cfg.Stealth[i].Timeout = d
		}
	}

	banDurationSet := false
	if cfg.Analysis.AutoBan.BanDurationRaw != "" {
		d, err := ParseDuration(cfg.Analysis.AutoBan.BanDurationRaw)
		if err != nil {
			return nil, fmt.Errorf("auto_ban: invalid ban_duration %q: %w",
				cfg.Analysis.AutoBan.BanDurationRaw, err)
		}
		cfg.Analysis.AutoBan.BanDuration = d
		banDurationSet = true
	}

	if cfg.Analysis.PortScan.WindowRaw != "" {
		d, err := ParseDuration(cfg.Analysis.PortScan.WindowRaw)
		if err != nil {
			return nil, fmt.Errorf("port_scan: invalid window %q: %w",
				cfg.Analysis.PortScan.WindowRaw, err)
		}
		cfg.Analysis.PortScan.Window = d
	}

	applyDefaults(&cfg, banDurationSet)
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// ParseDuration is time.ParseDuration with an additional "d" (day) unit, so
// values such as "7d" or "1d12h" are accepted. "0" / "0s" mean zero.
func ParseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, errors.New("empty duration")
	}
	if i := strings.IndexByte(s, 'd'); i > 0 {
		days, err := strconv.Atoi(s[:i])
		if err != nil || days < 0 {
			return 0, fmt.Errorf("invalid day count in %q", s)
		}
		total := time.Duration(days) * 24 * time.Hour
		if rest := s[i+1:]; rest != "" {
			d, err := time.ParseDuration(rest)
			if err != nil {
				return 0, err
			}
			total += d
		}
		return total, nil
	}
	return time.ParseDuration(s)
}

// applyDefaults fills in sensible defaults for zero-value fields.
func applyDefaults(cfg *Config, banDurationSet bool) {
	if cfg.General.LogLevel == "" {
		cfg.General.LogLevel = "info"
	}
	if cfg.General.DataDir == "" {
		cfg.General.DataDir = "/var/lib/skyguard"
	}
	if cfg.Dashboard.Listen == "" {
		cfg.Dashboard.Listen = DefaultDashboardListen
	}
	if cfg.Logging.DBPath == "" {
		cfg.Logging.DBPath = filepath.Join(cfg.General.DataDir, "skyguard.db")
	}
	if cfg.Logging.RetentionDays == 0 {
		cfg.Logging.RetentionDays = 30
	}
	if cfg.Logging.LogFirstBytes == 0 {
		cfg.Logging.LogFirstBytes = 512
	}
	if cfg.Analysis.GeoIP.DBPath == "" {
		cfg.Analysis.GeoIP.DBPath = filepath.Join(cfg.General.DataDir, "GeoLite2-City.mmdb")
	}
	ab := &cfg.Analysis.AutoBan
	if ab.Method == "" {
		ab.Method = "none"
	}
	ab.Method = strings.ToLower(strings.TrimSpace(ab.Method))
	if ab.IPTablesBackend == "" {
		ab.IPTablesBackend = "auto"
	}
	if ab.ScoreThreshold == 0 {
		ab.ScoreThreshold = 100
	}
	// An explicit "0s" means "permanent"; only default when omitted.
	if !banDurationSet {
		ab.BanDuration = 24 * time.Hour
	}
	for i := range cfg.Stealth {
		if cfg.Stealth[i].Timeout == 0 {
			cfg.Stealth[i].Timeout = 10 * time.Second
		}
	}
	for i := range cfg.Honeypots {
		cfg.Honeypots[i].Type = strings.ToLower(strings.TrimSpace(cfg.Honeypots[i].Type))
		if cfg.Honeypots[i].MaxAuthAttempts == 0 {
			cfg.Honeypots[i].MaxAuthAttempts = 3
		}
	}
}

// Validate checks the configuration for errors that would otherwise only
// surface at runtime (port clashes, bad addresses, unknown types).
func (c *Config) Validate() error {
	var errs []error
	ports := map[int]string{}
	claim := func(port int, owner string) {
		if port < 1 || port > 65535 {
			errs = append(errs, fmt.Errorf("%s: port %d out of range 1-65535", owner, port))
			return
		}
		if prev, ok := ports[port]; ok {
			errs = append(errs, fmt.Errorf("%s: port %d already used by %s", owner, port, prev))
			return
		}
		ports[port] = owner
	}

	for _, s := range c.Stealth {
		if !s.IsEnabled() {
			continue
		}
		owner := fmt.Sprintf("stealth service %q", s.Name)
		claim(s.ListenPort, owner)
		if _, _, err := net.SplitHostPort(s.RealTarget); err != nil {
			errs = append(errs, fmt.Errorf("%s: invalid real_target %q (want host:port)", owner, s.RealTarget))
		}
		if s.Timeout < 0 {
			errs = append(errs, fmt.Errorf("%s: timeout must be positive", owner))
		}
	}
	for _, h := range c.Honeypots {
		if !h.IsEnabled() {
			continue
		}
		owner := fmt.Sprintf("honeypot %q", h.Name)
		claim(h.Port, owner)
		switch h.Type {
		case "ssh", "ftp", "mysql", "http":
		default:
			errs = append(errs, fmt.Errorf("%s: unknown type %q (supported: ssh, ftp, mysql, http)", owner, h.Type))
		}
		if h.Type == "ssh" && h.Banner != "" && !strings.HasPrefix(h.Banner, "SSH-2.0-") {
			errs = append(errs, fmt.Errorf("%s: ssh banner must start with \"SSH-2.0-\"", owner))
		}
	}
	for _, p := range c.Passthrough {
		if !p.IsEnabled() {
			continue
		}
		owner := fmt.Sprintf("passthrough %q", p.Name)
		claim(p.ListenPort, owner)
		if _, _, err := net.SplitHostPort(p.RealTarget); err != nil {
			errs = append(errs, fmt.Errorf("%s: invalid real_target %q (want host:port)", owner, p.RealTarget))
		}
	}

	if c.Dashboard.Enabled {
		host, portStr, err := net.SplitHostPort(c.Dashboard.Listen)
		if err != nil {
			errs = append(errs, fmt.Errorf("dashboard: invalid listen %q (want host:port)", c.Dashboard.Listen))
		} else if port, err := strconv.Atoi(portStr); err == nil {
			// Only a wildcard/same-host bind can clash with our 0.0.0.0 listeners.
			ip := net.ParseIP(host)
			if host == "" || ip == nil || ip.IsUnspecified() || ip.IsLoopback() {
				claim(port, "dashboard")
			}
		}
	}

	switch c.Analysis.AutoBan.Method {
	case "none", "log", "iptables", "ufw":
	default:
		errs = append(errs, fmt.Errorf("auto_ban: unknown method %q (supported: none, iptables, ufw)", c.Analysis.AutoBan.Method))
	}
	switch c.Analysis.AutoBan.IPTablesBackend {
	case "auto", "legacy", "nft":
	default:
		errs = append(errs, fmt.Errorf("auto_ban: unknown iptables_backend %q (supported: auto, legacy, nft)", c.Analysis.AutoBan.IPTablesBackend))
	}
	if c.Analysis.AutoBan.BanDuration < 0 {
		errs = append(errs, errors.New("auto_ban: ban_duration must not be negative"))
	}

	for _, entry := range c.Whitelist.IPs {
		if _, err := ParseIPOrCIDR(entry); err != nil {
			errs = append(errs, fmt.Errorf("whitelist: %w", err))
		}
	}
	for _, entry := range c.Blacklist.IPs {
		if _, err := ParseIPOrCIDR(entry); err != nil {
			errs = append(errs, fmt.Errorf("blacklist: %w", err))
		}
	}

	return errors.Join(errs...)
}

// ParseIPOrCIDR parses "1.2.3.4", "2001:db8::1" or "10.0.0.0/8" into a
// network. Single addresses become a /32 (or /128) network.
func ParseIPOrCIDR(s string) (*net.IPNet, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q", s)
		}
		return n, nil
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP %q", s)
	}
	if v4 := ip.To4(); v4 != nil {
		return &net.IPNet{IP: v4, Mask: net.CIDRMask(32, 32)}, nil
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}, nil
}
