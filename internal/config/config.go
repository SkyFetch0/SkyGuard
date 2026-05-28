package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	General     GeneralConfig       `yaml:"general"`
	Stealth     []StealthService    `yaml:"stealth_services"`
	Honeypots   []HoneypotService   `yaml:"honeypot_services"`
	Passthrough []PassthroughService `yaml:"passthrough_services"`
	Analysis    AnalysisConfig      `yaml:"analysis"`
	Whitelist   WhitelistConfig     `yaml:"whitelist"`
	Blacklist   BlacklistConfig     `yaml:"blacklist"`
	Dashboard   DashboardConfig     `yaml:"dashboard"`
	Logging     LoggingConfig       `yaml:"logging"`
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
	FakeShell       bool   `yaml:"fake_shell"`
	ServerHeader    string `yaml:"server_header"`
}

// IsEnabled returns true if the honeypot is active (default: true when omitted).
func (h *HoneypotService) IsEnabled() bool {
	return h.Enabled == nil || *h.Enabled
}

type PassthroughService struct {
	Name       string `yaml:"name"`
	ListenPort int    `yaml:"listen_port"`
	RealTarget string `yaml:"real_target"`
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
	Scoring        ScoringConfig `yaml:"scoring"`
}

type ScoringConfig struct {
	HoneypotConnection int `yaml:"honeypot_connection"`
	FailedCredential   int `yaml:"failed_credential"`
	PortScanDetected   int `yaml:"port_scan_detected"`
	BlacklistedCountry int `yaml:"blacklisted_country"`
	RateLimitExceeded  int `yaml:"rate_limit_exceeded"`
}

type WhitelistConfig struct {
	IPs       []string `yaml:"ips"`
	Countries []string `yaml:"countries"`
}

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

// LoadConfig reads the YAML config file at path and returns a parsed Config.
// time.Duration fields stored as strings (e.g. "30s", "24h") are parsed after
// yaml.Unmarshal since the standard YAML library cannot decode them natively.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	// Parse time.Duration fields from their raw string representations.
	for i := range cfg.Stealth {
		if cfg.Stealth[i].TimeoutRaw != "" {
			d, err := time.ParseDuration(cfg.Stealth[i].TimeoutRaw)
			if err != nil {
				return nil, fmt.Errorf("stealth service %q: invalid timeout %q: %w",
					cfg.Stealth[i].Name, cfg.Stealth[i].TimeoutRaw, err)
			}
			cfg.Stealth[i].Timeout = d
		}
	}

	if cfg.Analysis.AutoBan.BanDurationRaw != "" {
		d, err := time.ParseDuration(cfg.Analysis.AutoBan.BanDurationRaw)
		if err != nil {
			return nil, fmt.Errorf("auto_ban: invalid ban_duration %q: %w",
				cfg.Analysis.AutoBan.BanDurationRaw, err)
		}
		cfg.Analysis.AutoBan.BanDuration = d
	}

	if cfg.Analysis.PortScan.WindowRaw != "" {
		d, err := time.ParseDuration(cfg.Analysis.PortScan.WindowRaw)
		if err != nil {
			return nil, fmt.Errorf("port_scan: invalid window %q: %w",
				cfg.Analysis.PortScan.WindowRaw, err)
		}
		cfg.Analysis.PortScan.Window = d
	}

	applyDefaults(&cfg)
	return &cfg, nil
}

// applyDefaults fills in sensible defaults for zero-value fields.
func applyDefaults(cfg *Config) {
	if cfg.General.LogLevel == "" {
		cfg.General.LogLevel = "info"
	}
	if cfg.General.DataDir == "" {
		cfg.General.DataDir = "/var/lib/skyguard"
	}
	if cfg.Dashboard.Listen == "" {
		cfg.Dashboard.Listen = "127.0.0.1:8080"
	}
	if cfg.Logging.RetentionDays == 0 {
		cfg.Logging.RetentionDays = 30
	}
	if cfg.Logging.LogFirstBytes == 0 {
		cfg.Logging.LogFirstBytes = 512
	}
	if cfg.Analysis.AutoBan.ScoreThreshold == 0 {
		cfg.Analysis.AutoBan.ScoreThreshold = 100
	}
	if cfg.Analysis.AutoBan.BanDuration == 0 {
		cfg.Analysis.AutoBan.BanDuration = 24 * time.Hour
	}
	for i := range cfg.Stealth {
		if cfg.Stealth[i].Timeout == 0 {
			cfg.Stealth[i].Timeout = 30 * time.Second
		}
	}
	for i := range cfg.Honeypots {
		if cfg.Honeypots[i].MaxAuthAttempts == 0 {
			cfg.Honeypots[i].MaxAuthAttempts = 3
		}
	}
}
