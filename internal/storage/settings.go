package storage

import (
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"
)

// AutoBanSettings holds the auto-ban parameters that can be changed at runtime
// (via the dashboard) without restarting the process.
type AutoBanSettings struct {
	Enabled        bool
	ScoreThreshold int
	BanDuration    time.Duration // 0 = permanent
}

func (a AutoBanSettings) fingerprint() string {
	return fmt.Sprintf("%t|%d|%s", a.Enabled, a.ScoreThreshold, a.BanDuration)
}

// Settings is a thread-safe, DB-backed holder for mutable runtime settings.
type Settings struct {
	db      *DB
	mu      sync.RWMutex
	autoBan AutoBanSettings
}

const (
	keyAutoBanEnabled   = "autoban_enabled"
	keyAutoBanThreshold = "autoban_threshold"
	keyAutoBanDuration  = "autoban_duration"
	// keyAutoBanSeed remembers which config-file values the stored settings
	// were derived from. When the operator edits the YAML, the fingerprint
	// changes and the file wins again; otherwise dashboard overrides persist.
	keyAutoBanSeed = "autoban_config_seed"
)

// LoadSettings returns the effective runtime settings. Values changed in the
// dashboard survive restarts, but editing the config file takes precedence
// over them (previously the first-ever values stuck forever and later YAML
// edits were silently ignored).
func (d *DB) LoadSettings(fromConfig AutoBanSettings) (*Settings, error) {
	s := &Settings{db: d, autoBan: fromConfig}

	seed, ok, err := d.getSetting(keyAutoBanSeed)
	if err != nil {
		return nil, err
	}
	if ok && seed == fromConfig.fingerprint() {
		if err := s.loadStored(); err != nil {
			return nil, err
		}
	}
	if err := d.setSetting(keyAutoBanSeed, fromConfig.fingerprint()); err != nil {
		return nil, err
	}
	if err := s.persist(s.autoBan); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Settings) loadStored() error {
	if v, ok, err := s.db.getSetting(keyAutoBanEnabled); err != nil {
		return err
	} else if ok {
		s.autoBan.Enabled = v == "1" || v == "true"
	}
	if v, ok, err := s.db.getSetting(keyAutoBanThreshold); err != nil {
		return err
	} else if ok {
		if n, e := strconv.Atoi(v); e == nil && n > 0 {
			s.autoBan.ScoreThreshold = n
		}
	}
	if v, ok, err := s.db.getSetting(keyAutoBanDuration); err != nil {
		return err
	} else if ok {
		if dur, e := time.ParseDuration(v); e == nil && dur >= 0 {
			s.autoBan.BanDuration = dur
		}
	}
	return nil
}

// AutoBan returns a copy of the current auto-ban settings.
func (s *Settings) AutoBan() AutoBanSettings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.autoBan
}

// SetAutoBan validates and stores new auto-ban settings, persisting them.
func (s *Settings) SetAutoBan(v AutoBanSettings) error {
	if v.ScoreThreshold <= 0 {
		return fmt.Errorf("score_threshold must be > 0")
	}
	if v.BanDuration < 0 {
		return fmt.Errorf("ban_duration must be >= 0")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.persist(v); err != nil {
		return err
	}
	s.autoBan = v
	return nil
}

func (s *Settings) persist(v AutoBanSettings) error {
	if err := s.db.setSetting(keyAutoBanEnabled, boolToStr(v.Enabled)); err != nil {
		return err
	}
	if err := s.db.setSetting(keyAutoBanThreshold, strconv.Itoa(v.ScoreThreshold)); err != nil {
		return err
	}
	return s.db.setSetting(keyAutoBanDuration, v.BanDuration.String())
}

func (d *DB) getSetting(key string) (string, bool, error) {
	var v string
	err := d.db.QueryRow(`SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("reading setting %q: %w", key, err)
	}
	return v, true, nil
}

func (d *DB) setSetting(key, value string) error {
	_, err := d.db.Exec(`
		INSERT INTO settings (key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	if err != nil {
		return fmt.Errorf("writing setting %q: %w", key, err)
	}
	return nil
}

func boolToStr(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// Service overrides: a honeypot switched on or off from the dashboard. The
// value remembers the config file's setting at the time of the switch; when
// the operator later edits that service in the YAML, the file wins again
// (the same precedence as the auto-ban settings).
func serviceKey(name string) string { return "service_enabled:" + name }

// ServiceOverride returns the dashboard's choice for a service, if one is
// stored and the config file has not changed that service since.
func (d *DB) ServiceOverride(name string, cfgEnabled bool) (enabled, ok bool, err error) {
	v, found, err := d.getSetting(serviceKey(name))
	if err != nil || !found {
		return false, false, err
	}
	var on, cfg int
	if _, err := fmt.Sscanf(v, "%d;cfg=%d", &on, &cfg); err != nil || (cfg == 1) != cfgEnabled {
		_, err := d.db.Exec(`DELETE FROM settings WHERE key = ?`, serviceKey(name))
		return false, false, err
	}
	return on == 1, true, nil
}

// SetServiceOverride stores the dashboard's choice for a service.
func (d *DB) SetServiceOverride(name string, enabled, cfgEnabled bool) error {
	return d.setSetting(serviceKey(name), fmt.Sprintf("%d;cfg=%d", boolToInt(enabled), boolToInt(cfgEnabled)))
}

// MCPSettings is the state of the MCP endpoint, switched from the dashboard.
// Only a hash of the access token is stored; the token itself is shown once.
type MCPSettings struct {
	Enabled      bool
	AllowActions bool // tools that change things (ban, unban, honeypot switch, container start/stop)
	TokenHash    string
	TokenCreated time.Time
}

const (
	keyMCPEnabled      = "mcp_enabled"
	keyMCPAllowActions = "mcp_allow_actions"
	keyMCPTokenHash    = "mcp_token_hash"
	keyMCPTokenCreated = "mcp_token_created"
)

// MCPSettings returns the stored MCP state (all off when never set).
func (d *DB) MCPSettings() (MCPSettings, error) {
	var m MCPSettings
	for key, set := range map[string]func(string){
		keyMCPEnabled:      func(v string) { m.Enabled = v == "1" },
		keyMCPAllowActions: func(v string) { m.AllowActions = v == "1" },
		keyMCPTokenHash:    func(v string) { m.TokenHash = v },
		keyMCPTokenCreated: func(v string) { m.TokenCreated, _ = time.Parse(tsLayout, v) },
	} {
		v, ok, err := d.getSetting(key)
		if err != nil {
			return m, err
		}
		if ok {
			set(v)
		}
	}
	return m, nil
}

// SaveMCPSettings stores the MCP state.
func (d *DB) SaveMCPSettings(m MCPSettings) error {
	created := ""
	if !m.TokenCreated.IsZero() {
		created = formatTS(m.TokenCreated)
	}
	for key, v := range map[string]string{
		keyMCPEnabled:      boolToStr(m.Enabled),
		keyMCPAllowActions: boolToStr(m.AllowActions),
		keyMCPTokenHash:    m.TokenHash,
		keyMCPTokenCreated: created,
	} {
		if err := d.setSetting(key, v); err != nil {
			return err
		}
	}
	return nil
}

const keyPortRules = "port_rules"

// PortRules returns the saved port access rules as the JSON the port rules
// manager wrote ("" when none were ever saved).
func (d *DB) PortRules() (string, error) {
	v, _, err := d.getSetting(keyPortRules)
	return v, err
}

// SavePortRules stores the port access rules' JSON.
func (d *DB) SavePortRules(js string) error { return d.setSetting(keyPortRules, js) }
