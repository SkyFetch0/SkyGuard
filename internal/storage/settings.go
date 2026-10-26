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
