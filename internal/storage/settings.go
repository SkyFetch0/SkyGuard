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
	BanDuration    time.Duration
}

// Settings is a thread-safe, DB-backed holder for mutable runtime settings.
// Values are seeded from the config file on first start and then persisted to
// the settings table so changes survive restarts.
type Settings struct {
	db      *DB
	mu      sync.RWMutex
	autoBan AutoBanSettings
}

const (
	keyAutoBanEnabled   = "autoban_enabled"
	keyAutoBanThreshold = "autoban_threshold"
	keyAutoBanDuration  = "autoban_duration"
)

// LoadSettings returns a Settings holder seeded with def, overridden by any
// values already stored in the database, and writes the effective values back.
func (d *DB) LoadSettings(def AutoBanSettings) (*Settings, error) {
	s := &Settings{db: d, autoBan: def}

	if v, ok, err := d.getSetting(keyAutoBanEnabled); err != nil {
		return nil, err
	} else if ok {
		s.autoBan.Enabled = v == "1" || v == "true"
	}
	if v, ok, err := d.getSetting(keyAutoBanThreshold); err != nil {
		return nil, err
	} else if ok {
		if n, e := strconv.Atoi(v); e == nil && n > 0 {
			s.autoBan.ScoreThreshold = n
		}
	}
	if v, ok, err := d.getSetting(keyAutoBanDuration); err != nil {
		return nil, err
	} else if ok {
		if dur, e := time.ParseDuration(v); e == nil {
			s.autoBan.BanDuration = dur
		}
	}

	if err := s.persistLocked(); err != nil {
		return nil, err
	}
	return s, nil
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
	s.autoBan = v
	return s.persistLocked()
}

// persistLocked writes the current settings to the DB. Caller must hold the
// lock (read or write) or be in a single-goroutine context (LoadSettings).
func (s *Settings) persistLocked() error {
	if err := s.db.setSetting(keyAutoBanEnabled, boolToStr(s.autoBan.Enabled)); err != nil {
		return err
	}
	if err := s.db.setSetting(keyAutoBanThreshold, strconv.Itoa(s.autoBan.ScoreThreshold)); err != nil {
		return err
	}
	if err := s.db.setSetting(keyAutoBanDuration, s.autoBan.BanDuration.String()); err != nil {
		return err
	}
	return nil
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
