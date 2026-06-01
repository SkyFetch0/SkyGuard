package analysis

import (
	"database/sql"
	"fmt"
	"sync"

	"github.com/skyguard/skyguard/internal/config"
	"github.com/skyguard/skyguard/internal/storage"
)

// ScoreEvent represents a type of security event that contributes to an IP's score.
type ScoreEvent string

const (
	EventHoneypotConnection ScoreEvent = "honeypot_connection"
	EventFailedCredential   ScoreEvent = "failed_credential"
	EventPortScan           ScoreEvent = "port_scan"
	EventBlacklistedCountry ScoreEvent = "blacklisted_country"
	EventRateLimitExceeded  ScoreEvent = "rate_limit_exceeded"
)

// Scorer records threat scores for IPs and decides when to ban.
type Scorer struct {
	mu        sync.Mutex
	db        *storage.DB
	config    config.ScoringConfig
	threshold int
}

// NewScorer creates a Scorer backed by the given database and auto-ban config.
func NewScorer(db *storage.DB, cfg config.AutoBanConfig) *Scorer {
	return &Scorer{
		db:        db,
		config:    cfg.Scoring,
		threshold: cfg.ScoreThreshold,
	}
}

// Record adds the score for event to ip and persists the updated total.
// It also increments the relevant activity counter column so the dashboard's
// "Top Attackers" table reflects real hit/attempt/connection counts.
// Returns the new cumulative score.
func (s *Scorer) Record(ip, country string, event ScoreEvent, port int) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delta := s.scoreForEvent(event)
	if delta == 0 {
		return 0, nil
	}

	db := s.db.DB()

	// Upsert the score and country in a single atomic statement.
	_, err := db.Exec(`
		INSERT INTO ip_scores (ip, score, country, last_seen)
		VALUES (?, ?, ?, datetime('now'))
		ON CONFLICT(ip) DO UPDATE SET
			score     = score + excluded.score,
			country   = CASE WHEN excluded.country != '' THEN excluded.country ELSE country END,
			last_seen = datetime('now')
	`, ip, delta, country)
	if err != nil {
		return 0, fmt.Errorf("upserting ip score for %s: %w", ip, err)
	}

	// Increment the per-event activity counter. Pass delta=0 so that
	// UpdateScore only touches the named counter, not the score again.
	if field := counterFieldForEvent(event); field != "" {
		if err := s.db.UpdateScore(ip, 0, field); err != nil {
			// Non-fatal: score is already persisted; counter update is best-effort.
			_ = err
		}
	}

	// total_connections tracks every scored event regardless of type.
	if err := s.db.UpdateScore(ip, 0, "total_connections"); err != nil {
		_ = err
	}

	var total int
	if err := db.QueryRow(`SELECT score FROM ip_scores WHERE ip = ?`, ip).Scan(&total); err != nil {
		return 0, fmt.Errorf("reading score for %s: %w", ip, err)
	}

	return total, nil
}

// counterFieldForEvent maps a ScoreEvent to the ip_scores column that should
// be incremented alongside the score. Returns "" for events with no dedicated
// counter column.
func counterFieldForEvent(event ScoreEvent) string {
	switch event {
	case EventHoneypotConnection:
		return "honeypot_hits"
	case EventFailedCredential:
		return "credential_attempts"
	default:
		return ""
	}
}

// ShouldBan reports whether ip's current score meets or exceeds the threshold.
func (s *Scorer) ShouldBan(ip string) (bool, error) {
	score, err := s.GetScore(ip)
	if err != nil {
		return false, err
	}
	return s.threshold > 0 && score >= s.threshold, nil
}

// GetScore returns the current threat score for ip, or 0 if unknown.
func (s *Scorer) GetScore(ip string) (int, error) {
	var score int
	err := s.db.DB().QueryRow(`SELECT score FROM ip_scores WHERE ip = ?`, ip).Scan(&score)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("querying score for %s: %w", ip, err)
	}
	return score, nil
}

// scoreForEvent maps a ScoreEvent to its configured point value.
func (s *Scorer) scoreForEvent(event ScoreEvent) int {
	switch event {
	case EventHoneypotConnection:
		return s.config.HoneypotConnection
	case EventFailedCredential:
		return s.config.FailedCredential
	case EventPortScan:
		return s.config.PortScanDetected
	case EventBlacklistedCountry:
		return s.config.BlacklistedCountry
	case EventRateLimitExceeded:
		return s.config.RateLimitExceeded
	default:
		return 0
	}
}