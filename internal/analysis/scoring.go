package analysis

import (
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

// Scorer converts security events into persisted threat scores. The ban
// decision itself lives in the server, because the threshold is a runtime
// setting that the dashboard can change.
type Scorer struct {
	db     *storage.DB
	points config.ScoringConfig
}

// NewScorer creates a Scorer backed by the given database and point table.
func NewScorer(db *storage.DB, points config.ScoringConfig) *Scorer {
	return &Scorer{db: db, points: points}
}

// Record adds the configured points for event to ip, updates the activity
// counters and returns the new cumulative score. port (when > 0) is recorded
// in the IP's list of touched ports.
func (s *Scorer) Record(ip, country string, event ScoreEvent, port int) (int, error) {
	return s.db.RecordScore(storage.ScoreEvent{
		IP:            ip,
		Country:       country,
		Delta:         s.pointsFor(event),
		HoneypotHit:   event == EventHoneypotConnection,
		CredentialHit: event == EventFailedCredential,
		Port:          port,
	})
}

func (s *Scorer) pointsFor(event ScoreEvent) int {
	switch event {
	case EventHoneypotConnection:
		return s.points.HoneypotConnection
	case EventFailedCredential:
		return s.points.FailedCredential
	case EventPortScan:
		return s.points.PortScanDetected
	case EventBlacklistedCountry:
		return s.points.BlacklistedCountry
	case EventRateLimitExceeded:
		return s.points.RateLimitExceeded
	default:
		return 0
	}
}
