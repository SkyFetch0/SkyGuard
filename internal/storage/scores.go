package storage

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// IPScore tracks the threat score and activity counters for a single IP address.
type IPScore struct {
	IP                 string    `json:"ip"`
	Score              int       `json:"score"`
	TotalConnections   int       `json:"total_connections"`
	HoneypotHits       int       `json:"honeypot_hits"`
	CredentialAttempts int       `json:"credential_attempts"`
	PortsScanned       []int     `json:"ports_scanned"`
	FirstSeen          time.Time `json:"first_seen"`
	LastSeen           time.Time `json:"last_seen"`
	Country            string    `json:"country"`
}

// ScoreEvent describes one scored event for RecordScore.
type ScoreEvent struct {
	IP            string
	Country       string
	Delta         int  // points added to the score
	HoneypotHit   bool // increments honeypot_hits
	CredentialHit bool // increments credential_attempts
	Port          int  // recorded in ports_scanned when > 0
}

// RecordScore atomically upserts the IP's row, adds Delta to its score, bumps
// the activity counters and remembers the touched port. It returns the new
// cumulative score.
func (d *DB) RecordScore(ev ScoreEvent) (int, error) {
	port := any(nil)
	if ev.Port > 0 {
		port = ev.Port
	}
	initialPorts := "[]"
	if ev.Port > 0 {
		initialPorts = fmt.Sprintf("[%d]", ev.Port)
	}

	var score int
	err := d.db.QueryRow(`
		INSERT INTO ip_scores (ip, score, country, total_connections, honeypot_hits,
		                       credential_attempts, ports_scanned, first_seen, last_seen)
		VALUES (?, ?, ?, 1, ?, ?, ?, `+sqlNow+`, `+sqlNow+`)
		ON CONFLICT(ip) DO UPDATE SET
			score               = score + excluded.score,
			country             = CASE WHEN excluded.country != '' THEN excluded.country ELSE country END,
			total_connections   = total_connections + 1,
			honeypot_hits       = honeypot_hits + excluded.honeypot_hits,
			credential_attempts = credential_attempts + excluded.credential_attempts,
			ports_scanned       = CASE
				WHEN ?7 IS NULL THEN ports_scanned
				WHEN EXISTS (SELECT 1 FROM json_each(ports_scanned) WHERE value = ?7) THEN ports_scanned
				WHEN json_array_length(ports_scanned) >= 64 THEN ports_scanned
				ELSE json_insert(ports_scanned, '$[#]', ?7) END,
			last_seen           = excluded.last_seen
		RETURNING score`,
		ev.IP, ev.Delta, ev.Country, boolToInt(ev.HoneypotHit), boolToInt(ev.CredentialHit),
		initialPorts, port,
	).Scan(&score)
	if err != nil {
		return 0, fmt.Errorf("recording score for %s: %w", ev.IP, err)
	}
	return score, nil
}

// GetScore returns the current threat score for ip, or 0 if ip is unknown.
func (d *DB) GetScore(ip string) (int, error) {
	var score int
	err := d.db.QueryRow(`SELECT score FROM ip_scores WHERE ip = ?`, ip).Scan(&score)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("getting score for %s: %w", ip, err)
	}
	return score, nil
}

// ResetScore sets ip's score back to zero (activity counters are kept). It is
// called when a ban is lifted, otherwise the very next event would re-ban.
func (d *DB) ResetScore(ip string) error {
	if _, err := d.db.Exec(`UPDATE ip_scores SET score = 0 WHERE ip = ?`, ip); err != nil {
		return fmt.Errorf("resetting score for %s: %w", ip, err)
	}
	return nil
}

const scoreColumns = `ip, score, total_connections, honeypot_hits, credential_attempts,
	ports_scanned, first_seen, last_seen, country`

// GetTopAttackers returns the IPs with the highest scores.
func (d *DB) GetTopAttackers(limit int) ([]*IPScore, error) {
	rows, err := d.db.Query(`SELECT `+scoreColumns+` FROM ip_scores
		WHERE score > 0 ORDER BY score DESC, last_seen DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("querying top attackers: %w", err)
	}
	defer rows.Close()
	return scanIPScores(rows)
}

// GetIPScore returns the score row for ip, or nil when the IP is unknown.
func (d *DB) GetIPScore(ip string) (*IPScore, error) {
	rows, err := d.db.Query(`SELECT `+scoreColumns+` FROM ip_scores WHERE ip = ?`, ip)
	if err != nil {
		return nil, fmt.Errorf("fetching score for %s: %w", ip, err)
	}
	defer rows.Close()
	scores, err := scanIPScores(rows)
	if err != nil || len(scores) == 0 {
		return nil, err
	}
	return scores[0], nil
}

func scanIPScores(rows *sql.Rows) ([]*IPScore, error) {
	results := []*IPScore{}
	for rows.Next() {
		s := &IPScore{}
		var portsJSON string
		var first, last dbTime
		if err := rows.Scan(&s.IP, &s.Score, &s.TotalConnections, &s.HoneypotHits,
			&s.CredentialAttempts, &portsJSON, &first, &last, &s.Country); err != nil {
			return nil, fmt.Errorf("scanning ip_scores row: %w", err)
		}
		if err := json.Unmarshal([]byte(portsJSON), &s.PortsScanned); err != nil || s.PortsScanned == nil {
			s.PortsScanned = []int{}
		}
		s.FirstSeen, s.LastSeen = first.Time, last.Time
		results = append(results, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating ip_scores rows: %w", err)
	}
	return results, nil
}
