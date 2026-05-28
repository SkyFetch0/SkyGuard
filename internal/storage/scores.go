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
	IP                 string
	Score              int
	TotalConnections   int
	HoneypotHits       int
	CredentialAttempts int
	PortsScanned       []int
	FirstSeen          time.Time
	LastSeen           time.Time
	Country            string
}

// GetOrCreateScore returns the IPScore for ip, inserting a new row with
// default values if one does not yet exist. country is only used on insert.
func (d *DB) GetOrCreateScore(ip, country string) (*IPScore, error) {
	const upsert = `
		INSERT INTO ip_scores (ip, country)
		VALUES (?, ?)
		ON CONFLICT(ip) DO NOTHING`

	if _, err := d.db.Exec(upsert, ip, country); err != nil {
		return nil, fmt.Errorf("upserting ip_scores row for %s: %w", ip, err)
	}

	return d.fetchScore(ip)
}

// UpdateScore increments the named counter field and updates score by delta.
// Valid field values: "honeypot_hits", "credential_attempts", "total_connections".
func (d *DB) UpdateScore(ip string, delta int, field string) error {
	allowed := map[string]bool{
		"honeypot_hits":       true,
		"credential_attempts": true,
		"total_connections":   true,
	}
	if !allowed[field] {
		return fmt.Errorf("unknown score field: %q", field)
	}

	// Using fmt.Sprintf for the column name is safe because we validate above.
	query := fmt.Sprintf(`
		UPDATE ip_scores
		SET    score   = score + ?,
		       %s      = %s + 1,
		       last_seen = datetime('now')
		WHERE  ip = ?`, field, field)

	res, err := d.db.Exec(query, delta, ip)
	if err != nil {
		return fmt.Errorf("updating score for %s: %w", ip, err)
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		// Row doesn't exist yet; create it first, then update.
		if _, err := d.db.Exec(`INSERT INTO ip_scores (ip) VALUES (?) ON CONFLICT(ip) DO NOTHING`, ip); err != nil {
			return fmt.Errorf("inserting ip_scores row for %s: %w", ip, err)
		}
		if _, err := d.db.Exec(query, delta, ip); err != nil {
			return fmt.Errorf("updating score for %s after insert: %w", ip, err)
		}
	}
	return nil
}

// AddPortScan appends port to the JSON array stored in ports_scanned for ip.
// Duplicate port numbers are silently ignored.
// The read-modify-write cycle runs inside a transaction to prevent TOCTOU races.
func (d *DB) AddPortScan(ip string, port int) error {
	tx, err := d.db.Begin()
	if err != nil {
		return fmt.Errorf("beginning transaction for AddPortScan: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck — rollback on any non-committed path

	// Ensure the row exists.
	if _, err := tx.Exec(`INSERT INTO ip_scores (ip) VALUES (?) ON CONFLICT(ip) DO NOTHING`, ip); err != nil {
		return fmt.Errorf("inserting ip_scores row for %s: %w", ip, err)
	}

	var portsJSON string
	if err := tx.QueryRow(`SELECT ports_scanned FROM ip_scores WHERE ip = ?`, ip).Scan(&portsJSON); err != nil {
		return fmt.Errorf("reading ports_scanned for %s: %w", ip, err)
	}

	var ports []int
	if err := json.Unmarshal([]byte(portsJSON), &ports); err != nil {
		ports = []int{}
	}

	// Deduplicate.
	for _, p := range ports {
		if p == port {
			return tx.Commit()
		}
	}
	ports = append(ports, port)

	updated, err := json.Marshal(ports)
	if err != nil {
		return fmt.Errorf("marshalling ports_scanned: %w", err)
	}

	if _, err := tx.Exec(`
		UPDATE ip_scores
		SET    ports_scanned = ?,
		       last_seen     = datetime('now')
		WHERE  ip = ?`, string(updated), ip); err != nil {
		return fmt.Errorf("updating ports_scanned for %s: %w", ip, err)
	}

	return tx.Commit()
}

// GetTopIPScores returns the IPs with the highest scores, up to limit entries.
func (d *DB) GetTopIPScores(limit int) ([]*IPScore, error) {
	const query = `
		SELECT ip, score, total_connections, honeypot_hits, credential_attempts,
		       ports_scanned, first_seen, last_seen, country
		FROM   ip_scores
		ORDER  BY score DESC
		LIMIT  ?`

	rows, err := d.db.Query(query, limit)
	if err != nil {
		return nil, fmt.Errorf("querying top attackers: %w", err)
	}
	defer rows.Close()

	return scanIPScores(rows)
}

// GetScore returns the current threat score for ip, or 0 if ip is unknown.
func (d *DB) GetScore(ip string) (int, error) {
	const query = `SELECT score FROM ip_scores WHERE ip = ?`
	row := d.db.QueryRow(query, ip)

	var score int
	if err := row.Scan(&score); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, nil
		}
		return 0, fmt.Errorf("getting score for %s: %w", ip, err)
	}
	return score, nil
}

// ─── helpers ────────────────────────────────────────────────────────────────

func (d *DB) fetchScore(ip string) (*IPScore, error) {
	const query = `
		SELECT ip, score, total_connections, honeypot_hits, credential_attempts,
		       ports_scanned, first_seen, last_seen, country
		FROM   ip_scores
		WHERE  ip = ?`

	rows, err := d.db.Query(query, ip)
	if err != nil {
		return nil, fmt.Errorf("fetching score for %s: %w", ip, err)
	}
	defer rows.Close()

	scores, err := scanIPScores(rows)
	if err != nil {
		return nil, err
	}
	if len(scores) == 0 {
		return nil, fmt.Errorf("ip_scores row not found for %s", ip)
	}
	return scores[0], nil
}

func scanIPScores(rows interface {
	Next() bool
	Scan(...any) error
	Err() error
}) ([]*IPScore, error) {
	var results []*IPScore

	for rows.Next() {
		s := &IPScore{}
		var portsJSON, firstStr, lastStr string

		if err := rows.Scan(
			&s.IP, &s.Score, &s.TotalConnections, &s.HoneypotHits,
			&s.CredentialAttempts, &portsJSON, &firstStr, &lastStr, &s.Country,
		); err != nil {
			return nil, fmt.Errorf("scanning ip_scores row: %w", err)
		}

		if err := json.Unmarshal([]byte(portsJSON), &s.PortsScanned); err != nil {
			s.PortsScanned = []int{}
		}

		first, err := parseTimestamp(firstStr)
		if err != nil {
			return nil, err
		}
		last, err := parseTimestamp(lastStr)
		if err != nil {
			return nil, err
		}
		s.FirstSeen = first
		s.LastSeen = last

		results = append(results, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating ip_scores rows: %w", err)
	}
	return results, nil
}