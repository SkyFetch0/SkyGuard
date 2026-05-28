package storage

import "fmt"

// Attacker represents an IP with aggregated attack statistics.
type Attacker struct {
	IP           string
	Country      string
	Score        int
	Connections  int64
	HoneypotHits int64
	LastSeen     string
}

// GetTopAttackers returns the top n IPs by threat score.
func (d *DB) GetTopAttackers(limit int) ([]*Attacker, error) {
	const query = `
		SELECT ip, country, score, total_connections, honeypot_hits, last_seen
		FROM   ip_scores
		ORDER  BY score DESC
		LIMIT  ?`

	rows, err := d.db.Query(query, limit)
	if err != nil {
		return nil, fmt.Errorf("querying top attackers: %w", err)
	}
	defer rows.Close()

	var results []*Attacker
	for rows.Next() {
		a := &Attacker{}
		if err := rows.Scan(&a.IP, &a.Country, &a.Score, &a.Connections, &a.HoneypotHits, &a.LastSeen); err != nil {
			return nil, fmt.Errorf("scanning attacker row: %w", err)
		}
		results = append(results, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating attacker rows: %w", err)
	}
	return results, nil
}