package storage

import (
	"fmt"
	"time"
)

// Connection represents a single network connection event.
type Connection struct {
	ID          int64
	Timestamp   time.Time
	SourceIP    string
	SourcePort  int
	DestPort    int
	Country     string
	City        string
	ServiceType string
	Action      string
	Data        string
}

// LogConnection inserts a new connection record into the database.
func (d *DB) LogConnection(c *Connection) error {
	const query = `
		INSERT INTO connections
			(timestamp, source_ip, source_port, dest_port, country, city, service_type, action, data)
		VALUES
			(?, ?, ?, ?, ?, ?, ?, ?, ?)`

	ts := c.Timestamp
	if ts.IsZero() {
		ts = time.Now().UTC()
	}

	_, err := d.db.Exec(query,
		ts.Format(time.RFC3339),
		c.SourceIP,
		c.SourcePort,
		c.DestPort,
		c.Country,
		c.City,
		c.ServiceType,
		c.Action,
		c.Data,
	)
	if err != nil {
		return fmt.Errorf("logging connection: %w", err)
	}
	return nil
}

// GetRecentConnections returns the most recent connections up to limit rows,
// ordered newest first.
func (d *DB) GetRecentConnections(limit int) ([]*Connection, error) {
	const query = `
		SELECT id, timestamp, source_ip, source_port, dest_port,
		       country, city, service_type, action, data
		FROM   connections
		ORDER  BY timestamp DESC
		LIMIT  ?`

	rows, err := d.db.Query(query, limit)
	if err != nil {
		return nil, fmt.Errorf("querying recent connections: %w", err)
	}
	defer rows.Close()

	return scanConnections(rows)
}

// GetConnectionsByIP returns recent connections from a specific source IP,
// ordered newest first, up to limit rows.
func (d *DB) GetConnectionsByIP(ip string, limit int) ([]*Connection, error) {
	const query = `
		SELECT id, timestamp, source_ip, source_port, dest_port,
		       country, city, service_type, action, data
		FROM   connections
		WHERE  source_ip = ?
		ORDER  BY timestamp DESC
		LIMIT  ?`

	rows, err := d.db.Query(query, ip, limit)
	if err != nil {
		return nil, fmt.Errorf("querying connections by IP: %w", err)
	}
	defer rows.Close()

	return scanConnections(rows)
}

// ConnectionFilter holds optional filter criteria for connection log searches.
type ConnectionFilter struct {
	IP          string
	Country     string
	ServiceType string
	Action      string
	Since       time.Time
	Until       time.Time
	Limit       int
	Offset      int
}

// SearchConnections returns connections matching all non-empty filter fields.
func (d *DB) SearchConnections(f ConnectionFilter) ([]*Connection, error) {
	if f.Limit <= 0 {
		f.Limit = 100
	}

	query := `
		SELECT id, timestamp, source_ip, source_port, dest_port,
		       country, city, service_type, action, data
		FROM   connections
		WHERE  1=1`

	args := []interface{}{}

	if f.IP != "" {
		query += " AND source_ip = ?"
		args = append(args, f.IP)
	}
	if f.Country != "" {
		query += " AND country = ?"
		args = append(args, f.Country)
	}
	if f.ServiceType != "" {
		query += " AND service_type = ?"
		args = append(args, f.ServiceType)
	}
	if f.Action != "" {
		query += " AND action = ?"
		args = append(args, f.Action)
	}
	if !f.Since.IsZero() {
		query += " AND datetime(timestamp) >= datetime(?)"
		args = append(args, f.Since.UTC().Format(time.RFC3339))
	}
	if !f.Until.IsZero() {
		query += " AND datetime(timestamp) <= datetime(?)"
		args = append(args, f.Until.UTC().Format(time.RFC3339))
	}

	query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
	args = append(args, f.Limit, f.Offset)

	rows, err := d.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("searching connections: %w", err)
	}
	defer rows.Close()
	return scanConnections(rows)
}

// TimelineBucket holds aggregate counts for a single time bucket.
type TimelineBucket struct {
	Bucket       string `json:"bucket"`
	Total        int64  `json:"total"`
	HoneypotHits int64  `json:"honeypot_hits"`
	Dropped      int64  `json:"dropped"`
	Forwarded    int64  `json:"forwarded"`
}

// GetTimeline returns per-hour connection counts for the last n hours.
func (d *DB) GetTimeline(hours int) ([]*TimelineBucket, error) {
	if hours <= 0 {
		hours = 24
	}
	const query = `
		SELECT
			strftime('%Y-%m-%dT%H:00:00Z', timestamp)         AS bucket,
			COUNT(*)                                            AS total,
			COALESCE(SUM(CASE WHEN action='honeypot'  THEN 1 ELSE 0 END),0) AS honeypot_hits,
			COALESCE(SUM(CASE WHEN action='dropped'   THEN 1 ELSE 0 END),0) AS dropped,
			COALESCE(SUM(CASE WHEN action='forwarded' THEN 1 ELSE 0 END),0) AS forwarded
		FROM   connections
		WHERE  datetime(timestamp) >= datetime('now', ? || ' hours')
		GROUP  BY bucket
		ORDER  BY bucket ASC`

	rows, err := d.db.Query(query, fmt.Sprintf("-%d", hours))
	if err != nil {
		return nil, fmt.Errorf("querying timeline: %w", err)
	}
	defer rows.Close()

	var buckets []*TimelineBucket
	for rows.Next() {
		b := &TimelineBucket{}
		if err := rows.Scan(&b.Bucket, &b.Total, &b.HoneypotHits, &b.Dropped, &b.Forwarded); err != nil {
			return nil, fmt.Errorf("scanning timeline bucket: %w", err)
		}
		buckets = append(buckets, b)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating timeline: %w", err)
	}
	return buckets, nil
}

// GetExtendedStats returns enriched aggregate stats including today counts, unique IPs/countries.
func (d *DB) GetExtendedStats() (map[string]interface{}, error) {
	const query = `
		SELECT
			COUNT(*)                                                              AS total,
			COALESCE(SUM(CASE WHEN action='honeypot'  THEN 1 ELSE 0 END), 0)    AS honeypot_hits,
			COALESCE(SUM(CASE WHEN action='forwarded' THEN 1 ELSE 0 END), 0)    AS forwarded,
			COALESCE(SUM(CASE WHEN action='dropped'   THEN 1 ELSE 0 END), 0)    AS dropped,
			COALESCE(SUM(CASE WHEN date(timestamp)=date('now') THEN 1 ELSE 0 END),0) AS today,
			COUNT(DISTINCT source_ip)                                             AS unique_ips,
			COUNT(DISTINCT country)                                               AS unique_countries
		FROM connections`

	row := d.db.QueryRow(query)

	var total, honeypot, forwarded, dropped, today, uniqueIPs, uniqueCountries int64
	if err := row.Scan(&total, &honeypot, &forwarded, &dropped, &today, &uniqueIPs, &uniqueCountries); err != nil {
		return nil, fmt.Errorf("scanning extended stats: %w", err)
	}

	const banQuery = `
		SELECT
			COUNT(*) AS active_bans,
			COALESCE(SUM(CASE WHEN date(banned_at)=date('now') THEN 1 ELSE 0 END),0) AS bans_today
		FROM banned_ips`

	banRow := d.db.QueryRow(banQuery)
	var activeBans, bansToday int64
	if err := banRow.Scan(&activeBans, &bansToday); err != nil {
		return nil, fmt.Errorf("scanning ban stats: %w", err)
	}

	return map[string]interface{}{
		"total":            total,
		"honeypot_hits":    honeypot,
		"forwarded":        forwarded,
		"dropped":          dropped,
		"connections_today": today,
		"unique_ips":       uniqueIPs,
		"unique_countries": uniqueCountries,
		"active_bans":      activeBans,
		"bans_today":       bansToday,
	}, nil
}

// CleanOldConnections deletes connection records older than days days.
func (d *DB) CleanOldConnections(days int) error {
	const query = `
		DELETE FROM connections
		WHERE  datetime(timestamp) < datetime('now', ? || ' days')`

	if _, err := d.db.Exec(query, fmt.Sprintf("-%d", days)); err != nil {
		return fmt.Errorf("cleaning old connections: %w", err)
	}
	return nil
}

// GetConnectionStats returns aggregate counters keyed by category:
//
//	"total"         – all connections
//	"honeypot_hits" – connections with action="honeypot"
//	"forwarded"     – connections with action="forwarded"
//	"dropped"       – connections with action="dropped"
func (d *DB) GetConnectionStats() (map[string]int64, error) {
	const query = `
		SELECT
			COUNT(*)                                                        AS total,
			COALESCE(SUM(CASE WHEN action = 'honeypot'   THEN 1 ELSE 0 END), 0) AS honeypot_hits,
			COALESCE(SUM(CASE WHEN action = 'forwarded'  THEN 1 ELSE 0 END), 0) AS forwarded,
			COALESCE(SUM(CASE WHEN action = 'dropped'    THEN 1 ELSE 0 END), 0) AS dropped
		FROM connections`

	row := d.db.QueryRow(query)

	var total, honeypot, forwarded, dropped int64
	if err := row.Scan(&total, &honeypot, &forwarded, &dropped); err != nil {
		return nil, fmt.Errorf("scanning connection stats: %w", err)
	}

	return map[string]int64{
		"total":         total,
		"honeypot_hits": honeypot,
		"forwarded":     forwarded,
		"dropped":       dropped,
	}, nil
}

// scanConnections is a helper that reads all rows into a []*Connection slice.
func scanConnections(rows interface {
	Next() bool
	Scan(...any) error
	Err() error
}) ([]*Connection, error) {
	var results []*Connection

	for rows.Next() {
		c := &Connection{}
		var tsStr string

		if err := rows.Scan(
			&c.ID, &tsStr, &c.SourceIP, &c.SourcePort, &c.DestPort,
			&c.Country, &c.City, &c.ServiceType, &c.Action, &c.Data,
		); err != nil {
			return nil, fmt.Errorf("scanning connection row: %w", err)
		}

		ts, err := time.Parse(time.RFC3339, tsStr)
		if err != nil {
			// Fall back to SQLite datetime format.
			ts, err = time.Parse("2006-01-02 15:04:05", tsStr)
			if err != nil {
				return nil, fmt.Errorf("parsing timestamp %q: %w", tsStr, err)
			}
		}
		c.Timestamp = ts
		results = append(results, c)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating connection rows: %w", err)
	}
	return results, nil
}