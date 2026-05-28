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