package storage

import (
	"fmt"
	"time"
)

// Credential represents a single authentication attempt captured by a honeypot.
type Credential struct {
	ID        int64
	Timestamp time.Time
	SourceIP  string
	Port      int
	Username  string
	Password  string
	Service   string
}

// LogCredential inserts a new credential record into the database.
func (d *DB) LogCredential(c *Credential) error {
	const query = `
		INSERT INTO credentials
			(timestamp, source_ip, port, username, password, service)
		VALUES
			(?, ?, ?, ?, ?, ?)`

	ts := c.Timestamp
	if ts.IsZero() {
		ts = time.Now().UTC()
	}

	_, err := d.db.Exec(query,
		ts.Format(time.RFC3339),
		c.SourceIP,
		c.Port,
		c.Username,
		c.Password,
		c.Service,
	)
	if err != nil {
		return fmt.Errorf("logging credential: %w", err)
	}
	return nil
}

// GetTopCredentials returns the most frequently attempted username/password
// combinations, up to limit entries. Each map contains:
//
//	"username" string
//	"password" string
//	"count"    int64
func (d *DB) GetTopCredentials(limit int) ([]map[string]interface{}, error) {
	const query = `
		SELECT   username, password, COUNT(*) AS cnt
		FROM     credentials
		GROUP BY username, password
		ORDER BY cnt DESC
		LIMIT    ?`

	rows, err := d.db.Query(query, limit)
	if err != nil {
		return nil, fmt.Errorf("querying top credentials: %w", err)
	}
	defer rows.Close()

	var results []map[string]interface{}
	for rows.Next() {
		var username, password string
		var count int64
		if err := rows.Scan(&username, &password, &count); err != nil {
			return nil, fmt.Errorf("scanning credential row: %w", err)
		}
		results = append(results, map[string]interface{}{
			"username": username,
			"password": password,
			"count":    count,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating credential rows: %w", err)
	}
	return results, nil
}

// GetCredentialsByIP returns all credential records for the given source IP,
// ordered by newest first.
func (d *DB) GetCredentialsByIP(ip string) ([]*Credential, error) {
	const query = `
		SELECT id, timestamp, source_ip, port, username, password, service
		FROM   credentials
		WHERE  source_ip = ?
		ORDER  BY timestamp DESC`

	rows, err := d.db.Query(query, ip)
	if err != nil {
		return nil, fmt.Errorf("querying credentials by IP: %w", err)
	}
	defer rows.Close()

	var results []*Credential
	for rows.Next() {
		c := &Credential{}
		var tsStr string
		if err := rows.Scan(&c.ID, &tsStr, &c.SourceIP, &c.Port,
			&c.Username, &c.Password, &c.Service); err != nil {
			return nil, fmt.Errorf("scanning credential row: %w", err)
		}
		ts, err := parseTimestamp(tsStr)
		if err != nil {
			return nil, err
		}
		c.Timestamp = ts
		results = append(results, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating credential rows: %w", err)
	}
	return results, nil
}

// CleanOldCredentials deletes credential records older than days days.
func (d *DB) CleanOldCredentials(days int) error {
	const query = `
		DELETE FROM credentials
		WHERE  timestamp < datetime('now', ? || ' days')`

	if _, err := d.db.Exec(query, fmt.Sprintf("-%d", days)); err != nil {
		return fmt.Errorf("cleaning old credentials: %w", err)
	}
	return nil
}

// parseTimestamp tries RFC3339 then the plain SQLite datetime format.
func parseTimestamp(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, s)
	if err == nil {
		return t, nil
	}
	t, err = time.Parse("2006-01-02 15:04:05", s)
	if err != nil {
		return time.Time{}, fmt.Errorf("parsing timestamp %q: %w", s, err)
	}
	return t, nil
}