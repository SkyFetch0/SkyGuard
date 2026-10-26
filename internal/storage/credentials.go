package storage

import (
	"fmt"
	"time"
)

// Credential represents a single authentication attempt captured by a honeypot.
type Credential struct {
	ID        int64     `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	SourceIP  string    `json:"source_ip"`
	Port      int       `json:"port"`
	Username  string    `json:"username"`
	Password  string    `json:"password"`
	Service   string    `json:"service"`
}

// LogCredential inserts a new credential record into the database.
func (d *DB) LogCredential(c *Credential) error {
	ts := c.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}
	_, err := d.db.Exec(`
		INSERT INTO credentials (timestamp, source_ip, port, username, password, service)
		VALUES (?, ?, ?, ?, ?, ?)`,
		formatTS(ts), c.SourceIP, c.Port, c.Username, c.Password, c.Service)
	if err != nil {
		return fmt.Errorf("logging credential: %w", err)
	}
	return nil
}

// CredentialCount is one row of the "top credentials" report.
type CredentialCount struct {
	Username string    `json:"username"`
	Password string    `json:"password"`
	Service  string    `json:"service"`
	Count    int64     `json:"count"`
	LastSeen time.Time `json:"last_seen"`
}

// GetTopCredentials returns the most frequently attempted
// service/username/password combinations.
func (d *DB) GetTopCredentials(limit int) ([]*CredentialCount, error) {
	rows, err := d.db.Query(`
		SELECT   username, password, service, COUNT(*) AS cnt, MAX(timestamp)
		FROM     credentials
		GROUP BY service, username, password
		ORDER BY cnt DESC, MAX(timestamp) DESC
		LIMIT    ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("querying top credentials: %w", err)
	}
	defer rows.Close()

	results := []*CredentialCount{}
	for rows.Next() {
		c := &CredentialCount{}
		var last dbTime
		if err := rows.Scan(&c.Username, &c.Password, &c.Service, &c.Count, &last); err != nil {
			return nil, fmt.Errorf("scanning credential row: %w", err)
		}
		c.LastSeen = last.Time
		results = append(results, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating credential rows: %w", err)
	}
	return results, nil
}

// GetCredentialsByIP returns the newest credential records for ip.
func (d *DB) GetCredentialsByIP(ip string, limit int) ([]*Credential, error) {
	rows, err := d.db.Query(`
		SELECT id, timestamp, source_ip, port, username, password, service
		FROM   credentials
		WHERE  source_ip = ?
		ORDER  BY timestamp DESC, id DESC
		LIMIT  ?`, ip, limit)
	if err != nil {
		return nil, fmt.Errorf("querying credentials by IP: %w", err)
	}
	defer rows.Close()

	results := []*Credential{}
	for rows.Next() {
		c := &Credential{}
		var ts dbTime
		if err := rows.Scan(&c.ID, &ts, &c.SourceIP, &c.Port, &c.Username, &c.Password, &c.Service); err != nil {
			return nil, fmt.Errorf("scanning credential row: %w", err)
		}
		c.Timestamp = ts.Time
		results = append(results, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating credential rows: %w", err)
	}
	return results, nil
}

// CleanOldCredentials deletes credential records older than days days.
func (d *DB) CleanOldCredentials(days int) (int64, error) {
	cutoff := formatTS(time.Now().Add(-time.Duration(days) * 24 * time.Hour))
	res, err := d.db.Exec(`DELETE FROM credentials WHERE timestamp < ?`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("cleaning old credentials: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}
