package storage

import (
	"fmt"
	"time"
)

// Connection actions. Every row in the connections table uses one of these so
// the dashboard counters add up.
const (
	ActionHoneypot  = "honeypot"
	ActionForwarded = "forwarded"
	ActionDropped   = "dropped"
)

// Connection represents a single network connection event.
type Connection struct {
	ID          int64     `json:"id"`
	Timestamp   time.Time `json:"timestamp"`
	SourceIP    string    `json:"source_ip"`
	SourcePort  int       `json:"source_port"`
	DestPort    int       `json:"dest_port"`
	Country     string    `json:"country"`
	City        string    `json:"city"`
	ServiceType string    `json:"service_type"`
	Action      string    `json:"action"`
	Data        string    `json:"data"`
}

// LogConnection inserts a new connection record into the database.
func (d *DB) LogConnection(c *Connection) error {
	const query = `
		INSERT INTO connections
			(timestamp, source_ip, source_port, dest_port, country, city, service_type, action, data)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`

	ts := c.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}
	_, err := d.db.Exec(query, formatTS(ts), c.SourceIP, c.SourcePort, c.DestPort,
		c.Country, c.City, c.ServiceType, c.Action, c.Data)
	if err != nil {
		return fmt.Errorf("logging connection: %w", err)
	}
	return nil
}

const connectionColumns = `id, timestamp, source_ip, source_port, dest_port,
	country, city, service_type, action, data`

// GetRecentConnections returns the most recent connections, newest first.
func (d *DB) GetRecentConnections(limit int) ([]*Connection, error) {
	return d.SearchConnections(ConnectionFilter{Limit: limit})
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

// SearchConnections returns connections matching all non-empty filter fields,
// newest first.
func (d *DB) SearchConnections(f ConnectionFilter) ([]*Connection, error) {
	if f.Limit <= 0 {
		f.Limit = 100
	}
	if f.Offset < 0 {
		f.Offset = 0
	}

	query := `SELECT ` + connectionColumns + ` FROM connections WHERE 1=1`
	var args []any

	if f.IP != "" {
		query += " AND source_ip = ?"
		args = append(args, f.IP)
	}
	if f.Country != "" {
		query += " AND country = ? COLLATE NOCASE"
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
		query += " AND timestamp >= ?"
		args = append(args, formatTS(f.Since))
	}
	if !f.Until.IsZero() {
		query += " AND timestamp <= ?"
		args = append(args, formatTS(f.Until))
	}
	query += " ORDER BY timestamp DESC, id DESC LIMIT ? OFFSET ?"
	args = append(args, f.Limit, f.Offset)

	rows, err := d.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("searching connections: %w", err)
	}
	defer rows.Close()

	results := []*Connection{}
	for rows.Next() {
		c := &Connection{}
		var ts dbTime
		if err := rows.Scan(&c.ID, &ts, &c.SourceIP, &c.SourcePort, &c.DestPort,
			&c.Country, &c.City, &c.ServiceType, &c.Action, &c.Data); err != nil {
			return nil, fmt.Errorf("scanning connection row: %w", err)
		}
		c.Timestamp = ts.Time
		results = append(results, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating connection rows: %w", err)
	}
	return results, nil
}

// TimelineBucket holds aggregate counts for a single hour.
type TimelineBucket struct {
	Bucket       string `json:"bucket"` // RFC3339, start of the hour (UTC)
	Total        int64  `json:"total"`
	HoneypotHits int64  `json:"honeypot_hits"`
	Dropped      int64  `json:"dropped"`
	Forwarded    int64  `json:"forwarded"`
}

// GetTimeline returns per-hour connection counts for the last n hours. Hours
// without traffic are included with zero counts so the chart's x-axis is linear.
func (d *DB) GetTimeline(hours int) ([]*TimelineBucket, error) {
	if hours <= 0 {
		hours = 24
	}
	now := time.Now().UTC().Truncate(time.Hour)
	start := now.Add(-time.Duration(hours-1) * time.Hour)

	const query = `
		SELECT
			substr(timestamp, 1, 13) || ':00:00Z'                             AS bucket,
			COUNT(*)                                                          AS total,
			COALESCE(SUM(CASE WHEN action='honeypot'  THEN 1 ELSE 0 END), 0) AS honeypot_hits,
			COALESCE(SUM(CASE WHEN action='dropped'   THEN 1 ELSE 0 END), 0) AS dropped,
			COALESCE(SUM(CASE WHEN action='forwarded' THEN 1 ELSE 0 END), 0) AS forwarded
		FROM   connections
		WHERE  timestamp >= ?
		GROUP  BY bucket`

	rows, err := d.db.Query(query, formatTS(start))
	if err != nil {
		return nil, fmt.Errorf("querying timeline: %w", err)
	}
	defer rows.Close()

	byBucket := map[string]*TimelineBucket{}
	for rows.Next() {
		b := &TimelineBucket{}
		if err := rows.Scan(&b.Bucket, &b.Total, &b.HoneypotHits, &b.Dropped, &b.Forwarded); err != nil {
			return nil, fmt.Errorf("scanning timeline bucket: %w", err)
		}
		byBucket[b.Bucket] = b
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating timeline: %w", err)
	}

	buckets := make([]*TimelineBucket, 0, hours)
	for t := start; !t.After(now); t = t.Add(time.Hour) {
		key := formatTS(t)
		if b, ok := byBucket[key]; ok {
			buckets = append(buckets, b)
		} else {
			buckets = append(buckets, &TimelineBucket{Bucket: key})
		}
	}
	return buckets, nil
}

// Stats is the aggregate shown on the dashboard overview.
type Stats struct {
	Total           int64 `json:"total"`
	HoneypotHits    int64 `json:"honeypot_hits"`
	Forwarded       int64 `json:"forwarded"`
	Dropped         int64 `json:"dropped"`
	Today           int64 `json:"connections_today"`
	UniqueIPs       int64 `json:"unique_ips"`
	UniqueCountries int64 `json:"unique_countries"`
	Credentials     int64 `json:"credentials"`
	ActiveBans      int64 `json:"active_bans"`
	BansToday       int64 `json:"bans_today"`
}

// GetStats returns aggregate counters for the dashboard.
func (d *DB) GetStats() (*Stats, error) {
	todayStart := formatTS(time.Now().UTC().Truncate(24 * time.Hour))
	now := formatTS(time.Now())

	s := &Stats{}
	err := d.db.QueryRow(`
		SELECT
			COUNT(*),
			COALESCE(SUM(CASE WHEN action='honeypot'  THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN action='forwarded' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN action='dropped'   THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN timestamp >= ? THEN 1 ELSE 0 END), 0),
			COUNT(DISTINCT source_ip),
			COUNT(DISTINCT NULLIF(country, ''))
		FROM connections`, todayStart).
		Scan(&s.Total, &s.HoneypotHits, &s.Forwarded, &s.Dropped, &s.Today, &s.UniqueIPs, &s.UniqueCountries)
	if err != nil {
		return nil, fmt.Errorf("scanning connection stats: %w", err)
	}

	if err := d.db.QueryRow(`SELECT COUNT(*) FROM credentials`).Scan(&s.Credentials); err != nil {
		return nil, fmt.Errorf("scanning credential stats: %w", err)
	}

	err = d.db.QueryRow(`
		SELECT
			COALESCE(SUM(CASE WHEN permanent = 1 OR expires_at > ? THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN banned_at >= ? THEN 1 ELSE 0 END), 0)
		FROM banned_ips`, now, todayStart).Scan(&s.ActiveBans, &s.BansToday)
	if err != nil {
		return nil, fmt.Errorf("scanning ban stats: %w", err)
	}
	return s, nil
}

// CleanOldConnections deletes connection records older than days days.
func (d *DB) CleanOldConnections(days int) (int64, error) {
	cutoff := formatTS(time.Now().Add(-time.Duration(days) * 24 * time.Hour))
	res, err := d.db.Exec(`DELETE FROM connections WHERE timestamp < ?`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("cleaning old connections: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}
