package storage

import (
	"fmt"
	"time"
)

// Aggregations behind the dashboard's charts. Every query takes a half-open
// window [since, until) so a period and the one before it never overlap.

// Summary counts what happened in a window.
type Summary struct {
	Connections  int64 `json:"connections"`
	HoneypotHits int64 `json:"honeypot_hits"`
	Forwarded    int64 `json:"forwarded"`
	Dropped      int64 `json:"dropped"`
	Credentials  int64 `json:"credentials"`
	UniqueIPs    int64 `json:"unique_ips"`
	BansIssued   int64 `json:"bans_issued"`
}

// Summary returns the counters for [since, until).
func (d *DB) Summary(since, until time.Time) (*Summary, error) {
	s, u := formatTS(since), formatTS(until)
	out := &Summary{}
	err := d.db.QueryRow(`
		SELECT COUNT(*),
		       COALESCE(SUM(action = 'honeypot'), 0),
		       COALESCE(SUM(action = 'forwarded'), 0),
		       COALESCE(SUM(action = 'dropped'), 0),
		       COUNT(DISTINCT source_ip)
		FROM connections WHERE timestamp >= ? AND timestamp < ?`, s, u).
		Scan(&out.Connections, &out.HoneypotHits, &out.Forwarded, &out.Dropped, &out.UniqueIPs)
	if err != nil {
		return nil, fmt.Errorf("summary: %w", err)
	}
	if err := d.db.QueryRow(`SELECT COUNT(*) FROM credentials WHERE timestamp >= ? AND timestamp < ?`, s, u).
		Scan(&out.Credentials); err != nil {
		return nil, fmt.Errorf("summary credentials: %w", err)
	}
	if err := d.db.QueryRow(`SELECT COUNT(*) FROM banned_ips WHERE banned_at >= ? AND banned_at < ?`, s, u).
		Scan(&out.BansIssued); err != nil {
		return nil, fmt.Errorf("summary bans: %w", err)
	}
	return out, nil
}

// Outcome is one destination in the decision flow: where connections ended up.
type Outcome struct {
	Key   string `json:"key"`
	Count int64  `json:"count"`
}

// OutcomeKeys lists every outcome in display order (the pipeline's order).
var OutcomeKeys = []string{"honeypot", "forwarded", "banned", "blacklist", "rate_limited", "port_scan", "stealth_probe", "dropped_other"}

// Outcomes classifies every connection in the window by what SkyGuard did
// with it. The keys follow the server's routing: a dropped row's data field
// carries the reason it was dropped.
func (d *DB) Outcomes(since, until time.Time) ([]Outcome, error) {
	rows, err := d.db.Query(`
		SELECT CASE
			WHEN action = 'honeypot'  THEN 'honeypot'
			WHEN action = 'forwarded' THEN 'forwarded'
			WHEN data = 'banned' THEN 'banned'
			WHEN data IN ('blacklisted_ip', 'blacklisted_country', 'country_not_allowed') THEN 'blacklist'
			WHEN data = 'rate_limited' THEN 'rate_limited'
			WHEN data = 'port_scan' THEN 'port_scan'
			WHEN data LIKE '%stealth:%' THEN 'stealth_probe'
			ELSE 'dropped_other' END AS outcome,
		       COUNT(*)
		FROM connections WHERE timestamp >= ? AND timestamp < ?
		GROUP BY outcome`, formatTS(since), formatTS(until))
	if err != nil {
		return nil, fmt.Errorf("outcomes: %w", err)
	}
	defer rows.Close()
	counts := map[string]int64{}
	for rows.Next() {
		var k string
		var n int64
		if err := rows.Scan(&k, &n); err != nil {
			return nil, err
		}
		counts[k] = n
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]Outcome, 0, len(OutcomeKeys))
	for _, k := range OutcomeKeys {
		out = append(out, Outcome{Key: k, Count: counts[k]})
	}
	return out, nil
}

// SourceCount is one source IP's activity in a window.
type SourceCount struct {
	IP       string    `json:"ip"`
	Country  string    `json:"country"`
	Count    int64     `json:"count"`
	Honeypot int64     `json:"honeypot"`
	LastSeen time.Time `json:"last_seen"`
	Banned   bool      `json:"banned"`
}

// TopSources returns the most active source IPs in the window, with their
// current ban state.
func (d *DB) TopSources(since, until time.Time, limit int) ([]*SourceCount, error) {
	now := formatTS(time.Now())
	rows, err := d.db.Query(`
		SELECT c.source_ip, COALESCE(MAX(NULLIF(c.country, '')), ''), COUNT(*),
		       COALESCE(SUM(c.action = 'honeypot'), 0), MAX(c.timestamp),
		       EXISTS (SELECT 1 FROM banned_ips b WHERE b.ip = c.source_ip AND (b.permanent = 1 OR b.expires_at > ?))
		FROM connections c
		WHERE c.timestamp >= ? AND c.timestamp < ?
		GROUP BY c.source_ip
		ORDER BY COUNT(*) DESC, MAX(c.timestamp) DESC
		LIMIT ?`, now, formatTS(since), formatTS(until), limit)
	if err != nil {
		return nil, fmt.Errorf("top sources: %w", err)
	}
	defer rows.Close()
	out := []*SourceCount{}
	for rows.Next() {
		s := &SourceCount{}
		var last dbTime
		if err := rows.Scan(&s.IP, &s.Country, &s.Count, &s.Honeypot, &last, &s.Banned); err != nil {
			return nil, err
		}
		s.LastSeen = last.Time
		out = append(out, s)
	}
	return out, rows.Err()
}

// KeyCount is one row of a breakdown.
type KeyCount struct {
	Key   string `json:"key"`
	Count int64  `json:"count"`
}

// connectionBreakdowns maps a breakdown name to its column; the name is never
// interpolated from user input directly.
var connectionBreakdowns = map[string]string{
	"service": "service_type",
	"country": "country",
	"port":    "CAST(dest_port AS TEXT)",
}

// Breakdown counts connections in the window grouped by "service", "country"
// or "port". Rows with an empty key (unknown country) are left out.
func (d *DB) Breakdown(by string, since, until time.Time, limit int) ([]KeyCount, error) {
	col, ok := connectionBreakdowns[by]
	if !ok {
		return nil, fmt.Errorf("unknown breakdown %q", by)
	}
	return d.keyCounts(`SELECT `+col+` AS k, COUNT(*) FROM connections
		WHERE timestamp >= ? AND timestamp < ? AND `+col+` != ''
		GROUP BY k ORDER BY COUNT(*) DESC, k LIMIT ?`, formatTS(since), formatTS(until), limit)
}

var credentialBreakdowns = map[string]string{
	"username": "username",
	"password": "password",
	"service":  "service",
}

// CredentialBreakdown counts captured credentials in the window grouped by
// "username", "password" or "service".
func (d *DB) CredentialBreakdown(by string, since, until time.Time, limit int) ([]KeyCount, error) {
	col, ok := credentialBreakdowns[by]
	if !ok {
		return nil, fmt.Errorf("unknown breakdown %q", by)
	}
	return d.keyCounts(`SELECT `+col+` AS k, COUNT(*) FROM credentials
		WHERE timestamp >= ? AND timestamp < ? AND `+col+` != ''
		GROUP BY k ORDER BY COUNT(*) DESC, k LIMIT ?`, formatTS(since), formatTS(until), limit)
}

func (d *DB) keyCounts(query string, args ...any) ([]KeyCount, error) {
	rows, err := d.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("breakdown: %w", err)
	}
	defer rows.Close()
	out := []KeyCount{}
	for rows.Next() {
		var k KeyCount
		if err := rows.Scan(&k.Key, &k.Count); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// Series returns per-bucket counts for [since, until) with buckets of one
// hour or one day (step must be time.Hour or 24*time.Hour), optionally for
// one source IP or destination port. Empty buckets are included with zeros so a chart's x-axis
// is linear.
// SeriesFilter narrows a series to one source IP and/or one destination port.
type SeriesFilter struct {
	IP   string
	Port int
}

func (d *DB) Series(since, until time.Time, step time.Duration, f SeriesFilter) ([]*TimelineBucket, error) {
	prefix := 13 // "2006-01-02T15"
	suffix := ":00:00Z"
	if step == 24*time.Hour {
		prefix, suffix = 10, "T00:00:00Z"
	} else if step != time.Hour {
		return nil, fmt.Errorf("unsupported bucket %s", step)
	}
	start := since.UTC().Truncate(step)
	s, u := formatTS(start), formatTS(until)
	// Optional filters; an empty IP or a zero port matches every row.
	connFilter := " AND (? = '' OR source_ip = ?) AND (? = 0 OR dest_port = ?)"
	credFilter := " AND (? = '' OR source_ip = ?) AND (? = 0 OR port = ?)"
	fargs := []any{f.IP, f.IP, f.Port, f.Port}

	byBucket := map[string]*TimelineBucket{}
	rows, err := d.db.Query(fmt.Sprintf(`
		SELECT substr(timestamp, 1, %d) || '%s' AS b, COUNT(*),
		       COALESCE(SUM(action = 'honeypot'), 0),
		       COALESCE(SUM(action = 'dropped'), 0),
		       COALESCE(SUM(action = 'forwarded'), 0)
		FROM connections WHERE timestamp >= ? AND timestamp < ?`+connFilter+` GROUP BY b`, prefix, suffix), append([]any{s, u}, fargs...)...)
	if err != nil {
		return nil, fmt.Errorf("series: %w", err)
	}
	for rows.Next() {
		b := &TimelineBucket{}
		if err := rows.Scan(&b.Bucket, &b.Total, &b.HoneypotHits, &b.Dropped, &b.Forwarded); err != nil {
			rows.Close()
			return nil, err
		}
		byBucket[b.Bucket] = b
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	crows, err := d.db.Query(fmt.Sprintf(`
		SELECT substr(timestamp, 1, %d) || '%s' AS b, COUNT(*)
		FROM credentials WHERE timestamp >= ? AND timestamp < ?`+credFilter+` GROUP BY b`, prefix, suffix), append([]any{s, u}, fargs...)...)
	if err != nil {
		return nil, fmt.Errorf("series credentials: %w", err)
	}
	for crows.Next() {
		var key string
		var n int64
		if err := crows.Scan(&key, &n); err != nil {
			crows.Close()
			return nil, err
		}
		if b, ok := byBucket[key]; ok {
			b.Credentials = n
		} else {
			byBucket[key] = &TimelineBucket{Bucket: key, Credentials: n}
		}
	}
	crows.Close()
	if err := crows.Err(); err != nil {
		return nil, err
	}

	var out []*TimelineBucket
	for t := start; t.Before(until); t = t.Add(step) {
		key := formatTS(t)
		if b, ok := byBucket[key]; ok {
			out = append(out, b)
		} else {
			out = append(out, &TimelineBucket{Bucket: key})
		}
	}
	return out, nil
}
