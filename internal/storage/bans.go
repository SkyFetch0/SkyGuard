package storage

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// BannedIP holds information about a banned IP address.
type BannedIP struct {
	ID        int64
	IP        string
	Reason    string
	BannedAt  time.Time
	ExpiresAt *time.Time
	Permanent bool
}

// BanIP adds or updates a ban record for the given IP.
// When permanent is true, duration is ignored and the ban never expires.
func (d *DB) BanIP(ip, reason string, duration time.Duration, permanent bool) error {
	var expiresAt *string
	if !permanent && duration > 0 {
		s := time.Now().UTC().Add(duration).Format(time.RFC3339)
		expiresAt = &s
	}

	const query = `
		INSERT INTO banned_ips (ip, reason, banned_at, expires_at, permanent)
		VALUES (?, ?, datetime('now'), ?, ?)
		ON CONFLICT(ip) DO UPDATE SET
			reason     = excluded.reason,
			banned_at  = excluded.banned_at,
			expires_at = excluded.expires_at,
			permanent  = excluded.permanent`

	var expiresVal interface{}
	if expiresAt != nil {
		expiresVal = *expiresAt
	}

	_, err := d.db.Exec(query, ip, reason, expiresVal, boolToInt(permanent))
	if err != nil {
		return fmt.Errorf("banning IP %s: %w", ip, err)
	}
	return nil
}

// UnbanIP removes a ban record for the given IP address.
func (d *DB) UnbanIP(ip string) error {
	const query = `DELETE FROM banned_ips WHERE ip = ?`
	_, err := d.db.Exec(query, ip)
	if err != nil {
		return fmt.Errorf("unbanning IP %s: %w", ip, err)
	}
	return nil
}

// IsBanned reports whether ip is currently banned.
// Expired non-permanent bans are treated as not banned.
func (d *DB) IsBanned(ip string) (bool, error) {
	const query = `
		SELECT permanent, expires_at
		FROM   banned_ips
		WHERE  ip = ?`

	row := d.db.QueryRow(query, ip)

	var permanent int
	var expiresStr sql.NullString
	if err := row.Scan(&permanent, &expiresStr); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("checking ban for %s: %w", ip, err)
	}

	if permanent == 1 {
		return true, nil
	}

	if !expiresStr.Valid {
		// No expiry and not permanent – treat as active ban.
		return true, nil
	}

	expires, err := parseTimestamp(expiresStr.String)
	if err != nil {
		return false, fmt.Errorf("parsing expires_at for %s: %w", ip, err)
	}
	return time.Now().UTC().Before(expires), nil
}

// GetBannedIPs returns all current ban records (including expired ones).
func (d *DB) GetBannedIPs() ([]*BannedIP, error) {
	const query = `
		SELECT id, ip, reason, banned_at, expires_at, permanent
		FROM   banned_ips
		ORDER  BY banned_at DESC`

	rows, err := d.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("querying banned IPs: %w", err)
	}
	defer rows.Close()

	var results []*BannedIP
	for rows.Next() {
		b := &BannedIP{}
		var bannedStr string
		var expiresStr sql.NullString
		var permanentInt int

		if err := rows.Scan(&b.ID, &b.IP, &b.Reason, &bannedStr, &expiresStr, &permanentInt); err != nil {
			return nil, fmt.Errorf("scanning banned IP row: %w", err)
		}

		t, err := parseTimestamp(bannedStr)
		if err != nil {
			return nil, err
		}
		b.BannedAt = t
		b.Permanent = permanentInt == 1

		if expiresStr.Valid {
			exp, err := parseTimestamp(expiresStr.String)
			if err != nil {
				return nil, err
			}
			b.ExpiresAt = &exp
		}

		results = append(results, b)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating banned IP rows: %w", err)
	}
	return results, nil
}

// GetExpiredBans returns the IPs of all non-permanent bans whose expiry has
// already passed. Callers use this to lift the corresponding firewall rules
// before the rows are purged by CleanExpiredBans.
func (d *DB) GetExpiredBans() ([]string, error) {
	// datetime() normalises the stored RFC3339 string ("...T...Z") before
	// comparing; a raw string compare against datetime('now') (space-separated)
	// would mis-order same-day timestamps at the 'T' vs ' ' character.
	const query = `
		SELECT ip
		FROM   banned_ips
		WHERE  permanent = 0
		  AND  expires_at IS NOT NULL
		  AND  datetime(expires_at) < datetime('now')`

	rows, err := d.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("querying expired bans: %w", err)
	}
	defer rows.Close()

	var ips []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, fmt.Errorf("scanning expired ban row: %w", err)
		}
		ips = append(ips, ip)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating expired ban rows: %w", err)
	}
	return ips, nil
}

// CleanExpiredBans removes all non-permanent ban records that have already expired.
func (d *DB) CleanExpiredBans() error {
	const query = `
		DELETE FROM banned_ips
		WHERE  permanent = 0
		  AND  expires_at IS NOT NULL
		  AND  datetime(expires_at) < datetime('now')`

	_, err := d.db.Exec(query)
	if err != nil {
		return fmt.Errorf("cleaning expired bans: %w", err)
	}
	return nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}