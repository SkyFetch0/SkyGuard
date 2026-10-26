package storage

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// BannedIP holds information about a banned IP address.
type BannedIP struct {
	ID        int64      `json:"id"`
	IP        string     `json:"ip"`
	Reason    string     `json:"reason"`
	BannedAt  time.Time  `json:"banned_at"`
	ExpiresAt *time.Time `json:"expires_at"`
	Permanent bool       `json:"permanent"`
}

// BanIP adds or updates a ban record for ip. A zero duration means the ban
// never expires, and is stored as permanent so every query agrees on it.
func (d *DB) BanIP(ip, reason string, duration time.Duration, permanent bool) error {
	if duration <= 0 {
		permanent = true
	}
	var expires any
	if !permanent {
		expires = formatTS(time.Now().Add(duration))
	}

	_, err := d.db.Exec(`
		INSERT INTO banned_ips (ip, reason, banned_at, expires_at, permanent)
		VALUES (?, ?, `+sqlNow+`, ?, ?)
		ON CONFLICT(ip) DO UPDATE SET
			reason     = excluded.reason,
			banned_at  = excluded.banned_at,
			expires_at = excluded.expires_at,
			permanent  = excluded.permanent`,
		ip, reason, expires, boolToInt(permanent))
	if err != nil {
		return fmt.Errorf("banning IP %s: %w", ip, err)
	}
	return nil
}

// UnbanIP removes the ban record for ip.
func (d *DB) UnbanIP(ip string) error {
	if _, err := d.db.Exec(`DELETE FROM banned_ips WHERE ip = ?`, ip); err != nil {
		return fmt.Errorf("unbanning IP %s: %w", ip, err)
	}
	return nil
}

// IsBanned reports whether ip is currently banned (expired bans do not count).
func (d *DB) IsBanned(ip string) (bool, error) {
	var n int
	err := d.db.QueryRow(`
		SELECT 1 FROM banned_ips
		WHERE ip = ? AND (permanent = 1 OR expires_at > ?)`, ip, formatTS(time.Now())).Scan(&n)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("checking ban for %s: %w", ip, err)
	}
	return true, nil
}

// GetActiveBans returns all bans that have not expired, newest first.
func (d *DB) GetActiveBans() ([]*BannedIP, error) {
	rows, err := d.db.Query(`
		SELECT id, ip, reason, banned_at, expires_at, permanent
		FROM   banned_ips
		WHERE  permanent = 1 OR expires_at > ?
		ORDER  BY banned_at DESC`, formatTS(time.Now()))
	if err != nil {
		return nil, fmt.Errorf("querying banned IPs: %w", err)
	}
	defer rows.Close()

	results := []*BannedIP{}
	for rows.Next() {
		b := &BannedIP{}
		var bannedAt, expiresAt dbTime
		var permanent int
		if err := rows.Scan(&b.ID, &b.IP, &b.Reason, &bannedAt, &expiresAt, &permanent); err != nil {
			return nil, fmt.Errorf("scanning banned IP row: %w", err)
		}
		b.BannedAt = bannedAt.Time
		b.Permanent = permanent == 1
		if expiresAt.Valid {
			t := expiresAt.Time
			b.ExpiresAt = &t
		}
		results = append(results, b)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating banned IP rows: %w", err)
	}
	return results, nil
}

// GetExpiredBans returns the IPs of all non-permanent bans whose expiry has
// passed. Callers lift the firewall rule and then call DeleteExpiredBan.
func (d *DB) GetExpiredBans() ([]string, error) {
	rows, err := d.db.Query(`
		SELECT ip FROM banned_ips
		WHERE  permanent = 0 AND expires_at IS NOT NULL AND expires_at <= ?`, formatTS(time.Now()))
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
	return ips, rows.Err()
}

// DeleteExpiredBan removes ip's ban row only if it is still expired, so a ban
// renewed between GetExpiredBans and this call is preserved.
func (d *DB) DeleteExpiredBan(ip string) error {
	_, err := d.db.Exec(`
		DELETE FROM banned_ips
		WHERE ip = ? AND permanent = 0 AND expires_at IS NOT NULL AND expires_at <= ?`,
		ip, formatTS(time.Now()))
	if err != nil {
		return fmt.Errorf("deleting expired ban %s: %w", ip, err)
	}
	return nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
