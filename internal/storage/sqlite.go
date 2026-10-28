package storage

import (
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// DB wraps a sql.DB with migration support.
type DB struct {
	db *sql.DB
}

// tsLayout is the single timestamp format used for every stored time value.
// It is fixed-width UTC, so plain string comparison and ORDER BY sort
// chronologically and can use indexes (mixing it with SQLite's
// "YYYY-MM-DD HH:MM:SS" form breaks ordering because ' ' < 'T').
const tsLayout = "2006-01-02T15:04:05Z"

// sqlNow is the SQL expression producing the current time in tsLayout.
const sqlNow = `strftime('%Y-%m-%dT%H:%M:%SZ','now')`

func formatTS(t time.Time) string { return t.UTC().Format(tsLayout) }

// New opens (or creates) the SQLite database at path and runs all migrations.
// The parent directory is created when missing.
func New(path string) (*DB, error) {
	if path == "" {
		return nil, fmt.Errorf("database path is empty")
	}
	if path != ":memory:" {
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			return nil, fmt.Errorf("creating database directory: %w", err)
		}
	}

	// Pragmas are passed via the DSN so they apply to every pooled connection.
	// busy_timeout makes writers wait instead of failing with SQLITE_BUSY, and
	// _txlock=immediate takes the write lock at BEGIN so read→write upgrades
	// inside a transaction cannot deadlock under concurrent load.
	q := url.Values{}
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "synchronous(NORMAL)")
	q.Add("_pragma", "foreign_keys(ON)")
	q.Set("_txlock", "immediate")
	dsn := "file:" + path + "?" + q.Encode()

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}
	if path == ":memory:" {
		// Every new connection to :memory: is a separate empty database.
		db.SetMaxOpenConns(1)
	}
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("opening database %s: %w", path, err)
	}

	d := &DB{db: db}
	if err := d.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("running migrations: %w", err)
	}
	return d, nil
}

// Close closes the underlying database connection.
func (d *DB) Close() error {
	return d.db.Close()
}

// migrate creates all required tables and indexes if they do not already
// exist, and normalises timestamps written by older versions.
func (d *DB) migrate() error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS connections (
			id           INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp    DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
			source_ip    TEXT     NOT NULL,
			source_port  INTEGER  NOT NULL,
			dest_port    INTEGER  NOT NULL,
			country      TEXT     NOT NULL DEFAULT '',
			city         TEXT     NOT NULL DEFAULT '',
			service_type TEXT     NOT NULL DEFAULT '',
			action       TEXT     NOT NULL DEFAULT '',
			data         TEXT     NOT NULL DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_connections_source_ip ON connections (source_ip)`,
		`CREATE INDEX IF NOT EXISTS idx_connections_timestamp ON connections (timestamp)`,
		`CREATE INDEX IF NOT EXISTS idx_connections_dest_port ON connections (dest_port)`,

		`CREATE TABLE IF NOT EXISTS credentials (
			id        INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
			source_ip TEXT     NOT NULL,
			port      INTEGER  NOT NULL,
			username  TEXT     NOT NULL DEFAULT '',
			password  TEXT     NOT NULL DEFAULT '',
			service   TEXT     NOT NULL DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_credentials_source_ip ON credentials (source_ip)`,
		`CREATE INDEX IF NOT EXISTS idx_credentials_timestamp ON credentials (timestamp)`,

		`CREATE TABLE IF NOT EXISTS banned_ips (
			id         INTEGER  PRIMARY KEY AUTOINCREMENT,
			ip         TEXT     NOT NULL UNIQUE,
			reason     TEXT     NOT NULL DEFAULT '',
			banned_at  DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
			expires_at DATETIME,
			permanent  INTEGER  NOT NULL DEFAULT 0
		)`,
		`CREATE INDEX IF NOT EXISTS idx_banned_ips_expires_at ON banned_ips (expires_at)`,

		`CREATE TABLE IF NOT EXISTS ip_scores (
			ip                  TEXT     PRIMARY KEY,
			score               INTEGER  NOT NULL DEFAULT 0,
			total_connections   INTEGER  NOT NULL DEFAULT 0,
			honeypot_hits       INTEGER  NOT NULL DEFAULT 0,
			credential_attempts INTEGER  NOT NULL DEFAULT 0,
			ports_scanned       TEXT     NOT NULL DEFAULT '[]',
			first_seen          DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
			last_seen           DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
			country             TEXT     NOT NULL DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_ip_scores_score ON ip_scores (score DESC)`,

		`CREATE TABLE IF NOT EXISTS settings (
			key   TEXT PRIMARY KEY,
			value TEXT NOT NULL
		)`,

		// Older versions wrote a mix of "YYYY-MM-DD HH:MM:SS" and RFC3339.
		// Rewrite anything not already in tsLayout; no-op on clean databases.
		`UPDATE connections SET timestamp = strftime('%Y-%m-%dT%H:%M:%SZ', timestamp)
			WHERE timestamp NOT GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z'
			  AND strftime('%Y-%m-%dT%H:%M:%SZ', timestamp) IS NOT NULL`,
		`UPDATE credentials SET timestamp = strftime('%Y-%m-%dT%H:%M:%SZ', timestamp)
			WHERE timestamp NOT GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z'
			  AND strftime('%Y-%m-%dT%H:%M:%SZ', timestamp) IS NOT NULL`,
		`UPDATE banned_ips SET
			banned_at  = COALESCE(strftime('%Y-%m-%dT%H:%M:%SZ', banned_at), banned_at),
			expires_at = CASE WHEN expires_at IS NULL THEN NULL
			                  ELSE COALESCE(strftime('%Y-%m-%dT%H:%M:%SZ', expires_at), expires_at) END
			WHERE banned_at NOT GLOB '*T*Z' OR (expires_at IS NOT NULL AND expires_at NOT GLOB '*T*Z')`,
		// A non-permanent ban without expiry used to mean "forever"; make it explicit.
		`UPDATE banned_ips SET permanent = 1 WHERE permanent = 0 AND expires_at IS NULL`,
	}

	for _, stmt := range statements {
		if _, err := d.db.Exec(stmt); err != nil {
			return fmt.Errorf("executing migration statement: %w\nSQL: %s", err, stmt)
		}
	}
	return nil
}

// dbTime scans a stored timestamp regardless of how the driver surfaces it
// (modernc returns time.Time for DATETIME columns, string for expressions).
type dbTime struct {
	Time  time.Time
	Valid bool
}

func (t *dbTime) Scan(src any) error {
	switch v := src.(type) {
	case nil:
		t.Time, t.Valid = time.Time{}, false
		return nil
	case time.Time:
		t.Time, t.Valid = v.UTC(), true
		return nil
	case string:
		return t.parse(v)
	case []byte:
		return t.parse(string(v))
	default:
		return fmt.Errorf("unsupported timestamp type %T", src)
	}
}

func (t *dbTime) parse(s string) error {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02 15:04:05", "2006-01-02 15:04:05.999999999-07:00"} {
		if p, err := time.Parse(layout, s); err == nil {
			t.Time, t.Valid = p.UTC(), true
			return nil
		}
	}
	return fmt.Errorf("parsing timestamp %q", s)
}

// BackupTo writes a consistent copy of the database to path while it is in
// use (VACUUM INTO), for example before an update.
func (d *DB) BackupTo(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%s already exists", path)
	}
	_, err := d.db.Exec("VACUUM INTO ?", path)
	return err
}

// Size is the database's size on disk in bytes (main file and WAL).
func (d *DB) Size() int64 {
	var pages, size int64
	_ = d.db.QueryRow("PRAGMA page_count").Scan(&pages)
	_ = d.db.QueryRow("PRAGMA page_size").Scan(&size)
	return pages * size
}
