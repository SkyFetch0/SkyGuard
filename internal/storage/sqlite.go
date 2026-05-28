package storage

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

// DB wraps a sql.DB with migration support.
type DB struct {
	db *sql.DB
}

// New opens (or creates) the SQLite database at path and runs all migrations.
func New(path string) (*DB, error) {
	// Pragmas are passed via the DSN so they apply to every pooled connection,
	// not just the first one. busy_timeout makes writers wait-and-retry on
	// SQLITE_BUSY instead of failing immediately under concurrent load.
	dsn := fmt.Sprintf("%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
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

// DB returns the raw *sql.DB for direct access when needed.
func (d *DB) DB() *sql.DB {
	return d.db
}

// migrate creates all required tables and indexes if they do not already exist.
func (d *DB) migrate() error {
	statements := []string{
		// ----------------------------------------------------------------
		// connections
		// ----------------------------------------------------------------
		`CREATE TABLE IF NOT EXISTS connections (
			id           INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp    DATETIME NOT NULL DEFAULT (datetime('now')),
			source_ip    TEXT     NOT NULL,
			source_port  INTEGER  NOT NULL,
			dest_port    INTEGER  NOT NULL,
			country      TEXT     NOT NULL DEFAULT '',
			city         TEXT     NOT NULL DEFAULT '',
			service_type TEXT     NOT NULL DEFAULT '',
			action       TEXT     NOT NULL DEFAULT '',
			data         TEXT     NOT NULL DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_connections_source_ip
			ON connections (source_ip)`,
		`CREATE INDEX IF NOT EXISTS idx_connections_timestamp
			ON connections (timestamp)`,
		`CREATE INDEX IF NOT EXISTS idx_connections_dest_port
			ON connections (dest_port)`,

		// ----------------------------------------------------------------
		// credentials
		// ----------------------------------------------------------------
		`CREATE TABLE IF NOT EXISTS credentials (
			id        INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp DATETIME NOT NULL DEFAULT (datetime('now')),
			source_ip TEXT     NOT NULL,
			port      INTEGER  NOT NULL,
			username  TEXT     NOT NULL DEFAULT '',
			password  TEXT     NOT NULL DEFAULT '',
			service   TEXT     NOT NULL DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_credentials_source_ip
			ON credentials (source_ip)`,
		`CREATE INDEX IF NOT EXISTS idx_credentials_timestamp
			ON credentials (timestamp)`,

		// ----------------------------------------------------------------
		// banned_ips
		// ----------------------------------------------------------------
		`CREATE TABLE IF NOT EXISTS banned_ips (
			id         INTEGER  PRIMARY KEY AUTOINCREMENT,
			ip         TEXT     NOT NULL UNIQUE,
			reason     TEXT     NOT NULL DEFAULT '',
			banned_at  DATETIME NOT NULL DEFAULT (datetime('now')),
			expires_at DATETIME,
			permanent  INTEGER  NOT NULL DEFAULT 0
		)`,
		`CREATE INDEX IF NOT EXISTS idx_banned_ips_ip
			ON banned_ips (ip)`,
		`CREATE INDEX IF NOT EXISTS idx_banned_ips_expires_at
			ON banned_ips (expires_at)`,

		// ----------------------------------------------------------------
		// ip_scores
		// ----------------------------------------------------------------
		`CREATE TABLE IF NOT EXISTS ip_scores (
			ip                  TEXT     PRIMARY KEY,
			score               INTEGER  NOT NULL DEFAULT 0,
			total_connections   INTEGER  NOT NULL DEFAULT 0,
			honeypot_hits       INTEGER  NOT NULL DEFAULT 0,
			credential_attempts INTEGER  NOT NULL DEFAULT 0,
			ports_scanned       TEXT     NOT NULL DEFAULT '[]',
			first_seen          DATETIME NOT NULL DEFAULT (datetime('now')),
			last_seen           DATETIME NOT NULL DEFAULT (datetime('now')),
			country             TEXT     NOT NULL DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_ip_scores_score
			ON ip_scores (score DESC)`,

		// ----------------------------------------------------------------
		// settings (mutable runtime configuration, key/value)
		// ----------------------------------------------------------------
		`CREATE TABLE IF NOT EXISTS settings (
			key   TEXT PRIMARY KEY,
			value TEXT NOT NULL
		)`,
	}

	for _, stmt := range statements {
		if _, err := d.db.Exec(stmt); err != nil {
			return fmt.Errorf("executing migration statement: %w\nSQL: %s", err, stmt)
		}
	}
	return nil
}