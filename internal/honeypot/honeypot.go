package honeypot

import (
	"fmt"
	"log/slog"
	"net"

	"github.com/skyguard/skyguard/internal/config"
	"github.com/skyguard/skyguard/internal/storage"
)

// Handler is implemented by every honeypot service type.
type Handler interface {
	Handle(conn net.Conn, sourceIP string) error
	Type() string
}

// EventLogger persists honeypot events to the database.
type EventLogger struct {
	db     *storage.DB
	logger *slog.Logger
	// onCredential, when set, is invoked after each captured credential so the
	// caller can apply threat scoring / auto-ban for failed-credential events.
	onCredential func(sourceIP string)
}

// NewEventLogger constructs an EventLogger backed by db.
func NewEventLogger(db *storage.DB, logger *slog.Logger) *EventLogger {
	return &EventLogger{db: db, logger: logger}
}

// OnCredential registers a hook invoked after every captured credential.
func (e *EventLogger) OnCredential(fn func(sourceIP string)) {
	e.onCredential = fn
}

// LogCredential records a credential attempt in the credentials table.
func (e *EventLogger) LogCredential(sourceIP string, port int, username, password, service string) {
	_, err := e.db.DB().Exec(
		`INSERT INTO credentials (source_ip, port, username, password, service) VALUES (?, ?, ?, ?, ?)`,
		sourceIP, port, username, password, service,
	)
	if err != nil {
		e.logger.Error("failed to log credential", "err", err, "source_ip", sourceIP)
	}
	if e.onCredential != nil {
		e.onCredential(sourceIP)
	}
}

// LogConnection records a honeypot connection event in the connections table.
func (e *EventLogger) LogConnection(sourceIP string, port int, service string, data string) {
	_, err := e.db.DB().Exec(
		`INSERT INTO connections (source_ip, source_port, dest_port, service_type, action, data) VALUES (?, 0, ?, ?, 'honeypot', ?)`,
		sourceIP, port, service, data,
	)
	if err != nil {
		e.logger.Error("failed to log connection", "err", err, "source_ip", sourceIP)
	}
}

// NewHandler returns the correct Handler implementation based on cfg.Type.
// Returns an error for unknown types instead of panicking.
func NewHandler(cfg config.HoneypotService, eventLogger *EventLogger) (Handler, error) {
	logger := eventLogger.logger.With("honeypot", cfg.Type, "port", cfg.Port)
	switch cfg.Type {
	case "ssh":
		return NewSSHHoneypot(cfg, eventLogger, logger), nil
	case "ftp":
		return NewFTPHoneypot(cfg, eventLogger, logger), nil
	case "mysql":
		return NewMySQLHoneypot(cfg, eventLogger, logger), nil
	case "http":
		return NewHTTPHoneypot(cfg, eventLogger, logger), nil
	default:
		return nil, fmt.Errorf("honeypot: unknown type %q (supported: ssh, ftp, mysql, http)", cfg.Type)
	}
}