package honeypot

import (
	"bufio"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/skyguard/skyguard/internal/config"
	"github.com/skyguard/skyguard/internal/storage"
)

// Session describes the client side of one honeypot connection. The server
// fills it in (including GeoIP data) before handing the connection over.
type Session struct {
	IP      string
	Port    int // local (honeypot) port
	Country string
	City    string
}

// Handler is implemented by every honeypot service type.
type Handler interface {
	Handle(conn net.Conn, sess Session) error
	Type() string
}

// EventLogger persists honeypot events to the database.
type EventLogger struct {
	db       *storage.DB
	logger   *slog.Logger
	maxBytes int
	// onCredential is invoked after each captured credential so the caller can
	// apply threat scoring / auto-ban for failed-credential events.
	onCredential func(sess Session)
}

// NewEventLogger constructs an EventLogger backed by db. maxBytes caps the
// size of attacker-controlled data stored per connection (logging.log_first_bytes).
func NewEventLogger(db *storage.DB, logger *slog.Logger, maxBytes int) *EventLogger {
	if maxBytes <= 0 {
		maxBytes = 512
	}
	return &EventLogger{db: db, logger: logger, maxBytes: maxBytes}
}

// OnCredential registers a hook invoked after every captured credential.
func (e *EventLogger) OnCredential(fn func(sess Session)) {
	e.onCredential = fn
}

// LogCredential records a credential attempt in the credentials table.
func (e *EventLogger) LogCredential(sess Session, username, password, service string) {
	err := e.db.LogCredential(&storage.Credential{
		SourceIP: sess.IP,
		Port:     sess.Port,
		Username: e.clean(username),
		Password: e.clean(password),
		Service:  service,
	})
	if err != nil {
		e.logger.Error("failed to log credential", "error", err, "source_ip", sess.IP)
	}
	if e.onCredential != nil {
		e.onCredential(sess)
	}
}

// LogConnection records a honeypot connection event in the connections table.
func (e *EventLogger) LogConnection(sess Session, service, data string) {
	err := e.db.LogConnection(&storage.Connection{
		SourceIP:    sess.IP,
		DestPort:    sess.Port,
		Country:     sess.Country,
		City:        sess.City,
		ServiceType: service,
		Action:      storage.ActionHoneypot,
		Data:        e.clean(data),
	})
	if err != nil {
		e.logger.Error("failed to log connection", "error", err, "source_ip", sess.IP)
	}
}

// clean makes attacker-supplied text safe to store and display: invalid UTF-8
// and control characters are replaced, and the result is length-capped.
func (e *EventLogger) clean(s string) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "�")
	}
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return ' '
		}
		if unicode.IsControl(r) {
			return '�'
		}
		return r
	}, s)
	if len(s) > e.maxBytes {
		s = s[:e.maxBytes]
		s = strings.ToValidUTF8(s, "")
	}
	return s
}

// NewHandler returns the Handler implementation for cfg.Type. dataDir is
// where persistent state (the SSH honeypot host keys) is kept.
func NewHandler(cfg config.HoneypotService, eventLogger *EventLogger, dataDir string) (Handler, error) {
	logger := eventLogger.logger.With("honeypot", cfg.Type, "port", cfg.Port)
	switch cfg.Type {
	case "ssh":
		return NewSSHHoneypot(cfg, eventLogger, logger, dataDir)
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

var errLineTooLong = errors.New("line too long")

// readLine reads one '\n'-terminated line of at most max bytes, so a client
// that never sends a newline cannot make us buffer unbounded data.
func readLine(r *bufio.Reader, max int) (string, error) {
	var buf []byte
	for {
		chunk, err := r.ReadSlice('\n')
		buf = append(buf, chunk...)
		if len(buf) > max {
			return "", errLineTooLong
		}
		if err == nil {
			return string(buf), nil
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			return string(buf), err
		}
	}
}
