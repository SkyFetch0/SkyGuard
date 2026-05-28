package honeypot

import (
	"bufio"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/skyguard/skyguard/internal/config"
)

// FTPHoneypot simulates a minimal FTP server that captures credentials.
type FTPHoneypot struct {
	cfg         config.HoneypotService
	eventLogger *EventLogger
	logger      *slog.Logger
}

// NewFTPHoneypot creates an FTPHoneypot.
func NewFTPHoneypot(cfg config.HoneypotService, eventLogger *EventLogger, logger *slog.Logger) *FTPHoneypot {
	if cfg.Banner == "" {
		cfg.Banner = "ProFTPD 1.3.5e Server (Debian) [::ffff:127.0.0.1]"
	}
	if cfg.MaxAuthAttempts == 0 {
		cfg.MaxAuthAttempts = 3
	}
	return &FTPHoneypot{cfg: cfg, eventLogger: eventLogger, logger: logger}
}

// Type implements Handler.
func (f *FTPHoneypot) Type() string { return "ftp" }

// Handle implements Handler.
// It presents a standard FTP greeting, collects USER/PASS pairs, always
// rejects them, and closes after MaxAuthAttempts failures.
func (f *FTPHoneypot) Handle(conn net.Conn, sourceIP string) error {
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(60 * time.Second))

	// Log the initial connection.
	f.eventLogger.LogConnection(sourceIP, f.cfg.Port, "ftp", "new connection")

	reader := bufio.NewReader(conn)

	// Step 1: Send FTP service-ready banner.
	if _, err := fmt.Fprintf(conn, "220 %s\r\n", f.cfg.Banner); err != nil {
		return fmt.Errorf("ftp: write banner: %w", err)
	}

	attempts := 0
	var currentUser string

	for attempts < f.cfg.MaxAuthAttempts {
		conn.SetDeadline(time.Now().Add(30 * time.Second))

		line, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("ftp: read command: %w", err)
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// FTP commands are case-insensitive; upper-case for easy matching.
		upper := strings.ToUpper(line)

		switch {
		case strings.HasPrefix(upper, "USER "):
			currentUser = strings.TrimSpace(line[5:])
			f.logger.Debug("ftp USER", "source_ip", sourceIP, "user", currentUser)
			fmt.Fprintf(conn, "331 Password required for %s\r\n", currentUser)

		case strings.HasPrefix(upper, "PASS "):
			password := strings.TrimSpace(line[5:])
			attempts++

			f.logger.Info("ftp credential attempt",
				"source_ip", sourceIP,
				"user", currentUser,
				"pass", password,
				"attempt", attempts,
			)
			f.eventLogger.LogCredential(sourceIP, f.cfg.Port, currentUser, password, "ftp")

			fmt.Fprintf(conn, "530 Login incorrect.\r\n")

			if attempts >= f.cfg.MaxAuthAttempts {
				fmt.Fprintf(conn, "421 Too many failed login attempts. Goodbye.\r\n")
				return nil
			}

		case upper == "QUIT":
			fmt.Fprintf(conn, "221 Goodbye.\r\n")
			return nil

		default:
			// Any other command before successful login.
			fmt.Fprintf(conn, "530 Please login with USER and PASS.\r\n")
		}
	}

	return nil
}