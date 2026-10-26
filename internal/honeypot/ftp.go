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

const (
	ftpMaxLine     = 1024
	ftpMaxCommands = 50
)

// NewFTPHoneypot creates an FTPHoneypot.
func NewFTPHoneypot(cfg config.HoneypotService, eventLogger *EventLogger, logger *slog.Logger) *FTPHoneypot {
	if cfg.Banner == "" {
		cfg.Banner = "ProFTPD 1.3.5e Server (Debian)"
	}
	if cfg.MaxAuthAttempts <= 0 {
		cfg.MaxAuthAttempts = 3
	}
	return &FTPHoneypot{cfg: cfg, eventLogger: eventLogger, logger: logger}
}

// Type implements Handler.
func (f *FTPHoneypot) Type() string { return "ftp" }

// Handle presents an FTP greeting, collects USER/PASS pairs, always rejects
// them, and closes after MaxAuthAttempts failures.
func (f *FTPHoneypot) Handle(conn net.Conn, sess Session) error {
	defer conn.Close()

	attempts, commands := 0, 0
	var lastCmd string
	defer func() {
		f.eventLogger.LogConnection(sess, "ftp",
			fmt.Sprintf("attempts=%d commands=%d last=%q", attempts, commands, lastCmd))
	}()

	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	reply := func(format string, args ...any) error {
		_, err := fmt.Fprintf(conn, format+"\r\n", args...)
		return err
	}
	if err := reply("220 %s", f.cfg.Banner); err != nil {
		return err
	}

	reader := bufio.NewReaderSize(conn, ftpMaxLine)
	currentUser := ""
	for attempts < f.cfg.MaxAuthAttempts && commands < ftpMaxCommands {
		_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
		line, err := readLine(reader, ftpMaxLine)
		if err != nil {
			return nil // client went away or misbehaved; already logged in defer
		}
		line = strings.TrimRight(line, "\r\n")
		if strings.TrimSpace(line) == "" {
			continue
		}
		commands++

		verb, arg, _ := strings.Cut(line, " ")
		verb = strings.ToUpper(verb)
		lastCmd = verb

		switch verb {
		case "USER":
			currentUser = strings.TrimSpace(arg)
			_ = reply("331 Password required for %s", currentUser)
		case "PASS":
			attempts++
			f.logger.Info("ftp credential attempt", "source_ip", sess.IP, "user", currentUser, "attempt", attempts)
			f.eventLogger.LogCredential(sess, currentUser, arg, "ftp")
			time.Sleep(300 * time.Millisecond)
			_ = reply("530 Login incorrect.")
		case "QUIT":
			_ = reply("221 Goodbye.")
			return nil
		case "SYST":
			_ = reply("215 UNIX Type: L8")
		case "FEAT":
			_ = reply("211-Features:\r\n MDTM\r\n SIZE\r\n UTF8\r\n211 End")
		case "AUTH":
			_ = reply("500 AUTH not understood")
		case "NOOP":
			_ = reply("200 NOOP command successful")
		default:
			_ = reply("530 Please login with USER and PASS")
		}
	}
	if attempts >= f.cfg.MaxAuthAttempts {
		_ = reply("421 Too many failed login attempts. Goodbye.")
	}
	return nil
}
