package honeypot

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/skyguard/skyguard/internal/config"
)

// SSHHoneypot simulates a bare-bones SSH service. It sends the SSH banner,
// reads the client's banner and a small amount of binary data, then closes
// the connection. No real SSH handshake is performed.
type SSHHoneypot struct {
	cfg         config.HoneypotService
	eventLogger *EventLogger
	logger      *slog.Logger
}

// NewSSHHoneypot creates an SSHHoneypot using the supplied config and loggers.
func NewSSHHoneypot(cfg config.HoneypotService, eventLogger *EventLogger, logger *slog.Logger) *SSHHoneypot {
	if cfg.Banner == "" {
		cfg.Banner = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
	}
	return &SSHHoneypot{cfg: cfg, eventLogger: eventLogger, logger: logger}
}

// Type implements Handler.
func (s *SSHHoneypot) Type() string { return "ssh" }

// Handle implements Handler.
// It sends the SSH version banner, reads the client's version string, collects
// a small buffer of binary protocol data, waits a few seconds to appear
// genuine, then closes the connection.
func (s *SSHHoneypot) Handle(conn net.Conn, sourceIP string) error {
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(30 * time.Second))

	// Step 1: Send our SSH version banner.
	banner := s.cfg.Banner
	if _, err := fmt.Fprintf(conn, "%s\r\n", banner); err != nil {
		return fmt.Errorf("ssh: write banner: %w", err)
	}

	// Step 2: Read the client's version string (ends with \n).
	reader := bufio.NewReader(conn)
	clientBanner, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		s.eventLogger.LogConnection(sourceIP, s.cfg.Port, "ssh", "")
		return fmt.Errorf("ssh: read client banner: %w", err)
	}
	clientBanner = strings.TrimSpace(clientBanner)

	s.logger.Info("ssh connection",
		"source_ip", sourceIP,
		"client_banner", clientBanner,
	)

	// Step 3: Read a small chunk of subsequent binary SSH messages.
	// Real SSH continues with KEX_INIT etc.; we just drain up to 4 KB.
	buf := make([]byte, 4096)
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	n, _ := reader.Read(buf)
	raw := buf[:n]

	// Combine collected data for the event log.
	logData := fmt.Sprintf("banner=%q bytes_read=%d", clientBanner, n)
	s.eventLogger.LogConnection(sourceIP, s.cfg.Port, "ssh", logData)

	// Step 4: Simulate a processing delay so scanners wait.
	time.Sleep(3 * time.Second)

	// Step 5: Send a minimal rejection that looks like an SSH error packet.
	// Real implementations send a disconnect packet (type 1); we approximate.
	if n > 0 {
		_ = raw // already captured above; avoid unused-variable lint
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(conn, "SSH-2.0-OpenSSH_8.9p1\r\nDisconnected: Authentication failed.\r\n")

	return nil
}