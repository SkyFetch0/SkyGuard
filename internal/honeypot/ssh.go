package honeypot

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/skyguard/skyguard/internal/config"
)

// SSHHoneypot simulates a minimal SSH service that captures credentials.
// It implements a simplified SSH userauth exchange: banner negotiation,
// fake KEX_INIT, and a userauth loop that reads username/password pairs
// before rejecting them with SSH_MSG_USERAUTH_FAILURE.
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
	if cfg.MaxAuthAttempts == 0 {
		cfg.MaxAuthAttempts = 3
	}
	return &SSHHoneypot{cfg: cfg, eventLogger: eventLogger, logger: logger}
}

// Type implements Handler.
func (s *SSHHoneypot) Type() string { return "ssh" }

// Handle implements Handler.
// Flow: version exchange → fake KEX_INIT drain → userauth loop (captures
// username + password per attempt) → SSH_MSG_USERAUTH_FAILURE each time →
// disconnect after MaxAuthAttempts.
func (s *SSHHoneypot) Handle(conn net.Conn, sourceIP string) error {
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(30 * time.Second))

	// ── Step 1: Version exchange ──────────────────────────────────────────
	if _, err := fmt.Fprintf(conn, "%s\r\n", s.cfg.Banner); err != nil {
		return fmt.Errorf("ssh: write banner: %w", err)
	}

	reader := bufio.NewReader(conn)
	clientBanner, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		s.eventLogger.LogConnection(sourceIP, s.cfg.Port, "ssh", "")
		return fmt.Errorf("ssh: read client banner: %w", err)
	}
	clientBanner = strings.TrimSpace(clientBanner)

	s.logger.Info("ssh connection", "source_ip", sourceIP, "client_banner", clientBanner)

	// ── Step 2: Drain the client's KEXINIT packet ─────────────────────────
	// A real SSH client sends a binary KEXINIT immediately after the version
	// string. We read and discard it so the client advances to userauth.
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := drainSSHPacket(reader); err != nil {
		// Client disconnected before sending KEXINIT — log and exit cleanly.
		s.eventLogger.LogConnection(sourceIP, s.cfg.Port, "ssh",
			fmt.Sprintf("banner=%q kexinit_err=%v", clientBanner, err))
		return nil
	}

	// Send our own fake KEXINIT so the client proceeds.
	if _, err := conn.Write(buildFakeKEXInit()); err != nil {
		return fmt.Errorf("ssh: write kexinit: %w", err)
	}

	// Drain NEWKEYS / any remaining handshake packets the client sends.
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	for i := 0; i < 3; i++ {
		if err := drainSSHPacket(reader); err != nil {
			break
		}
	}

	// ── Step 3: Userauth loop ─────────────────────────────────────────────
	attempts := 0
	for attempts < s.cfg.MaxAuthAttempts {
		conn.SetDeadline(time.Now().Add(30 * time.Second))

		pkt, err := readSSHPacket(reader)
		if err != nil {
			break
		}
		if len(pkt) < 1 {
			continue
		}

		msgType := pkt[0]

		// SSH_MSG_SERVICE_REQUEST (5) — reply with SERVICE_ACCEPT.
		if msgType == 5 {
			if _, err := conn.Write(buildSSHPacket([]byte{6})); err != nil {
				return fmt.Errorf("ssh: write service_accept: %w", err)
			}
			continue
		}

		// SSH_MSG_USERAUTH_REQUEST (50).
		if msgType != 50 || len(pkt) < 5 {
			continue
		}

		username, password, ok := parseUserauthRequest(pkt)
		if !ok {
			continue
		}

		attempts++
		s.logger.Info("ssh credential attempt",
			"source_ip", sourceIP,
			"user", username,
			"pass", password,
			"attempt", attempts,
		)
		s.eventLogger.LogCredential(sourceIP, s.cfg.Port, username, password, "ssh")

		if attempts >= s.cfg.MaxAuthAttempts {
			// SSH_MSG_DISCONNECT (1): too many auth failures.
			conn.Write(buildSSHDisconnect("Too many authentication failures")) //nolint:errcheck
			break
		}

		// SSH_MSG_USERAUTH_FAILURE (51).
		if _, err := conn.Write(buildUserauthFailure()); err != nil {
			break
		}
	}

	logData := fmt.Sprintf("banner=%q attempts=%d", clientBanner, attempts)
	s.eventLogger.LogConnection(sourceIP, s.cfg.Port, "ssh", logData)
	return nil
}

// ── SSH binary helpers ────────────────────────────────────────────────────────

// readSSHPacket reads one SSH binary packet (RFC 4253 §6) and returns the
// payload (without packet_length, padding_length, or padding bytes).
func readSSHPacket(r *bufio.Reader) ([]byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	pktLen := binary.BigEndian.Uint32(hdr[:4])
	if pktLen == 0 || pktLen > 35000 {
		return nil, fmt.Errorf("ssh: packet length %d out of range", pktLen)
	}
	paddingLen := int(hdr[4])
	payloadLen := int(pktLen) - 1 - paddingLen
	if payloadLen < 0 {
		return nil, fmt.Errorf("ssh: invalid padding length")
	}
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	padding := make([]byte, paddingLen)
	_, _ = io.ReadFull(r, padding)
	return payload, nil
}

// drainSSHPacket reads and discards one SSH packet.
func drainSSHPacket(r *bufio.Reader) error {
	_, err := readSSHPacket(r)
	return err
}

// buildSSHPacket wraps payload in an SSH binary packet frame.
func buildSSHPacket(payload []byte) []byte {
	paddingLen := 8 - ((len(payload) + 5) % 8)
	if paddingLen < 4 {
		paddingLen += 8
	}
	pktLen := uint32(1 + len(payload) + paddingLen)
	buf := make([]byte, 4+1+len(payload)+paddingLen)
	binary.BigEndian.PutUint32(buf[0:], pktLen)
	buf[4] = byte(paddingLen)
	copy(buf[5:], payload)
	return buf
}

// buildFakeKEXInit returns a minimal SSH_MSG_KEXINIT (20) packet.
// The name-list fields are populated with a single widely-supported algorithm
// so a real client can parse it without errors.
func buildFakeKEXInit() []byte {
	// cookie (16 bytes) + msg_type
	payload := make([]byte, 0, 256)
	payload = append(payload, 20)             // SSH_MSG_KEXINIT
	payload = append(payload, make([]byte, 16)...) // random cookie (zeroed, fine for a honeypot)
	for i := 0; i < 10; i++ {                // 10 name-list fields
		name := "diffie-hellman-group14-sha256"
		if i == 1 {
			name = "ssh-rsa"
		} else if i == 2 || i == 3 {
			name = "aes128-ctr"
		} else if i == 4 || i == 5 {
			name = "hmac-sha2-256"
		} else if i == 6 || i == 7 {
			name = "none"
		}
		b := []byte(name)
		payload = appendUint32(payload, uint32(len(b)))
		payload = append(payload, b...)
	}
	payload = append(payload, 0)                   // first_kex_packet_follows = false
	payload = appendUint32(payload, 0)             // reserved
	return buildSSHPacket(payload)
}

// buildUserauthFailure returns SSH_MSG_USERAUTH_FAILURE (51) with
// "password" as the only allowed continuation method.
func buildUserauthFailure() []byte {
	method := []byte("password")
	payload := make([]byte, 0, 16)
	payload = append(payload, 51) // SSH_MSG_USERAUTH_FAILURE
	payload = appendUint32(payload, uint32(len(method)))
	payload = append(payload, method...)
	payload = append(payload, 0) // partial_success = false
	return buildSSHPacket(payload)
}

// buildSSHDisconnect returns SSH_MSG_DISCONNECT (1).
func buildSSHDisconnect(reason string) []byte {
	b := []byte(reason)
	payload := make([]byte, 0, 16+len(b))
	payload = append(payload, 1)             // SSH_MSG_DISCONNECT
	payload = appendUint32(payload, 11)      // reason code: SSH_DISCONNECT_BY_APPLICATION
	payload = appendUint32(payload, uint32(len(b)))
	payload = append(payload, b...)
	payload = appendUint32(payload, 0)       // language tag (empty)
	return buildSSHPacket(payload)
}

// parseUserauthRequest parses SSH_MSG_USERAUTH_REQUEST (50) and returns
// username, password, and ok=true for password-method requests.
// Format: byte(50) + string(username) + string(service) + string(method) +
//         bool(false) + string(password)
func parseUserauthRequest(payload []byte) (username, password string, ok bool) {
	if len(payload) < 5 || payload[0] != 50 {
		return
	}
	pos := 1
	username, pos, ok = readSSHString(payload, pos)
	if !ok {
		return
	}
	_, pos, ok = readSSHString(payload, pos) // service name
	if !ok {
		return
	}
	method, pos, ok := readSSHString(payload, pos)
	if !ok {
		return "", "", false
	}
	if method != "password" {
		return "", "", false
	}
	if pos >= len(payload) {
		return "", "", false
	}
	pos++ // skip boolean (false = not a change password request)
	password, _, ok = readSSHString(payload, pos)
	return username, password, ok
}

// readSSHString reads a uint32-prefixed string from buf at offset pos.
func readSSHString(buf []byte, pos int) (s string, newPos int, ok bool) {
	if pos+4 > len(buf) {
		return
	}
	l := int(binary.BigEndian.Uint32(buf[pos:]))
	pos += 4
	if pos+l > len(buf) {
		return
	}
	return string(buf[pos : pos+l]), pos + l, true
}

func appendUint32(b []byte, v uint32) []byte {
	return append(b, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}