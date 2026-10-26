package honeypot

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"time"

	"github.com/skyguard/skyguard/internal/config"
)

// MySQLHoneypot simulates a MySQL 5.x server handshake to capture login
// attempts from automated scanners.
type MySQLHoneypot struct {
	cfg         config.HoneypotService
	eventLogger *EventLogger
	logger      *slog.Logger
}

// NewMySQLHoneypot creates a MySQLHoneypot.
func NewMySQLHoneypot(cfg config.HoneypotService, eventLogger *EventLogger, logger *slog.Logger) *MySQLHoneypot {
	if cfg.Banner == "" {
		cfg.Banner = "5.7.38-log"
	}
	return &MySQLHoneypot{cfg: cfg, eventLogger: eventLogger, logger: logger}
}

// Type implements Handler.
func (m *MySQLHoneypot) Type() string { return "mysql" }

// Handle implements Handler.
// It sends a realistic MySQL initial handshake packet, reads the client's
// handshake response to extract the attempted username, then replies with an
// Access denied error packet. MySQL never sends the password in clear text
// (only a salted scramble), so only the username is recorded.
func (m *MySQLHoneypot) Handle(conn net.Conn, sess Session) error {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	if _, err := conn.Write(m.buildHandshakePacket()); err != nil {
		m.eventLogger.LogConnection(sess, "mysql", "write handshake failed")
		return nil
	}

	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		m.eventLogger.LogConnection(sess, "mysql", "no handshake response")
		return nil
	}
	payloadLen := int(uint32(header[0]) | uint32(header[1])<<8 | uint32(header[2])<<16)
	if payloadLen > 8192 {
		m.eventLogger.LogConnection(sess, "mysql", fmt.Sprintf("oversized handshake response (%d bytes)", payloadLen))
		return nil
	}
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(conn, payload); err != nil {
		m.eventLogger.LogConnection(sess, "mysql", "truncated handshake response")
		return nil
	}

	username := parseHandshakeUsername(payload)
	m.logger.Info("mysql login attempt", "source_ip", sess.IP, "user", username)
	m.eventLogger.LogConnection(sess, "mysql", fmt.Sprintf("user=%q", username))
	m.eventLogger.LogCredential(sess, username, "", "mysql")

	errMsg := fmt.Sprintf("Access denied for user '%s'@'%s' (using password: YES)", username, sess.IP)
	if _, err := conn.Write(buildErrPacket(1045, "28000", errMsg)); err != nil {
		m.logger.Debug("mysql: write err packet failed", "source_ip", sess.IP, "error", err)
	}
	return nil
}

// buildHandshakePacket constructs a MySQL Protocol v10 Initial Handshake packet.
func (m *MySQLHoneypot) buildHandshakePacket() []byte {
	serverVersion := m.cfg.Banner + "\x00"

	// Random auth-plugin-data (20 bytes split 8+12).
	authData := make([]byte, 20)
	// Real servers use printable, NUL-free scramble bytes.
	_, _ = rand.Read(authData)
	for i := range authData {
		authData[i] = 0x21 + authData[i]%0x5e
	}

	authPluginName := "mysql_native_password\x00"

	// Capability flags (common subset understood by most clients).
	// CLIENT_LONG_PASSWORD | CLIENT_FOUND_ROWS | CLIENT_LONG_FLAG |
	// CLIENT_CONNECT_WITH_DB | CLIENT_NO_SCHEMA | CLIENT_PROTOCOL_41 |
	// CLIENT_TRANSACTIONS | CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH
	// CLIENT_COMPRESS (0x20) and CLIENT_SSL (0x800) are deliberately not offered.
	capLow := uint16(0xF7DF)
	capHigh := uint16(0x0201)

	// Assemble the payload.
	var payload []byte
	payload = append(payload, 0x0a) // protocol version
	payload = append(payload, []byte(serverVersion)...)

	// Connection ID (little-endian uint32) — use crypto/rand for unpredictability.
	connID := make([]byte, 4)
	if _, err := rand.Read(connID); err != nil {
		// Fallback: zero connID is valid in the protocol.
		connID = []byte{0, 0, 0, 1}
	}
	// Clamp to [1, 65535] to keep it in a realistic range.
	connIDVal := (uint32(connID[0])<<8|uint32(connID[1]))%65534 + 1
	binary.LittleEndian.PutUint32(connID, connIDVal)
	payload = append(payload, connID...)

	// Auth-plugin-data part 1 (first 8 bytes).
	payload = append(payload, authData[:8]...)
	payload = append(payload, 0x00) // filler

	// Capability flags low 2 bytes.
	capLowB := make([]byte, 2)
	binary.LittleEndian.PutUint16(capLowB, capLow)
	payload = append(payload, capLowB...)

	payload = append(payload, 0x21) // character set: utf8
	// Status flags.
	payload = append(payload, 0x02, 0x00)

	// Capability flags high 2 bytes.
	capHighB := make([]byte, 2)
	binary.LittleEndian.PutUint16(capHighB, capHigh)
	payload = append(payload, capHighB...)

	// Auth plugin data length = 21 (20 bytes + 1 null terminator).
	payload = append(payload, byte(len(authData)+1))

	// Reserved (10 zero bytes).
	payload = append(payload, make([]byte, 10)...)

	// Auth-plugin-data part 2 (remaining 12 bytes + null terminator).
	payload = append(payload, authData[8:]...)
	payload = append(payload, 0x00)

	// Auth plugin name.
	payload = append(payload, []byte(authPluginName)...)

	// Prepend the 4-byte packet header: 3-byte length + sequence number 0.
	pktLen := len(payload)
	header := []byte{
		byte(pktLen),
		byte(pktLen >> 8),
		byte(pktLen >> 16),
		0x00, // sequence id
	}
	return append(header, payload...)
}

// parseHandshakeUsername extracts the username from a MySQL HandshakeResponse41 payload.
// Layout: 4 capability + 4 max_packet + 1 charset + 23 reserved + username\0 + ...
func parseHandshakeUsername(payload []byte) string {
	const headerLen = 4 + 4 + 1 + 23 // 32 bytes
	if len(payload) <= headerLen {
		return ""
	}
	rest := payload[headerLen:]
	// Username is null-terminated.
	end := bytes.IndexByte(rest, 0)
	if end < 0 {
		return string(rest)
	}
	return string(rest[:end])
}

// buildErrPacket constructs a MySQL ERR packet.
func buildErrPacket(errorCode uint16, sqlState, message string) []byte {
	var payload []byte
	payload = append(payload, 0xff) // ERR header

	errCodeB := make([]byte, 2)
	binary.LittleEndian.PutUint16(errCodeB, errorCode)
	payload = append(payload, errCodeB...)

	payload = append(payload, '#')
	payload = append(payload, []byte(sqlState)...)
	payload = append(payload, []byte(message)...)

	pktLen := len(payload)
	header := []byte{
		byte(pktLen),
		byte(pktLen >> 8),
		byte(pktLen >> 16),
		0x02, // sequence id (follows handshake=0 and response=1)
	}
	return append(header, payload...)
}
