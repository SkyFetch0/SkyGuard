package stealth

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/skyguard/skyguard/internal/config"
	"github.com/skyguard/skyguard/internal/proxy"
	"github.com/skyguard/skyguard/internal/storage"
)

// Handler implements protocol-detection–based stealth port logic.
// Legitimate clients that send the expected signature byte-prefix are
// forwarded to the real backend; all other connections are closed silently.
type Handler struct {
	cfg    config.StealthService
	proxy  *proxy.Proxy
	db     *storage.DB
	logger *slog.Logger
}

// NewHandler creates a new stealth Handler.
func NewHandler(cfg config.StealthService, prx *proxy.Proxy, db *storage.DB, logger *slog.Logger) *Handler {
	return &Handler{
		cfg:    cfg,
		proxy:  prx,
		db:     db,
		logger: logger,
	}
}

// Name returns the service name from config.
func (h *Handler) Name() string { return h.cfg.Name }

// IsCountryAllowed reports whether the given ISO country code is permitted to
// access this stealth service. If AllowedCountries is empty, all countries are
// allowed (backward-compatible with configs that omit the field).
func (h *Handler) IsCountryAllowed(countryCode string) bool {
	if len(h.cfg.AllowedCountries) == 0 {
		return true
	}
	for _, c := range h.cfg.AllowedCountries {
		if strings.EqualFold(c, countryCode) {
			return true
		}
	}
	return false
}

// Handle reads the first bytes from conn, checks for the configured protocol
// signature, and either forwards the connection or closes it.
func (h *Handler) Handle(conn net.Conn, sourceIP string) error {
	defer func() {
		// Ensure the connection is always closed if we return early.
		// proxy.Forward closes it itself on success, but closing twice is safe.
		conn.Close()
	}()

	timeout := h.cfg.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}

	// Read the first chunk – enough to check the signature.
	peekSize := max(len(h.cfg.ProtocolSignature), 16)
	buf := make([]byte, peekSize)

	n, err := conn.Read(buf)
	if err != nil {
		if isTimeout(err) {
			h.logger.Info("stealth: syn scan or timeout",
				"service", h.cfg.Name,
				"source_ip", sourceIP,
			)
		} else if !isEOF(err) {
			h.logger.Debug("stealth: read error",
				"service", h.cfg.Name,
				"source_ip", sourceIP,
				"error", err,
			)
		}
		return nil
	}

	// Disable the read deadline for the forwarded connection.
	_ = conn.SetReadDeadline(time.Time{})

	prefix := buf[:n]
	sig := h.cfg.ProtocolSignature

	if sig != "" && !strings.HasPrefix(string(prefix), sig) {
		h.logger.Info("stealth: unknown probe",
			"service", h.cfg.Name,
			"source_ip", sourceIP,
			"first_bytes", string(prefix),
		)
		return nil
	}

	h.logger.Debug("stealth: forwarding connection",
		"service", h.cfg.Name,
		"source_ip", sourceIP,
		"target", h.cfg.RealTarget,
	)

	// Wrap the connection so the already-read bytes are replayed first.
	wrapped := &prefixedConn{
		Conn:   conn,
		prefix: prefix,
	}

	return h.proxy.Forward(wrapped, h.cfg.RealTarget)
}

// prefixedConn replays the initially peeked bytes before delegating to the
// underlying net.Conn, ensuring no data is lost after the protocol peek.
type prefixedConn struct {
	net.Conn
	prefix []byte
	read   int
}

func (p *prefixedConn) Read(b []byte) (int, error) {
	if p.read < len(p.prefix) {
		n := copy(b, p.prefix[p.read:])
		p.read += n
		return n, nil
	}
	return p.Conn.Read(b)
}

// isTimeout reports whether err is a net.Error timeout.
func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// isEOF reports whether err signals a clean connection close.
func isEOF(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}