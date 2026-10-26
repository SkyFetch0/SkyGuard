package stealth

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/skyguard/skyguard/internal/config"
	"github.com/skyguard/skyguard/internal/proxy"
	"github.com/skyguard/skyguard/internal/storage"
)

// Handler implements protocol-detection based stealth port logic.
// Clients whose first bytes match the configured signature are forwarded to
// the real backend; everything else is closed silently without a banner, so
// scanners learn nothing about the service.
type Handler struct {
	cfg    config.StealthService
	proxy  *proxy.Proxy
	logger *slog.Logger
}

// Recorder is called once per connection with the routing decision
// (storage.ActionForwarded / storage.ActionDropped) and a short reason.
type Recorder func(action, data string)

// NewHandler creates a new stealth Handler.
func NewHandler(cfg config.StealthService, prx *proxy.Proxy, logger *slog.Logger) *Handler {
	return &Handler{cfg: cfg, proxy: prx, logger: logger}
}

// Name returns the service name from config.
func (h *Handler) Name() string { return h.cfg.Name }

// RestrictsCountries reports whether allowed_countries is configured.
func (h *Handler) RestrictsCountries() bool { return len(h.cfg.AllowedCountries) > 0 }

// IsCountryAllowed reports whether the ISO country code may access this
// service. An empty AllowedCountries list allows every country.
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

// Handle waits for the protocol signature and forwards or drops conn.
func (h *Handler) Handle(conn net.Conn, sourceIP string, record Recorder) error {
	defer conn.Close()

	sig := []byte(h.cfg.ProtocolSignature)
	if len(sig) == 0 {
		// Without a signature there is nothing to wait for (and waiting would
		// deadlock server-speaks-first protocols): forward straight away.
		record(storage.ActionForwarded, "stealth: no signature configured")
		return h.proxy.Forward(conn, h.cfg.RealTarget)
	}

	timeout := h.cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}

	// TCP may deliver the signature in several segments, so read exactly
	// len(sig) bytes instead of trusting a single Read call.
	buf := make([]byte, len(sig))
	n, err := io.ReadFull(conn, buf)
	if err != nil {
		reason := "stealth: read error"
		switch {
		case isTimeout(err):
			reason = "stealth: no data before timeout"
		case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
			reason = "stealth: closed by client"
		}
		if n > 0 {
			reason += fmt.Sprintf(" first_bytes=%q", buf[:n])
		}
		h.logger.Debug(reason, "source_ip", sourceIP)
		record(storage.ActionDropped, reason)
		return nil
	}

	if !bytes.Equal(buf, sig) {
		h.logger.Info("stealth: unknown probe", "source_ip", sourceIP, "first_bytes", fmt.Sprintf("%q", buf))
		record(storage.ActionDropped, fmt.Sprintf("stealth: signature mismatch first_bytes=%q", buf))
		return nil
	}

	_ = conn.SetReadDeadline(time.Time{})
	h.logger.Debug("stealth: forwarding connection", "source_ip", sourceIP, "target", h.cfg.RealTarget)
	record(storage.ActionForwarded, "stealth: signature matched")

	// Replay the bytes we consumed before handing the stream to the backend.
	return h.proxy.Forward(&prefixedConn{Conn: conn, prefix: buf}, h.cfg.RealTarget)
}

// prefixedConn replays the initially peeked bytes before delegating to the
// underlying net.Conn, ensuring no data is lost after the protocol peek.
type prefixedConn struct {
	net.Conn
	prefix []byte
}

func (p *prefixedConn) Read(b []byte) (int, error) {
	if len(p.prefix) > 0 {
		n := copy(b, p.prefix)
		p.prefix = p.prefix[n:]
		return n, nil
	}
	return p.Conn.Read(b)
}

// CloseWrite lets the proxy half-close the client side.
func (p *prefixedConn) CloseWrite() error {
	if cw, ok := p.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return p.Conn.Close()
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
