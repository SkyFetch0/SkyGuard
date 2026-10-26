package proxy

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"time"
)

// Proxy forwards TCP connections to a backend target.
type Proxy struct {
	logger       *slog.Logger
	dialTimeout  time.Duration
	drainTimeout time.Duration
}

// New creates a Proxy with the provided structured logger.
func New(logger *slog.Logger) *Proxy {
	return &Proxy{logger: logger, dialTimeout: 10 * time.Second, drainTimeout: 30 * time.Second}
}

// closeWriter is implemented by *net.TCPConn (and our wrappers) to send FIN
// while still reading the other direction.
type closeWriter interface{ CloseWrite() error }

// Forward dials targetAddr and copies data in both directions until both
// sides are done. When one direction ends, its write side is half-closed so
// the peer sees EOF but can still flush its response (closing both sockets
// immediately would truncate it). A stuck peer is cut off after drainTimeout.
func (p *Proxy) Forward(client net.Conn, targetAddr string) error {
	backend, err := net.DialTimeout("tcp", targetAddr, p.dialTimeout)
	if err != nil {
		return fmt.Errorf("dialing backend %s: %w", targetAddr, err)
	}
	defer backend.Close()
	defer client.Close()

	p.logger.Debug("proxy connection established", "client", client.RemoteAddr(), "target", targetAddr)

	done := make(chan struct{}, 2)
	pipe := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(closeWriter); ok {
			_ = cw.CloseWrite()
		} else {
			_ = dst.Close()
		}
		done <- struct{}{}
	}
	go pipe(backend, client)
	go pipe(client, backend)

	<-done
	timer := time.AfterFunc(p.drainTimeout, func() {
		client.Close()
		backend.Close()
	})
	<-done
	timer.Stop()
	return nil
}
