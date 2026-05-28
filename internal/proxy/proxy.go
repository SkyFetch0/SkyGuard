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
	logger *slog.Logger
}

// New creates a Proxy with the provided structured logger.
func New(logger *slog.Logger) *Proxy {
	return &Proxy{logger: logger}
}

// Forward dials targetAddr and bidirectionally copies data between clientConn
// and the backend. Both connections are closed when either side finishes.
func (p *Proxy) Forward(clientConn net.Conn, targetAddr string) error {
	backendConn, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		return fmt.Errorf("dialing backend %s: %w", targetAddr, err)
	}

	p.logger.Debug("proxy connection established",
		"client", clientConn.RemoteAddr(),
		"target", targetAddr,
	)

	done := make(chan struct{}, 2)

	go pipe(backendConn, clientConn, done)
	go pipe(clientConn, backendConn, done)

	// Wait for the first half to finish, then close both ends so the second
	// goroutine unblocks immediately.
	<-done
	clientConn.Close()
	backendConn.Close()
	<-done

	return nil
}

// pipe copies from src to dst and signals done when finished or on error.
func pipe(dst, src net.Conn, done chan struct{}) {
	defer func() { done <- struct{}{} }()
	_, _ = io.Copy(dst, src)
}