package stealth

import (
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/skyguard/skyguard/internal/config"
	"github.com/skyguard/skyguard/internal/proxy"
	"github.com/skyguard/skyguard/internal/storage"
)

func echoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	return ln.Addr().String()
}

func run(t *testing.T, sig string, client func(net.Conn)) (string, string) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := NewHandler(config.StealthService{
		Name: "t", RealTarget: echoServer(t), ProtocolSignature: sig, Timeout: time.Second,
	}, proxy.New(logger), logger)

	srvConn, cliConn := net.Pipe()
	var action, data string
	done := make(chan struct{})
	go func() {
		_ = h.Handle(srvConn, "198.51.100.1", func(a, d string) { action, data = a, d })
		close(done)
	}()
	client(cliConn)
	cliConn.Close()
	<-done
	return action, data
}

func TestSignatureSplitAcrossWrites(t *testing.T) {
	action, _ := run(t, "SSH-2.0-", func(c net.Conn) {
		// A real TCP stream may deliver the signature in pieces.
		_, _ = c.Write([]byte("SSH-"))
		time.Sleep(20 * time.Millisecond)
		_, _ = c.Write([]byte("2.0-OpenSSH_9.6\r\n"))
		buf := make([]byte, len("SSH-2.0-OpenSSH_9.6\r\n"))
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := io.ReadFull(c, buf); err != nil {
			t.Errorf("echo via proxy failed: %v", err)
		} else if string(buf) != "SSH-2.0-OpenSSH_9.6\r\n" {
			t.Errorf("prefix not replayed, got %q", buf)
		}
	})
	if action != storage.ActionForwarded {
		t.Fatalf("action = %q, want forwarded", action)
	}
}

func TestWrongSignatureAndTimeoutDropped(t *testing.T) {
	action, data := run(t, "SSH-2.0-", func(c net.Conn) {
		_, _ = c.Write([]byte("GET / HTTP/1.1\r\n"))
	})
	if action != storage.ActionDropped {
		t.Errorf("wrong signature: action = %q (%s)", action, data)
	}
	action, _ = run(t, "SSH-2.0-", func(c net.Conn) { time.Sleep(1500 * time.Millisecond) })
	if action != storage.ActionDropped {
		t.Errorf("timeout: action = %q", action)
	}
}
