package honeypot

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/skyguard/skyguard/internal/config"
	"github.com/skyguard/skyguard/internal/storage"
)

func setup(t *testing.T) (*storage.DB, *EventLogger, *[]Session) {
	t.Helper()
	dir := t.TempDir()
	db, err := storage.New(filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	ev := NewEventLogger(db, slog.New(slog.NewTextHandler(io.Discard, nil)), 512)
	var hooks []Session
	ev.OnCredential(func(s Session) { hooks = append(hooks, s) })
	return db, ev, &hooks
}

// serve runs h on a real loopback listener (x/crypto needs a real stream).
func serve(t *testing.T, h Handler) string {
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
			go func() { _ = h.Handle(c, Session{IP: "203.0.113.7", Port: 22, Country: "NL"}) }()
		}
	}()
	return ln.Addr().String()
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in time")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestSSHHoneypotCapturesPasswords(t *testing.T) {
	db, ev, hooks := setup(t)
	dataDir := t.TempDir()
	cfg := config.HoneypotService{Name: "ssh", Type: "ssh", Port: 22, MaxAuthAttempts: 2}
	h, err := NewSSHHoneypot(cfg, ev, ev.logger, dataDir)
	if err != nil {
		t.Fatal(err)
	}
	addr := serve(t, h)

	tries := 0
	_, err = ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User: "root",
		Auth: []ssh.AuthMethod{ssh.RetryableAuthMethod(ssh.PasswordCallback(func() (string, error) {
			tries++
			return fmt.Sprintf("hunter%d", tries), nil
		}), 5)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err == nil {
		t.Fatal("honeypot must never authenticate")
	}

	var creds []*storage.Credential
	waitFor(t, func() bool {
		creds, _ = db.GetCredentialsByIP("203.0.113.7", 10)
		return len(creds) >= 2
	})
	got := map[string]bool{}
	for _, c := range creds {
		if c.Username != "root" || c.Service != "ssh" {
			t.Errorf("unexpected credential %+v", c)
		}
		got[c.Password] = true
	}
	if !got["hunter1"] || !got["hunter2"] {
		t.Errorf("passwords not captured: %v", got)
	}
	if len(*hooks) < 2 || (*hooks)[0].Country != "NL" {
		t.Errorf("credential hook not invoked with session: %+v", *hooks)
	}

	// Host keys persist so the fingerprint is stable across restarts.
	h2, err := NewSSHHoneypot(cfg, ev, ev.logger, dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if string(h.hostKeys[0].PublicKey().Marshal()) != string(h2.hostKeys[0].PublicKey().Marshal()) {
		t.Error("host key changed between instances")
	}
}

func TestHTTPHoneypotCapturesLoginForm(t *testing.T) {
	db, ev, _ := setup(t)
	h := NewHTTPHoneypot(config.HoneypotService{Port: 80, ServerHeader: "nginx/1.18.0"}, ev, ev.logger)
	addr := serve(t, h)

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	body := "log=admin&pwd=s3cret&wp-submit=Log+In"
	fmt.Fprintf(c, "POST /wp-login.php HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	resp, _ := io.ReadAll(c)
	c.Close()
	if !strings.Contains(string(resp), "Server: nginx/1.18.0") {
		t.Errorf("server_header not used:\n%s", resp)
	}
	waitFor(t, func() bool {
		creds, _ := db.GetCredentialsByIP("203.0.113.7", 10)
		return len(creds) == 1 && creds[0].Username == "admin" && creds[0].Password == "s3cret"
	})
}

func TestFTPHoneypot(t *testing.T) {
	db, ev, _ := setup(t)
	h := NewFTPHoneypot(config.HoneypotService{Port: 21, MaxAuthAttempts: 1}, ev, ev.logger)
	addr := serve(t, h)

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	r := bufio.NewReader(c)
	line, _ := r.ReadString('\n')
	if !strings.HasPrefix(line, "220 ") {
		t.Fatalf("banner = %q", line)
	}
	fmt.Fprint(c, "USER anonymous\r\nPASS guest@\r\n")
	waitFor(t, func() bool {
		creds, _ := db.GetCredentialsByIP("203.0.113.7", 10)
		return len(creds) == 1 && creds[0].Username == "anonymous"
	})
}

func TestCleanCapsAndSanitises(t *testing.T) {
	ev := &EventLogger{maxBytes: 8}
	if got := ev.clean("ab\x00c\ndéfghijk"); len(got) > 8 || strings.ContainsRune(got, 0) {
		t.Errorf("clean = %q", got)
	}
}
