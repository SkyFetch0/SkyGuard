package server

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/skyguard/skyguard/internal/config"
	"github.com/skyguard/skyguard/internal/storage"
)

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func startServer(t *testing.T) (*Server, *storage.DB, map[string]int) {
	t.Helper()
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { backend.Close() })
	go func() {
		for {
			c, err := backend.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()

	ports := map[string]int{"ftp": freePort(t), "stealth": freePort(t), "dash": freePort(t), "mysql": freePort(t)}
	dir := t.TempDir()
	yaml := fmt.Sprintf(`
general: {data_dir: %q}
stealth_services:
  - {name: ssh, listen_port: %d, real_target: %q, protocol_signature: "SSH-2.0-", timeout: 2s}
honeypot_services:
  - {name: ftp, port: %d, type: ftp, max_auth_attempts: 1}
  - {name: mysql, port: %d, type: mysql, enabled: false}
analysis:
  auto_ban: {enabled: true, score_threshold: 20, ban_duration: 1h, method: none,
             scoring: {honeypot_connection: 10, failed_credential: 15}}
dashboard: {enabled: true, listen: "127.0.0.1:%d", auth: {username: admin, password: "long enough pw"}}
`, dir, ports["stealth"], backend.Addr().String(), ports["ftp"], ports["mysql"], ports["dash"])
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	db, err := storage.New(filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	srv, err := New(cfg, db, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	return srv, db, ports
}

func TestServerEndToEnd(t *testing.T) {
	srv, db, ports := startServer(t)

	// FTP honeypot from loopback: credential captured, but loopback is always
	// whitelisted, so it must never be scored or banned.
	c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", ports["ftp"]))
	if err != nil {
		t.Fatal(err)
	}
	r := bufio.NewReader(c)
	_, _ = r.ReadString('\n')
	fmt.Fprint(c, "USER root\r\nPASS toor\r\n")
	_, _ = io.ReadAll(r)
	c.Close()

	deadline := time.Now().Add(3 * time.Second)
	for {
		creds, _ := db.GetCredentialsByIP("127.0.0.1", 5)
		if len(creds) == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("credential not recorded")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if score, _ := db.GetScore("127.0.0.1"); score != 0 {
		t.Errorf("whitelisted loopback was scored: %d", score)
	}

	// Stealth: a real-looking SSH client is forwarded to the backend.
	s, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", ports["stealth"]))
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprint(s, "SSH-2.0-test\r\n")
	_ = s.SetReadDeadline(time.Now().Add(3 * time.Second))
	line, err := bufio.NewReader(s).ReadString('\n')
	if err != nil || line != "SSH-2.0-test\r\n" {
		t.Fatalf("stealth forward failed: %q %v", line, err)
	}

	// Dashboard health endpoint works without credentials.
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/healthz", ports["dash"]))
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("healthz: %v %v", resp, err)
	}
	resp.Body.Close()

	// Stop must not hang on the still-open proxied stealth session.
	done := make(chan error, 1)
	go func() { done <- srv.Stop() }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Stop hung on an open proxied connection")
	}
	s.Close()

	conns, _ := db.SearchConnections(storage.ConnectionFilter{Limit: 50})
	actions := map[string]int{}
	for _, c := range conns {
		actions[c.ServiceType+"/"+c.Action]++
	}
	if actions["ftp/honeypot"] != 1 || actions["stealth/forwarded"] != 1 {
		t.Errorf("unexpected connection log: %v", actions)
	}
}

func TestBanPolicy(t *testing.T) {
	srv, db, _ := startServer(t)
	defer srv.Stop()

	attacker := "203.0.113.9"
	score, _ := db.RecordScore(storage.ScoreEvent{IP: attacker, Delta: 25})
	if !srv.maybeAutoBan(attacker, score, "test") {
		t.Fatal("expected auto-ban above threshold")
	}
	if banned, _ := db.IsBanned(attacker); !banned {
		t.Fatal("ban not stored")
	}
	if err := srv.UnbanIP(attacker); err != nil {
		t.Fatal(err)
	}
	if s, _ := db.GetScore(attacker); s != 0 {
		t.Errorf("unban must reset the score (got %d), otherwise the next event re-bans", s)
	}

	if srv.maybeAutoBan("127.0.0.1", 1000, "test") {
		t.Error("loopback must never be auto-banned")
	}
	if err := srv.BanIP("::1", "manual", time.Hour, false); err == nil || !strings.Contains(err.Error(), "whitelisted") {
		t.Errorf("manual ban of whitelisted IP: %v", err)
	}

	// Expired bans are lifted and the score reset. Score first, then ban: the
	// maintenance loop's start-up pass may lift this already-expired ban
	// concurrently, and points recorded after a lift legitimately count again.
	_, _ = db.RecordScore(storage.ScoreEvent{IP: "198.51.100.4", Delta: 99})
	_ = db.BanIP("198.51.100.4", "x", time.Millisecond, false)
	time.Sleep(1100 * time.Millisecond) // stored with second precision
	srv.releaseExpiredBans()
	if active, _ := db.GetActiveBans(); len(active) != 0 {
		t.Errorf("expired ban still active: %+v", active[0])
	}
	if s, _ := db.GetScore("198.51.100.4"); s != 0 {
		t.Errorf("score after expiry = %d", s)
	}
}

func TestServiceSwitchAtRuntime(t *testing.T) {
	srv, db, ports := startServer(t)
	mysqlAddr := fmt.Sprintf("127.0.0.1:%d", ports["mysql"])
	dial := func() error {
		c, err := net.DialTimeout("tcp", mysqlAddr, time.Second)
		if err == nil {
			c.Close()
		}
		return err
	}
	if dial() == nil {
		t.Fatal("disabled honeypot is listening")
	}
	if err := srv.SetServiceEnabled("mysql", true); err != nil {
		t.Fatal(err)
	}
	if err := dial(); err != nil {
		t.Fatalf("enabled honeypot not reachable: %v", err)
	}
	if err := srv.SetServiceEnabled("ssh", false); err == nil {
		t.Error("stealth service must not be switchable")
	}
	var st []string
	for _, s := range srv.Services() {
		st = append(st, fmt.Sprintf("%s:%v", s.Name, s.Running))
	}
	if strings.Join(st, ",") != "ftp:true,mysql:true,ssh:true" {
		t.Errorf("services = %v", st)
	}
	if err := srv.SetServiceEnabled("mysql", false); err != nil {
		t.Fatal(err)
	}
	if dial() == nil {
		t.Error("switched-off honeypot still listening")
	}
	if err := srv.SetServiceEnabled("mysql", true); err != nil {
		t.Fatal(err)
	}
	_ = srv.Stop()

	// The choice survives a restart (same database, same config).
	if on, ok, err := db.ServiceOverride("mysql", false); err != nil || !ok || !on {
		t.Fatalf("override not stored: %v %v %v", on, ok, err)
	}
	// An edit of that service in the config file wins over the stored choice.
	if _, ok, _ := db.ServiceOverride("mysql", true); ok {
		t.Error("override should be dropped once the config changes the service")
	}
}
