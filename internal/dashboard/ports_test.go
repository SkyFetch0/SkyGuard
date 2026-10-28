package dashboard

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/skyguard/skyguard/internal/config"
	"github.com/skyguard/skyguard/internal/firewall"
	"github.com/skyguard/skyguard/internal/portrules"
	"github.com/skyguard/skyguard/internal/storage"
)

type nopGuard struct{ applied []firewall.PortRule }

func (g *nopGuard) Apply(r []firewall.PortRule, _ []string) error  { g.applied = r; return nil }
func (g *nopGuard) Ensure(r []firewall.PortRule, _ []string) error { return nil }
func (g *nopGuard) Remove()                                        { g.applied = nil }
func (g *nopGuard) Dropped() map[string]uint64                     { return map[string]uint64{} }
func (g *nopGuard) IPv6() bool                                     { return false }
func (g *nopGuard) NATPorts() []firewall.NATPort                   { return nil }

func TestPortRulesAPI(t *testing.T) {
	db, err := storage.New(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	settings, _ := db.LoadSettings(storage.AutoBanSettings{Enabled: true, ScoreThreshold: 50, BanDuration: time.Hour})
	fw, _ := firewall.New("none", firewall.Options{}, logger)
	d := New(config.DashboardConfig{Listen: "127.0.0.1:0", Auth: config.DashboardAuth{Username: "admin", Password: "correct horse"}},
		db, fw, settings, &fakeBans{db: db}, logger)
	g := &nopGuard{}
	m := portrules.New(g, "", db, nil, logger)
	m.Protected = func() []portrules.Protected { return []portrules.Protected{{Port: 22, Why: "SSH"}} }
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	d.SetPortRules(m, func(context.Context) []portrules.Listener {
		return []portrules.Listener{{Proto: "tcp", Port: 27017, Addrs: []string{"0.0.0.0"}, Scope: "public", Service: "MongoDB", Risk: "database"}}
	})
	ts := httptest.NewServer(d.routes())
	t.Cleanup(ts.Close)

	v := dash(t, ts, "GET", "/api/ports", nil)
	if v["available"] != true || len(v["listeners"].([]any)) != 1 || v["client_ip"] != "127.0.0.1" {
		t.Fatalf("view %v", v)
	}
	rules, _ := json.Marshal([]map[string]any{{"id": "db", "ports": "27017", "proto": "tcp", "mode": "allow", "sources": []string{"private"}, "enabled": true}})
	if res := dash(t, ts, "POST", "/api/ports", url.Values{"rules": {string(rules)}}); res["trial"] != false || len(g.applied) != 1 {
		t.Fatalf("set %v %v", res, g.applied)
	}
	if js, _ := db.PortRules(); !strings.Contains(js, "27017") {
		t.Errorf("not stored: %s", js)
	}
	ssh, _ := json.Marshal([]map[string]any{{"id": "ssh", "ports": "22", "proto": "tcp", "mode": "allow", "sources": []string{"203.0.113.5"}, "enabled": true}})
	if res := dash(t, ts, "POST", "/api/ports", url.Values{"rules": {string(ssh)}}); res["trial"] != true {
		t.Fatalf("ssh change without a trial: %v", res)
	}
	dash(t, ts, "POST", "/api/ports/revert", nil)
	if len(g.applied) != 1 || g.applied[0].ID != "db" {
		t.Errorf("revert brought back %v", g.applied)
	}

	// bad input and missing CSRF header are refused
	req, _ := http.NewRequest("POST", ts.URL+"/api/ports", strings.NewReader("rules=nope"))
	req.SetBasicAuth("admin", "correct horse")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-SkyGuard-Request", "1")
	if resp, _ := http.DefaultClient.Do(req); resp.StatusCode != 400 {
		t.Errorf("bad JSON: %d", resp.StatusCode)
	}
	req, _ = http.NewRequest("POST", ts.URL+"/api/ports/confirm", nil)
	req.SetBasicAuth("admin", "correct horse")
	if resp, _ := http.DefaultClient.Do(req); resp.StatusCode != 403 {
		t.Errorf("no CSRF header: %d", resp.StatusCode)
	}
}
