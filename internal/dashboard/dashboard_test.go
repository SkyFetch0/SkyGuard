package dashboard

import (
	"encoding/json"
	"errors"
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
	"github.com/skyguard/skyguard/internal/storage"
)

type fakeBans struct {
	db     *storage.DB
	banned []string
	ftpOn  bool
}

func (f *fakeBans) BanIP(ip, reason string, d time.Duration, perm bool) error {
	f.banned = append(f.banned, ip)
	return f.db.BanIP(ip, reason, d, perm)
}
func (f *fakeBans) UnbanIP(ip string) error      { return f.db.UnbanIP(ip) }
func (f *fakeBans) IsWhitelisted(ip string) bool { return ip == "127.0.0.1" || ip == "10.0.0.1" }
func (f *fakeBans) Services() []ServiceStatus {
	return []ServiceStatus{
		{Name: "fake-ftp", Kind: "honeypot", Type: "ftp", Port: 21, Enabled: f.ftpOn, Running: f.ftpOn, Toggleable: true},
		{Name: "ssh", Kind: "stealth", Type: "stealth", Port: 9911, Enabled: true, Running: true},
	}
}
func (f *fakeBans) SetServiceEnabled(name string, on bool) error {
	if name != "fake-ftp" {
		return errors.New("only honeypots can be switched")
	}
	f.ftpOn = on
	return nil
}

func newTestDashboard(t *testing.T) (http.Handler, *fakeBans) {
	t.Helper()
	db, err := storage.New(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	settings, err := db.LoadSettings(storage.AutoBanSettings{Enabled: true, ScoreThreshold: 50, BanDuration: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	fw, _ := firewall.New("none", firewall.Options{}, logger)
	bans := &fakeBans{db: db}
	d := New(config.DashboardConfig{Listen: "127.0.0.1:0", Auth: config.DashboardAuth{Username: "admin", Password: "correct horse"}},
		db, fw, settings, bans, logger)
	return d.routes(), bans
}

func do(h http.Handler, method, path string, form url.Values, auth bool, headers map[string]string) *httptest.ResponseRecorder {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req := httptest.NewRequest(method, path, body)
	req.RemoteAddr = "192.0.2.10:5555"
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if auth {
		req.SetBasicAuth("admin", "correct horse")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestHealthzAndAuth(t *testing.T) {
	h, _ := newTestDashboard(t)
	if rec := do(h, "GET", "/healthz", nil, false, nil); rec.Code != 200 {
		t.Errorf("/healthz without auth = %d", rec.Code)
	}
	if rec := do(h, "GET", "/api/stats", nil, false, nil); rec.Code != 401 {
		t.Errorf("/api/stats without auth = %d", rec.Code)
	}
	rec := do(h, "GET", "/", nil, true, nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `<script src="/assets/app.js">`) {
		t.Errorf("index = %d", rec.Code)
	}
	if csp := rec.Header().Get("Content-Security-Policy"); strings.Contains(csp, "script-src 'self' 'unsafe-inline'") {
		t.Errorf("CSP still allows inline scripts: %s", csp)
	}
	for _, p := range []string{"/assets/app.js", "/assets/charts.js", "/assets/app.css", "/assets/fonts/public-sans-latin-wght-normal.woff2"} {
		if rec := do(h, "GET", p, nil, true, nil); rec.Code != 200 {
			t.Errorf("%s = %d", p, rec.Code)
		}
	}
	for _, p := range []string{"/api/stats", "/api/connections", "/api/banned", "/api/attackers", "/api/credentials", "/api/timeline",
		"/api/settings", "/api/firewall", "/api/summary?range=7d", "/api/series?range=30d", "/api/credentials/breakdown", "/api/services"} {
		rec := do(h, "GET", p, nil, true, nil)
		if rec.Code != 200 || strings.TrimSpace(rec.Body.String()) == "null" {
			t.Errorf("%s = %d %q", p, rec.Code, rec.Body.String())
		}
	}
}

func TestAuthThrottleIsPerIP(t *testing.T) {
	h, _ := newTestDashboard(t)
	for i := 0; i < authFailThreshold; i++ {
		req := httptest.NewRequest("GET", "/api/stats", nil)
		req.RemoteAddr = "198.51.100.66:1000"
		req.SetBasicAuth("admin", "wrong")
		h.ServeHTTP(httptest.NewRecorder(), req)
	}
	req := httptest.NewRequest("GET", "/api/stats", nil)
	req.RemoteAddr = "198.51.100.66:1000"
	req.SetBasicAuth("admin", "correct horse")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("attacker IP not throttled: %d", rec.Code)
	}
	// The real admin from another address must not be locked out.
	if rec := do(h, "GET", "/api/stats", nil, true, nil); rec.Code != 200 {
		t.Errorf("admin locked out by someone else's failures: %d", rec.Code)
	}
}

func TestBanEndpoint(t *testing.T) {
	h, bans := newTestDashboard(t)
	form := url.Values{"ip": {"203.0.113.5"}, "duration": {"7d"}}

	if rec := do(h, "POST", "/api/ban", form, true, nil); rec.Code != http.StatusForbidden {
		t.Errorf("ban without CSRF header = %d", rec.Code)
	}
	if rec := do(h, "GET", "/api/ban", nil, true, nil); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /api/ban = %d", rec.Code)
	}
	hdr := map[string]string{"X-SkyGuard-Request": "1"}
	if rec := do(h, "POST", "/api/ban", form, true, hdr); rec.Code != 200 {
		t.Fatalf("ban = %d %s", rec.Code, rec.Body.String())
	}
	if len(bans.banned) != 1 {
		t.Errorf("BanManager not used: %v", bans.banned)
	}
	rec := do(h, "POST", "/api/ban", url.Values{"ip": {"10.0.0.1"}}, true, hdr)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "whitelisted") {
		t.Errorf("banning whitelisted IP = %d %s", rec.Code, rec.Body.String())
	}
	if rec := do(h, "GET", "/api/ip?ip=203.0.113.5", nil, true, nil); !strings.Contains(rec.Body.String(), `"banned":true`) {
		t.Errorf("ip detail = %s", rec.Body.String())
	}
	if rec := do(h, "POST", "/api/unban", url.Values{"ip": {"203.0.113.5"}}, true, hdr); rec.Code != 200 {
		t.Errorf("unban = %d", rec.Code)
	}
}

func TestSettingsPartialUpdate(t *testing.T) {
	h, _ := newTestDashboard(t)
	hdr := map[string]string{"X-SkyGuard-Request": "1"}
	if rec := do(h, "POST", "/api/settings", url.Values{"score_threshold": {"75"}}, true, hdr); rec.Code != 200 {
		t.Fatalf("settings = %d %s", rec.Code, rec.Body.String())
	}
	body := do(h, "GET", "/api/settings", nil, true, nil).Body.String()
	if !strings.Contains(body, `"auto_ban_enabled":true`) || !strings.Contains(body, `"score_threshold":75`) {
		t.Errorf("partial update changed other fields: %s", body)
	}
}

func TestCSVSafe(t *testing.T) {
	if csvSafe("=HYPERLINK(1)") != "'=HYPERLINK(1)" || csvSafe("method=GET") != "method=GET" {
		t.Error("csvSafe wrong")
	}
}

func TestRefuseUnsafeExposure(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	d := &Dashboard{cfg: config.DashboardConfig{Listen: "0.0.0.0:9090"}, logger: logger}
	if err := d.checkExposure(); err == nil {
		t.Error("expected refusal for unauthenticated public dashboard")
	}
	d.cfg.Auth = config.DashboardAuth{Username: "admin", Password: "CHANGE_ME_NOW"}
	if err := d.checkExposure(); err == nil {
		t.Error("expected refusal for default password on public dashboard")
	}
	d.cfg.Listen = "127.0.0.1:9090"
	if err := d.checkExposure(); err != nil {
		t.Errorf("loopback should only warn: %v", err)
	}
}

func TestSummaryAndSeries(t *testing.T) {
	h, bans := newTestDashboard(t)
	db := bans.db
	now := time.Now().UTC()
	_ = db.LogConnection(&storage.Connection{Timestamp: now.Add(-2 * time.Hour), SourceIP: "203.0.113.5", DestPort: 22, ServiceType: "ssh", Action: storage.ActionHoneypot})
	_ = db.LogConnection(&storage.Connection{Timestamp: now.Add(-1 * time.Hour), SourceIP: "203.0.113.5", DestPort: 9911, ServiceType: "stealth", Action: storage.ActionDropped, Data: "stealth: signature mismatch"})
	_ = db.LogConnection(&storage.Connection{Timestamp: now.Add(-30 * time.Hour), SourceIP: "198.51.100.1", DestPort: 21, ServiceType: "ftp", Action: storage.ActionHoneypot})
	_ = db.LogCredential(&storage.Credential{Timestamp: now.Add(-2 * time.Hour), SourceIP: "203.0.113.5", Port: 22, Username: "root", Password: "toor", Service: "ssh"})

	var sum struct {
		Current, Previous storage.Summary
		Outcomes          []storage.Outcome
		TopSources        []storage.SourceCount `json:"top_sources"`
		Services          []storage.KeyCount
	}
	rec := do(h, "GET", "/api/summary?range=24h", nil, true, nil)
	if err := json.Unmarshal(rec.Body.Bytes(), &sum); err != nil {
		t.Fatal(err, rec.Body.String())
	}
	if sum.Current.Connections != 2 || sum.Previous.Connections != 1 || sum.Current.Credentials != 1 {
		t.Errorf("summary periods wrong: %+v / %+v", sum.Current, sum.Previous)
	}
	got := map[string]int64{}
	for _, o := range sum.Outcomes {
		got[o.Key] = o.Count
	}
	if got["honeypot"] != 1 || got["stealth_probe"] != 1 || len(sum.Outcomes) != len(storage.OutcomeKeys) {
		t.Errorf("outcomes = %v", got)
	}
	if len(sum.TopSources) != 1 || sum.TopSources[0].IP != "203.0.113.5" || sum.TopSources[0].Count != 2 {
		t.Errorf("top sources = %+v", sum.TopSources)
	}

	var series struct{ Buckets []storage.TimelineBucket }
	rec = do(h, "GET", "/api/series?range=7d", nil, true, nil)
	_ = json.Unmarshal(rec.Body.Bytes(), &series)
	var total, creds int64
	for _, b := range series.Buckets {
		total += b.Total
		creds += b.Credentials
	}
	if len(series.Buckets) != 7*24 || total != 3 || creds != 1 {
		t.Errorf("7d series: %d buckets, %d connections, %d credentials", len(series.Buckets), total, creds)
	}
	rec = do(h, "GET", "/api/series?range=30d", nil, true, nil)
	_ = json.Unmarshal(rec.Body.Bytes(), &series)
	if len(series.Buckets) != 30 {
		t.Errorf("30d series has %d buckets", len(series.Buckets))
	}
}

func TestServiceSwitch(t *testing.T) {
	h, bans := newTestDashboard(t)
	hdr := map[string]string{"X-SkyGuard-Request": "1"}
	if rec := do(h, "POST", "/api/services", url.Values{"name": {"fake-ftp"}, "enabled": {"1"}}, true, nil); rec.Code != http.StatusForbidden {
		t.Errorf("switch without CSRF header = %d", rec.Code)
	}
	if rec := do(h, "POST", "/api/services", url.Values{"name": {"fake-ftp"}, "enabled": {"1"}}, true, hdr); rec.Code != 200 || !bans.ftpOn {
		t.Errorf("switch on = %d %s", rec.Code, rec.Body.String())
	}
	if rec := do(h, "POST", "/api/services", url.Values{"name": {"ssh"}, "enabled": {"0"}}, true, hdr); rec.Code != http.StatusConflict {
		t.Errorf("switching a stealth service must be refused, got %d", rec.Code)
	}
	if rec := do(h, "POST", "/api/services", url.Values{"name": {"fake-ftp"}}, true, hdr); rec.Code != http.StatusBadRequest {
		t.Errorf("missing enabled = %d", rec.Code)
	}
}
