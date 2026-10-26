package storage

import (
	"path/filepath"
	"testing"
	"time"
)

func newTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := New(filepath.Join(t.TempDir(), "sub", "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestTimestampNormalizationAndOrdering(t *testing.T) {
	db := newTestDB(t)
	// Simulate rows written by older versions in SQLite's space-separated format.
	if _, err := db.db.Exec(`INSERT INTO connections (timestamp, source_ip, source_port, dest_port, action)
		VALUES ('2024-01-01 23:00:00', '1.1.1.1', 0, 22, 'honeypot')`); err != nil {
		t.Fatal(err)
	}
	if err := db.LogConnection(&Connection{Timestamp: time.Date(2024, 1, 1, 1, 0, 0, 0, time.UTC), SourceIP: "2.2.2.2", Action: ActionDropped}); err != nil {
		t.Fatal(err)
	}
	if err := db.migrate(); err != nil { // re-running migrations must be idempotent
		t.Fatal(err)
	}
	rows, err := db.GetRecentConnections(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].SourceIP != "1.1.1.1" {
		t.Fatalf("expected the 23:00 row first, got %+v", rows)
	}
	if rows[0].Timestamp.Hour() != 23 {
		t.Errorf("timestamp not parsed: %v", rows[0].Timestamp)
	}
}

func TestBansLifecycle(t *testing.T) {
	db := newTestDB(t)
	if err := db.BanIP("1.2.3.4", "test", time.Hour, false); err != nil {
		t.Fatal(err)
	}
	if err := db.BanIP("5.6.7.8", "forever", 0, false); err != nil { // 0 => permanent
		t.Fatal(err)
	}
	if err := db.BanIP("9.9.9.9", "old", time.Hour, false); err != nil {
		t.Fatal(err)
	}
	if _, err := db.db.Exec(`UPDATE banned_ips SET expires_at = '2000-01-01T00:00:00Z' WHERE ip = '9.9.9.9'`); err != nil {
		t.Fatal(err)
	}

	for ip, want := range map[string]bool{"1.2.3.4": true, "5.6.7.8": true, "9.9.9.9": false, "8.8.8.8": false} {
		if got, err := db.IsBanned(ip); err != nil || got != want {
			t.Errorf("IsBanned(%s) = %v, %v; want %v", ip, got, err, want)
		}
	}
	active, err := db.GetActiveBans()
	if err != nil || len(active) != 2 {
		t.Fatalf("active bans = %d, %v; want 2", len(active), err)
	}
	for _, b := range active {
		if b.IP == "5.6.7.8" && (!b.Permanent || b.ExpiresAt != nil) {
			t.Errorf("zero-duration ban not stored as permanent: %+v", b)
		}
	}
	expired, err := db.GetExpiredBans()
	if err != nil || len(expired) != 1 || expired[0] != "9.9.9.9" {
		t.Fatalf("expired = %v, %v", expired, err)
	}
	if err := db.DeleteExpiredBan("1.2.3.4"); err != nil { // not expired: must be kept
		t.Fatal(err)
	}
	if err := db.DeleteExpiredBan("9.9.9.9"); err != nil {
		t.Fatal(err)
	}
	stats, err := db.GetStats()
	if err != nil {
		t.Fatal(err)
	}
	if stats.ActiveBans != 2 {
		t.Errorf("active bans stat = %d, want 2", stats.ActiveBans)
	}
}

func TestRecordScore(t *testing.T) {
	db := newTestDB(t)
	steps := []ScoreEvent{
		{IP: "1.2.3.4", Delta: 10, HoneypotHit: true, Port: 22},
		{IP: "1.2.3.4", Country: "NL", Delta: 15, CredentialHit: true, Port: 22},
		{IP: "1.2.3.4", Delta: 25, Port: 3306},
	}
	var score int
	var err error
	for _, ev := range steps {
		if score, err = db.RecordScore(ev); err != nil {
			t.Fatal(err)
		}
	}
	if score != 50 {
		t.Errorf("score = %d, want 50", score)
	}
	s, err := db.GetIPScore("1.2.3.4")
	if err != nil || s == nil {
		t.Fatal(s, err)
	}
	if s.TotalConnections != 3 || s.HoneypotHits != 1 || s.CredentialAttempts != 1 || s.Country != "NL" {
		t.Errorf("counters wrong: %+v", s)
	}
	if len(s.PortsScanned) != 2 || s.PortsScanned[0] != 22 || s.PortsScanned[1] != 3306 {
		t.Errorf("ports = %v, want [22 3306]", s.PortsScanned)
	}
	if err := db.ResetScore("1.2.3.4"); err != nil {
		t.Fatal(err)
	}
	if got, _ := db.GetScore("1.2.3.4"); got != 0 {
		t.Errorf("score after reset = %d", got)
	}
}

func TestTimelineFillsGaps(t *testing.T) {
	db := newTestDB(t)
	if err := db.LogConnection(&Connection{SourceIP: "1.1.1.1", Action: ActionHoneypot, Timestamp: time.Now().Add(-3 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	b, err := db.GetTimeline(24)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 24 {
		t.Fatalf("got %d buckets, want 24", len(b))
	}
	var total int64
	for _, x := range b {
		total += x.HoneypotHits
	}
	if total != 1 {
		t.Errorf("honeypot hits across buckets = %d, want 1", total)
	}
}

func TestSettingsConfigPrecedence(t *testing.T) {
	db := newTestDB(t)
	cfgA := AutoBanSettings{Enabled: true, ScoreThreshold: 50, BanDuration: time.Hour}

	s, err := db.LoadSettings(cfgA)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetAutoBan(AutoBanSettings{Enabled: false, ScoreThreshold: 80, BanDuration: 2 * time.Hour}); err != nil {
		t.Fatal(err)
	}

	// Restart with the same config: dashboard override survives.
	s, err = db.LoadSettings(cfgA)
	if err != nil {
		t.Fatal(err)
	}
	if got := s.AutoBan(); got.ScoreThreshold != 80 || got.Enabled {
		t.Errorf("dashboard override lost: %+v", got)
	}

	// Operator edits the config file: the file wins.
	cfgB := AutoBanSettings{Enabled: true, ScoreThreshold: 30, BanDuration: time.Hour}
	s, err = db.LoadSettings(cfgB)
	if err != nil {
		t.Fatal(err)
	}
	if got := s.AutoBan(); got != cfgB {
		t.Errorf("config edit ignored: %+v", got)
	}
}
