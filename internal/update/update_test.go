package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func TestCompare(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"1.2.0", "1.10.0", -1}, {"v2.0.0", "1.9.9", 1}, {"1.2.0", "1.2.0", 0},
		{"1.2.0-rc.1", "1.2.0", -1}, {"1.2.0-rc.2", "1.2.0-rc.10", -1}, {"1.2.0-beta", "1.2.0-alpha", 1},
		{"dev", "0.0.1", -1}, {"dev", "dev", 0}, {"1.2", "1.0.0", -1},
	} {
		if got := Compare(c.a, c.b); got != c.want {
			t.Errorf("Compare(%s, %s) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestVerify(t *testing.T) {
	pub, priv, _ := GenerateKey()
	bin := []byte("#!/bin/sh\necho new\n")
	h := sha256.Sum256(bin)
	sums := []byte(hex.EncodeToString(h[:]) + "  " + AssetName() + "\n" + strings.Repeat("0", 64) + "  other\n")
	sig, err := Sign(priv, sums)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := Keys(pub)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(bin, AssetName(), sums, []byte(sig), keys); err != nil {
		t.Errorf("a good release: %v", err)
	}
	if err := Verify(bin, AssetName(), sums, nil, nil); err != nil {
		t.Errorf("checksum only, no key: %v", err)
	}
	if err := Verify(append(bin, 'x'), AssetName(), sums, []byte(sig), keys); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Errorf("a changed binary: %v", err)
	}
	if err := Verify(bin, AssetName(), sums, nil, keys); err == nil || !strings.Contains(err.Error(), "not signed") {
		t.Errorf("unsigned with a key: %v", err)
	}
	other, _, _ := GenerateKey()
	k2, _ := Keys(other)
	if err := Verify(bin, AssetName(), sums, []byte(sig), k2); err == nil || !strings.Contains(err.Error(), "trusted key") {
		t.Errorf("signed by someone else: %v", err)
	}
	tampered := append([]byte{}, sums...)
	tampered[0] ^= 1
	if err := Verify(bin, AssetName(), tampered, []byte(sig), keys); err == nil {
		t.Error("changed sums passed the signature")
	}
	if _, err := Keys("not a key"); err == nil {
		t.Error("a bad key was accepted")
	}
}

// stage writes an executable at <data>/updates/<v>/skyguard.
func stage(t *testing.T, dataDir, v string) string {
	t.Helper()
	p := filepath.Join(Dir(dataDir), v, "skyguard")
	_ = os.MkdirAll(filepath.Dir(p), 0o755)
	if err := os.WriteFile(p, []byte("#!/bin/sh\necho skyguard "+v+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLaunchCountsAttemptsAndRollsBack(t *testing.T) {
	dir := t.TempDir()
	self := filepath.Join(dir, "base")
	_ = os.WriteFile(self, []byte("x"), 0o755)
	old := time.Now().Add(-time.Hour)
	_ = os.Chtimes(self, old, old)
	base := Build{Version: "1.0.0"}

	if got := Launch(dir, self, base, quiet); got != "" {
		t.Fatalf("no update applied, yet launched %q", got)
	}
	good := stage(t, dir, "1.1.0")
	bad := stage(t, dir, "1.2.0")
	st := &State{Current: &Slot{Version: "1.2.0", Path: bad, AppliedAt: time.Now()}, Previous: &Slot{Version: "1.1.0", Path: good, Good: true}}
	_ = st.Save(dir)
	for i := 1; i <= MaxAttempts; i++ {
		if got := Launch(dir, self, base, quiet); got != bad {
			t.Fatalf("attempt %d launched %q", i, got)
		}
	}
	// the fourth start without it ever staying up: back to 1.1.0
	if got := Launch(dir, self, base, quiet); got != good {
		t.Fatalf("after %d failed starts launched %q, want the previous", MaxAttempts, got)
	}
	st, _ = LoadState(dir)
	if st.Current.Version != "1.1.0" || st.Failure == nil || st.Failure.From != "1.2.0" || st.Failure.To != "1.1.0" || st.Failure.At.IsZero() {
		t.Fatalf("state %+v failure %+v", st.Current, st.Failure)
	}
	// a good version is not counted
	for i := 0; i < 5; i++ {
		Launch(dir, self, base, quiet)
	}
	if st, _ = LoadState(dir); st.Current.Attempts != 0 || st.Current.Version != "1.1.0" {
		t.Errorf("a good version was counted: %+v", st.Current)
	}

	// MarkGood ends the counting for a new version
	st.Current = &Slot{Version: "1.2.0", Path: bad, AppliedAt: time.Now()}
	_ = st.Save(dir)
	Launch(dir, self, base, quiet)
	if err := MarkGood(dir, "1.2.0"); err != nil {
		t.Fatal(err)
	}
	if st, _ = LoadState(dir); !st.Current.Good || st.Current.Attempts != 0 {
		t.Errorf("not marked good: %+v", st.Current)
	}

	// a missing binary falls back at once
	_ = os.Remove(bad)
	if got := Launch(dir, self, base, quiet); got != "" {
		t.Errorf("a missing binary launched %q", got)
	}
}

func TestLaunchPrefersANewerInstalledBinary(t *testing.T) {
	dir := t.TempDir()
	self := filepath.Join(dir, "base")
	_ = os.WriteFile(self, []byte("x"), 0o755)
	p := stage(t, dir, "1.1.0")
	save := func(applied time.Time) {
		_ = (&State{Current: &Slot{Version: "1.1.0", Path: p, AppliedAt: applied, Good: true}}).Save(dir)
	}
	save(time.Now())
	if got := Launch(dir, self, Build{Version: "1.2.0"}, quiet); got != "" {
		t.Errorf("an older update won over installed 1.2.0: %q", got)
	}
	// a local build ("dev"): the newer of the two choices wins
	old := time.Now().Add(-time.Hour)
	_ = os.Chtimes(self, old, old)
	save(time.Now())
	if got := Launch(dir, self, Build{Version: "dev"}, quiet); got != p {
		t.Errorf("an update applied after the dev build was skipped: %q", got)
	}
	save(time.Now().Add(-2 * time.Hour))
	if got := Launch(dir, self, Build{Version: "dev"}, quiet); got != "" {
		t.Errorf("a dev build made after the update did not win: %q", got)
	}
}

// fakeGitHub serves one release with a test binary.
func fakeGitHub(t *testing.T, version, script, priv string) *httptest.Server {
	t.Helper()
	bin := []byte(script)
	h := sha256.Sum256(bin)
	sums := []byte(hex.EncodeToString(h[:]) + "  " + AssetName() + "\n")
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/releases"):
			assets := []map[string]string{
				{"name": AssetName(), "browser_download_url": srv.URL + "/dl/bin"},
				{"name": "SHA256SUMS", "browser_download_url": srv.URL + "/dl/sums"},
			}
			if priv != "" {
				assets = append(assets, map[string]string{"name": "SHA256SUMS.sig", "browser_download_url": srv.URL + "/dl/sig"})
			}
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{"tag_name": "v9.9.9-rc.1", "prerelease": true, "assets": assets},
				{"tag_name": "v" + version, "name": "SkyGuard " + version, "body": "Fixes things.", "html_url": srv.URL + "/rel", "published_at": time.Now(), "assets": assets},
				{"tag_name": "v0.1.0", "assets": assets},
			})
		case r.URL.Path == "/dl/bin":
			_, _ = w.Write(bin)
		case r.URL.Path == "/dl/sums":
			_, _ = w.Write(sums)
		case r.URL.Path == "/dl/sig":
			s, _ := Sign(priv, sums)
			_, _ = io.WriteString(w, s)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestApplyStagesBacksUpAndRestarts(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "skyguard.yaml")
	_ = os.WriteFile(cfg, []byte("general: {}\n"), 0o600)
	pub, priv, _ := GenerateKey()
	// a stand-in for the new binary: answers -version and -check-config
	script := "#!/bin/sh\ncase \"$1\" in -version) echo skyguard 1.4.0;; -check-config) echo ok;; esac\n"
	gh := fakeGitHub(t, "1.4.0", script, priv)

	restarted := make(chan struct{}, 1)
	var backedUp string
	m := NewManager(Options{DataDir: dir, ConfigPath: cfg, Base: "/usr/local/bin/skyguard", Build: Build{Version: "1.3.0"},
		Source: &GitHub{API: gh.URL, Repo: "o/r"}, Channel: "stable", ExtraKeys: []string{pub},
		Backup:  func(p string) error { backedUp = p; return os.WriteFile(p, []byte("db"), 0o600) },
		Restart: func() { restarted <- struct{}{} }, Logger: quiet})

	rel, err := m.Check(context.Background())
	if err != nil || rel.Version != "1.4.0" || !rel.Signed {
		t.Fatalf("check: %+v %v (pre-releases must be skipped on stable)", rel, err)
	}
	if v := m.View(); !v.Available || !v.SignedOnly {
		t.Fatalf("view %+v", v)
	}
	if err := m.Apply("1.5.0"); err == nil {
		t.Error("a version that was not found was applied")
	}
	if err := m.Apply("1.4.0"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-restarted:
	case <-time.After(10 * time.Second):
		t.Fatalf("no restart; status %+v", m.View().Status)
	}
	st, _ := LoadState(dir)
	if st.Current == nil || st.Current.Version != "1.4.0" || st.Current.Good || st.Previous != nil {
		t.Fatalf("state %+v", st)
	}
	if b, _ := os.ReadFile(st.Current.Path); string(b) != script {
		t.Error("the staged binary is not the download")
	}
	if !strings.Contains(backedUp, "pre-update-1.3.0-to-1.4.0-") {
		t.Errorf("database backup %q", backedUp)
	}
	if b, _ := os.ReadFile(strings.TrimSuffix(backedUp, ".db") + ".yaml"); string(b) != "general: {}\n" {
		t.Error("the config was not backed up")
	}
	if err := m.Apply("1.4.0"); err == nil {
		t.Error("a second update ran while one was restarting")
	}
}

func TestApplyRefusesWhatWouldNotRun(t *testing.T) {
	for _, c := range []struct {
		name, script, want string
		signed             bool
	}{
		{"rejects the config", "#!/bin/sh\ncase \"$1\" in -version) echo skyguard 1.4.0;; *) echo 'invalid configuration: x'; exit 1;; esac\n", "does not accept the current config", true},
		{"wrong version", "#!/bin/sh\necho skyguard 1.0.0\n", "does not run here", true},
		{"unsigned", "#!/bin/sh\necho skyguard 1.4.0\n", "not signed", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			cfg := filepath.Join(dir, "skyguard.yaml")
			_ = os.WriteFile(cfg, []byte("{}"), 0o600)
			pub, priv, _ := GenerateKey()
			if !c.signed {
				priv = ""
			}
			gh := fakeGitHub(t, "1.4.0", c.script, priv)
			m := NewManager(Options{DataDir: dir, ConfigPath: cfg, Build: Build{Version: "1.3.0"},
				Source: &GitHub{API: gh.URL, Repo: "o/r"}, ExtraKeys: []string{pub}, Restart: func() { t.Error("restarted") }, Logger: quiet})
			if _, err := m.Check(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err := m.Apply("1.4.0"); err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(10 * time.Second)
			for m.View().Status.Phase != "failed" && time.Now().Before(deadline) {
				time.Sleep(20 * time.Millisecond)
			}
			s := m.View().Status
			if s.Phase != "failed" || !strings.Contains(s.Error, c.want) {
				t.Fatalf("status %+v", s)
			}
			if st, _ := LoadState(dir); st.Current != nil {
				t.Error("a failed update was made current")
			}
		})
	}
}

func TestRollback(t *testing.T) {
	dir := t.TempDir()
	p := stage(t, dir, "1.1.0")
	restarted := make(chan struct{}, 1)
	m := NewManager(Options{DataDir: dir, Build: Build{Version: "1.1.0"}, Slot: "1.1.0", Restart: func() { restarted <- struct{}{} }, Logger: quiet})
	if err := m.Rollback(); err == nil {
		t.Error("rolled back with nothing applied")
	}
	_ = (&State{Current: &Slot{Version: "1.1.0", Path: p, Good: true}}).Save(dir)
	if v := m.View(); !v.CanRollback || v.RollbackTo != "the installed version" {
		t.Fatalf("view %+v", v)
	}
	if err := m.Rollback(); err != nil {
		t.Fatal(err)
	}
	<-restarted
	if st, _ := LoadState(dir); st.Current != nil || st.History[len(st.History)-1].Result != "rolled-back" {
		t.Errorf("state %+v", st)
	}
}
