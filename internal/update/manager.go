package update

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

// CheckEvery is how often the manager looks for a new release.
const CheckEvery = 6 * time.Hour

// Options wires the manager to the running server.
type Options struct {
	DataDir    string
	ConfigPath string
	Base       string // the binary the service starts
	Build      Build  // this process
	Slot       string // the staged version this process is, "" for the base

	Source    *GitHub
	Channel   string
	Check     bool     // look for releases on a timer
	ExtraKeys []string // update.public_key

	Backup   func(path string) error // a consistent copy of the database
	DBSize   func() int64
	Precheck func() error // refuses an update the moment would make unsafe
	Restart  func()       // stops the server and starts the base again

	Logger *slog.Logger
}

// Status is what an update in progress is doing.
type Status struct {
	Phase   string     `json:"phase"` // idle, downloading, verifying, testing, backing-up, restarting, failed
	Version string     `json:"version,omitempty"`
	Error   string     `json:"error,omitempty"`
	Started *time.Time `json:"started,omitempty"`
}

// Manager checks for and installs updates.
type Manager struct {
	o Options

	mu        sync.Mutex
	status    Status
	latest    *Release
	checkedAt time.Time
	checkErr  string
}

// NewManager makes a manager.
func NewManager(o Options) *Manager {
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	return &Manager{o: o, status: Status{Phase: "idle"}}
}

// Run marks this version good once it has stayed up, and checks for
// releases on a timer until ctx ends.
func (m *Manager) Run(ctx context.Context) {
	if m.o.Slot != "" {
		go func() {
			select {
			case <-ctx.Done():
			case <-time.After(GoodAfter):
				if err := MarkGood(m.o.DataDir, m.o.Slot); err != nil {
					m.o.Logger.Error("recording the update as good", "error", err)
				} else {
					m.o.Logger.Info("update is running fine", "version", m.o.Slot)
				}
			}
		}()
	}
	if !m.o.Check || m.o.Source == nil {
		return
	}
	t := time.NewTimer(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			cctx, cancel := context.WithTimeout(ctx, time.Minute)
			_, _ = m.Check(cctx)
			cancel()
			t.Reset(CheckEvery)
		}
	}
}

// Check asks GitHub for the newest release now.
func (m *Manager) Check(ctx context.Context) (*Release, error) {
	if m.o.Source == nil {
		return nil, errors.New("no update source is configured")
	}
	rel, err := m.o.Source.Newest(ctx, m.o.Channel)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.checkedAt = time.Now().UTC()
	if err != nil {
		m.checkErr = err.Error()
		m.o.Logger.Warn("update check failed", "error", err)
		return nil, err
	}
	m.checkErr, m.latest = "", rel
	if rel != nil && Compare(rel.Version, m.o.Build.Version) > 0 {
		m.o.Logger.Info("a new SkyGuard release is available", "version", rel.Version, "running", m.o.Build.Version)
	}
	return rel, nil
}

// View is everything the dashboard shows about versions and updates.
type View struct {
	Running     Build      `json:"running"`
	Staged      bool       `json:"staged"` // running an applied update, not the installed binary
	Installed   string     `json:"installed"`
	Platform    string     `json:"platform"` // the asset this machine downloads
	InDocker    bool       `json:"in_docker"`
	Repo        string     `json:"repo"`
	Channel     string     `json:"channel"`
	Checks      bool       `json:"checks"`
	CheckedAt   *time.Time `json:"checked_at,omitempty"`
	CheckError  string     `json:"check_error,omitempty"`
	Latest      *Release   `json:"latest,omitempty"`
	Available   bool       `json:"available"`
	SignedOnly  bool       `json:"signed_only"` // this build trusts a signing key
	Status      Status     `json:"status"`
	State       *State     `json:"state"`
	CanRollback bool       `json:"can_rollback"`
	RollbackTo  string     `json:"rollback_to,omitempty"`
	Backups     []string   `json:"backups"`
}

// View reports the current state.
func (m *Manager) View() View {
	keys, _ := Keys(m.o.ExtraKeys...)
	st, _ := LoadState(m.o.DataDir)
	v := View{Running: m.o.Build, Staged: m.o.Slot != "", Installed: m.o.Build.Version, Platform: AssetName(), Channel: m.o.Channel,
		Checks: m.o.Check, SignedOnly: len(keys) > 0, State: st, Backups: m.backups()}
	if m.o.Source != nil {
		v.Repo = m.o.Source.Repo
	}
	if _, err := os.Stat("/.dockerenv"); err == nil {
		v.InDocker = true
	}
	if m.o.Slot != "" {
		v.Installed = "" // the base's version is not known from here
	}
	if st.Current != nil {
		v.CanRollback = true
		v.RollbackTo = "the installed version"
		if st.Previous != nil {
			v.RollbackTo = st.Previous.Version
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.checkedAt.IsZero() {
		t := m.checkedAt
		v.CheckedAt = &t
	}
	v.CheckError, v.Latest, v.Status = m.checkErr, m.latest, m.status
	v.Available = m.latest != nil && Compare(m.latest.Version, m.o.Build.Version) > 0
	return v
}

func (m *Manager) setPhase(phase string) {
	m.mu.Lock()
	m.status.Phase = phase
	m.mu.Unlock()
	m.o.Logger.Info("update", "phase", phase, "version", m.status.Version)
}

// Apply installs version (the newest release found by the last check) in
// the background; Status follows it. The server restarts at the end.
func (m *Manager) Apply(version string) error {
	m.mu.Lock()
	if p := m.status.Phase; p != "idle" && p != "failed" {
		m.mu.Unlock()
		return fmt.Errorf("an update is already %s", p)
	}
	rel := m.latest
	if rel == nil || rel.Version != version {
		m.mu.Unlock()
		return fmt.Errorf("version %s is not the newest release found; check again first", version)
	}
	if Compare(version, m.o.Build.Version) <= 0 {
		m.mu.Unlock()
		return fmt.Errorf("SkyGuard %s is already running", m.o.Build.Version)
	}
	if rel.Binary == "" || rel.Sums == "" {
		m.mu.Unlock()
		return fmt.Errorf("release %s has no %s or SHA256SUMS", version, AssetName())
	}
	if m.o.Precheck != nil {
		if err := m.o.Precheck(); err != nil {
			m.mu.Unlock()
			return err
		}
	}
	now := time.Now().UTC()
	m.status = Status{Phase: "downloading", Version: version, Started: &now}
	m.mu.Unlock()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		if err := m.install(ctx, rel); err != nil {
			m.mu.Lock()
			m.status.Phase, m.status.Error = "failed", err.Error()
			m.mu.Unlock()
			m.o.Logger.Error("update failed; nothing was changed", "version", version, "error", err)
			return
		}
		m.setPhase("restarting")
		time.Sleep(500 * time.Millisecond) // let the dashboard see it
		m.o.Restart()
	}()
	return nil
}

func (m *Manager) install(ctx context.Context, rel *Release) error {
	client := &http.Client{Timeout: 5 * time.Minute}
	token := m.o.Source.Token
	bin, err := download(ctx, client, rel.Binary, token, 200<<20)
	if err != nil {
		return fmt.Errorf("downloading %s: %w", rel.Asset, err)
	}
	sums, err := download(ctx, client, rel.Sums, token, 1<<20)
	if err != nil {
		return fmt.Errorf("downloading SHA256SUMS: %w", err)
	}
	var sig []byte
	if rel.Signature != "" {
		if sig, err = download(ctx, client, rel.Signature, token, 1<<16); err != nil {
			return fmt.Errorf("downloading the signature: %w", err)
		}
	}
	m.setPhase("verifying")
	keys, err := Keys(m.o.ExtraKeys...)
	if err != nil {
		return err
	}
	if err := Verify(bin, rel.Asset, sums, sig, keys); err != nil {
		return err
	}

	// Staged next to the data, never over the installed binary.
	dir := filepath.Join(Dir(m.o.DataDir), rel.Version)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	path := filepath.Join(dir, "skyguard")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, bin, 0o755); err != nil {
		return fmt.Errorf("writing the new binary: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}

	// It must run on this machine and accept the config as it is.
	m.setPhase("testing")
	out, err := run(ctx, path, "-version")
	if err != nil || !strings.Contains(out, rel.Version) {
		return fmt.Errorf("the new binary does not run here (%v): %s", err, strings.TrimSpace(out))
	}
	if out, err := run(ctx, path, "-check-config", "-config", m.o.ConfigPath); err != nil {
		return fmt.Errorf("SkyGuard %s does not accept the current config: %s", rel.Version, lastLine(out))
	}

	m.setPhase("backing-up")
	if err := m.backup(rel.Version); err != nil {
		return err
	}

	st, err := LoadState(m.o.DataDir)
	if err != nil {
		return err
	}
	prev := st.Previous
	if st.Current != nil && st.Current.Good {
		prev = st.Current
	} else if st.Current == nil {
		prev = nil // going back means the installed binary
	}
	st.Previous = prev
	st.Current = &Slot{Version: rel.Version, Path: path, AppliedAt: time.Now().UTC()}
	st.Failure = nil
	st.record(Event{From: m.o.Build.Version, To: rel.Version, Result: "applied"})
	if err := st.Save(m.o.DataDir); err != nil {
		return fmt.Errorf("saving the update state: %w", err)
	}
	m.prune(st)
	return nil
}

// backup copies the database and the config into <data_dir>/backups,
// keeping the last three of each.
func (m *Manager) backup(to string) error {
	dir := filepath.Join(m.o.DataDir, "backups")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	if m.o.DBSize != nil {
		var fs syscall.Statfs_t
		if err := syscall.Statfs(dir, &fs); err == nil {
			free := int64(fs.Bavail) * int64(fs.Bsize)
			if need := m.o.DBSize()*12/10 + 64<<20; free < need {
				return fmt.Errorf("not enough free space for a database backup: %d MB free, %d MB needed", free>>20, need>>20)
			}
		}
	}
	stamp := time.Now().UTC().Format("20060102-150405")
	base := fmt.Sprintf("pre-update-%s-to-%s-%s", safe(m.o.Build.Version), safe(to), stamp)
	if m.o.Backup != nil {
		if err := m.o.Backup(filepath.Join(dir, base+".db")); err != nil {
			return fmt.Errorf("backing up the database: %w", err)
		}
	}
	if b, err := os.ReadFile(m.o.ConfigPath); err == nil {
		if err := os.WriteFile(filepath.Join(dir, base+".yaml"), b, 0o600); err != nil {
			return fmt.Errorf("backing up the config: %w", err)
		}
	}
	// keep the newest three sets
	sets := m.backupSets()
	for i := 0; i < len(sets)-3; i++ {
		for _, ext := range []string{".db", ".yaml"} {
			_ = os.Remove(filepath.Join(dir, sets[i]+ext))
		}
	}
	return nil
}

func (m *Manager) backupSets() []string {
	files, _ := filepath.Glob(filepath.Join(m.o.DataDir, "backups", "pre-update-*.db"))
	var out []string
	for _, f := range files {
		out = append(out, strings.TrimSuffix(filepath.Base(f), ".db"))
	}
	// the stamp sorts last; names share their prefix
	sort.Slice(out, func(i, j int) bool { return out[i][len(out[i])-15:] < out[j][len(out[j])-15:] })
	return out
}

func (m *Manager) backups() []string {
	out := []string{}
	for _, s := range m.backupSets() {
		out = append(out, filepath.Join(m.o.DataDir, "backups", s+".db"))
	}
	return out
}

// prune removes staged versions that are neither current nor previous.
func (m *Manager) prune(st *State) {
	keep := map[string]bool{}
	for _, s := range []*Slot{st.Current, st.Previous} {
		if s != nil {
			keep[s.Version] = true
		}
	}
	dirs, _ := os.ReadDir(Dir(m.o.DataDir))
	for _, d := range dirs {
		if d.IsDir() && IsRelease(d.Name()) && !keep[d.Name()] {
			_ = os.RemoveAll(filepath.Join(Dir(m.o.DataDir), d.Name()))
		}
	}
}

// Rollback goes back to the previous version (or the installed one) and
// restarts.
func (m *Manager) Rollback() error {
	m.mu.Lock()
	if p := m.status.Phase; p != "idle" && p != "failed" {
		m.mu.Unlock()
		return fmt.Errorf("an update is %s", p)
	}
	m.mu.Unlock()
	if m.o.Precheck != nil {
		if err := m.o.Precheck(); err != nil {
			return err
		}
	}
	st, err := LoadState(m.o.DataDir)
	if err != nil {
		return err
	}
	if st.Current == nil {
		return errors.New("the installed version is running: there is nothing to go back from")
	}
	from := st.Current.Version
	to := "installed"
	if st.Previous != nil {
		to = st.Previous.Version
	}
	st.Current, st.Previous = st.Previous, nil
	st.record(Event{From: from, To: to, Result: "rolled-back", Reason: "asked for in the dashboard"})
	if err := st.Save(m.o.DataDir); err != nil {
		return err
	}
	m.mu.Lock()
	now := time.Now().UTC()
	m.status = Status{Phase: "restarting", Version: to, Started: &now}
	m.mu.Unlock()
	go func() {
		time.Sleep(500 * time.Millisecond)
		m.o.Restart()
	}()
	return nil
}

func run(ctx context.Context, bin string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = append(os.Environ(), EnvBase+"=test") // never hand over from a test run
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	l := lines[len(lines)-1]
	if len(l) > 400 {
		l = l[:400]
	}
	return l
}

func safe(v string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' {
			return r
		}
		return '_'
	}, v)
}
