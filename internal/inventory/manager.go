package inventory

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/skyguard/skyguard/internal/containers"
)

// Store keeps scans and the OSV cache (storage.DB).
type Store interface {
	Inventory() (map[string]string, error)
	SaveInventory(key, data string) error
	DeleteInventory(key string) error
	InventoryOSV() bool
	SetInventoryOSV(on bool) error
	VulnCache
}

// TargetTimeout bounds one target's scan; a file system inside it that
// does not answer (a FUSE mount, say) cannot hold the scanner up longer.
var TargetTimeout = 90 * time.Second

// ScanEvery is how often everything is scanned again.
const ScanEvery = 24 * time.Hour

// Options wires the manager.
type Options struct {
	Store Store
	// Containers is nil when container management is off: then only the
	// host is scanned.
	Containers *containers.Manager
	// HostRoot is where the host's files are ("/" natively; from a
	// container, a read-only mount at /host or /proc/1/root); "" when they
	// cannot be seen, with HostReason saying why.
	HostRoot, HostReason string
	OSVAPI               string
	Logger               *slog.Logger
}

// Status is a scan or check in progress.
type Status struct {
	Phase   string     `json:"phase"` // idle, scanning, checking
	Done    int        `json:"done"`
	Total   int        `json:"total"`
	Current string     `json:"current,omitempty"`
	Error   string     `json:"error,omitempty"`
	Started *time.Time `json:"started,omitempty"`
}

// Manager scans targets and keeps the results.
type Manager struct {
	o   Options
	osv *OSV

	mu      sync.Mutex
	targets map[string]*Target
	status  Status
	stuck   int // scans abandoned on timeout whose goroutine may still be blocked
}

// NewManager loads the stored results.
func NewManager(o Options) *Manager {
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.OSVAPI == "" {
		o.OSVAPI = "https://api.osv.dev"
	}
	m := &Manager{o: o, targets: map[string]*Target{}, status: Status{Phase: "idle"},
		osv: &OSV{API: o.OSVAPI, Cache: o.Store}}
	if stored, err := o.Store.Inventory(); err == nil {
		for k, js := range stored {
			var t Target
			if json.Unmarshal([]byte(js), &t) == nil {
				m.targets[k] = &t
			}
		}
	}
	return m
}

// Run scans a few minutes after start when the results are older than a
// day, and every day after that; with OSV.dev on, it checks after each scan.
func (m *Manager) Run(ctx context.Context) {
	first := 3 * time.Minute
	if newest := m.newest(); !newest.IsZero() {
		if wait := time.Until(newest.Add(ScanEvery)); wait > first {
			first = wait
		}
	}
	t := time.NewTimer(first)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := m.Scan(); err != nil {
				m.o.Logger.Info("scheduled software scan skipped", "reason", err)
			}
			t.Reset(ScanEvery)
		}
	}
}

func (m *Manager) newest() time.Time {
	m.mu.Lock()
	defer m.mu.Unlock()
	var n time.Time
	for _, t := range m.targets {
		if t.ScannedAt.After(n) {
			n = t.ScannedAt
		}
	}
	return n
}

// OSVEnabled reports whether versions may be sent to OSV.dev.
func (m *Manager) OSVEnabled() bool { return m.o.Store.InventoryOSV() }

// SetOSV switches the OSV.dev check.
func (m *Manager) SetOSV(on bool) error { return m.o.Store.SetInventoryOSV(on) }

func (m *Manager) begin(phase string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.status.Phase != "idle" {
		return fmt.Errorf("SkyGuard is already %s", m.status.Phase)
	}
	if m.stuck >= 3 {
		return errors.New("earlier scans are stuck on file systems that do not answer; restart SkyGuard to scan again")
	}
	now := time.Now().UTC()
	m.status = Status{Phase: phase, Started: &now}
	return nil
}

func (m *Manager) end(err error) {
	m.mu.Lock()
	m.status = Status{Phase: "idle"}
	if err != nil {
		m.status.Error = err.Error()
	}
	m.mu.Unlock()
}

// Scan reads every target again, in the background.
func (m *Manager) Scan() error {
	if err := m.begin("scanning"); err != nil {
		return err
	}
	go func() {
		err := m.scanAll()
		if err == nil && m.OSVEnabled() {
			m.mu.Lock()
			m.status.Phase = "checking"
			m.mu.Unlock()
			err = m.check()
		}
		m.end(err)
	}()
	return nil
}

// Check compares what was found with OSV.dev, in the background.
func (m *Manager) Check() error {
	if !m.OSVEnabled() {
		return errors.New("checking against OSV.dev is off; switch it on first")
	}
	if err := m.begin("checking"); err != nil {
		return err
	}
	go func() { m.end(m.check()) }()
	return nil
}

type job struct {
	meta Meta
	fs   func() (FS, error)
	note string // why it is not scanned, instead of fs
}

func (m *Manager) jobs(ctx context.Context) []job {
	var out []job
	if m.o.HostRoot != "" {
		root := m.o.HostRoot
		out = append(out, job{meta: Meta{Key: "host", Kind: "host", Name: hostname(), Running: true, Host: true},
			fs: func() (FS, error) { return OpenRoot(root, "read from the server's files") }})
	} else {
		out = append(out, job{meta: Meta{Key: "host", Kind: "host", Name: hostname(), Running: true}, note: m.o.HostReason})
	}
	if m.o.Containers == nil || !m.o.Containers.AnyEnabled() {
		return out
	}
	infos, errs := m.o.Containers.ScanInfos(ctx)
	for _, e := range errs {
		m.o.Logger.Warn("software scan: listing containers", "error", e)
	}
	for _, si := range infos {
		si := si
		meta := Meta{Key: si.Engine + ":" + si.ID, Kind: si.Engine, Name: si.Name, Image: si.Image, Running: si.Running,
			WorkingDir: si.WorkingDir, Command: si.Command, Env: si.Env, Labels: si.Labels}
		j := job{meta: meta}
		switch {
		case si.Kind == "virtual-machine":
			j.note = "a virtual machine has its own disk and kernel: SkyGuard does not read inside it"
		case si.Running && si.PID > 0 && procVisible(si.PID):
			j.fs = func() (FS, error) { return containerRoot(si) }
		case si.Engine == "docker":
			j.fs = func() (FS, error) { return &apiFS{ctr: m.o.Containers, engine: si.Engine, id: si.ID}, nil }
		case !si.Running:
			j.note = "stopped: start it to see what is inside"
		default:
			j.note = "SkyGuard cannot see this instance's processes (in Docker it needs pid: host)"
		}
		out = append(out, j)
	}
	return out
}

func procVisible(pid int) bool {
	_, err := os.Stat("/proc/" + strconv.Itoa(pid) + "/root")
	return err == nil
}

// containerRoot opens a running container's root through its first
// process, and checks afterwards that the process still belongs to that
// container: the root descriptor is then bound to it, whatever happens to
// the PID later.
func containerRoot(si containers.ScanInfo) (FS, error) {
	dir := "/proc/" + strconv.Itoa(si.PID) + "/root"
	r, err := OpenRoot(dir, "read from its file system, inside its own root")
	if err != nil {
		return nil, err
	}
	cg, err := os.ReadFile("/proc/" + strconv.Itoa(si.PID) + "/cgroup")
	ok := err == nil && (si.Engine == "docker" && bytes.Contains(cg, []byte(si.ID)) ||
		si.Engine == "incus" && (bytes.Contains(cg, []byte("lxc.payload."+si.Name)) || bytes.Contains(cg, []byte("/lxc/"+si.Name))))
	if !ok {
		r.Close()
		return nil, errors.New("its process changed while it was being opened; scanned again next time")
	}
	return r, nil
}

func (m *Manager) scanAll() error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
	defer cancel()
	jobs := m.jobs(ctx)
	m.mu.Lock()
	m.status.Total = len(jobs)
	m.mu.Unlock()
	present := map[string]bool{}
	for i, j := range jobs {
		present[j.meta.Key] = true
		m.mu.Lock()
		m.status.Done, m.status.Current = i, j.meta.Name
		m.mu.Unlock()
		t := m.scanOne(ctx, j)
		// a target that could not be read this time keeps what was found before
		m.mu.Lock()
		if old := m.targets[t.Key]; old != nil && len(t.Packages) == 0 && t.Error != "" {
			t.Packages, t.Apps, t.OS = old.Packages, old.Apps, old.OS
		}
		m.targets[t.Key] = t
		m.mu.Unlock()
		m.save(t)
	}
	m.mu.Lock()
	for k := range m.targets {
		if !present[k] {
			delete(m.targets, k)
			_ = m.o.Store.DeleteInventory(k)
		}
	}
	m.status.Done = len(jobs)
	m.mu.Unlock()
	m.o.Logger.Info("software scan finished", "targets", len(jobs))
	return nil
}

func (m *Manager) scanOne(ctx context.Context, j job) *Target {
	empty := func(msg string) *Target {
		return &Target{Key: j.meta.Key, Kind: j.meta.Kind, Name: clean(j.meta.Name), Image: clean(j.meta.Image), Running: j.meta.Running,
			Apps: []App{}, Packages: []Package{}, Findings: []Finding{}, Error: msg, ScannedAt: time.Now().UTC()}
	}
	if j.fs == nil {
		return empty(j.note)
	}
	done := make(chan *Target, 1)
	tctx, cancel := context.WithTimeout(ctx, TargetTimeout)
	defer cancel()
	go func() {
		fs, err := j.fs()
		if err != nil {
			done <- empty(err.Error())
			return
		}
		defer fs.Close()
		done <- Scan(tctx, fs, j.meta)
	}()
	select {
	case t := <-done:
		return t
	case <-time.After(TargetTimeout + 5*time.Second):
		// a read is blocked in the kernel; the goroutine is left behind
		m.mu.Lock()
		m.stuck++
		m.mu.Unlock()
		m.o.Logger.Warn("software scan: a target did not answer and was abandoned", "target", j.meta.Name)
		return empty(fmt.Sprintf("did not finish in %s: a file system inside it does not answer", TargetTimeout))
	}
}

func (m *Manager) save(t *Target) {
	b, err := json.Marshal(t)
	if err == nil {
		err = m.o.Store.SaveInventory(t.Key, string(b))
	}
	if err != nil {
		m.o.Logger.Error("saving a software scan", "target", t.Name, "error", err)
	}
}

func (m *Manager) check() error {
	m.mu.Lock()
	var all []Package
	targets := make([]*Target, 0, len(m.targets))
	for _, t := range m.targets {
		all = append(all, t.Packages...)
		targets = append(targets, t)
	}
	m.status.Total = len(all)
	m.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	res, err := m.osv.Check(ctx, all)
	if err != nil {
		m.o.Logger.Warn("OSV.dev check failed", "error", err)
		return err
	}
	now := time.Now().UTC()
	m.mu.Lock()
	for _, t := range targets {
		t.Findings = []Finding{}
		seen := map[string]bool{}
		for _, p := range t.Packages {
			for _, f := range res[pkgKey{p.Ecosystem, p.Name, p.Version}] {
				if k := f.ID + "|" + p.Name; !seen[k] {
					seen[k] = true
					t.Findings = append(t.Findings, f)
				}
			}
		}
		sort.SliceStable(t.Findings, func(i, j int) bool {
			return sevRank(t.Findings[i].Severity) < sevRank(t.Findings[j].Severity)
		})
		t.VulnCheckedAt = &now
	}
	m.mu.Unlock()
	for _, t := range targets {
		m.save(t)
	}
	m.o.Logger.Info("OSV.dev check finished", "packages", len(all))
	return nil
}

func sevRank(s string) int {
	switch s {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	}
	return 4
}

// Summary is one target in the overview.
type Summary struct {
	Key           string         `json:"key"`
	Kind          string         `json:"kind"`
	Name          string         `json:"name"`
	Image         string         `json:"image,omitempty"`
	Running       bool           `json:"running"`
	Via           string         `json:"via,omitempty"`
	OS            *OSInfo        `json:"os,omitempty"`
	Apps          []App          `json:"apps"`
	Packages      int            `json:"packages"`
	Checkable     int            `json:"checkable"` // packages OSV.dev has advisories for
	Severity      map[string]int `json:"severity"`
	Fixable       int            `json:"fixable"`
	ScannedAt     time.Time      `json:"scanned_at"`
	VulnCheckedAt *time.Time     `json:"vuln_checked_at,omitempty"`
	Error         string         `json:"error,omitempty"`
	Notes         []string       `json:"notes,omitempty"`
}

// View is the overview.
type View struct {
	Targets    []Summary `json:"targets"`
	Status     Status    `json:"status"`
	OSV        bool      `json:"osv"`
	HostReason string    `json:"host_reason,omitempty"`
	Containers bool      `json:"containers"` // container management is on, so containers are scanned
}

// View reports every target, without the package lists.
func (m *Manager) View() View {
	v := View{OSV: m.OSVEnabled(), HostReason: m.o.HostReason, Targets: []Summary{},
		Containers: m.o.Containers != nil && m.o.Containers.AnyEnabled()}
	m.mu.Lock()
	defer m.mu.Unlock()
	v.Status = m.status
	for _, t := range m.targets {
		s := Summary{Key: t.Key, Kind: t.Kind, Name: t.Name, Image: t.Image, Running: t.Running, Via: t.Via, OS: t.OS,
			Apps: t.Apps, Packages: len(t.Packages), Severity: map[string]int{}, ScannedAt: t.ScannedAt,
			VulnCheckedAt: t.VulnCheckedAt, Error: t.Error, Notes: t.Notes}
		if len(s.Apps) > 40 {
			s.Apps = s.Apps[:40]
		}
		for _, p := range t.Packages {
			if p.Ecosystem != "" {
				s.Checkable++
			}
		}
		for _, f := range t.Findings {
			s.Severity[f.Severity]++
			if f.Fixed != "" {
				s.Fixable++
			}
		}
		v.Targets = append(v.Targets, s)
	}
	sort.Slice(v.Targets, func(i, j int) bool {
		a, b := v.Targets[i], v.Targets[j]
		if (a.Kind == "host") != (b.Kind == "host") {
			return a.Kind == "host"
		}
		if wa, wb := weight(a.Severity), weight(b.Severity); wa != wb {
			return wa > wb
		}
		return a.Name < b.Name
	})
	return v
}

func weight(s map[string]int) int {
	return s["critical"]*1000000 + s["high"]*1000 + s["medium"]
}

// Target returns one target in full.
func (m *Manager) Target(key string) (*Target, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.targets[key]
	if !ok {
		return nil, false
	}
	c := *t
	return &c, true
}

func hostname() string {
	h, _ := os.Hostname()
	if h == "" {
		return "this server"
	}
	return h
}

// apiFS reads a Docker container's files through the Docker API, for
// containers that are stopped or whose processes SkyGuard cannot see.
type apiFS struct {
	ctr        *containers.Manager
	engine, id string
}

func (a *apiFS) ReadFile(p string, max int64) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	b, err := a.ctr.ReadFile(ctx, a.engine, a.id, p, max)
	switch {
	case containers.IsNotFound(err):
		return nil, os.ErrNotExist
	case errors.Is(err, containers.ErrNotRegular):
		return nil, ErrNotRegular
	}
	return b, err
}

func (a *apiFS) ReadDir(string, int) ([]string, error) { return nil, ErrUnsupported }

func (a *apiFS) OpenFile(p string, max int64) (File, error) {
	if max > 30<<20 {
		max = 30 << 20
	}
	b, err := a.ReadFile(p, max)
	if err != nil {
		return nil, err
	}
	return memFile{bytes.NewReader(b)}, nil
}

func (a *apiFS) Via() string  { return "read through the Docker API" }
func (a *apiFS) Close() error { return nil }

type memFile struct{ *bytes.Reader }

func (memFile) Close() error { return nil }
