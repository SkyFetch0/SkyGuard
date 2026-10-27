package containers

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Reserved is a host port SkyGuard itself listens on (or tried to).
type Reserved struct {
	Port   int
	Proto  string
	Owner  string // "honeypot fake-http"
	Failed string // why the listener could not start, if it could not
}

// Manager puts the configured engines behind one API and makes every change
// go through the same checks: read-only mode, SkyGuard's own container, port
// conflicts. Changes run one at a time.
type Manager struct {
	engines  []Engine
	readOnly bool
	logger   *slog.Logger

	// Reserved lists the host ports SkyGuard listens on; set by the server.
	Reserved func() []Reserved

	mu sync.Mutex
}

// NewManager returns a manager for the given engines.
func NewManager(engines []Engine, readOnly bool, logger *slog.Logger) *Manager {
	return &Manager{engines: engines, readOnly: readOnly, logger: logger}
}

// EngineStatus says whether an engine answered.
type EngineStatus struct {
	Name      string   `json:"name"`
	Available bool     `json:"available"`
	Version   string   `json:"version,omitempty"`
	Error     string   `json:"error,omitempty"`
	Restart   []string `json:"restart_policies"`
}

// Snapshot is every engine's containers and networks at one moment.
type Snapshot struct {
	Engines    []EngineStatus `json:"engines"`
	Containers []Container    `json:"containers"`
	Networks   []Network      `json:"networks"`
	ReadOnly   bool           `json:"read_only"`
}

// Snapshot queries the engines in parallel. An engine that does not answer
// is reported as unavailable; the others are still listed.
func (m *Manager) Snapshot(ctx context.Context) Snapshot {
	type result struct {
		st    EngineStatus
		cs    []Container
		ns    []Network
		index int
	}
	results := make([]result, len(m.engines))
	var wg sync.WaitGroup
	for i, e := range m.engines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
			defer cancel()
			r := result{st: EngineStatus{Name: e.Name(), Restart: e.RestartPolicies()}, index: i}
			v, err := e.Version(ctx)
			if err == nil {
				r.cs, r.ns, err = e.List(ctx)
			}
			if err != nil {
				r.st.Error = friendlyError(e.Name(), err)
			} else {
				r.st.Available, r.st.Version = true, v
			}
			results[i] = r
		}()
	}
	wg.Wait()
	snap := Snapshot{ReadOnly: m.readOnly, Engines: []EngineStatus{}, Containers: []Container{}, Networks: []Network{}}
	for _, r := range results {
		snap.Engines = append(snap.Engines, r.st)
		for i := range r.cs {
			r.cs[i].fill()
		}
		snap.Containers = append(snap.Containers, r.cs...)
		snap.Networks = append(snap.Networks, r.ns...)
	}
	return snap
}

// fill replaces nil lists with empty ones, so clients get [] and not null.
func (c *Container) fill() {
	if c.Ports == nil {
		c.Ports = []Port{}
	}
	if c.Networks == nil {
		c.Networks = []Endpoint{}
	}
	if c.Exposed == nil {
		c.Exposed = []string{}
	}
	if c.Mounts == nil {
		c.Mounts = []string{}
	}
	for i := range c.Networks {
		if c.Networks[i].Aliases == nil {
			c.Networks[i].Aliases = []string{}
		}
	}
}

// friendlyError turns a missing or unreadable socket into a sentence that
// says what to do about it.
func friendlyError(engine string, err error) string {
	switch {
	case errors.Is(err, syscall.ENOENT):
		return fmt.Sprintf("the %s socket does not exist: is %s installed and running, and is its socket mounted into SkyGuard's container?", engine, engine)
	case errors.Is(err, syscall.EACCES), errors.Is(err, syscall.EPERM):
		return fmt.Sprintf("permission denied on the %s socket: SkyGuard must run as root", engine)
	case errors.Is(err, syscall.ECONNREFUSED):
		return fmt.Sprintf("%s is not running (connection refused on its socket)", engine)
	}
	return err.Error()
}

func (m *Manager) engine(name string) (Engine, error) {
	for _, e := range m.engines {
		if e.Name() == name {
			return e, nil
		}
	}
	return nil, fmt.Errorf("container engine %q is not enabled", name)
}

// Inspect returns one container with its full settings.
func (m *Manager) Inspect(ctx context.Context, engine, id string) (*Container, error) {
	e, err := m.engine(engine)
	if err != nil {
		return nil, err
	}
	c, err := e.Inspect(ctx, id)
	if err != nil {
		return nil, err
	}
	c.fill()
	return c, nil
}

// change runs fn for an existing container after the common checks and
// returns the container as it is afterwards. That is looked up by name: a
// Docker container that had to be recreated has a new ID.
func (m *Manager) change(ctx context.Context, engine, id, what string, fn func(Engine, *Container) error) (*Container, error) {
	if m.readOnly {
		return nil, ErrReadOnly
	}
	e, err := m.engine(engine)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	c, err := e.Inspect(ctx, id)
	if err != nil {
		return nil, err
	}
	if err := fn(e, c); err != nil {
		m.logger.Warn("container change failed", "engine", engine, "container", c.Name, "change", what, "error", err)
		return nil, err
	}
	m.logger.Info("container changed from the dashboard", "engine", engine, "container", c.Name, "change", what)
	if after, err := e.Inspect(ctx, c.Name); err == nil {
		c = after
	}
	c.fill()
	return c, nil
}

// Action starts, stops or restarts a container.
func (m *Manager) Action(ctx context.Context, engine, id, action string) (*Container, error) {
	if !slices.Contains(Actions, action) {
		return nil, fmt.Errorf("unknown action %q", action)
	}
	return m.change(ctx, engine, id, action, func(e Engine, c *Container) error {
		if c.Self && action != "start" {
			return ErrSelf
		}
		return e.Action(ctx, c.ID, action)
	})
}

// Connect joins a container to a network. With create set, the network is
// created first (a new bridge).
func (m *Manager) Connect(ctx context.Context, engine, id, network string, create bool) (*Container, error) {
	if !ValidName(network) {
		return nil, fmt.Errorf("%q is not a valid network name", network)
	}
	return m.change(ctx, engine, id, "connect "+network, func(e Engine, c *Container) error {
		if c.NetworkMode != "" {
			return fmt.Errorf("%s uses network mode %s and cannot join other networks", c.Name, c.NetworkMode)
		}
		if create {
			if err := e.CreateNetwork(ctx, network); err != nil {
				return fmt.Errorf("creating network %s: %w", network, err)
			}
		}
		return e.Connect(ctx, c.ID, network)
	})
}

// Disconnect takes a container off a network.
func (m *Manager) Disconnect(ctx context.Context, engine, id, network string) (*Container, error) {
	return m.change(ctx, engine, id, "disconnect "+network, func(e Engine, c *Container) error {
		if c.Self {
			return ErrSelf
		}
		return e.Disconnect(ctx, c.ID, network)
	})
}

// CreateNetwork adds an empty bridge network.
func (m *Manager) CreateNetwork(ctx context.Context, engine, name string) error {
	if m.readOnly {
		return ErrReadOnly
	}
	if !ValidName(name) {
		return fmt.Errorf("%q is not a valid network name (letters, digits, . _ -)", name)
	}
	e, err := m.engine(engine)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := e.CreateNetwork(ctx, name); err != nil {
		return err
	}
	m.logger.Info("network created from the dashboard", "engine", engine, "network", name)
	return nil
}

// Update changes restart policy and resource limits in place.
func (m *Manager) Update(ctx context.Context, engine, id string, s Settings) (*Container, error) {
	return m.change(ctx, engine, id, "settings", func(e Engine, c *Container) error {
		return e.Update(ctx, c.ID, s)
	})
}

// SetPorts replaces a container's published ports after checking that no
// other container, SkyGuard listener or host program already has them.
func (m *Manager) SetPorts(ctx context.Context, engine, id string, ports []Port) (*Container, error) {
	return m.change(ctx, engine, id, "ports", func(e Engine, c *Container) error {
		if c.Self {
			return ErrSelf
		}
		if err := m.checkPorts(ctx, c, ports); err != nil {
			return err
		}
		return e.SetPorts(ctx, c.ID, ports)
	})
}

// overlaps reports whether two host addresses can collide ("" is every address).
func overlaps(a, b string) bool { return a == "" || b == "" || a == b }

func (m *Manager) checkPorts(ctx context.Context, c *Container, ports []Port) error {
	mine := map[string]bool{}
	for _, p := range c.Ports {
		mine[fmt.Sprintf("%d/%s", p.HostPort, p.Proto)] = true
	}
	var others []Container
	for _, e := range m.engines {
		cs, _, err := e.List(ctx)
		if err != nil {
			continue
		}
		others = append(others, cs...)
	}
	var reserved []Reserved
	if m.Reserved != nil {
		reserved = m.Reserved()
	}
	for _, p := range ports {
		if p.HostPort == 0 {
			continue
		}
		for _, r := range reserved {
			if r.Port == p.HostPort && r.Proto == p.Proto && r.Failed == "" {
				return fmt.Errorf("host port %d/%s is used by SkyGuard's %s; switch it off or move it first", p.HostPort, p.Proto, r.Owner)
			}
		}
		for _, o := range others {
			if o.Engine == c.Engine && o.ID == c.ID {
				continue
			}
			for _, op := range o.Ports {
				if op.HostPort == p.HostPort && op.Proto == p.Proto && overlaps(op.HostIP, p.HostIP) && o.Running {
					return fmt.Errorf("host port %d/%s is already published by %s container %s", p.HostPort, p.Proto, o.Engine, o.Name)
				}
			}
		}
		if !mine[fmt.Sprintf("%d/%s", p.HostPort, p.Proto)] {
			if err := probePort(p); err != nil {
				return err
			}
		}
	}
	return nil
}

// probePort tries to bind the port briefly: a program on the host that is
// not a container (an nginx, an sshd) shows up here. When SkyGuard does not
// share the host's network namespace this sees only its own, which is harmless.
func probePort(p Port) error {
	addr := net.JoinHostPort(p.HostIP, fmt.Sprint(p.HostPort))
	var err error
	if p.Proto == "udp" {
		var pc net.PacketConn
		if pc, err = net.ListenPacket("udp", addr); err == nil {
			pc.Close()
		}
	} else {
		var ln net.Listener
		if ln, err = net.Listen("tcp", addr); err == nil {
			ln.Close()
		}
	}
	if errors.Is(err, syscall.EADDRINUSE) {
		return fmt.Errorf("host port %d/%s is already in use by a program on the host", p.HostPort, p.Proto)
	}
	return nil // permission problems and unknown addresses are left to the engine
}

// PortOwner is one claimant of a host port.
type PortOwner struct {
	Kind    string `json:"kind"` // skyguard, docker, incus
	Name    string `json:"name"`
	ID      string `json:"id,omitempty"`
	HostIP  string `json:"host_ip,omitempty"`
	Target  string `json:"target,omitempty"` // container port
	Running bool   `json:"running"`
	Failed  string `json:"failed,omitempty"`
}

// PortUse is everything that claims one host port.
type PortUse struct {
	Port     int         `json:"port"`
	Proto    string      `json:"proto"`
	Owners   []PortOwner `json:"owners"`
	Conflict bool        `json:"conflict"`
}

// HostPorts lists every host port a container publishes or SkyGuard
// listens on, conflicts first. A SkyGuard listener that failed because a
// container holds its port counts as a conflict: it is the usual way a
// honeypot on 80 meets a reverse proxy on 80.
func HostPorts(snap Snapshot, reserved []Reserved) []PortUse {
	byKey := map[string]*PortUse{}
	get := func(port int, proto string) *PortUse {
		k := fmt.Sprintf("%d/%s", port, proto)
		if byKey[k] == nil {
			byKey[k] = &PortUse{Port: port, Proto: proto}
		}
		return byKey[k]
	}
	for _, r := range reserved {
		u := get(r.Port, r.Proto)
		u.Owners = append(u.Owners, PortOwner{Kind: "skyguard", Name: r.Owner, Running: r.Failed == "", Failed: r.Failed})
	}
	for _, c := range snap.Containers {
		for _, p := range c.Ports {
			if p.HostPort == 0 {
				continue
			}
			u := get(p.HostPort, p.Proto)
			u.Owners = append(u.Owners, PortOwner{Kind: c.Engine, Name: c.Name, ID: c.ID, HostIP: p.HostIP, Target: fmt.Sprint(p.ContainerPort), Running: c.Running})
		}
	}
	out := make([]PortUse, 0, len(byKey))
	for _, u := range byKey {
		for i := range u.Owners {
			for j := i + 1; j < len(u.Owners); j++ {
				a, b := u.Owners[i], u.Owners[j]
				if overlaps(a.HostIP, b.HostIP) && (a.Running || a.Failed != "") && (b.Running || b.Failed != "") {
					u.Conflict = true
				}
			}
		}
		sort.SliceStable(u.Owners, func(i, j int) bool { return u.Owners[i].Kind == "skyguard" && u.Owners[j].Kind != "skyguard" })
		out = append(out, *u)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Conflict != out[j].Conflict {
			return out[i].Conflict
		}
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		return strings.Compare(out[i].Proto, out[j].Proto) < 0
	})
	return out
}
