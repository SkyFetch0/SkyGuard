// Package containers lets the dashboard see and manage the containers that
// run next to SkyGuard: Docker (Engine API over /var/run/docker.sock) and
// Incus (REST API over /var/lib/incus/unix.socket). Both APIs are spoken
// directly over the unix socket, so no CLI has to be installed.
//
// Access to either socket is equivalent to root on the host, which is why the
// feature is off unless the config file enables it.
package containers

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Port is one published port: HostPort on the host forwards to ContainerPort.
type Port struct {
	HostIP        string `json:"host_ip,omitempty"` // "" = every address
	HostPort      int    `json:"host_port"`         // 0 = a random free port
	ContainerPort int    `json:"container_port"`
	Proto         string `json:"proto"`            // tcp or udp
	Device        string `json:"device,omitempty"` // Incus proxy device that holds it
	Inherited     bool   `json:"inherited,omitempty"`
}

// String formats the port the way `docker run -p` takes it.
func (p Port) String() string {
	s := fmt.Sprintf("%d:%d/%s", p.HostPort, p.ContainerPort, p.Proto)
	if p.HostIP != "" {
		host := p.HostIP
		if strings.Contains(host, ":") {
			host = "[" + host + "]"
		}
		s = host + ":" + s
	}
	return s
}

// Endpoint is a container's membership of one network.
type Endpoint struct {
	Network string   `json:"network"`
	IP      string   `json:"ip,omitempty"`
	Aliases []string `json:"aliases,omitempty"`
	Device  string   `json:"device,omitempty"` // Incus nic device
}

// Container is one Docker container or Incus instance.
type Container struct {
	Engine      string     `json:"engine"`
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Image       string     `json:"image"`
	Kind        string     `json:"kind"`  // container or virtual-machine
	State       string     `json:"state"` // running, exited, paused, created, restarting, stopped, frozen…
	Running     bool       `json:"running"`
	Status      string     `json:"status"`
	Created     time.Time  `json:"created"`
	Ports       []Port     `json:"ports"`
	Exposed     []string   `json:"exposed,omitempty"` // ports the image declares, e.g. "80/tcp"
	Networks    []Endpoint `json:"networks"`
	NetworkMode string     `json:"network_mode,omitempty"` // Docker: host, none, container:<id>
	Project     string     `json:"project,omitempty"`      // Docker Compose project
	Self        bool       `json:"self,omitempty"`         // SkyGuard's own container

	// Filled in by Inspect only.
	Restart        string   `json:"restart,omitempty"`
	ComposeService string   `json:"compose_service,omitempty"`
	ComposeFiles   []string `json:"compose_files,omitempty"` // as Compose recorded them, on the host
	MemoryMB       int64    `json:"memory_mb"`               // 0 = no limit
	CPUs           float64  `json:"cpus"`                    // 0 = no limit
	Mounts         []string `json:"mounts,omitempty"`
	EnvCount       int      `json:"env_count,omitempty"`
}

// Network is a Docker network or an Incus network.
type Network struct {
	Engine     string   `json:"engine"`
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Driver     string   `json:"driver"`
	Subnet     string   `json:"subnet,omitempty"`
	Internal   bool     `json:"internal,omitempty"`
	Builtin    bool     `json:"builtin,omitempty"` // Docker's default bridge
	Attachable bool     `json:"attachable"`        // containers can be connected from the dashboard
	Members    []string `json:"members"`           // container IDs
}

// Settings are the properties that change without recreating a container.
// A nil field is left as it is.
type Settings struct {
	Restart  *string
	MemoryMB *int64
	CPUs     *float64
}

// Engine is one container runtime.
type Engine interface {
	Name() string
	Version(ctx context.Context) (string, error)
	List(ctx context.Context) ([]Container, []Network, error)
	Inspect(ctx context.Context, id string) (*Container, error)
	Action(ctx context.Context, id, action string) error
	Connect(ctx context.Context, id, network string) error
	Disconnect(ctx context.Context, id, network string) error
	CreateNetwork(ctx context.Context, name string) error
	SetPorts(ctx context.Context, id string, ports []Port) error
	Update(ctx context.Context, id string, s Settings) error
	RestartPolicies() []string

	Create(ctx context.Context, spec CreateSpec) (string, error)
	Remove(ctx context.Context, id string, volumes bool) error
	Logs(ctx context.Context, id string, lines int) (string, error)
	DeleteNetwork(ctx context.Context, name string) error
}

// Snapshotter is implemented by engines that keep instance snapshots (Incus).
type Snapshotter interface {
	Snapshots(ctx context.Context, id string) ([]InstanceSnapshot, error)
	TakeSnapshot(ctx context.Context, id, name string) error
	RestoreSnapshot(ctx context.Context, id, name string) error
	DeleteSnapshot(ctx context.Context, id, name string) error
}

// InstanceSnapshot is one saved state of an instance.
type InstanceSnapshot struct {
	Name     string    `json:"name"`
	Created  time.Time `json:"created"`
	Stateful bool      `json:"stateful,omitempty"`
}

// CreateSpec describes a new container or instance.
type CreateSpec struct {
	Name     string
	Image    string // Docker: nginx:alpine; Incus: images:debian/12 or a local alias
	Ports    []Port
	Network  string   // optional: the network it starts on
	Env      []string // Docker only: KEY=value
	Restart  string
	MemoryMB int64
	CPUs     float64
	VM       bool // Incus: a virtual machine instead of a container
	Start    bool
}

// Actions every engine supports. Pause freezes the processes in place
// (Docker pause, Incus freeze); resume thaws them.
var Actions = []string{"start", "stop", "restart", "pause", "resume"}

// ErrReadOnly is returned for changes when containers.read_only is set.
var ErrReadOnly = errors.New("container management is read-only (containers.read_only in the config file)")

// ErrSelf protects SkyGuard's own container: stopping or recreating it from
// the dashboard would take the dashboard down mid-request.
var ErrSelf = errors.New("this is SkyGuard's own container; manage it with docker compose on the host")

// nameRE is what both engines accept as a container or network name.
var nameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$`)

// ValidName reports whether s is safe to use as a container or network name.
func ValidName(s string) bool { return nameRE.MatchString(s) }

// ParsePorts reads a comma- or newline-separated list in `docker run -p`
// form: "8080:80", "8080:80/udp", "127.0.0.1:8443:443/tcp", "[::1]:53:53/udp".
// An empty string is an empty list (every port unpublished).
func ParsePorts(spec string) ([]Port, error) {
	var out []Port
	seen := map[string]bool{}
	for _, f := range strings.FieldsFunc(spec, func(r rune) bool { return r == ',' || r == '\n' || r == ' ' }) {
		p, err := parsePort(strings.TrimSpace(f))
		if err != nil {
			return nil, err
		}
		key := fmt.Sprintf("%s|%d|%s", p.HostIP, p.HostPort, p.Proto)
		if p.HostPort != 0 && seen[key] {
			return nil, fmt.Errorf("host port %d/%s is listed twice", p.HostPort, p.Proto)
		}
		seen[key] = true
		out = append(out, p)
	}
	return out, nil
}

func parsePort(s string) (Port, error) {
	p := Port{Proto: "tcp"}
	if i := strings.LastIndex(s, "/"); i >= 0 {
		p.Proto = strings.ToLower(s[i+1:])
		s = s[:i]
	}
	if p.Proto != "tcp" && p.Proto != "udp" {
		return p, fmt.Errorf("%q: protocol must be tcp or udp", s)
	}
	// An optional host address in front: "1.2.3.4:" or "[::1]:".
	if strings.HasPrefix(s, "[") {
		end := strings.Index(s, "]:")
		if end < 0 {
			return p, fmt.Errorf("%q: unterminated IPv6 address", s)
		}
		p.HostIP, s = s[1:end], s[end+2:]
	} else if parts := strings.Split(s, ":"); len(parts) == 3 {
		p.HostIP, s = parts[0], parts[1]+":"+parts[2]
	}
	if p.HostIP != "" {
		a, err := netip.ParseAddr(p.HostIP)
		if err != nil {
			return p, fmt.Errorf("%q: invalid host address", p.HostIP)
		}
		p.HostIP = a.String()
		if a.IsUnspecified() {
			p.HostIP = ""
		}
	}
	hp, cp, ok := strings.Cut(s, ":")
	if !ok {
		return p, fmt.Errorf("%q: expected host-port:container-port", s)
	}
	var err error
	if hp == "0" { // a random free host port, as Docker assigns for "-p 80"
		p.HostPort = 0
	} else if p.HostPort, err = portNumber(hp); err != nil {
		return p, err
	}
	if p.ContainerPort, err = portNumber(cp); err != nil {
		return p, err
	}
	return p, nil
}

func portNumber(s string) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("%q is not a port number (1-65535)", s)
	}
	return n, nil
}

// sortContainers orders running containers first, then by name.
func sortContainers(cs []Container) {
	sort.SliceStable(cs, func(i, j int) bool {
		if cs[i].Running != cs[j].Running {
			return cs[i].Running
		}
		return cs[i].Name < cs[j].Name
	})
}

func sortPorts(ps []Port) {
	sort.Slice(ps, func(i, j int) bool {
		if ps[i].HostPort != ps[j].HostPort {
			return ps[i].HostPort < ps[j].HostPort
		}
		if ps[i].Proto != ps[j].Proto {
			return ps[i].Proto < ps[j].Proto
		}
		return ps[i].HostIP < ps[j].HostIP
	})
}
