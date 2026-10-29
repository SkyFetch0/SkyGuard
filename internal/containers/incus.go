package containers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"math"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Incus talks to the Incus REST API. Published ports are Incus proxy
// devices; networks are managed Incus networks joined through nic devices.
type Incus struct {
	c       *unixClient
	project string
	logger  *slog.Logger
}

// NewIncus returns a client for the daemon listening on socket. An empty
// project means the default one.
func NewIncus(socket, project string, logger *slog.Logger) *Incus {
	return &Incus{c: newUnixClient(socket, "incus"), project: project, logger: logger}
}

func (x *Incus) Name() string { return "incus" }

// RestartPolicies map onto boot.autostart: "last-state" (unset) restarts what
// was running when the host went down, "always" is true, "no" is false.
func (x *Incus) RestartPolicies() []string { return []string{"no", "last-state", "always"} }

type incusReply struct {
	Type      string          `json:"type"` // sync, async or error
	Operation string          `json:"operation"`
	Error     string          `json:"error"`
	Metadata  json.RawMessage `json:"metadata"`
}

func (x *Incus) call(ctx context.Context, method, path string, q url.Values, body any, hdr http.Header, out any) (http.Header, error) {
	if q == nil {
		q = url.Values{}
	}
	if x.project != "" {
		q.Set("project", x.project)
	}
	resp, err := x.c.do(ctx, method, path, q, body, hdr)
	if err != nil {
		return nil, fmt.Errorf("incus: %w", err)
	}
	var r incusReply
	if err := json.Unmarshal(resp.body, &r); err != nil {
		return nil, &APIError{Engine: "incus", Status: resp.status, Message: fmt.Sprintf("unexpected reply (HTTP %d)", resp.status)}
	}
	if r.Type == "error" || resp.status >= 400 {
		return nil, &APIError{Engine: "incus", Status: resp.status, Message: cmpOr(r.Error, http.StatusText(resp.status))}
	}
	if r.Type == "async" {
		return resp.header, x.wait(ctx, r.Operation)
	}
	if out != nil && len(r.Metadata) > 0 {
		if err := json.Unmarshal(r.Metadata, out); err != nil {
			return nil, fmt.Errorf("incus: decoding %s: %w", path, err)
		}
	}
	return resp.header, nil
}

// wait blocks until a background operation (start, stop, a device change) ends.
func (x *Incus) wait(ctx context.Context, op string) error {
	if !strings.HasPrefix(op, "/1.0/operations/") {
		return fmt.Errorf("incus: unexpected operation %q", op)
	}
	var res struct {
		Status string `json:"status"`
		Err    string `json:"err"`
	}
	if _, err := x.call(ctx, "GET", op+"/wait", url.Values{"timeout": {"120"}}, nil, nil, &res); err != nil {
		return err
	}
	if res.Status != "Success" {
		return &APIError{Engine: "incus", Status: 500, Message: cmpOr(res.Err, "operation "+strings.ToLower(res.Status))}
	}
	return nil
}

func (x *Incus) Version(ctx context.Context) (string, error) {
	var s struct {
		Auth        string `json:"auth"`
		Environment struct {
			ServerVersion string `json:"server_version"`
		} `json:"environment"`
	}
	if _, err := x.call(ctx, "GET", "/1.0", nil, nil, nil, &s); err != nil {
		return "", err
	}
	if s.Auth != "trusted" {
		return "", errors.New("incus: SkyGuard is not trusted by the daemon (run it as root or in the incus-admin group)")
	}
	return s.Environment.ServerVersion, nil
}

type incusDevice = map[string]string

type incusInstance struct {
	Name            string                 `json:"name"`
	Status          string                 `json:"status"`
	Type            string                 `json:"type"`
	CreatedAt       time.Time              `json:"created_at"`
	Description     string                 `json:"description"`
	Config          map[string]string      `json:"config"`
	ExpandedConfig  map[string]string      `json:"expanded_config"`
	Devices         map[string]incusDevice `json:"devices"`
	ExpandedDevices map[string]incusDevice `json:"expanded_devices"`
	State           *struct {
		Pid     int `json:"pid"`
		Network map[string]struct {
			Addresses []struct {
				Family  string `json:"family"`
				Address string `json:"address"`
				Scope   string `json:"scope"`
			} `json:"addresses"`
		} `json:"network"`
	} `json:"state"`
}

func (x *Incus) toContainer(in incusInstance) Container {
	c := Container{
		Engine:  "incus",
		ID:      in.Name,
		Name:    in.Name,
		Kind:    in.Type,
		State:   strings.ToLower(in.Status),
		Running: in.Status == "Running",
		Status:  in.Status,
		Created: in.CreatedAt,
	}
	ec := in.ExpandedConfig
	c.Image = cmpOr(ec["image.description"], strings.TrimSpace(ec["image.os"]+" "+ec["image.release"]))
	if in.State != nil {
		c.PID = in.State.Pid
	}
	for _, key := range slices.Sorted(maps.Keys(in.ExpandedDevices)) {
		dev := in.ExpandedDevices[key]
		_, local := in.Devices[key]
		switch dev["type"] {
		case "nic":
			net := cmpOr(dev["network"], dev["parent"])
			if net == "" {
				continue
			}
			iface := cmpOr(dev["name"], key)
			ep := Endpoint{Network: net, Device: key}
			if in.State != nil {
				for _, a := range in.State.Network[iface].Addresses {
					if a.Scope == "global" && (ep.IP == "" || a.Family == "inet") {
						ep.IP = a.Address
					}
				}
			}
			c.Networks = append(c.Networks, ep)
		case "proxy":
			if p, ok := parseProxy(dev); ok {
				p.Device, p.Inherited = key, !local
				c.Ports = append(c.Ports, p)
			}
		}
	}
	sortPorts(c.Ports)
	return c
}

// parseProxy reads a single-port proxy device: listen tcp:0.0.0.0:8080,
// connect tcp:127.0.0.1:80. Port ranges are left alone.
func parseProxy(dev incusDevice) (Port, bool) {
	lp, lhost, lport, ok1 := splitProxyAddr(dev["listen"])
	cp, _, cport, ok2 := splitProxyAddr(dev["connect"])
	if !ok1 || !ok2 || lp != cp {
		return Port{}, false
	}
	return Port{HostIP: lhost, HostPort: lport, ContainerPort: cport, Proto: lp}, true
}

func splitProxyAddr(s string) (proto, host string, port int, ok bool) {
	proto, rest, found := strings.Cut(s, ":")
	if !found || (proto != "tcp" && proto != "udp") {
		return "", "", 0, false
	}
	ap, err := netip.ParseAddrPort(rest)
	if err != nil {
		return "", "", 0, false
	}
	host = ap.Addr().String()
	if ap.Addr().IsUnspecified() {
		host = ""
	}
	return proto, host, int(ap.Port()), true
}

func proxyAddr(proto, host string, port int) string {
	if host == "" {
		host = "0.0.0.0"
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return fmt.Sprintf("%s:%s:%d", proto, host, port)
}

func (x *Incus) List(ctx context.Context) ([]Container, []Network, error) {
	var insts []incusInstance
	if _, err := x.call(ctx, "GET", "/1.0/instances", url.Values{"recursion": {"2"}}, nil, nil, &insts); err != nil {
		return nil, nil, err
	}
	var nets []struct {
		Name    string            `json:"name"`
		Type    string            `json:"type"`
		Managed bool              `json:"managed"`
		Config  map[string]string `json:"config"`
	}
	if _, err := x.call(ctx, "GET", "/1.0/networks", url.Values{"recursion": {"1"}}, nil, nil, &nets); err != nil {
		return nil, nil, err
	}
	members := map[string][]string{}
	out := make([]Container, 0, len(insts))
	for _, in := range insts {
		c := x.toContainer(in)
		for _, ep := range c.Networks {
			members[ep.Network] = append(members[ep.Network], c.ID)
		}
		out = append(out, c)
	}
	sortContainers(out)
	networks := []Network{}
	for _, n := range nets {
		// Unmanaged networks are the host's own interfaces (eth0, docker0, lo).
		if !n.Managed {
			continue
		}
		nw := Network{Engine: "incus", ID: n.Name, Name: n.Name, Driver: n.Type, Attachable: true, Members: members[n.Name]}
		if nw.Members == nil {
			nw.Members = []string{}
		}
		if a := n.Config["ipv4.address"]; a != "" && a != "none" {
			nw.Subnet = a
		}
		networks = append(networks, nw)
	}
	return out, networks, nil
}

func (x *Incus) path(name string) string { return "/1.0/instances/" + url.PathEscape(name) }

func (x *Incus) Inspect(ctx context.Context, id string) (*Container, error) {
	var in incusInstance
	if _, err := x.call(ctx, "GET", x.path(id), url.Values{"recursion": {"1"}}, nil, nil, &in); err != nil {
		return nil, err
	}
	c := x.toContainer(in)
	ec := in.ExpandedConfig
	switch ec["boot.autostart"] {
	case "true", "1":
		c.Restart = "always"
	case "false", "0":
		c.Restart = "no"
	default:
		c.Restart = "last-state"
	}
	c.MemoryMB = parseMemoryMB(ec["limits.memory"])
	if n, err := strconv.Atoi(ec["limits.cpu"]); err == nil {
		c.CPUs = float64(n)
	}
	for _, key := range slices.Sorted(maps.Keys(in.ExpandedDevices)) {
		dev := in.ExpandedDevices[key]
		if dev["type"] == "disk" {
			src := dev["source"]
			if dev["pool"] != "" {
				src = dev["pool"] + "/" + cmpOr(src, "root")
			}
			c.Mounts = append(c.Mounts, fmt.Sprintf("disk %s → %s", src, dev["path"]))
		}
	}
	return &c, nil
}

// parseMemoryMB reads limits.memory ("512MiB", "2GB", "1073741824"); a
// percentage or an unknown form reads as 0.
func parseMemoryMB(s string) int64 {
	s = strings.TrimSpace(s)
	if s == "" || strings.HasSuffix(s, "%") {
		return 0
	}
	units := []struct {
		suffix string
		mult   float64
	}{{"KiB", 1 << 10}, {"MiB", 1 << 20}, {"GiB", 1 << 30}, {"TiB", 1 << 40}, {"kB", 1e3}, {"KB", 1e3}, {"MB", 1e6}, {"GB", 1e9}, {"TB", 1e12}, {"B", 1}}
	mult := 1.0
	for _, u := range units {
		if strings.HasSuffix(s, u.suffix) {
			s, mult = strings.TrimSuffix(s, u.suffix), u.mult
			break
		}
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0
	}
	return int64(math.Round(f * mult / (1 << 20)))
}

func (x *Incus) Action(ctx context.Context, id, action string) error {
	if !slices.Contains(Actions, action) {
		return fmt.Errorf("unknown action %q", action)
	}
	verb := map[string]string{"pause": "freeze", "resume": "unfreeze"}[action]
	_, err := x.call(ctx, "PUT", x.path(id)+"/state", nil, map[string]any{"action": cmpOr(verb, action), "timeout": 30}, nil, nil)
	return err
}

// incusPut is the writable part of an instance.
type incusPut struct {
	Architecture string                 `json:"architecture"`
	Config       map[string]string      `json:"config"`
	Devices      map[string]incusDevice `json:"devices"`
	Ephemeral    bool                   `json:"ephemeral"`
	Profiles     []string               `json:"profiles"`
	Stateful     bool                   `json:"stateful"`
	Description  string                 `json:"description"`
	Restore      string                 `json:"restore,omitempty"`
}

// modify reads an instance, lets fn change it and writes it back, guarded
// by the ETag so a concurrent change made elsewhere is not overwritten.
func (x *Incus) modify(ctx context.Context, id string, fn func(cur *incusInstance, put *incusPut) error) error {
	var raw json.RawMessage
	hdr, err := x.call(ctx, "GET", x.path(id), nil, nil, nil, &raw)
	if err != nil {
		return err
	}
	// One document, read whole and as the writable subset.
	var cur incusInstance
	var put incusPut
	if err := json.Unmarshal(raw, &cur); err != nil {
		return fmt.Errorf("incus: decoding %s: %w", id, err)
	}
	if err := json.Unmarshal(raw, &put); err != nil {
		return fmt.Errorf("incus: decoding %s: %w", id, err)
	}
	if put.Config == nil {
		put.Config = map[string]string{}
	}
	if put.Devices == nil {
		put.Devices = map[string]incusDevice{}
	}
	if err := fn(&cur, &put); err != nil {
		return err
	}
	h := http.Header{}
	if etag := hdr.Get("ETag"); etag != "" {
		h.Set("If-Match", etag)
	}
	_, err = x.call(ctx, "PUT", x.path(id), nil, put, h, nil)
	return err
}

func (x *Incus) Connect(ctx context.Context, id, network string) error {
	return x.modify(ctx, id, func(cur *incusInstance, put *incusPut) error {
		used := map[string]bool{}
		for key, dev := range cur.ExpandedDevices {
			if dev["type"] != "nic" {
				continue
			}
			if cmpOr(dev["network"], dev["parent"]) == network {
				return fmt.Errorf("%s is already on %s", id, network)
			}
			used[cmpOr(dev["name"], key)] = true
		}
		iface := ""
		for i := 0; iface == ""; i++ {
			if n := fmt.Sprintf("eth%d", i); !used[n] {
				iface = n
			}
		}
		key := iface
		if _, taken := cur.ExpandedDevices[key]; taken {
			key = "nic-" + network
		}
		put.Devices[key] = incusDevice{"type": "nic", "network": network, "name": iface}
		return nil
	})
}

func (x *Incus) Disconnect(ctx context.Context, id, network string) error {
	return x.modify(ctx, id, func(cur *incusInstance, put *incusPut) error {
		for key, dev := range cur.ExpandedDevices {
			if dev["type"] != "nic" || cmpOr(dev["network"], dev["parent"]) != network {
				continue
			}
			if _, local := put.Devices[key]; local {
				delete(put.Devices, key)
			} else {
				// From a profile: masked for this instance only.
				put.Devices[key] = incusDevice{"type": "none"}
			}
			return nil
		}
		return fmt.Errorf("%s is not on %s", id, network)
	})
}

// Incus network names become bridge interface names, which Linux caps at 15 bytes.
func (x *Incus) CreateNetwork(ctx context.Context, name string) error {
	if len(name) > 15 {
		return errors.New("an Incus network name can be at most 15 characters (it becomes the bridge's interface name)")
	}
	body := map[string]any{"name": name, "type": "bridge", "description": "created from the SkyGuard dashboard",
		"config": map[string]string{"ipv4.address": "auto", "ipv4.nat": "true", "ipv6.address": "none"}}
	_, err := x.call(ctx, "POST", "/1.0/networks", nil, body, nil, nil)
	return err
}

// SetPorts makes the instance's single-port proxy devices match ports.
// Incus changes devices on a running instance, so nothing restarts.
func (x *Incus) SetPorts(ctx context.Context, id string, ports []Port) error {
	return x.modify(ctx, id, func(cur *incusInstance, put *incusPut) error {
		if cur.Type == "virtual-machine" && len(ports) > 0 {
			return errors.New("virtual machines take only NAT proxy devices with a fixed address; add them with incus config device add")
		}
		want := map[string]Port{}
		for _, p := range ports {
			want[p.String()] = p
		}
		for key, dev := range cur.ExpandedDevices {
			if dev["type"] != "proxy" {
				continue
			}
			p, ok := parseProxy(dev)
			if !ok {
				continue // a port range or a unix socket: not shown, not touched
			}
			if _, keep := want[p.String()]; keep {
				delete(want, p.String())
				continue
			}
			if _, local := put.Devices[key]; local {
				delete(put.Devices, key)
			} else {
				put.Devices[key] = incusDevice{"type": "none"}
			}
		}
		for _, k := range slices.Sorted(maps.Keys(want)) {
			p := want[k]
			key := fmt.Sprintf("proxy-%s-%d", p.Proto, p.HostPort)
			for i := 2; ; i++ {
				_, a := cur.ExpandedDevices[key]
				_, b := put.Devices[key]
				if !a && !b {
					break
				}
				key = fmt.Sprintf("proxy-%s-%d-%d", p.Proto, p.HostPort, i)
			}
			if p.HostPort == 0 {
				return errors.New("Incus needs a fixed host port")
			}
			put.Devices[key] = incusDevice{
				"type":    "proxy",
				"listen":  proxyAddr(p.Proto, p.HostIP, p.HostPort),
				"connect": proxyAddr(p.Proto, "127.0.0.1", p.ContainerPort),
			}
		}
		return nil
	})
}

func (x *Incus) Update(ctx context.Context, id string, s Settings) error {
	return x.modify(ctx, id, func(_ *incusInstance, put *incusPut) error {
		if s.Restart != nil {
			switch *s.Restart {
			case "always":
				put.Config["boot.autostart"] = "true"
			case "no":
				put.Config["boot.autostart"] = "false"
			case "last-state":
				delete(put.Config, "boot.autostart")
			default:
				return fmt.Errorf("unknown restart policy %q", *s.Restart)
			}
		}
		if s.MemoryMB != nil {
			switch {
			case *s.MemoryMB < 0:
				return errors.New("the memory limit cannot be negative")
			case *s.MemoryMB == 0:
				delete(put.Config, "limits.memory")
			default:
				put.Config["limits.memory"] = fmt.Sprintf("%dMiB", *s.MemoryMB)
			}
		}
		if s.CPUs != nil {
			n := *s.CPUs
			switch {
			case n < 0:
				return errors.New("the CPU limit cannot be negative")
			case n == 0:
				delete(put.Config, "limits.cpu")
			case n != math.Trunc(n):
				return errors.New("Incus takes a whole number of CPUs")
			default:
				put.Config["limits.cpu"] = strconv.Itoa(int(n))
			}
		}
		return nil
	})
}

// imageServers are the remotes a new instance can come from, by prefix.
var imageServers = map[string]string{
	"images": "https://images.linuxcontainers.org",
}

// imageSource reads "images:debian/12" (a public image server) or a bare
// alias or fingerprint of an image already on this host.
func imageSource(ref string) (map[string]any, error) {
	if ref == "" || strings.ContainsAny(ref, " \t\n\"'") {
		return nil, fmt.Errorf("%q is not an image", ref)
	}
	if remote, alias, ok := strings.Cut(ref, ":"); ok {
		server, known := imageServers[remote]
		if !known {
			return nil, fmt.Errorf("unknown image server %q (use images:<distro>/<release>, or an image already on this host)", remote)
		}
		return map[string]any{"type": "image", "alias": alias, "server": server, "protocol": "simplestreams", "mode": "pull"}, nil
	}
	return map[string]any{"type": "image", "alias": ref}, nil
}

func (x *Incus) Create(ctx context.Context, spec CreateSpec) (string, error) {
	src, err := imageSource(spec.Image)
	if err != nil {
		return "", err
	}
	if len(spec.Env) > 0 {
		return "", errors.New("environment variables are a Docker setting; set Incus config keys with incus config set")
	}
	typ := "container"
	if spec.VM {
		typ = "virtual-machine"
		if len(spec.Ports) > 0 {
			return "", errors.New("virtual machines take only NAT proxy devices with a fixed address; add ports later with incus config device add")
		}
	}
	cfg := map[string]string{}
	switch spec.Restart {
	case "always":
		cfg["boot.autostart"] = "true"
	case "no":
		cfg["boot.autostart"] = "false"
	case "", "last-state":
	default:
		return "", fmt.Errorf("unknown restart policy %q", spec.Restart)
	}
	if spec.MemoryMB > 0 {
		cfg["limits.memory"] = fmt.Sprintf("%dMiB", spec.MemoryMB)
	}
	if spec.CPUs > 0 {
		if spec.CPUs != math.Trunc(spec.CPUs) {
			return "", errors.New("Incus takes a whole number of CPUs")
		}
		cfg["limits.cpu"] = strconv.Itoa(int(spec.CPUs))
	}
	devices := map[string]incusDevice{}
	if spec.Network != "" {
		devices["eth0"] = incusDevice{"type": "nic", "network": spec.Network, "name": "eth0"}
	}
	for _, p := range spec.Ports {
		if p.HostPort == 0 {
			return "", errors.New("Incus needs a fixed host port")
		}
		devices[fmt.Sprintf("proxy-%s-%d", p.Proto, p.HostPort)] = incusDevice{
			"type": "proxy", "listen": proxyAddr(p.Proto, p.HostIP, p.HostPort), "connect": proxyAddr(p.Proto, "127.0.0.1", p.ContainerPort),
		}
	}
	body := map[string]any{"name": spec.Name, "type": typ, "source": src, "profiles": []string{"default"},
		"config": cfg, "devices": devices, "description": "created from the SkyGuard dashboard"}
	if _, err := x.call(ctx, "POST", "/1.0/instances", nil, body, nil, nil); err != nil {
		return "", err
	}
	if spec.Start {
		if err := x.Action(ctx, spec.Name, "start"); err != nil {
			return spec.Name, fmt.Errorf("created, but it did not start: %w", err)
		}
	}
	return spec.Name, nil
}

// Remove stops the instance if it runs and deletes it with its snapshots.
// Incus keeps no separate volumes for an instance's root disk, so volumes
// changes nothing here; custom volumes attached to it are never deleted.
func (x *Incus) Remove(ctx context.Context, id string, _ bool) error {
	var st struct {
		Status string `json:"status"`
	}
	if _, err := x.call(ctx, "GET", x.path(id)+"/state", nil, nil, nil, &st); err != nil {
		return err
	}
	if st.Status != "Stopped" {
		if _, err := x.call(ctx, "PUT", x.path(id)+"/state", nil, map[string]any{"action": "stop", "timeout": 30, "force": true}, nil, nil); err != nil {
			return fmt.Errorf("stopping before removal: %w", err)
		}
	}
	_, err := x.call(ctx, "DELETE", x.path(id), nil, nil, nil, nil)
	return err
}

// Logs returns the end of the instance's console log, or of its LXC log
// when the console log is not available.
func (x *Incus) Logs(ctx context.Context, id string, lines int) (string, error) {
	q := url.Values{}
	if x.project != "" {
		q.Set("project", x.project)
	}
	for _, path := range []string{x.path(id) + "/console", x.path(id) + "/logs/lxc.log"} {
		resp, err := x.c.do(ctx, "GET", path, q, nil, nil)
		if err != nil {
			return "", fmt.Errorf("incus: %w", err)
		}
		if resp.status == 200 && !strings.HasPrefix(resp.header.Get("Content-Type"), "application/json") {
			return lastLines(string(resp.body), lines), nil
		}
	}
	return "", &APIError{Engine: "incus", Status: 404, Message: "no console or LXC log for " + id}
}

func lastLines(s string, n int) string {
	s = strings.TrimRight(s, "\n")
	parts := strings.Split(s, "\n")
	if len(parts) > n {
		parts = parts[len(parts)-n:]
	}
	return strings.Join(parts, "\n") + "\n"
}

func (x *Incus) DeleteNetwork(ctx context.Context, name string) error {
	_, err := x.call(ctx, "DELETE", "/1.0/networks/"+url.PathEscape(name), nil, nil, nil, nil)
	return err
}

func (x *Incus) Snapshots(ctx context.Context, id string) ([]InstanceSnapshot, error) {
	var raw []struct {
		Name      string    `json:"name"`
		CreatedAt time.Time `json:"created_at"`
		Stateful  bool      `json:"stateful"`
	}
	if _, err := x.call(ctx, "GET", x.path(id)+"/snapshots", url.Values{"recursion": {"1"}}, nil, nil, &raw); err != nil {
		return nil, err
	}
	out := make([]InstanceSnapshot, 0, len(raw))
	for _, r := range raw {
		out = append(out, InstanceSnapshot{Name: r.Name, Created: r.CreatedAt, Stateful: r.Stateful})
	}
	slices.SortFunc(out, func(a, b InstanceSnapshot) int { return b.Created.Compare(a.Created) })
	return out, nil
}

func (x *Incus) TakeSnapshot(ctx context.Context, id, name string) error {
	_, err := x.call(ctx, "POST", x.path(id)+"/snapshots", nil, map[string]any{"name": name}, nil, nil)
	return err
}

// RestoreSnapshot puts the instance back to the snapshot; what changed
// since is lost.
func (x *Incus) RestoreSnapshot(ctx context.Context, id, name string) error {
	return x.modify(ctx, id, func(_ *incusInstance, put *incusPut) error {
		put.Restore = name
		return nil
	})
}

func (x *Incus) DeleteSnapshot(ctx context.Context, id, name string) error {
	_, err := x.call(ctx, "DELETE", x.path(id)+"/snapshots/"+url.PathEscape(name), nil, nil, nil, nil)
	return err
}

var (
	_ Engine      = (*Incus)(nil)
	_ Snapshotter = (*Incus)(nil)
	_ Engine      = (*Docker)(nil)
)

// Socket is the unix socket the client talks to.
func (x *Incus) Socket() string { return x.c.socket }
