package containers

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// APIError is an error reply from an engine's API.
type APIError struct {
	Engine  string
	Status  int
	Message string
}

func (e *APIError) Error() string { return e.Engine + ": " + e.Message }

// Docker talks to the Docker Engine API.
type Docker struct {
	c      *unixClient
	logger *slog.Logger
	selfID string

	mu      sync.Mutex
	prefix  string // "/v1.47", negotiated on first use
	version string
}

// NewDocker returns a client for the daemon listening on socket.
func NewDocker(socket string, logger *slog.Logger) *Docker {
	return &Docker{c: newUnixClient(socket, "docker"), logger: logger, selfID: detectSelfID()}
}

func (d *Docker) Name() string { return "docker" }

// RestartPolicies are Docker's restart policies, in the order the panel shows them.
func (d *Docker) RestartPolicies() []string {
	return []string{"no", "on-failure", "unless-stopped", "always"}
}

// targetAPI is the API version SkyGuard is written against. Newer daemons
// still serve it; older ones are asked for their own newest version.
const targetAPI = "1.47"

func (d *Docker) negotiate(ctx context.Context) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.prefix != "" {
		return d.prefix, nil
	}
	resp, err := d.c.do(ctx, "GET", "/version", nil, nil, nil)
	if err != nil {
		return "", fmt.Errorf("docker: %w", err)
	}
	var v struct {
		Version       string
		APIVersion    string `json:"ApiVersion"`
		MinAPIVersion string `json:"MinAPIVersion"`
	}
	if resp.status != 200 || json.Unmarshal(resp.body, &v) != nil || v.APIVersion == "" {
		return "", fmt.Errorf("docker: unexpected /version reply (HTTP %d)", resp.status)
	}
	use := targetAPI
	if apiLess(v.APIVersion, use) {
		use = v.APIVersion
	}
	if v.MinAPIVersion != "" && apiLess(use, v.MinAPIVersion) {
		use = v.MinAPIVersion
	}
	d.prefix, d.version = "/v"+use, v.Version
	return d.prefix, nil
}

// apiLess compares "1.44"-style versions.
func apiLess(a, b string) bool {
	pa, pb := strings.SplitN(a, ".", 2), strings.SplitN(b, ".", 2)
	for i := 0; i < 2; i++ {
		var x, y int
		if i < len(pa) {
			x, _ = strconv.Atoi(pa[i])
		}
		if i < len(pb) {
			y, _ = strconv.Atoi(pb[i])
		}
		if x != y {
			return x < y
		}
	}
	return false
}

func (d *Docker) call(ctx context.Context, method, path string, q url.Values, body, out any) error {
	prefix, err := d.negotiate(ctx)
	if err != nil {
		return err
	}
	resp, err := d.c.do(ctx, method, prefix+path, q, body, nil)
	if err != nil {
		return fmt.Errorf("docker: %w", err)
	}
	if resp.status == 304 { // already started / already stopped
		return nil
	}
	if resp.status >= 300 {
		var e struct{ Message string }
		_ = json.Unmarshal(resp.body, &e)
		if e.Message == "" {
			e.Message = strings.TrimSpace(string(resp.body))
		}
		return &APIError{Engine: "docker", Status: resp.status, Message: e.Message}
	}
	if out != nil && len(resp.body) > 0 {
		if err := json.Unmarshal(resp.body, out); err != nil {
			return fmt.Errorf("docker: decoding %s: %w", path, err)
		}
	}
	return nil
}

func (d *Docker) Version(ctx context.Context) (string, error) {
	if _, err := d.negotiate(ctx); err != nil {
		return "", err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.version, nil
}

type dockerEndpoint struct {
	NetworkID         string
	IPAddress         string
	GlobalIPv6Address string
	Aliases           []string
	Links             []string
	DriverOpts        map[string]string
	IPAMConfig        *struct {
		IPv4Address string `json:",omitempty"`
		IPv6Address string `json:",omitempty"`
	}
}

type dockerMount struct {
	Type        string
	Name        string
	Source      string
	Destination string
	RW          bool
}

type dockerSummary struct {
	ID      string `json:"Id"`
	Names   []string
	Image   string
	State   string
	Status  string
	Created int64
	Ports   []struct {
		IP          string
		PrivatePort int
		PublicPort  int
		Type        string
	}
	Labels     map[string]string
	HostConfig struct {
		NetworkMode string
	}
	NetworkSettings struct {
		Networks map[string]dockerEndpoint
	}
}

// pseudoNetworks are network modes, not networks a container can be patched into.
var pseudoNetworks = map[string]bool{"host": true, "none": true}

func (d *Docker) List(ctx context.Context) ([]Container, []Network, error) {
	var sums []dockerSummary
	if err := d.call(ctx, "GET", "/containers/json", url.Values{"all": {"1"}}, nil, &sums); err != nil {
		return nil, nil, err
	}
	var nets []struct {
		ID         string `json:"Id"`
		Name       string
		Driver     string
		Scope      string
		Internal   bool
		Attachable bool
		IPAM       struct {
			Config []struct{ Subnet string }
		}
	}
	if err := d.call(ctx, "GET", "/networks", nil, nil, &nets); err != nil {
		return nil, nil, err
	}

	members := map[string][]string{}
	out := make([]Container, 0, len(sums))
	for _, s := range sums {
		c := Container{
			Engine:  "docker",
			ID:      s.ID,
			Image:   s.Image,
			Kind:    "container",
			State:   s.State,
			Running: s.State == "running",
			Status:  s.Status,
			Created: time.Unix(s.Created, 0).UTC(),
			Project: s.Labels["com.docker.compose.project"],
			Self:    d.selfID != "" && s.ID == d.selfID,
		}
		if len(s.Names) > 0 {
			c.Name = strings.TrimPrefix(s.Names[0], "/")
		}
		if m := s.HostConfig.NetworkMode; m == "host" || m == "none" || strings.HasPrefix(m, "container:") {
			c.NetworkMode = m
		}
		seen := map[string]bool{}
		for _, p := range s.Ports {
			exp := fmt.Sprintf("%d/%s", p.PrivatePort, p.Type)
			if !slices.Contains(c.Exposed, exp) {
				c.Exposed = append(c.Exposed, exp)
			}
			if p.PublicPort == 0 {
				continue
			}
			host := p.IP
			if host == "0.0.0.0" || host == "::" {
				host = "" // one entry for the IPv4 and IPv6 wildcard pair
			}
			port := Port{HostIP: host, HostPort: p.PublicPort, ContainerPort: p.PrivatePort, Proto: p.Type}
			if k := port.String(); !seen[k] {
				seen[k] = true
				c.Ports = append(c.Ports, port)
			}
		}
		sortPorts(c.Ports)
		for _, name := range slices.Sorted(maps.Keys(s.NetworkSettings.Networks)) {
			if pseudoNetworks[name] {
				continue
			}
			ep := s.NetworkSettings.Networks[name]
			ip := ep.IPAddress
			if ip == "" {
				ip = ep.GlobalIPv6Address
			}
			c.Networks = append(c.Networks, Endpoint{Network: name, IP: ip, Aliases: ep.Aliases})
			members[name] = append(members[name], s.ID)
		}
		out = append(out, c)
	}
	sortContainers(out)

	networks := make([]Network, 0, len(nets))
	for _, n := range nets {
		if pseudoNetworks[n.Name] {
			continue
		}
		nw := Network{
			Engine:   "docker",
			ID:       n.ID,
			Name:     n.Name,
			Driver:   n.Driver,
			Internal: n.Internal,
			Builtin:  n.Name == "bridge",
			// Swarm overlays only take standalone containers when created attachable.
			Attachable: n.Scope != "swarm" || n.Attachable,
			Members:    members[n.Name],
		}
		if nw.Members == nil {
			nw.Members = []string{}
		}
		if len(n.IPAM.Config) > 0 {
			nw.Subnet = n.IPAM.Config[0].Subnet
		}
		networks = append(networks, nw)
	}
	// Networks in use first, then by name; the default bridge last among them.
	slices.SortStableFunc(networks, func(a, b Network) int {
		if (len(a.Members) > 0) != (len(b.Members) > 0) {
			if len(a.Members) > 0 {
				return -1
			}
			return 1
		}
		if a.Builtin != b.Builtin {
			if b.Builtin {
				return -1
			}
			return 1
		}
		return strings.Compare(a.Name, b.Name)
	})
	return out, networks, nil
}

// dockerInspect is the part of GET /containers/{id}/json SkyGuard reads.
// Config and HostConfig stay generic maps so a recreate copies every field,
// including ones newer than this code.
type dockerInspect struct {
	ID      string `json:"Id"`
	Name    string
	Created time.Time
	Image   string
	State   struct {
		Status  string
		Running bool
		Paused  bool
	}
	Config          map[string]any
	HostConfig      map[string]any
	NetworkSettings struct {
		Networks map[string]dockerEndpoint
	}
	Mounts []dockerMount
}

func (d *Docker) inspect(ctx context.Context, id string) (*dockerInspect, error) {
	var in dockerInspect
	if err := d.call(ctx, "GET", "/containers/"+url.PathEscape(id)+"/json", nil, nil, &in); err != nil {
		return nil, err
	}
	if in.Config == nil {
		in.Config = map[string]any{}
	}
	if in.HostConfig == nil {
		in.HostConfig = map[string]any{}
	}
	return &in, nil
}

func (d *Docker) Inspect(ctx context.Context, id string) (*Container, error) {
	in, err := d.inspect(ctx, id)
	if err != nil {
		return nil, err
	}
	str := func(m map[string]any, k string) string { s, _ := m[k].(string); return s }
	num := func(m map[string]any, k string) float64 { f, _ := m[k].(float64); return f }
	labels, _ := in.Config["Labels"].(map[string]any)
	project, _ := labels["com.docker.compose.project"].(string)

	c := &Container{
		Engine:  "docker",
		ID:      in.ID,
		Name:    strings.TrimPrefix(in.Name, "/"),
		Image:   str(in.Config, "Image"),
		Kind:    "container",
		State:   in.State.Status,
		Running: in.State.Running,
		Status:  in.State.Status,
		Created: in.Created,
		Project: project,
		Self:    d.selfID != "" && in.ID == d.selfID,
	}
	if project != "" {
		c.ComposeService, _ = labels["com.docker.compose.service"].(string)
		dir, _ := labels["com.docker.compose.project.working_dir"].(string)
		files, _ := labels["com.docker.compose.project.config_files"].(string)
		for _, f := range strings.Split(files, ",") {
			if f = strings.TrimSpace(f); f == "" {
				continue
			}
			if !filepath.IsAbs(f) && dir != "" {
				f = filepath.Join(dir, f)
			}
			c.ComposeFiles = append(c.ComposeFiles, f)
		}
	}
	if m := str(in.HostConfig, "NetworkMode"); m == "host" || m == "none" || strings.HasPrefix(m, "container:") {
		c.NetworkMode = m
	}
	// Ports as configured, so a stopped container shows them too.
	bindings, _ := in.HostConfig["PortBindings"].(map[string]any)
	for key, list := range bindings {
		cport, proto, _ := strings.Cut(key, "/")
		cp, _ := strconv.Atoi(cport)
		items, _ := list.([]any)
		for _, it := range items {
			b, _ := it.(map[string]any)
			hp, _ := strconv.Atoi(str(b, "HostPort"))
			host := str(b, "HostIp")
			if host == "0.0.0.0" || host == "::" {
				host = ""
			}
			c.Ports = append(c.Ports, Port{HostIP: host, HostPort: hp, ContainerPort: cp, Proto: proto})
		}
	}
	sortPorts(c.Ports)
	exposed, _ := in.Config["ExposedPorts"].(map[string]any)
	c.Exposed = slices.Sorted(maps.Keys(exposed))
	for _, name := range slices.Sorted(maps.Keys(in.NetworkSettings.Networks)) {
		if pseudoNetworks[name] {
			continue
		}
		ep := in.NetworkSettings.Networks[name]
		c.Networks = append(c.Networks, Endpoint{Network: name, IP: ep.IPAddress, Aliases: ep.Aliases})
	}
	if rp, ok := in.HostConfig["RestartPolicy"].(map[string]any); ok {
		c.Restart = str(rp, "Name")
	}
	if c.Restart == "" {
		c.Restart = "no"
	}
	c.MemoryMB = int64(num(in.HostConfig, "Memory")) >> 20
	c.CPUs = num(in.HostConfig, "NanoCpus") / 1e9
	env, _ := in.Config["Env"].([]any)
	c.EnvCount = len(env)
	for _, m := range in.Mounts {
		src := m.Source
		if m.Type == "volume" && m.Name != "" {
			src = m.Name
		}
		s := fmt.Sprintf("%s %s → %s", m.Type, src, m.Destination)
		if !m.RW {
			s += " (read-only)"
		}
		c.Mounts = append(c.Mounts, s)
	}
	return c, nil
}

func (d *Docker) Action(ctx context.Context, id, action string) error {
	// No stop timeout is passed: Docker then uses the container's own
	// (docker run --stop-timeout, 10 s by default), which a database may need.
	if !slices.Contains(Actions, action) {
		return fmt.Errorf("unknown action %q", action)
	}
	verb := map[string]string{"pause": "pause", "resume": "unpause"}[action]
	return d.call(ctx, "POST", "/containers/"+url.PathEscape(id)+"/"+cmpOr(verb, action), nil, nil, nil)
}

func (d *Docker) Connect(ctx context.Context, id, network string) error {
	return d.call(ctx, "POST", "/networks/"+url.PathEscape(network)+"/connect", nil, map[string]any{"Container": id}, nil)
}

func (d *Docker) Disconnect(ctx context.Context, id, network string) error {
	return d.call(ctx, "POST", "/networks/"+url.PathEscape(network)+"/disconnect", nil, map[string]any{"Container": id}, nil)
}

func (d *Docker) CreateNetwork(ctx context.Context, name string) error {
	body := map[string]any{
		"Name":   name,
		"Driver": "bridge",
		"Labels": map[string]string{"io.skyguard.created": "dashboard"},
	}
	return d.call(ctx, "POST", "/networks/create", nil, body, nil)
}

func (d *Docker) Update(ctx context.Context, id string, s Settings) error {
	if s.Restart != nil && !slices.Contains(d.RestartPolicies(), *s.Restart) {
		return fmt.Errorf("unknown restart policy %q", *s.Restart)
	}
	if s.MemoryMB != nil && (*s.MemoryMB < 0 || (*s.MemoryMB > 0 && *s.MemoryMB < 6)) {
		return errors.New("a Docker memory limit is 0 (none) or at least 6 MB")
	}
	if s.CPUs != nil && *s.CPUs < 0 {
		return errors.New("the CPU limit cannot be negative")
	}
	in, err := d.inspect(ctx, id)
	if err != nil {
		return err
	}
	curMem, _ := in.HostConfig["Memory"].(float64)
	curCPU, _ := in.HostConfig["NanoCpus"].(float64)
	body := map[string]any{}
	removing := false
	if s.Restart != nil {
		body["RestartPolicy"] = map[string]any{"Name": *s.Restart}
	}
	if s.MemoryMB != nil && *s.MemoryMB<<20 != int64(curMem) {
		body["Memory"] = *s.MemoryMB << 20
		// Memory plus swap must not fall below memory; -1 leaves swap
		// unlimited, as docker run does.
		body["MemorySwap"] = -1
		removing = removing || *s.MemoryMB == 0
	}
	if s.CPUs != nil && int64(*s.CPUs*1e9) != int64(curCPU) {
		body["NanoCpus"] = int64(*s.CPUs * 1e9)
		removing = removing || *s.CPUs == 0
	}
	if len(body) == 0 {
		return nil
	}
	// Docker's update call reads 0 as "unchanged", so taking a limit away
	// needs a new container; everything else changes in place.
	if removing {
		return d.recreate(ctx, id, func(in *dockerInspect) error {
			for k, v := range body {
				in.HostConfig[k] = v
			}
			if _, ok := body["Memory"]; ok && body["Memory"] == int64(0) {
				in.HostConfig["MemorySwap"] = 0
			}
			return nil
		})
	}
	var res struct{ Warnings []string }
	if err := d.call(ctx, "POST", "/containers/"+url.PathEscape(id)+"/update", nil, body, &res); err != nil {
		return err
	}
	for _, w := range res.Warnings {
		d.logger.Warn("docker update", "container", id, "warning", w)
	}
	return nil
}

// SetPorts changes a container's published ports. Docker cannot change the
// ports of an existing container, so it is recreated.
func (d *Docker) SetPorts(ctx context.Context, id string, ports []Port) error {
	return d.recreate(ctx, id, func(in *dockerInspect) error {
		mode, _ := in.HostConfig["NetworkMode"].(string)
		if mode == "host" || mode == "none" || strings.HasPrefix(mode, "container:") {
			return fmt.Errorf("the container uses network mode %q, which publishes no ports", mode)
		}
		bindings := map[string][]map[string]string{}
		exposed, _ := in.Config["ExposedPorts"].(map[string]any)
		if exposed == nil {
			exposed = map[string]any{}
		}
		for _, p := range ports {
			key := fmt.Sprintf("%d/%s", p.ContainerPort, p.Proto)
			hp := ""
			if p.HostPort > 0 {
				hp = strconv.Itoa(p.HostPort)
			}
			bindings[key] = append(bindings[key], map[string]string{"HostIp": p.HostIP, "HostPort": hp})
			exposed[key] = map[string]any{}
		}
		in.HostConfig["PortBindings"] = bindings
		in.Config["ExposedPorts"] = exposed
		return nil
	})
}

// recreate replaces a container with a copy that mutate has changed, the way
// docker compose does it: same image, configuration, volumes and networks;
// the old one is renamed out of the way and only removed once the new one
// runs. Any failure puts the old container back.
func (d *Docker) recreate(ctx context.Context, id string, mutate func(*dockerInspect) error) error {
	in, err := d.inspect(ctx, id)
	if err != nil {
		return err
	}
	if in.State.Paused {
		return errors.New("unpause the container first")
	}
	// Stopping a --rm container deletes it, and there would be nothing to put back.
	if auto, _ := in.HostConfig["AutoRemove"].(bool); auto {
		return errors.New("the container was started with --rm, so stopping it would delete it; recreate it yourself with the new settings")
	}
	if err := mutate(in); err != nil {
		return err
	}
	mode, _ := in.HostConfig["NetworkMode"].(string)
	name := strings.TrimPrefix(in.Name, "/")

	// docker run names the host after the short ID; a copied one would carry the old ID.
	if h, _ := in.Config["Hostname"].(string); len(in.ID) >= 12 && h == in.ID[:12] {
		delete(in.Config, "Hostname")
	}
	ref, _ := in.Config["Image"].(string)
	in.Config["Image"] = d.imageRef(ctx, ref, in.Image)
	keepAnonymousVolumes(in.HostConfig, in.Mounts)

	primary, rest := splitNetworks(mode, in.NetworkSettings.Networks)
	body := maps.Clone(in.Config)
	body["HostConfig"] = in.HostConfig
	if primary != "" {
		body["NetworkingConfig"] = map[string]any{"EndpointsConfig": map[string]any{
			primary: endpointConfig(primary, in.NetworkSettings.Networks[primary], in.ID),
		}}
	}

	wasRunning := in.State.Running
	if wasRunning {
		if err := d.Action(ctx, in.ID, "stop"); err != nil {
			return fmt.Errorf("stopping the container: %w", err)
		}
	}
	// Rollback must finish even if the request that started this goes away.
	bg, cancel := context.WithTimeout(context.WithoutCancel(ctx), 90*time.Second)
	defer cancel()
	old := fmt.Sprintf("%s-skyguard-old-%d", name, time.Now().Unix())
	if err := d.call(ctx, "POST", "/containers/"+url.PathEscape(in.ID)+"/rename", url.Values{"name": {old}}, nil, nil); err != nil {
		if wasRunning {
			_ = d.Action(bg, in.ID, "start")
		}
		return fmt.Errorf("renaming the old container: %w", err)
	}
	restore := func(newID string, cause error) error {
		if newID != "" {
			_ = d.call(bg, "DELETE", "/containers/"+url.PathEscape(newID), url.Values{"force": {"1"}}, nil, nil)
		}
		rerr := d.call(bg, "POST", "/containers/"+url.PathEscape(in.ID)+"/rename", url.Values{"name": {name}}, nil, nil)
		if rerr == nil && wasRunning {
			rerr = d.Action(bg, in.ID, "start")
		}
		if rerr != nil {
			d.logger.Error("restoring a container after a failed port change", "container", name, "old_name", old, "error", rerr)
			return fmt.Errorf("%w; restoring the old container also failed: %v (it is named %s)", cause, rerr, old)
		}
		return fmt.Errorf("%w (the old container was put back unchanged)", cause)
	}

	var created struct {
		ID       string `json:"Id"`
		Warnings []string
	}
	if err := d.call(ctx, "POST", "/containers/create", url.Values{"name": {name}}, body, &created); err != nil {
		return restore("", fmt.Errorf("creating the container with the new ports: %w", err))
	}
	for _, net := range rest {
		cfg := endpointConfig(net, in.NetworkSettings.Networks[net], in.ID)
		if err := d.call(ctx, "POST", "/networks/"+url.PathEscape(net)+"/connect", nil,
			map[string]any{"Container": created.ID, "EndpointConfig": cfg}, nil); err != nil {
			return restore(created.ID, fmt.Errorf("connecting network %s: %w", net, err))
		}
	}
	if wasRunning {
		if err := d.call(ctx, "POST", "/containers/"+url.PathEscape(created.ID)+"/start", nil, nil, nil); err != nil {
			return restore(created.ID, fmt.Errorf("starting with the new ports: %w", err))
		}
	}
	if err := d.call(bg, "DELETE", "/containers/"+url.PathEscape(in.ID), url.Values{"force": {"1"}}, nil, nil); err != nil {
		d.logger.Warn("the old container could not be removed after a port change", "name", old, "error", err)
	}
	return nil
}

// imageRef keeps the image's name when it still points at the image the
// container runs; otherwise (the tag moved since) the exact image ID is used,
// so a port change never doubles as an upgrade.
func (d *Docker) imageRef(ctx context.Context, ref, imageID string) string {
	if ref == "" || strings.HasPrefix(ref, "sha256:") || !imageRefRE.MatchString(ref) {
		return cmpOr(imageID, ref)
	}
	var img struct {
		ID string `json:"Id"`
	}
	if err := d.call(ctx, "GET", "/images/"+ref+"/json", nil, nil, &img); err != nil || img.ID != imageID {
		return cmpOr(imageID, ref)
	}
	return ref
}

var imageRefRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/:@-]*$`)

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// keepAnonymousVolumes carries volumes that are not named in the container's
// own configuration (an image's VOLUME, `-v /data`) over by name, as docker
// compose does; otherwise the new container would start with empty ones.
func keepAnonymousVolumes(hc map[string]any, mounts []dockerMount) {
	covered := map[string]bool{}
	binds, _ := hc["Binds"].([]any)
	for _, b := range binds {
		s, _ := b.(string)
		if parts := strings.Split(s, ":"); len(parts) >= 2 {
			covered[parts[1]] = true
		}
	}
	if ms, ok := hc["Mounts"].([]any); ok {
		for _, m := range ms {
			mm, _ := m.(map[string]any)
			if t, _ := mm["Target"].(string); t != "" {
				covered[t] = true
			}
		}
	}
	for _, m := range mounts {
		if m.Type != "volume" || m.Name == "" || covered[m.Destination] {
			continue
		}
		b := m.Name + ":" + m.Destination
		if !m.RW {
			b += ":ro"
		}
		binds = append(binds, b)
	}
	if len(binds) > 0 {
		hc["Binds"] = binds
	}
}

// splitNetworks returns the network the container is created on (the one its
// network mode names) and the ones it is connected to afterwards.
func splitNetworks(mode string, nets map[string]dockerEndpoint) (string, []string) {
	names := slices.Sorted(maps.Keys(nets))
	primary := ""
	if _, ok := nets[mode]; ok {
		primary = mode
	} else if mode == "default" || mode == "" {
		if _, ok := nets["bridge"]; ok {
			primary = "bridge"
		}
	}
	if primary == "" && len(names) > 0 {
		primary = names[0]
	}
	var rest []string
	for _, n := range names {
		if n != primary && !pseudoNetworks[n] {
			rest = append(rest, n)
		}
	}
	return primary, rest
}

func endpointConfig(network string, ep dockerEndpoint, oldID string) map[string]any {
	cfg := map[string]any{}
	if ep.IPAMConfig != nil && (ep.IPAMConfig.IPv4Address != "" || ep.IPAMConfig.IPv6Address != "") {
		cfg["IPAMConfig"] = ep.IPAMConfig
	}
	if network != "bridge" { // the default bridge takes no aliases
		var aliases []string
		for _, a := range ep.Aliases {
			if len(oldID) < 12 || a != oldID[:12] {
				aliases = append(aliases, a)
			}
		}
		if len(aliases) > 0 {
			cfg["Aliases"] = aliases
		}
	}
	if len(ep.Links) > 0 {
		cfg["Links"] = ep.Links
	}
	if len(ep.DriverOpts) > 0 {
		cfg["DriverOpts"] = ep.DriverOpts
	}
	return cfg
}

// detectSelfID finds the ID of the Docker container SkyGuard runs in, if any.
// Docker bind-mounts /etc/hostname from the container's own directory; the
// cgroup path names the container when the cgroup namespace is the host's.
func detectSelfID() string {
	if b, err := os.ReadFile("/proc/self/mountinfo"); err == nil {
		if id := selfFromMountinfo(b); id != "" {
			return id
		}
	}
	if b, err := os.ReadFile("/proc/self/cgroup"); err == nil {
		if m := cgroupIDRE.FindSubmatch(b); m != nil {
			return string(m[1])
		}
	}
	return ""
}

var (
	containerDirRE = regexp.MustCompile(`/containers/([0-9a-f]{64})/`)
	cgroupIDRE     = regexp.MustCompile(`docker[-/]([0-9a-f]{64})`)
)

func selfFromMountinfo(b []byte) string {
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) > 4 && f[4] == "/etc/hostname" {
			if m := containerDirRE.FindStringSubmatch(f[3]); m != nil {
				return m[1]
			}
		}
	}
	return ""
}

// raw is call for endpoints that do not answer in JSON (logs, image pulls).
func (d *Docker) raw(ctx context.Context, method, path string, q url.Values) (*response, error) {
	prefix, err := d.negotiate(ctx)
	if err != nil {
		return nil, err
	}
	resp, err := d.c.do(ctx, method, prefix+path, q, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("docker: %w", err)
	}
	if resp.status >= 300 {
		var e struct{ Message string }
		_ = json.Unmarshal(resp.body, &e)
		return nil, &APIError{Engine: "docker", Status: resp.status, Message: cmpOr(e.Message, strings.TrimSpace(string(resp.body)))}
	}
	return resp, nil
}

// pull fetches an image unless it is already there. The daemon streams
// progress as JSON lines and reports a failure as a line with "error",
// still under HTTP 200.
func (d *Docker) pull(ctx context.Context, ref string) error {
	var img struct{}
	if err := d.call(ctx, "GET", "/images/"+ref+"/json", nil, nil, &img); err == nil {
		return nil
	}
	from := ref
	if last := from[strings.LastIndex(from, "/")+1:]; !strings.ContainsAny(last, ":@") {
		from += ":latest" // without a tag the API would pull every tag
	}
	resp, err := d.raw(ctx, "POST", "/images/create", url.Values{"fromImage": {from}})
	if err != nil {
		return fmt.Errorf("pulling %s: %w", ref, err)
	}
	sc := bufio.NewScanner(bytes.NewReader(resp.body))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		var line struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(sc.Bytes(), &line) == nil && line.Error != "" {
			return fmt.Errorf("pulling %s: %s", ref, line.Error)
		}
	}
	return nil
}

func (d *Docker) Create(ctx context.Context, spec CreateSpec) (string, error) {
	if !imageRefRE.MatchString(spec.Image) {
		return "", fmt.Errorf("%q is not an image reference", spec.Image)
	}
	if spec.VM {
		return "", errors.New("Docker runs containers only")
	}
	if spec.Restart != "" && !slices.Contains(d.RestartPolicies(), spec.Restart) {
		return "", fmt.Errorf("unknown restart policy %q", spec.Restart)
	}
	if spec.MemoryMB > 0 && spec.MemoryMB < 6 {
		return "", errors.New("a Docker memory limit is 0 (none) or at least 6 MB")
	}
	if err := d.pull(ctx, spec.Image); err != nil {
		return "", err
	}
	bindings := map[string][]map[string]string{}
	exposed := map[string]any{}
	for _, p := range spec.Ports {
		key := fmt.Sprintf("%d/%s", p.ContainerPort, p.Proto)
		hp := ""
		if p.HostPort > 0 {
			hp = strconv.Itoa(p.HostPort)
		}
		bindings[key] = append(bindings[key], map[string]string{"HostIp": p.HostIP, "HostPort": hp})
		exposed[key] = map[string]any{}
	}
	hc := map[string]any{
		"PortBindings":  bindings,
		"RestartPolicy": map[string]any{"Name": cmpOr(spec.Restart, "no")},
	}
	if spec.MemoryMB > 0 {
		hc["Memory"], hc["MemorySwap"] = spec.MemoryMB<<20, -1
	}
	if spec.CPUs > 0 {
		hc["NanoCpus"] = int64(spec.CPUs * 1e9)
	}
	if spec.Network != "" {
		hc["NetworkMode"] = spec.Network
	}
	body := map[string]any{
		"Image":        spec.Image,
		"Env":          spec.Env,
		"ExposedPorts": exposed,
		"Labels":       map[string]string{"io.skyguard.created": "dashboard"},
		"HostConfig":   hc,
	}
	var created struct {
		ID string `json:"Id"`
	}
	if err := d.call(ctx, "POST", "/containers/create", url.Values{"name": {spec.Name}}, body, &created); err != nil {
		return "", err
	}
	if spec.Start {
		if err := d.Action(ctx, created.ID, "start"); err != nil {
			return created.ID, fmt.Errorf("created, but it did not start: %w", err)
		}
	}
	return created.ID, nil
}

// Remove deletes a container (stopping it first). Named volumes always
// stay; anonymous ones go only when volumes is set.
func (d *Docker) Remove(ctx context.Context, id string, volumes bool) error {
	q := url.Values{"force": {"1"}}
	if volumes {
		q.Set("v", "1")
	}
	return d.call(ctx, "DELETE", "/containers/"+url.PathEscape(id), q, nil, nil)
}

// Logs returns the last lines of a container's stdout and stderr.
func (d *Docker) Logs(ctx context.Context, id string, lines int) (string, error) {
	resp, err := d.raw(ctx, "GET", "/containers/"+url.PathEscape(id)+"/logs", url.Values{
		"stdout": {"1"}, "stderr": {"1"}, "timestamps": {"1"}, "tail": {strconv.Itoa(lines)},
	})
	if err != nil {
		return "", err
	}
	if strings.Contains(resp.header.Get("Content-Type"), "multiplexed") || looksMultiplexed(resp.body) {
		return demux(resp.body), nil
	}
	return string(resp.body), nil // a TTY container: one raw stream
}

// looksMultiplexed recognises Docker's stream framing on daemons that do
// not label it: a stream byte of 0-2, then three zero bytes.
func looksMultiplexed(b []byte) bool {
	return len(b) >= 8 && b[0] <= 2 && b[1] == 0 && b[2] == 0 && b[3] == 0
}

// demux strips the 8-byte frame headers of a stdout/stderr stream.
func demux(b []byte) string {
	var out strings.Builder
	for len(b) >= 8 {
		n := int(b[4])<<24 | int(b[5])<<16 | int(b[6])<<8 | int(b[7])
		b = b[8:]
		if n > len(b) {
			n = len(b)
		}
		out.Write(b[:n])
		b = b[n:]
	}
	return out.String()
}

func (d *Docker) DeleteNetwork(ctx context.Context, name string) error {
	if name == "bridge" || pseudoNetworks[name] {
		return fmt.Errorf("%s is one of Docker's own networks", name)
	}
	return d.call(ctx, "DELETE", "/networks/"+url.PathEscape(name), nil, nil, nil)
}

// Socket is the unix socket the client talks to.
func (x *Docker) Socket() string { return x.c.socket }
