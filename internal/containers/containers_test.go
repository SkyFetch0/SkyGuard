package containers

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// serveUnix runs h on a unix socket in a temporary directory.
func serveUnix(t *testing.T, h http.Handler) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "api.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(h)
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)
	return sock
}

func TestParsePorts(t *testing.T) {
	ps, err := ParsePorts("8080:80, 127.0.0.1:8443:443/tcp\n[::1]:5353:53/udp 0:9000")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, p := range ps {
		got = append(got, p.String())
	}
	if strings.Join(got, " ") != "8080:80/tcp 127.0.0.1:8443:443/tcp [::1]:5353:53/udp 0:9000/tcp" {
		t.Errorf("parsed %v", got)
	}
	if ps, _ := ParsePorts("0.0.0.0:80:80"); ps[0].HostIP != "" {
		t.Errorf("wildcard host kept as %q", ps[0].HostIP)
	}
	for _, bad := range []string{"80", "80:80/sctp", "70000:80", "a:80", "1.2.3:80:80", "80:80,80:81"} {
		if _, err := ParsePorts(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if ps, err := ParsePorts("  "); err != nil || len(ps) != 0 {
		t.Errorf("empty spec: %v %v", ps, err)
	}
}

func TestSelfFromMountinfo(t *testing.T) {
	id := strings.Repeat("ab", 32)
	in := "601 590 0:52 / / rw - overlay overlay rw\n" +
		"612 601 8:1 /var/lib/docker/containers/" + id + "/hostname /etc/hostname rw,relatime - ext4 /dev/sda1 rw\n"
	if got := selfFromMountinfo([]byte(in)); got != id {
		t.Errorf("got %q", got)
	}
	// On the host, the shm mounts of other containers must not match.
	host := "700 25 0:60 / /var/lib/docker/containers/" + id + "/mounts/shm rw - tmpfs shm rw\n"
	if got := selfFromMountinfo([]byte(host)); got != "" {
		t.Errorf("host matched %q", got)
	}
}

// fakeDocker is the slice of the Engine API the dashboard uses.
type fakeDocker struct {
	mu      sync.Mutex
	calls   []string
	running map[string]bool
}

func (f *fakeDocker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, r.Method+" "+r.URL.Path)
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.URL.Path == "/version":
		_, _ = io.WriteString(w, `{"Version":"29.0.0","ApiVersion":"1.52","MinAPIVersion":"1.44"}`)
	case r.URL.Path == "/v1.47/containers/json":
		_, _ = io.WriteString(w, `[
		  {"Id":"aaa","Names":["/web"],"Image":"nginx","State":"running","Status":"Up 2 hours","Created":1700000000,
		   "Ports":[{"IP":"0.0.0.0","PrivatePort":80,"PublicPort":80,"Type":"tcp"},{"IP":"::","PrivatePort":80,"PublicPort":80,"Type":"tcp"},{"PrivatePort":443,"Type":"tcp"}],
		   "Labels":{"com.docker.compose.project":"site"},"HostConfig":{"NetworkMode":"site_default"},
		   "NetworkSettings":{"Networks":{"site_default":{"IPAddress":"172.18.0.2"}}}},
		  {"Id":"bbb","Names":["/sky"],"Image":"skyguard","State":"running","Status":"Up","Created":1700000000,
		   "HostConfig":{"NetworkMode":"host"},"NetworkSettings":{"Networks":{"host":{}}}}]`)
	case r.URL.Path == "/v1.47/networks":
		_, _ = io.WriteString(w, `[{"Name":"bridge","Id":"n0","Driver":"bridge","Scope":"local"},{"Name":"host","Id":"n1","Driver":"host","Scope":"local"},
		  {"Name":"site_default","Id":"n2","Driver":"bridge","Scope":"local","IPAM":{"Config":[{"Subnet":"172.18.0.0/16"}]}},
		  {"Name":"swarm","Id":"n3","Driver":"overlay","Scope":"swarm"}]`)
	case strings.HasPrefix(r.URL.Path, "/v1.47/containers/") && strings.HasSuffix(r.URL.Path, "/json"):
		id := strings.Split(r.URL.Path, "/")[3]
		name := map[string]string{"aaa": "web", "web": "web", "bbb": "sky", "sky": "sky"}[id]
		if name == "" {
			w.WriteHeader(404)
			_, _ = io.WriteString(w, `{"message":"No such container: `+id+`"}`)
			return
		}
		cid := map[string]string{"web": "aaa", "sky": "bbb"}[name]
		mode := map[string]string{"web": "site_default", "sky": "host"}[name]
		_ = json.NewEncoder(w).Encode(map[string]any{"Id": cid, "Name": "/" + name, "State": map[string]any{"Status": "running", "Running": true},
			"Config":     map[string]any{"Image": "nginx", "Env": []string{"A=1"}},
			"HostConfig": map[string]any{"NetworkMode": mode, "Memory": 64 << 20, "NanoCpus": 1.5e9, "RestartPolicy": map[string]any{"Name": "always"}, "PortBindings": map[string]any{"80/tcp": []any{map[string]any{"HostIp": "", "HostPort": "80"}}}},
		})
	case strings.HasSuffix(r.URL.Path, "/stop") || strings.HasSuffix(r.URL.Path, "/start"):
		id := strings.Split(r.URL.Path, "/")[3]
		if strings.HasSuffix(r.URL.Path, "/start") && f.running[id] {
			w.WriteHeader(304)
			return
		}
		f.running[id] = strings.HasSuffix(r.URL.Path, "/start")
		w.WriteHeader(204)
	case strings.HasSuffix(r.URL.Path, "/connect"):
		w.WriteHeader(200)
	default:
		w.WriteHeader(500)
		_, _ = io.WriteString(w, `{"message":"unexpected `+r.Method+` `+r.URL.Path+`"}`)
	}
}

func TestDockerAgainstFakeAPI(t *testing.T) {
	f := &fakeDocker{running: map[string]bool{"aaa": true}}
	d := NewDocker(serveUnix(t, f), quiet())
	d.selfID = "bbb"
	ctx := context.Background()

	if v, err := d.Version(ctx); err != nil || v != "29.0.0" {
		t.Fatalf("version %q %v", v, err)
	}
	cs, ns, err := d.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]Container{}
	for _, c := range cs {
		byName[c.Name] = c
	}
	web := byName["web"]
	if web.Name != "web" || web.Project != "site" || len(web.Ports) != 1 || web.Ports[0].String() != "80:80/tcp" {
		t.Errorf("web = %+v (the IPv4/IPv6 wildcard pair must be one port)", web)
	}
	if strings.Join(web.Exposed, ",") != "80/tcp,443/tcp" {
		t.Errorf("exposed %v", web.Exposed)
	}
	if sky := byName["sky"]; !sky.Self || sky.NetworkMode != "host" || len(sky.Networks) != 0 {
		t.Errorf("sky = %+v", sky)
	}
	var names []string
	for _, n := range ns {
		names = append(names, n.Name)
		if n.Name == "swarm" && n.Attachable {
			t.Error("a non-attachable swarm overlay is attachable")
		}
	}
	if strings.Join(names, ",") != "site_default,swarm,bridge" {
		t.Errorf("networks %v (in use first, the default bridge last, host hidden)", names)
	}

	in, err := d.Inspect(ctx, "aaa")
	if err != nil || in.Restart != "always" || in.MemoryMB != 64 || in.CPUs != 1.5 || in.EnvCount != 1 {
		t.Fatalf("inspect %+v %v", in, err)
	}

	m := NewManager([]Engine{d}, false, quiet())
	if _, err := m.Action(ctx, "docker", "bbb", "stop"); !errors.Is(err, ErrSelf) {
		t.Errorf("stopping SkyGuard's own container: %v", err)
	}
	if _, err := m.Connect(ctx, "docker", "bbb", "site_default", false); err == nil || !strings.Contains(err.Error(), "network mode host") {
		t.Errorf("connecting a host-network container: %v", err)
	}
	if _, err := m.Action(ctx, "docker", "aaa", "start"); err != nil {
		t.Errorf("start of a running container (304) is not an error: %v", err)
	}
	c, err := m.Action(ctx, "docker", "aaa", "stop")
	if err != nil || c.Name != "web" {
		t.Fatalf("stop: %+v %v", c, err)
	}
	if _, err := m.Inspect(ctx, "docker", "nope"); err == nil || !strings.Contains(err.Error(), "No such container") {
		t.Errorf("missing container: %v", err)
	}
	if _, err := m.Connect(ctx, "docker", "aaa", "bad name!", false); err == nil {
		t.Error("invalid network name accepted")
	}

	// Ports SkyGuard listens on are refused before Docker is asked.
	m.Reserved = func() []Reserved { return []Reserved{{Port: 8080, Proto: "tcp", Owner: "honeypot fake-http-alt"}} }
	if _, err := m.SetPorts(ctx, "docker", "aaa", []Port{{HostPort: 8080, ContainerPort: 80, Proto: "tcp"}}); err == nil || !strings.Contains(err.Error(), "fake-http-alt") {
		t.Errorf("reserved port: %v", err)
	}

	ro := NewManager([]Engine{d}, true, quiet())
	if _, err := ro.Action(ctx, "docker", "aaa", "start"); !errors.Is(err, ErrReadOnly) {
		t.Errorf("read-only: %v", err)
	}
	if _, err := ro.Inspect(ctx, "docker", "aaa"); err != nil {
		t.Errorf("read-only mode still reads: %v", err)
	}
}

func TestSnapshotReportsUnavailableEngines(t *testing.T) {
	d := NewDocker(filepath.Join(t.TempDir(), "missing.sock"), quiet())
	snap := NewManager([]Engine{d}, false, quiet()).Snapshot(context.Background())
	if len(snap.Engines) != 1 || snap.Engines[0].Available || !strings.Contains(snap.Engines[0].Error, "does not exist") {
		t.Errorf("engines %+v", snap.Engines)
	}
	if snap.Containers == nil || snap.Networks == nil {
		t.Error("lists must be empty, not null, for the dashboard")
	}
}

// fakeIncus serves one instance and records the devices written back.
type fakeIncus struct {
	mu      sync.Mutex
	devices map[string]map[string]string
	ifMatch string
}

func (f *fakeIncus) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	sync := func(meta any) {
		_ = json.NewEncoder(w).Encode(map[string]any{"type": "sync", "status_code": 200, "metadata": meta})
	}
	switch {
	case r.URL.Path == "/1.0":
		sync(map[string]any{"auth": "trusted", "environment": map[string]any{"server_version": "6.0.0"}})
	case r.URL.Path == "/1.0/instances" && r.Method == "GET":
		sync([]any{f.instance()})
	case r.URL.Path == "/1.0/networks":
		sync([]any{map[string]any{"name": "incusbr0", "type": "bridge", "managed": true, "config": map[string]string{"ipv4.address": "10.0.0.1/24"}},
			map[string]any{"name": "eth0", "type": "physical", "managed": false}})
	case r.URL.Path == "/1.0/instances/c1" && r.Method == "GET":
		w.Header().Set("ETag", `"v1"`)
		sync(f.instance())
	case r.URL.Path == "/1.0/instances/c1" && r.Method == "PUT":
		f.ifMatch = r.Header.Get("If-Match")
		var put incusPut
		_ = json.NewDecoder(r.Body).Decode(&put)
		f.devices = put.Devices
		_ = json.NewEncoder(w).Encode(map[string]any{"type": "async", "operation": "/1.0/operations/op1"})
	case r.URL.Path == "/1.0/operations/op1/wait":
		sync(map[string]any{"status": "Success"})
	case r.URL.Path == "/1.0/instances/c1/state":
		_ = json.NewEncoder(w).Encode(map[string]any{"type": "async", "operation": "/1.0/operations/op2"})
	case r.URL.Path == "/1.0/operations/op2/wait":
		sync(map[string]any{"status": "Failure", "err": "The instance is already stopped"})
	default:
		w.WriteHeader(404)
		_ = json.NewEncoder(w).Encode(map[string]any{"type": "error", "error": "not found", "error_code": 404})
	}
}

func (f *fakeIncus) instance() map[string]any {
	expanded := map[string]map[string]string{
		"eth0": {"type": "nic", "network": "incusbr0", "name": "eth0"}, // from the default profile
		"root": {"type": "disk", "pool": "default", "path": "/"},
	}
	for k, v := range f.devices {
		expanded[k] = v
	}
	return map[string]any{"name": "c1", "status": "Running", "type": "container",
		"config": map[string]string{}, "expanded_config": map[string]string{"image.description": "Alpine 3.22", "limits.memory": "512MiB"},
		"devices": f.devices, "expanded_devices": expanded, "profiles": []string{"default"},
		"state": map[string]any{"network": map[string]any{"eth0": map[string]any{"addresses": []any{
			map[string]string{"family": "inet6", "address": "fe80::1", "scope": "link"},
			map[string]string{"family": "inet", "address": "10.0.0.5", "scope": "global"}}}}}}
}

func TestIncusAgainstFakeAPI(t *testing.T) {
	f := &fakeIncus{devices: map[string]map[string]string{
		"web": {"type": "proxy", "listen": "tcp:0.0.0.0:8080", "connect": "tcp:127.0.0.1:80"},
		"rng": {"type": "proxy", "listen": "tcp:0.0.0.0:9000-9010", "connect": "tcp:127.0.0.1:9000-9010"},
	}}
	x := NewIncus(serveUnix(t, f), "", quiet())
	ctx := context.Background()
	cs, ns, err := x.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	c := cs[0]
	if c.Image != "Alpine 3.22" || len(c.Networks) != 1 || c.Networks[0].IP != "10.0.0.5" || len(c.Ports) != 1 || c.Ports[0].String() != "8080:80/tcp" {
		t.Errorf("c1 = %+v", c)
	}
	if len(ns) != 1 || ns[0].Name != "incusbr0" || ns[0].Members[0] != "c1" {
		t.Errorf("networks %+v (unmanaged host interfaces hidden)", ns)
	}

	if err := x.Connect(ctx, "c1", "incusbr0"); err == nil {
		t.Error("joining a network twice accepted")
	}
	if err := x.Connect(ctx, "c1", "backend"); err != nil {
		t.Fatal(err)
	}
	if d := f.devices["eth1"]; d["network"] != "backend" || d["name"] != "eth1" || f.ifMatch != `"v1"` {
		t.Errorf("nic %v, If-Match %q", d, f.ifMatch)
	}
	// A nic inherited from a profile is masked, not deleted.
	if err := x.Disconnect(ctx, "c1", "incusbr0"); err != nil {
		t.Fatal(err)
	}
	if f.devices["eth0"]["type"] != "none" {
		t.Errorf("profile nic not masked: %v", f.devices["eth0"])
	}

	ports, _ := ParsePorts("8443:443")
	if err := x.SetPorts(ctx, "c1", ports); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.devices["web"]; ok {
		t.Error("the removed port's device is still there")
	}
	if d := f.devices["proxy-tcp-8443"]; d["listen"] != "tcp:0.0.0.0:8443" || d["connect"] != "tcp:127.0.0.1:443" {
		t.Errorf("new proxy %v", d)
	}
	if _, ok := f.devices["rng"]; !ok {
		t.Error("a port-range device the panel does not show was removed")
	}

	if err := x.Action(ctx, "c1", "stop"); err == nil || !strings.Contains(err.Error(), "already stopped") {
		t.Errorf("failed operation: %v", err)
	}
	if err := x.CreateNetwork(ctx, "a-very-long-network"); err == nil {
		t.Error("over-long Incus network name accepted")
	}
	if parseMemoryMB("2GiB") != 2048 || parseMemoryMB("1GB") != 954 || parseMemoryMB("50%") != 0 {
		t.Error("memory parsing")
	}
}

func TestHostPortsConflicts(t *testing.T) {
	snap := Snapshot{Containers: []Container{
		{Engine: "docker", Name: "npm", Running: true, Ports: []Port{{HostPort: 80, ContainerPort: 80, Proto: "tcp"}, {HostPort: 443, ContainerPort: 443, Proto: "tcp"}}},
		{Engine: "docker", Name: "old", Running: false, Ports: []Port{{HostPort: 443, ContainerPort: 443, Proto: "tcp"}}},
		{Engine: "incus", Name: "dns", Running: true, Ports: []Port{{HostIP: "127.0.0.1", HostPort: 53, ContainerPort: 53, Proto: "udp"}}},
	}}
	reserved := []Reserved{
		{Port: 80, Proto: "tcp", Owner: "honeypot fake-http", Failed: "address already in use"},
		{Port: 21, Proto: "tcp", Owner: "honeypot fake-ftp"},
	}
	uses := HostPorts(snap, reserved)
	if uses[0].Port != 80 || !uses[0].Conflict || uses[0].Owners[0].Kind != "skyguard" {
		t.Errorf("the honeypot that lost port 80 to the proxy comes first: %+v", uses[0])
	}
	for _, u := range uses[1:] {
		if u.Conflict {
			t.Errorf("port %d flagged (a stopped container claims nothing)", u.Port)
		}
	}
	if len(uses) != 4 {
		t.Errorf("uses %+v", uses)
	}
}
