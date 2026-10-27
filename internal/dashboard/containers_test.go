package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/skyguard/skyguard/internal/config"
	"github.com/skyguard/skyguard/internal/containers"
	"github.com/skyguard/skyguard/internal/firewall"
	"github.com/skyguard/skyguard/internal/storage"
)

// memEngine is an in-memory container engine.
type memEngine struct {
	cs   map[string]*containers.Container
	nets map[string]bool
}

func newMemEngine() *memEngine {
	return &memEngine{
		cs: map[string]*containers.Container{
			"npm": {Engine: "docker", ID: "npm", Name: "npm", State: "running", Running: true,
				Ports:    []containers.Port{{HostPort: 80, ContainerPort: 80, Proto: "tcp"}, {HostPort: 443, ContainerPort: 443, Proto: "tcp"}},
				Networks: []containers.Endpoint{{Network: "proxy"}}},
			"app": {Engine: "docker", ID: "app", Name: "app", State: "running", Running: true, Networks: []containers.Endpoint{{Network: "bridge"}}},
		},
		nets: map[string]bool{"bridge": true, "proxy": true},
	}
}

func (m *memEngine) Name() string                            { return "docker" }
func (m *memEngine) Version(context.Context) (string, error) { return "29.0.0", nil }
func (m *memEngine) RestartPolicies() []string               { return []string{"no", "always"} }
func (m *memEngine) List(context.Context) ([]containers.Container, []containers.Network, error) {
	var cs []containers.Container
	for _, id := range []string{"app", "npm"} {
		cs = append(cs, *m.cs[id])
	}
	var ns []containers.Network
	for n := range m.nets {
		ns = append(ns, containers.Network{Engine: "docker", ID: n, Name: n, Driver: "bridge", Attachable: true, Members: []string{}})
	}
	return cs, ns, nil
}
func (m *memEngine) Inspect(_ context.Context, id string) (*containers.Container, error) {
	c, ok := m.cs[id]
	if !ok {
		return nil, &containers.APIError{Engine: "docker", Status: 404, Message: "No such container: " + id}
	}
	cp := *c
	return &cp, nil
}
func (m *memEngine) Action(_ context.Context, id, a string) error {
	m.cs[id].Running = a != "stop"
	return nil
}
func (m *memEngine) Connect(_ context.Context, id, n string) error {
	if !m.nets[n] {
		return &containers.APIError{Engine: "docker", Status: 404, Message: "network " + n + " not found"}
	}
	m.cs[id].Networks = append(m.cs[id].Networks, containers.Endpoint{Network: n})
	return nil
}
func (m *memEngine) Disconnect(context.Context, string, string) error { return nil }
func (m *memEngine) CreateNetwork(_ context.Context, n string) error {
	if m.nets[n] {
		return errors.New("network with name " + n + " already exists")
	}
	m.nets[n] = true
	return nil
}
func (m *memEngine) SetPorts(_ context.Context, id string, ps []containers.Port) error {
	m.cs[id].Ports = ps
	return nil
}
func (m *memEngine) Update(_ context.Context, id string, s containers.Settings) error {
	if s.MemoryMB != nil {
		m.cs[id].MemoryMB = *s.MemoryMB
	}
	return nil
}

func newContainerDashboard(t *testing.T, readOnly bool) (http.Handler, *memEngine) {
	t.Helper()
	db, err := storage.New(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	settings, _ := db.LoadSettings(storage.AutoBanSettings{Enabled: true, ScoreThreshold: 50, BanDuration: time.Hour})
	fw, _ := firewall.New("none", firewall.Options{}, logger)
	d := New(config.DashboardConfig{Listen: "127.0.0.1:0", Auth: config.DashboardAuth{Username: "admin", Password: "correct horse"}},
		db, fw, settings, &fakeBans{db: db}, logger)
	eng := newMemEngine()
	m := containers.NewManager([]containers.Engine{eng}, readOnly, logger)
	// The fake-http honeypot lost port 80 to the reverse proxy.
	m.Reserved = func() []containers.Reserved {
		return []containers.Reserved{{Port: 80, Proto: "tcp", Owner: "honeypot fake-http", Failed: "address already in use"}, {Port: 21, Proto: "tcp", Owner: "honeypot fake-ftp"}}
	}
	d.SetContainers(m)
	return d.routes(), eng
}

var csrfHeader = map[string]string{"X-SkyGuard-Request": "1"}

func TestContainersDisabled(t *testing.T) {
	h, _ := newTestDashboard(t)
	rr := do(h, "GET", "/api/containers", nil, true, nil)
	if rr.Code != 200 || rr.Body.String() != "{\"enabled\":false}\n" {
		t.Errorf("%d %s", rr.Code, rr.Body)
	}
	rr = do(h, "POST", "/api/containers/action", url.Values{"engine": {"docker"}, "id": {"x"}, "action": {"stop"}}, true, csrfHeader)
	if rr.Code != 404 {
		t.Errorf("change with management off: %d", rr.Code)
	}
}

func TestContainersAPI(t *testing.T) {
	h, eng := newContainerDashboard(t, false)

	if rr := do(h, "GET", "/api/containers", nil, false, nil); rr.Code != 401 {
		t.Fatalf("unauthenticated list: %d", rr.Code)
	}
	rr := do(h, "GET", "/api/containers", nil, true, nil)
	var list struct {
		Enabled    bool
		Containers []containers.Container
		HostPorts  []containers.PortUse `json:"host_ports"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &list); err != nil || !list.Enabled || len(list.Containers) != 2 {
		t.Fatalf("list %d %s", rr.Code, rr.Body)
	}
	if hp := list.HostPorts[0]; hp.Port != 80 || !hp.Conflict || len(hp.Owners) != 2 {
		t.Errorf("the honeypot's lost port 80 must lead the host ports: %+v", hp)
	}

	// State changes need the CSRF header.
	form := url.Values{"engine": {"docker"}, "id": {"app"}, "network": {"proxy"}}
	if rr := do(h, "POST", "/api/containers/connect", form, true, nil); rr.Code != 403 {
		t.Errorf("connect without the CSRF header: %d", rr.Code)
	}
	rr = do(h, "POST", "/api/containers/connect", form, true, csrfHeader)
	var after containers.Container
	_ = json.Unmarshal(rr.Body.Bytes(), &after)
	if rr.Code != 200 || len(after.Networks) != 2 {
		t.Errorf("connect: %d %s", rr.Code, rr.Body)
	}
	form.Set("network", "backend")
	form.Set("create", "1")
	if rr := do(h, "POST", "/api/containers/connect", form, true, csrfHeader); rr.Code != 200 || !eng.nets["backend"] {
		t.Errorf("connect to a new network: %d %s", rr.Code, rr.Body)
	}

	// Ports: parsed, conflict-checked, applied.
	ports := url.Values{"engine": {"docker"}, "id": {"app"}, "ports": {"8080:80"}}
	if rr := do(h, "POST", "/api/containers/ports", ports, true, csrfHeader); rr.Code != 200 || eng.cs["app"].Ports[0].HostPort != 8080 {
		t.Errorf("ports: %d %s", rr.Code, rr.Body)
	}
	ports.Set("ports", "443:443")
	if rr := do(h, "POST", "/api/containers/ports", ports, true, csrfHeader); rr.Code != 409 {
		t.Errorf("a port another container publishes: %d %s", rr.Code, rr.Body)
	}
	ports.Set("ports", "21:21")
	if rr := do(h, "POST", "/api/containers/ports", ports, true, csrfHeader); rr.Code != 409 {
		t.Errorf("a port a SkyGuard honeypot listens on: %d %s", rr.Code, rr.Body)
	}
	ports.Set("ports", "80:80/sctp")
	if rr := do(h, "POST", "/api/containers/ports", ports, true, csrfHeader); rr.Code != 400 {
		t.Errorf("a malformed port list: %d", rr.Code)
	}

	settings := url.Values{"engine": {"docker"}, "id": {"app"}, "memory_mb": {"256"}}
	if rr := do(h, "POST", "/api/containers/settings", settings, true, csrfHeader); rr.Code != 200 || eng.cs["app"].MemoryMB != 256 {
		t.Errorf("settings: %d %s", rr.Code, rr.Body)
	}
	settings.Set("memory_mb", "lots")
	if rr := do(h, "POST", "/api/containers/settings", settings, true, csrfHeader); rr.Code != 400 {
		t.Errorf("bad memory: %d", rr.Code)
	}

	if rr := do(h, "GET", "/api/containers/inspect?engine=docker&id=ghost", nil, true, nil); rr.Code != 404 {
		t.Errorf("missing container: %d", rr.Code)
	}
	if rr := do(h, "POST", "/api/containers/action", url.Values{"engine": {"docker"}, "id": {"npm"}, "action": {"stop"}}, true, csrfHeader); rr.Code != 200 || eng.cs["npm"].Running {
		t.Errorf("stop: %d %s", rr.Code, rr.Body)
	}
	if rr := do(h, "POST", "/api/containers/action", url.Values{"engine": {"docker"}, "id": {"npm"}, "action": {"rm -rf"}}, true, csrfHeader); rr.Code != 409 {
		t.Errorf("unknown action: %d", rr.Code)
	}
	if rr := do(h, "POST", "/api/containers/networks", url.Values{"engine": {"docker"}, "name": {"../etc"}}, true, csrfHeader); rr.Code != 409 {
		t.Errorf("bad network name: %d", rr.Code)
	}
	if rr := do(h, "POST", "/api/containers/networks", url.Values{"engine": {"docker"}, "name": {"db"}}, true, csrfHeader); rr.Code != 200 {
		t.Errorf("create network: %d %s", rr.Code, rr.Body)
	}

	// /api/info tells the client the screen is live.
	rr = do(h, "GET", "/api/info", nil, true, nil)
	var info map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &info)
	if info["containers"] != true {
		t.Errorf("info %v", info)
	}
}

func TestContainersReadOnly(t *testing.T) {
	h, eng := newContainerDashboard(t, true)
	rr := do(h, "POST", "/api/containers/action", url.Values{"engine": {"docker"}, "id": {"npm"}, "action": {"stop"}}, true, csrfHeader)
	if rr.Code != 403 || !eng.cs["npm"].Running {
		t.Errorf("read-only stop: %d %s", rr.Code, rr.Body)
	}
	rr = do(h, "GET", "/api/containers", nil, true, nil)
	if rr.Code != 200 || !json.Valid(rr.Body.Bytes()) {
		t.Errorf("read-only list: %d", rr.Code)
	}
	var v map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &v)
	if v["read_only"] != true {
		t.Errorf("read_only not reported: %v", fmt.Sprint(v["read_only"]))
	}
}
