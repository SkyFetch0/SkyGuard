package containers

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"
)

// These tests drive a real Docker / Incus daemon and change its state. They
// run only when asked: SKYGUARD_IT_DOCKER=1 / SKYGUARD_IT_INCUS=1.

func sh(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

func find(t *testing.T, e Engine, name string) Container {
	t.Helper()
	cs, _, err := e.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cs {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("container %s not listed", name)
	return Container{}
}

func netNames(c Container) []string {
	var out []string
	for _, n := range c.Networks {
		out = append(out, n.Network)
	}
	return out
}

func TestDockerIntegration(t *testing.T) {
	if os.Getenv("SKYGUARD_IT_DOCKER") == "" {
		t.Skip("set SKYGUARD_IT_DOCKER=1 to run against the local Docker daemon")
	}
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	d := NewDocker("/var/run/docker.sock", logger)
	m := NewManager([]Engine{d}, false, logger)
	cleanup := func() {
		_ = exec.Command("sh", "-c", "docker rm -f $(docker ps -aq --filter name=sg-it-) ; docker network rm sg-it-a sg-it-b sg-it-c").Run()
	}
	cleanup()
	t.Cleanup(cleanup)

	sh(t, "docker", "network", "create", "sg-it-a")
	sh(t, "docker", "network", "create", "sg-it-b")
	sh(t, "docker", "run", "-d", "--name", "sg-it-web", "--network", "sg-it-a", "--network-alias", "frontend",
		"-p", "18080:80", "-v", "/data", "nginx:alpine")
	sh(t, "docker", "exec", "sg-it-web", "sh", "-c", "echo kept > /data/marker")
	sh(t, "docker", "run", "-d", "--name", "sg-it-db", "--network", "sg-it-b", "redis:alpine")

	web := find(t, d, "sg-it-web")
	if !web.Running || len(web.Ports) != 1 || web.Ports[0].String() != "18080:80/tcp" {
		t.Fatalf("web listed as %+v", web)
	}
	if v, err := d.Version(ctx); err != nil || v == "" {
		t.Fatalf("version %q %v", v, err)
	}

	// The cable: web joins db's network.
	if _, err := m.Connect(ctx, "docker", web.ID, "sg-it-b", false); err != nil {
		t.Fatal(err)
	}
	if got := netNames(find(t, d, "sg-it-web")); !slices.Equal(got, []string{"sg-it-a", "sg-it-b"}) {
		t.Fatalf("networks after connect: %v", got)
	}
	sh(t, "docker", "exec", "sg-it-web", "ping", "-c1", "-W2", "sg-it-db")
	// And a brand-new network for a pair.
	if _, err := m.Connect(ctx, "docker", web.ID, "sg-it-c", true); err != nil {
		t.Fatal(err)
	}

	// A port held by another container is refused before anything changes.
	sh(t, "docker", "run", "-d", "--name", "sg-it-other", "-p", "18090:80", "nginx:alpine")
	if _, err := m.SetPorts(ctx, "docker", web.ID, []Port{{HostPort: 18090, ContainerPort: 80, Proto: "tcp"}}); err == nil || !strings.Contains(err.Error(), "sg-it-other") {
		t.Fatalf("conflict not caught: %v", err)
	}

	// A port held by a host program: the engine fails to start the new
	// container, and the old one comes back as it was.
	ln, err := net.Listen("tcp", ":18095")
	if err != nil {
		t.Fatal(err)
	}
	err = d.SetPorts(ctx, web.ID, []Port{{HostPort: 18095, ContainerPort: 80, Proto: "tcp"}})
	ln.Close()
	if err == nil || !strings.Contains(err.Error(), "put back") {
		t.Fatalf("expected a rolled-back failure, got %v", err)
	}
	back := find(t, d, "sg-it-web")
	if back.ID != web.ID || !back.Running || back.Ports[0].HostPort != 18080 {
		t.Fatalf("old container not restored: %+v", back)
	}

	// The real change: new ports, same everything else.
	ports, _ := ParsePorts("18081:80, 127.0.0.1:18443:443/tcp")
	if _, err := m.SetPorts(ctx, "docker", web.ID, ports); err != nil {
		t.Fatal(err)
	}
	nw := find(t, d, "sg-it-web")
	if nw.ID == web.ID || !nw.Running {
		t.Fatalf("not recreated: %+v", nw)
	}
	var got []string
	for _, p := range nw.Ports {
		got = append(got, p.String())
	}
	if !slices.Equal(got, []string{"18081:80/tcp", "127.0.0.1:18443:443/tcp"}) {
		t.Fatalf("ports %v", got)
	}
	if n := netNames(nw); !slices.Equal(n, []string{"sg-it-a", "sg-it-b", "sg-it-c"}) {
		t.Fatalf("networks lost in the recreate: %v", n)
	}
	if out := sh(t, "docker", "exec", "sg-it-web", "cat", "/data/marker"); out != "kept" {
		t.Fatalf("anonymous volume lost: %q", out)
	}
	if out := sh(t, "docker", "inspect", "-f", "{{json .NetworkSettings.Networks}}", "sg-it-web"); !strings.Contains(out, `"frontend"`) {
		t.Fatalf("network alias lost: %s", out)
	}
	if out := sh(t, "docker", "ps", "-a", "--filter", "name=skyguard-old", "-q"); out != "" {
		t.Fatalf("old container left behind: %s", out)
	}
	var resp *http.Response
	for i := 0; i < 50; i++ {
		if resp, err = http.Get("http://127.0.0.1:18081/"); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("nginx on the new port: %v %v", resp, err)
	}
	resp.Body.Close()

	// Settings in place.
	pol, mem, cpus := "unless-stopped", int64(64), 0.5
	if _, err := m.Update(ctx, "docker", nw.ID, Settings{Restart: &pol, MemoryMB: &mem, CPUs: &cpus}); err != nil {
		t.Fatal(err)
	}
	in, err := d.Inspect(ctx, nw.ID)
	if err != nil || in.Restart != "unless-stopped" || in.MemoryMB != 64 || in.CPUs != 0.5 {
		t.Fatalf("after update: %+v %v", in, err)
	}
	zero, nocpu := int64(0), 0.0
	if _, err := m.Update(ctx, "docker", nw.ID, Settings{MemoryMB: &zero, CPUs: &nocpu}); err != nil {
		t.Fatal(err)
	}
	if in, _ = d.Inspect(ctx, "sg-it-web"); in == nil || in.MemoryMB != 0 || in.CPUs != 0 {
		t.Fatalf("limits not removed: %+v", in)
	}

	nw = find(t, d, "sg-it-web") // taking a limit away recreated it
	if _, err := m.Disconnect(ctx, "docker", nw.ID, "sg-it-b"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Action(ctx, "docker", nw.ID, "stop"); err != nil {
		t.Fatal(err)
	}
	if find(t, d, "sg-it-web").Running {
		t.Fatal("still running after stop")
	}
	if _, err := m.Action(ctx, "docker", nw.ID, "start"); err != nil {
		t.Fatal(err)
	}
	snap := m.Snapshot(ctx)
	if !snap.Engines[0].Available || len(HostPorts(snap, nil)) == 0 {
		t.Fatalf("snapshot %+v", snap.Engines)
	}
}

func TestIncusIntegration(t *testing.T) {
	name := os.Getenv("SKYGUARD_IT_INCUS") // an existing, running container
	if name == "" {
		t.Skip("set SKYGUARD_IT_INCUS=<instance> to run against the local Incus daemon")
	}
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	x := NewIncus("/var/lib/incus/unix.socket", "", logger)
	m := NewManager([]Engine{x}, false, logger)
	t.Cleanup(func() {
		_ = exec.Command("incus", "config", "device", "remove", name, "eth1").Run()
		_ = exec.Command("sh", "-c", "for d in $(incus config device list "+name+" | grep proxy-); do incus config device remove "+name+" $d; done").Run()
		_ = exec.Command("incus", "network", "delete", "sgit0").Run()
	})
	if v, err := x.Version(ctx); err != nil || v == "" {
		t.Fatalf("version %q %v", v, err)
	}
	c := find(t, x, name)
	if !c.Running || len(c.Networks) == 0 {
		t.Fatalf("listed as %+v", c)
	}
	if err := m.CreateNetwork(ctx, "incus", "sgit0"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Connect(ctx, "incus", name, "sgit0", false); err != nil {
		t.Fatal(err)
	}
	if n := netNames(find(t, x, name)); !slices.Contains(n, "sgit0") {
		t.Fatalf("not connected: %v", n)
	}
	if _, err := m.Connect(ctx, "incus", name, "sgit0", false); err == nil {
		t.Fatal("double connect accepted")
	}
	ports, _ := ParsePorts("18180:80,127.0.0.1:18153:53/udp")
	if _, err := m.SetPorts(ctx, "incus", name, ports); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, p := range find(t, x, name).Ports {
		got = append(got, p.String())
	}
	if !slices.Equal(got, []string{"127.0.0.1:18153:53/udp", "18180:80/tcp"}) {
		t.Fatalf("ports %v", got)
	}
	if _, err := m.SetPorts(ctx, "incus", name, ports[:1]); err != nil {
		t.Fatal(err)
	}
	if p := find(t, x, name).Ports; len(p) != 1 {
		t.Fatalf("port not removed: %v", p)
	}
	pol, mem, cpus := "always", int64(256), 1.0
	if _, err := m.Update(ctx, "incus", name, Settings{Restart: &pol, MemoryMB: &mem, CPUs: &cpus}); err != nil {
		t.Fatal(err)
	}
	in, err := x.Inspect(ctx, name)
	if err != nil || in.Restart != "always" || in.MemoryMB != 256 || in.CPUs != 1 {
		t.Fatalf("after update %+v %v", in, err)
	}
	pol, mem, cpus = "last-state", 0, 0
	if _, err := m.Update(ctx, "incus", name, Settings{Restart: &pol, MemoryMB: &mem, CPUs: &cpus}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Disconnect(ctx, "incus", name, "sgit0"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.SetPorts(ctx, "incus", name, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Action(ctx, "incus", name, "restart"); err != nil {
		t.Fatal(err)
	}
	if !find(t, x, name).Running {
		t.Fatal("not running after restart")
	}
}
