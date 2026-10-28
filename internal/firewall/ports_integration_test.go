package firewall

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestPortGuardOnTheKernel drives real iptables, Docker and a network
// namespace that plays an outside client. It changes the host's firewall, so
// it runs only with SKYGUARD_IT_PORTS=1 (as root, with Docker running).
func TestPortGuardOnTheKernel(t *testing.T) {
	if os.Getenv("SKYGUARD_IT_PORTS") == "" {
		t.Skip("set SKYGUARD_IT_PORTS=1 to run against the host's iptables and Docker")
	}
	sh := func(cmd string) (string, error) {
		out, err := exec.Command("bash", "-c", cmd).CombinedOutput()
		return strings.TrimSpace(string(out)), err
	}
	must := func(cmd string) {
		if out, err := sh(cmd); err != nil {
			t.Fatalf("%s: %v\n%s", cmd, err, out)
		}
	}
	cleanup := func() {
		_, _ = sh(`docker rm -f sg-pt-web sg-pt-out; ip netns del sgpt; ip link del sgpt-h`)
	}
	// helper web servers are stopped by PID: a pattern kill could hit any
	// shell whose command line happens to contain the same words
	tmp := t.TempDir()
	if err := os.WriteFile(tmp+"/serve.py", []byte(helperServer), 0o644); err != nil {
		t.Fatal(err)
	}
	serve := func(netns, addr, port string) {
		t.Helper()
		pid := tmp + "/" + port + ".pid"
		prefix := ""
		if netns != "" {
			prefix = "ip netns exec " + netns + " "
		}
		// not "python3 -m http.server": it looks up its own name in DNS before
		// it listens, which hangs inside a namespace with no resolver
		must(fmt.Sprintf(`cd %s && { %ssetsid python3 serve.py %s %s >%s.log 2>&1 & echo $! >%s; }`, tmp, prefix, addr, port, pid, pid))
		t.Cleanup(func() { _, _ = sh("kill $(cat " + pid + ")") })
		for i := 0; i < 50; i++ {
			if out, _ := sh(prefix + "ss -Hltn sport = :" + port); out != "" {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		log, _ := sh("cat " + pid + ".log; ps -o pid,stat,cmd -p $(cat " + pid + ")")
		t.Fatalf("the helper server on %s:%s did not start: %s", addr, port, log)
	}
	cleanup()
	t.Cleanup(cleanup)
	g, err := NewPortGuard("auto", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(g.Remove)

	// an outside client at 198.51.100.10 (and 2001:db8:1::10), the host at .1
	must(`ip netns add sgpt && ip link add sgpt-h type veth peer name sgpt-c && ip link set sgpt-c netns sgpt &&
	  ip addr add 198.51.100.1/24 dev sgpt-h && ip link set sgpt-h up &&
	  ip netns exec sgpt ip addr add 198.51.100.10/24 dev sgpt-c &&
	  ip netns exec sgpt ip link set sgpt-c up && ip netns exec sgpt ip link set lo up && ip netns exec sgpt ip route add default via 198.51.100.1`)
	v6 := g.IPv6()
	bind := "0.0.0.0"
	if v6 {
		must(`ip -6 addr add 2001:db8:1::1/64 dev sgpt-h nodad && ip netns exec sgpt ip -6 addr add 2001:db8:1::10/64 dev sgpt-c nodad`)
		bind = "::"
	} else {
		t.Log("this kernel has no IPv6: the IPv6 checks are skipped")
	}
	must(`docker run -d --name sg-pt-web -p 18600:80 nginx:alpine`)
	serve("", bind, "18601")
	time.Sleep(time.Second) // nginx

	reach := func(from, url string) bool {
		cmd := fmt.Sprintf("curl -s -m 3 -o /dev/null -w %%{http_code} %s", url)
		if from == "outside" {
			cmd = "ip netns exec sgpt " + cmd
		}
		out, _ := sh(cmd)
		return out == "200"
	}
	check := func(what string, got, want bool) {
		t.Helper()
		if got != want {
			t.Errorf("%s: reachable=%v, want %v", what, got, want)
		}
	}
	check("docker port before any rule", reach("outside", "http://198.51.100.1:18600/"), true)
	check("host port before any rule", reach("outside", "http://198.51.100.1:18601/"), true)

	// Only 203.0.113.5 may reach either port: the outside client is shut out,
	// over IPv4 and IPv6, while the server itself still gets in.
	rules := []PortRule{
		{ID: "web", Ports: "18600", Proto: "tcp", Mode: "allow", Sources: []string{"203.0.113.5"}, Enabled: true},
		{ID: "host", Ports: "18601", Proto: "tcp", Mode: "allow", Sources: []string{"203.0.113.5"}, Enabled: true},
	}
	if err := g.Apply(rules, nil); err != nil {
		t.Fatal(err)
	}
	check("docker port, outsider, allow-list", reach("outside", "http://198.51.100.1:18600/"), false)
	check("host port, outsider, allow-list", reach("outside", "http://198.51.100.1:18601/"), false)
	if v6 {
		check("host port over IPv6, outsider", reach("outside", "http://[2001:db8:1::1]:18601/"), false)
	}
	check("docker port from the server itself", reach("local", "http://127.0.0.1:18600/"), true)
	check("host port from the server itself", reach("local", "http://127.0.0.1:18601/"), true)
	if d := g.Dropped(); d["web"] == 0 || d["host"] == 0 {
		t.Errorf("drop counters %v", d)
	}

	// A container reaching out to another machine's port 18600 is not affected.
	serve("sgpt", "198.51.100.10", "18600")
	out, _ := sh(`docker run --rm --name sg-pt-out alpine:3 wget -q -T 3 -O /dev/null http://198.51.100.10:18600/ && echo ok`)
	if !strings.HasSuffix(out, "ok") {
		t.Errorf("a container's outbound connection to port 18600 elsewhere was blocked: %s", out)
	}

	// Let the outsider in: same rules, one more source.
	rules[0].Sources = append(rules[0].Sources, "198.51.100.10")
	rules[1].Sources = append(rules[1].Sources, "198.51.100.0/24", "2001:db8:1::/64")
	if err := g.Apply(rules, nil); err != nil {
		t.Fatal(err)
	}
	check("docker port, outsider now listed", reach("outside", "http://198.51.100.1:18600/"), true)
	check("host port, outsider's network listed", reach("outside", "http://198.51.100.1:18601/"), true)
	if v6 {
		check("host port over IPv6, network listed", reach("outside", "http://[2001:db8:1::1]:18601/"), true)
	}

	// Everyone except the outsider.
	if err := g.Apply([]PortRule{{ID: "web", Ports: "18600", Proto: "tcp", Mode: "deny", Sources: []string{"198.51.100.10"}, Enabled: true}}, nil); err != nil {
		t.Fatal(err)
	}
	check("docker port, outsider on the deny list", reach("outside", "http://198.51.100.1:18600/"), false)
	check("host port, no rule any more", reach("outside", "http://198.51.100.1:18601/"), true)

	// No rules: everything open again, and the hooks stay single.
	if err := g.Apply(nil, nil); err != nil {
		t.Fatal(err)
	}
	check("docker port, rules cleared", reach("outside", "http://198.51.100.1:18600/"), true)
	if n, _ := sh(`iptables -S INPUT | grep -c "j SKYGUARD-PORTS$"`); n != "1" {
		t.Errorf("INPUT hook count %s", n)
	}
	if n, _ := sh(`iptables -S DOCKER-USER | grep -c "j SKYGUARD-PORTS-FWD$"`); n != "1" {
		t.Errorf("DOCKER-USER hook count %s", n)
	}
}

const helperServer = `import http.server, socket, socketserver, sys
class S(socketserver.TCPServer):
    allow_reuse_address = True
    address_family = socket.AF_INET6 if ":" in sys.argv[1] else socket.AF_INET
S((sys.argv[1], int(sys.argv[2])), http.server.SimpleHTTPRequestHandler).serve_forever()`
