package portrules

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/skyguard/skyguard/internal/firewall"
)

// TestRoutedAddressOnTheKernel builds the setup of a server with an extra
// IP routed to an Incus instance: the "instance" is a network namespace
// with 203.0.113.79 on a veth, the host routes that address to it, and
// FORWARD accepts it at the top the way a saved rule file does. An outside
// client in another namespace connects through the host. It changes the
// host's firewall, so it runs only with SKYGUARD_IT_PORTS=1 (as root).
func TestRoutedAddressOnTheKernel(t *testing.T) {
	if os.Getenv("SKYGUARD_IT_PORTS") == "" {
		t.Skip("set SKYGUARD_IT_PORTS=1 to run against the host's iptables")
	}
	sh := func(cmd string) (string, error) {
		out, err := exec.Command("bash", "-c", cmd).CombinedOutput()
		return strings.TrimSpace(string(out)), err
	}
	must := func(cmd string) {
		t.Helper()
		if out, err := sh(cmd); err != nil {
			t.Fatalf("%s: %v\n%s", cmd, err, out)
		}
	}
	cleanup := func() {
		_, _ = sh(`ip netns del sgro; ip netns del sgrv; ip link del sgro-h; ip link del sgrv-h;
		  iptables -D FORWARD -d 203.0.113.79/32 -j ACCEPT; iptables -D FORWARD -s 203.0.113.79/32 -j ACCEPT;
		  iptables -t nat -D PREROUTING -d 203.0.113.80/32 -j DNAT --to-destination 203.0.113.79`)
	}
	cleanup()
	t.Cleanup(cleanup)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	must(`sysctl -qw net.ipv4.ip_forward=1 net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0
	  ip netns add sgro && ip link add sgro-h type veth peer name sgro-c && ip link set sgro-c netns sgro
	  ip addr add 198.51.100.1/24 dev sgro-h && ip link set sgro-h up
	  ip netns exec sgro ip addr add 198.51.100.10/24 dev sgro-c && ip netns exec sgro ip link set sgro-c up
	  ip netns exec sgro ip link set lo up && ip netns exec sgro ip route add 203.0.113.0/24 via 198.51.100.1
	  ip netns add sgrv && ip link add sgrv-h type veth peer name sgrv-c && ip link set sgrv-c netns sgrv
	  ip addr add 169.254.0.1/32 dev sgrv-h && ip link set sgrv-h up && ip route add 203.0.113.79/32 dev sgrv-h
	  ip netns exec sgrv ip addr add 203.0.113.79/32 dev sgrv-c && ip netns exec sgrv ip link set sgrv-c up
	  ip netns exec sgrv ip link set lo up && ip netns exec sgrv ip route add 169.254.0.1 dev sgrv-c
	  ip netns exec sgrv ip route add default via 169.254.0.1
	  iptables -I FORWARD 1 -d 203.0.113.79/32 -j ACCEPT && iptables -I FORWARD 1 -s 203.0.113.79/32 -j ACCEPT
	  iptables -t nat -I PREROUTING -d 203.0.113.80/32 -j DNAT --to-destination 203.0.113.79`)

	tmp := t.TempDir()
	_ = os.WriteFile(tmp+"/serve.py", []byte(serveScript), 0o644)
	serve := func(ns, addr, port string) {
		t.Helper()
		pid := fmt.Sprintf("%s/%s-%s.pid", tmp, ns, port)
		must(fmt.Sprintf(`cd %s && { ip netns exec %s setsid python3 serve.py %s %s >/dev/null 2>&1 & echo $! >%s; }`, tmp, ns, addr, port, pid))
		t.Cleanup(func() { _, _ = sh("kill $(cat " + pid + ")") })
		for i := 0; i < 50; i++ {
			if out, _ := sh(fmt.Sprintf("ip netns exec %s ss -Hltn sport = :%s", ns, port)); out != "" {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatalf("helper server %s:%s did not start", addr, port)
	}
	serve("sgrv", "0.0.0.0", "13306") // the instance's MySQL
	serve("sgrv", "0.0.0.0", "12222") // and its SSH
	reach := func(from, url string) bool {
		out, _ := sh(fmt.Sprintf("ip netns exec %s curl -s -m 3 -o /dev/null -w %%{http_code} %s", from, url))
		return out == "200"
	}
	check := func(what string, got, want bool) {
		t.Helper()
		if got != want {
			t.Errorf("%s: reachable=%v, want %v", what, got, want)
		}
	}
	const mysql, ssh, viaDNAT = "http://203.0.113.79:13306/", "http://203.0.113.79:12222/", "http://203.0.113.80:13306/"
	check("routed address before anything", reach("sgro", mysql), true)
	check("DNAT-ed address before anything", reach("sgro", viaDNAT), true)

	// SkyGuard sees the address, what is behind it and what listens there.
	var routed *Route
	for _, r := range HostRoutes("/proc/net") {
		if r.Addr.String() == "203.0.113.79" {
			r := r
			routed = &r
		}
	}
	if routed == nil || routed.Dev != "sgrv-h" {
		t.Fatalf("host route not found: %+v", HostRoutes("/proc/net"))
	}
	g, err := firewall.NewPortGuard("auto", logger)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(g.Remove)
	var dnat []DNAT
	for _, r := range g.DNATRules() {
		dnat = append(dnat, DNAT{Dest: r.Dest, Proto: r.Proto, Port: r.Port, To: r.To})
	}
	addrs := Discover(LocalAddrs("/proc/net"), HostRoutes("/proc/net"), Namespaces("/proc"), dnat)
	byIP := map[string]Address{}
	for _, a := range addrs {
		byIP[a.IP] = a
	}
	if a := byIP["203.0.113.79"]; a.Kind != "routed" || a.pid == 0 || a.Device != "sgrv-h" || !a.Public {
		t.Errorf("routed address %+v", a)
	}
	if a := byIP["203.0.113.80"]; a.Kind != "dnat" || a.Target != "203.0.113.79" || a.pid == 0 {
		t.Errorf("DNAT-ed address %+v", a)
	}
	ls := ForwardedListeners("/proc", addrs, SocketOwners("/proc"), dnat)
	found := map[string]bool{}
	for _, l := range ls {
		found[fmt.Sprintf("%s:%d", l.Address, l.Port)] = true
	}
	if !found["203.0.113.79:13306"] || !found["203.0.113.79:12222"] || !found["203.0.113.80:13306"] {
		t.Errorf("listeners behind the forwarded addresses: %+v", ls)
	}

	// A ban reaches it, although FORWARD accepts the address before DOCKER-USER.
	fw, err := firewall.New("iptables", firewall.Options{IPTablesBackend: "auto"}, logger)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = sh("iptables -D FORWARD -j SKYGUARD") })
	if err := fw.Ban("198.51.100.10"); err != nil {
		t.Fatal(err)
	}
	check("routed address, client banned", reach("sgro", mysql), false)
	check("DNAT-ed address, client banned", reach("sgro", viaDNAT), false)
	if err := fw.Unban("198.51.100.10"); err != nil {
		t.Fatal(err)
	}
	check("routed address, ban lifted", reach("sgro", mysql), true)

	// A rule for the instance's address: only 203.0.113.200 may reach MySQL.
	vmdb := PortRuleFor("vmdb", "13306", "allow", []string{"203.0.113.200"}, []string{"203.0.113.79"})
	own := firewall.Scope{NoFollow: []string{"203.0.113.79", "203.0.113.80"}}
	if err := g.Apply([]firewall.PortRule{vmdb}, nil, own); err != nil {
		t.Fatal(err)
	}
	check("instance's MySQL, outsider, address rule", reach("sgro", mysql), false)
	check("instance's SSH, no rule for it", reach("sgro", ssh), true)
	check("the DNAT-ed address keeps to its own rules", reach("sgro", viaDNAT), true)
	if g.Dropped()["vmdb"] == 0 {
		t.Errorf("no drops counted: %v", g.Dropped())
	}
	// the instance's own outbound connections are untouched
	serve("sgro", "198.51.100.10", "13306")
	check("instance connecting out to port 13306", reach("sgrv", "http://198.51.100.10:13306/"), true)

	// A rule for the DNAT-ed address works on what the client asked for.
	front := PortRuleFor("front", "13306", "allow", []string{"203.0.113.200"}, []string{"203.0.113.80"})
	if err := g.Apply([]firewall.PortRule{front}, nil, own); err != nil {
		t.Fatal(err)
	}
	check("DNAT-ed address, address rule", reach("sgro", viaDNAT), false)
	check("routed address, rule for the other one", reach("sgro", mysql), true)

	// A server-wide rule leaves the instance alone, unless it follows them.
	srv := PortRuleFor("srvssh", "12222", "allow", []string{"192.0.2.1"}, nil)
	if err := g.Apply([]firewall.PortRule{srv}, nil, own); err != nil {
		t.Fatal(err)
	}
	check("server-wide rule, instance keeps its own", reach("sgro", ssh), true)
	if err := g.Apply([]firewall.PortRule{srv}, nil, firewall.Scope{Follow: []string{"203.0.113.79"}, NoFollow: []string{"203.0.113.80"}}); err != nil {
		t.Fatal(err)
	}
	check("server-wide rule, instance follows it", reach("sgro", ssh), false)

	if n, _ := sh(`iptables -S FORWARD | grep -n "" | grep -m1 -E "SKYGUARD-PORTS-FWD|203.0.113.79" | cut -d: -f2-`); !strings.Contains(n, "SKYGUARD") {
		t.Errorf("the port rules must come before the host's own ACCEPT: first match %q", n)
	}
}

// PortRuleFor makes a valid enabled rule for tests.
func PortRuleFor(id, ports, mode string, sources, addrs []string) firewall.PortRule {
	r := firewall.PortRule{ID: id, Ports: ports, Proto: "tcp", Mode: mode, Sources: sources, Addresses: addrs, Enabled: true}
	_ = r.Validate()
	return r
}

const serveScript = `import http.server, socket, socketserver, sys
class S(socketserver.TCPServer):
    allow_reuse_address = True
S((sys.argv[1], int(sys.argv[2])), http.server.SimpleHTTPRequestHandler).serve_forever()`
