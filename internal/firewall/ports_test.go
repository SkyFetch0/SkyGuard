package firewall

import (
	"io"
	"log/slog"
	"strings"
	"testing"
)

func TestPortRuleValidate(t *testing.T) {
	r := PortRule{ID: "r1", Proto: "TCP", Ports: "9300:9200", Mode: "allow"}
	if err := r.Validate(); err == nil {
		t.Error("a reversed range was accepted")
	}
	r = PortRule{ID: "r1", Ports: " 9200 - 9300 ", Mode: "allow", Sources: []string{"203.0.113.5", "10.1.2.3/8", "203.0.113.5", "::ffff:198.51.100.7", "private"}}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	if r.Proto != "tcp" || r.Ports != "9200-9300" || strings.Join(r.Sources, ",") != "203.0.113.5,10.0.0.0/8,198.51.100.7,private" {
		t.Errorf("normalised to %+v", r)
	}
	for _, bad := range []PortRule{
		{ID: "x", Ports: "0", Mode: "allow"},
		{ID: "x", Ports: "80", Mode: "maybe"},
		{ID: "x", Ports: "80", Mode: "deny"}, // nothing to keep out
		{ID: "x", Ports: "80", Mode: "allow", Sources: []string{"example.com"}},
		{ID: "X Y", Ports: "80", Mode: "allow"},
		{ID: "x", Ports: "80", Mode: "allow", Name: `a"b`},
	} {
		if err := bad.Validate(); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}

func TestCompilePortRules(t *testing.T) {
	rules := []PortRule{
		{ID: "mongo", Ports: "27017", Proto: "tcp", Mode: "allow", Sources: []string{"203.0.113.5", "private", "2001:db8::/32"}, Enabled: true},
		{ID: "es", Ports: "9200-9300", Proto: "both", Mode: "deny", Sources: []string{"198.51.100.0/24"}, Enabled: true},
		{ID: "off", Ports: "22", Proto: "tcp", Mode: "allow", Enabled: false},
	}
	v4 := Compile(rules, []string{"192.0.2.10"}, false)
	for _, want := range []string{
		":SKYGUARD-PORTS - [0:0]", ":SKYGUARD-PORTS-FWD - [0:0]", "-A SKYGUARD-PORTS -i lo -j RETURN",
		"-A SKYGUARD-PORTS -s 203.0.113.5/32 -p tcp -m tcp --dport 27017 -j RETURN",
		"-A SKYGUARD-PORTS -s 10.0.0.0/8 -p tcp -m tcp --dport 27017 -j RETURN",
		"-A SKYGUARD-PORTS -s 192.0.2.10/32 -p tcp -m tcp --dport 27017 -j RETURN", // the whitelist always passes
		`-A SKYGUARD-PORTS -p tcp -m tcp --dport 27017 -m conntrack --ctstate NEW -m comment --comment "sg:mongo" -j DROP`,
		"-A SKYGUARD-PORTS-FWD -s 203.0.113.5/32 -p tcp -m conntrack --ctstate DNAT --ctorigdstport 27017 --ctdir ORIGINAL -j RETURN",
		`-A SKYGUARD-PORTS-FWD -p tcp -m conntrack --ctstate DNAT --ctorigdstport 27017 --ctdir ORIGINAL -m conntrack --ctstate NEW -m comment --comment "sg:mongo" -j DROP`,
		`-A SKYGUARD-PORTS -s 198.51.100.0/24 -p udp -m udp --dport 9200:9300 -m conntrack --ctdir ORIGINAL -m comment --comment "sg:es" -j DROP`,
		"COMMIT",
	} {
		if !strings.Contains(v4, want+"\n") {
			t.Errorf("missing line:\n%s\nin:\n%s", want, v4)
		}
	}
	if strings.Contains(v4, "2001:db8") || strings.Contains(v4, "sg:off") || strings.Contains(v4, "fc00") {
		t.Errorf("wrong family or a disabled rule in the IPv4 set:\n%s", v4)
	}
	v6 := Compile(rules, nil, true)
	if !strings.Contains(v6, "-s 2001:db8::/32 -p tcp") || !strings.Contains(v6, "-s fc00::/7") || strings.Contains(v6, "203.0.113.5") {
		t.Errorf("IPv6 set:\n%s", v6)
	}
	// IPv6 clients are not let in just because the list has only IPv4 sources.
	if !strings.Contains(v6, `--dport 27017 -m conntrack --ctstate NEW -m comment --comment "sg:mongo" -j DROP`) {
		t.Error("the IPv6 side of an allow rule must drop everyone not listed")
	}
}

func TestPortGuardApplyHooksAfterBans(t *testing.T) {
	var restored []string
	var calls []string
	chains := map[string]string{
		"iptables INPUT":       "-P INPUT ACCEPT\n-A INPUT -j SKYGUARD\n-A INPUT -s 192.0.2.10/32 -j ACCEPT\n",
		"iptables DOCKER-USER": "-N DOCKER-USER\n-A DOCKER-USER -j SKYGUARD\n",
	}
	g := &PortGuard{logger: slog.New(slog.NewTextHandler(io.Discard, nil)), v4: "iptables",
		restore: func(bin string, in []byte) ([]byte, error) {
			restored = append(restored, bin+"\n"+string(in))
			return nil, nil
		},
		run: func(name string, args ...string) ([]byte, error) {
			args = args[2:] // -w 5
			calls = append(calls, name+" "+strings.Join(args, " "))
			if args[0] == "-S" {
				if out, ok := chains[name+" "+args[1]]; ok {
					return []byte(out), nil
				}
				return nil, exitErr(1)
			}
			if args[0] == "-I" {
				chains[name+" "+args[1]] += "-A " + args[1] + " -j " + args[4] + "\n"
			}
			return nil, nil
		}}
	rules := []PortRule{{ID: "a", Ports: "27017", Proto: "tcp", Mode: "allow", Enabled: true}}
	if err := g.Apply(rules, nil); err != nil {
		t.Fatal(err)
	}
	if err := g.Apply(rules, nil); err != nil { // the second time the hooks exist already
		t.Fatal(err)
	}
	inserts := 0
	for _, c := range calls {
		if strings.Contains(c, " -I ") {
			inserts++
			if c != "iptables -I INPUT 2 -j SKYGUARD-PORTS" && c != "iptables -I DOCKER-USER 2 -j SKYGUARD-PORTS-FWD" {
				t.Errorf("hooked at the wrong place: %s", c)
			}
		}
	}
	if inserts != 2 || len(restored) != 2 {
		t.Errorf("inserts %d, restores %d: %v", inserts, len(restored), calls)
	}
}

func TestParseCounters(t *testing.T) {
	raw := `Chain SKYGUARD-PORTS (1 references)
    pkts      bytes target     prot opt in     out     source               destination
       0        0 RETURN     all  --  lo     *       0.0.0.0/0            0.0.0.0/0
       3      180 RETURN     tcp  --  *      *       203.0.113.5          0.0.0.0/0            tcp dpt:27017
      42     2520 DROP       tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:27017 ctstate NEW /* sg:mongo */
       7      420 DROP       udp  --  *      *       198.51.100.0/24      0.0.0.0/0            udp dpts:9200:9300 ctdir ORIGINAL /* sg:es */
`
	c := parseCounters([]byte(raw))
	if c["mongo"] != 42 || c["es"] != 7 || len(c) != 2 {
		t.Errorf("counters %v", c)
	}
}

func TestParseNAT(t *testing.T) {
	raw := `-N DOCKER
-A DOCKER -i docker0 -j RETURN
-A DOCKER -d 127.0.0.1/32 ! -i docker0 -p tcp -m tcp --dport 18700 -j DNAT --to-destination 172.17.0.2:80
-A DOCKER ! -i br-1a2b -p udp -m udp --dport 18701 -j DNAT --to-destination 172.19.0.4:53
`
	got := parseNAT([]byte(raw))
	if len(got) != 2 || got[0] != (NATPort{Proto: "tcp", Port: 18700, HostIP: "127.0.0.1", Dest: "172.17.0.2:80"}) ||
		got[1] != (NATPort{Proto: "udp", Port: 18701, Dest: "172.19.0.4:53"}) {
		t.Errorf("%+v", got)
	}
}
