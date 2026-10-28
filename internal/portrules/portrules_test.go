package portrules

import (
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/skyguard/skyguard/internal/firewall"
)

type fakeGuard struct {
	applied [][]firewall.PortRule
	removed int
	fail    bool
	ensured int
}

func (g *fakeGuard) Apply(r []firewall.PortRule, _ []string) error {
	if g.fail {
		g.fail = false
		return errors.New("iptables-restore: line 3 failed")
	}
	g.applied = append(g.applied, r)
	return nil
}
func (g *fakeGuard) Ensure(r []firewall.PortRule, x []string) error { g.ensured++; return nil }
func (g *fakeGuard) Remove()                                        { g.removed++ }
func (g *fakeGuard) Dropped() map[string]uint64                     { return map[string]uint64{"db": 7} }
func (g *fakeGuard) IPv6() bool                                     { return true }
func (g *fakeGuard) NATPorts() []firewall.NATPort                   { return nil }

func (g *fakeGuard) last() []firewall.PortRule {
	if len(g.applied) == 0 {
		return nil
	}
	return g.applied[len(g.applied)-1]
}

type fakeStore struct{ js string }

func (s *fakeStore) PortRules() (string, error)    { return s.js, nil }
func (s *fakeStore) SavePortRules(js string) error { s.js = js; return nil }

func newTest(t *testing.T) (*Manager, *fakeGuard, *fakeStore) {
	t.Helper()
	g, st := &fakeGuard{}, &fakeStore{}
	m := New(g, "", st, []string{"192.0.2.10"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	m.Protected = func() []Protected { return []Protected{{Port: 22, Why: "SSH"}, {Port: 9090, Why: "the dashboard"}} }
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	return m, g, st
}

func rule(id, ports, mode string, src ...string) firewall.PortRule {
	return firewall.PortRule{ID: id, Ports: ports, Proto: "tcp", Mode: mode, Sources: src, Enabled: true}
}

func TestOrdinaryChangeIsSavedAtOnce(t *testing.T) {
	m, g, st := newTest(t)
	if len(g.applied) != 0 {
		t.Fatal("the firewall was touched with no rules saved")
	}
	res, err := m.Set([]firewall.PortRule{rule("db", "27017", "allow", "private")})
	if err != nil || res.Trial {
		t.Fatalf("%+v %v", res, err)
	}
	if !strings.Contains(st.js, `"27017"`) || len(g.last()) != 1 {
		t.Errorf("stored %q, applied %v", st.js, g.applied)
	}
	v := m.View()
	if v.Unsaved || len(v.Rules) != 1 || v.Rules[0].Dropped != 7 || !v.IPv6 || v.AlwaysAllowed[2] != "192.0.2.10" {
		t.Errorf("view %+v", v)
	}

	// Same rules after a restart.
	m2 := New(g, "", st, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := m2.Start(); err != nil || len(g.last()) != 1 || g.last()[0].ID != "db" {
		t.Fatalf("restart: %v %v", err, g.applied)
	}

	// Removing every rule takes the chains out.
	if _, err := m.Set(nil); err != nil || g.removed != 1 || st.js != `{"rules":[]}` {
		t.Errorf("clear: %v removed=%d stored=%s", err, g.removed, st.js)
	}
}

func TestProtectedPortNeedsConfirming(t *testing.T) {
	m, g, st := newTest(t)
	m.trialFor = time.Hour
	res, err := m.Set([]firewall.PortRule{rule("ssh", "20-30", "allow", "203.0.113.5"), rule("db", "27017", "allow")})
	if err != nil || !res.Trial || len(res.Ports) != 1 || res.Ports[0] != 22 {
		t.Fatalf("%+v %v", res, err)
	}
	if st.js != "" || len(g.last()) != 2 {
		t.Fatalf("a trial must be enforced but not saved: stored %q", st.js)
	}
	if v := m.View(); !v.Unsaved || v.Rules[0].Protected != "SSH" || v.Rules[1].Protected != "" {
		t.Errorf("view %+v", v)
	}
	if err := m.Confirm(); err != nil || !strings.Contains(st.js, `"ssh"`) {
		t.Fatalf("confirm: %v %q", err, st.js)
	}
	if err := m.Confirm(); err == nil {
		t.Error("confirmed twice")
	}

	// The same SSH rule again needs no new trial; lifting it neither.
	if res, _ := m.Set([]firewall.PortRule{rule("ssh", "20-30", "allow", "203.0.113.5")}); res.Trial {
		t.Error("an unchanged protected rule asked for a trial")
	}
	if res, _ := m.Set(nil); res.Trial {
		t.Error("lifting a rule asked for a trial")
	}
	// A UDP rule cannot lock SSH out.
	u := rule("dns", "22", "deny", "198.51.100.0/24")
	u.Proto = "udp"
	if res, _ := m.Set([]firewall.PortRule{u}); res.Trial {
		t.Error("a UDP rule asked for a trial")
	}
}

func TestUnconfirmedTrialIsUndone(t *testing.T) {
	m, g, st := newTest(t)
	if _, err := m.Set([]firewall.PortRule{rule("db", "27017", "allow", "private")}); err != nil {
		t.Fatal(err)
	}
	saved := st.js
	m.trialFor = 30 * time.Millisecond
	if res, _ := m.Set([]firewall.PortRule{rule("dash", "9090", "allow", "203.0.113.5")}); !res.Trial {
		t.Fatal("no trial")
	}
	deadline := time.Now().Add(2 * time.Second)
	for m.View().Unsaved && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	v := m.View()
	if v.Unsaved || v.Reverted == nil || len(v.Rules) != 1 || v.Rules[0].ID != "db" || g.last()[0].ID != "db" || st.js != saved {
		t.Errorf("not undone: %+v, applied %v", v, g.last())
	}

	// Revert ends one at once.
	m.trialFor = time.Hour
	_, _ = m.Set([]firewall.PortRule{rule("dash", "9090", "deny", "198.51.100.7")})
	if err := m.Revert(); err != nil || g.last()[0].ID != "db" || m.View().Unsaved {
		t.Errorf("revert: %v %v", err, g.last())
	}
}

func TestRefusedRulesKeepThePreviousOnes(t *testing.T) {
	m, g, st := newTest(t)
	_, _ = m.Set([]firewall.PortRule{rule("db", "27017", "allow", "private")})
	saved := st.js
	g.fail = true
	if _, err := m.Set([]firewall.PortRule{rule("es", "9200", "allow")}); err == nil {
		t.Fatal("no error")
	}
	if g.last()[0].ID != "db" || st.js != saved || m.View().Rules[0].ID != "db" {
		t.Errorf("the previous rules were not restored: %v", g.last())
	}
	for _, bad := range [][]firewall.PortRule{
		{rule("a", "80", "allow"), rule("a", "81", "allow")},
		{rule("a", "70000", "allow")},
	} {
		if _, err := m.Set(bad); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
}

func TestUnavailable(t *testing.T) {
	st := &fakeStore{js: `{"rules":[{"id":"db","ports":"27017","proto":"tcp","mode":"allow","enabled":true}]}`}
	m := New(nil, "iptables is not installed", st, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	if v := m.View(); v.Available || v.Reason == "" || len(v.Rules) != 1 {
		t.Errorf("view %+v", v)
	}
	if _, err := m.Set(nil); !errors.Is(err, ErrUnavailable) {
		t.Errorf("set: %v", err)
	}
	m.Maintain() // no guard: nothing to do, no panic
}

const procTCP = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:6989 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1001 1 0 100 0 0 10 0
   1: 0100007F:0CEA 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1002 1 0 100 0 0 10 0
   2: 0100007F:0CEA 0100007F:D431 01 00000000:00000000 00:00000000 00000000     0        0 1003 1 0 100 0 0 10 0
   3: 01FEF50A:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1004 1 0 100 0 0 10 0
`

const procTCP6 = `  sl  local_address                         remote_address                        st
   0: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1005 1 0
`

func TestListeners(t *testing.T) {
	socks := parseSockets(strings.NewReader(procTCP), "tcp", "0A")
	socks = append(socks, parseSockets(strings.NewReader(procTCP6), "tcp", "0A")...)
	if len(socks) != 4 || socks[0].Port != 27017 || socks[1].Addr.String() != "127.0.0.1" || socks[2].Addr.String() != "10.245.254.1" || socks[3].Addr.String() != "::" {
		t.Fatalf("sockets %+v", socks)
	}
	owners := map[string]string{"1001": "docker-proxy", "1002": "node", "1004": "dnsmasq", "1005": "sshd"}
	nat := []firewall.NATPort{{Proto: "tcp", Port: 9200, Dest: "172.17.0.3:9200"}, {Proto: "tcp", Port: 27017, Dest: "172.17.0.2:27017"}}
	claims := []Claim{{Proto: "tcp", Port: 27017, Owner: "mongo", Kind: "docker"}, {Proto: "tcp", Port: 5000, Owner: "gone", Kind: "docker"}}
	ls := Listeners(socks, owners, nat, claims)
	got := map[int]Listener{}
	for _, l := range ls {
		got[l.Port] = l
	}
	if len(ls) != 5 || ls[0].Scope != "public" || ls[len(ls)-1].Scope != "local" {
		t.Fatalf("order %+v", ls)
	}
	if m := got[27017]; m.Owner != "mongo" || m.Kind != "docker" || m.Risk != "database" || m.Service != "MongoDB" || m.Process != "docker-proxy" {
		t.Errorf("mongo %+v", m)
	}
	if es := got[9200]; es.Owner != "172.17.0.3:9200" || es.Kind != "docker" || es.Scope != "public" {
		t.Errorf("nat-only port %+v", es)
	}
	if got[22].Process != "sshd" || got[22].Kind != "host" || got[53].Scope != "private" || got[3306].Scope != "local" || got[3306].Process != "node" || got[3306].Risk != "database" {
		t.Errorf("listeners %+v", got)
	}
}
