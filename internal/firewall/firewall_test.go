package firewall

import (
	"errors"
	"io"
	"log/slog"
	"os/exec"
	"strings"
	"testing"
)

// fakeIPTables emulates iptables -C/-I/-D/-N/-S against an in-memory rule set.
type fakeIPTables struct {
	rules map[string]int // "bin chain rule..." -> count
	calls []string
}

func (f *fakeIPTables) run(name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	if len(args) >= 2 && args[0] == "-w" {
		args = args[2:]
	}
	op, rest := args[0], args[1:]
	key := func(r []string) string { return name + " " + strings.Join(r, " ") }
	switch op {
	case "-S", "-N":
		return nil, nil
	case "-C":
		if f.rules[key(rest)] > 0 {
			return nil, nil
		}
		return nil, exitErr(1)
	case "-I":
		// strip position: -I CHAIN 1 rule...
		r := append([]string{rest[0]}, rest[2:]...)
		f.rules[key(r)]++
		return nil, nil
	case "-D":
		f.rules[key(rest)]--
		return nil, nil
	}
	return nil, errors.New("unexpected op " + op)
}

// exitErr produces a real *exec.ExitError with the given status.
func exitErr(code int) error {
	err := exec.Command("sh", "-c", "exit "+string(rune('0'+code))).Run()
	return err
}

func newFake() (*IPTablesFirewall, *fakeIPTables) {
	f := &fakeIPTables{rules: map[string]int{}}
	fw := &IPTablesFirewall{
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		run:    f.run, v4: "iptables", v6: "ip6tables", backend: "test",
	}
	return fw, f
}

func TestIPTablesBanIsIdempotentAndUsesChain(t *testing.T) {
	fw, f := newFake()
	for i := 0; i < 3; i++ {
		if err := fw.Ban("1.2.3.4"); err != nil {
			t.Fatal(err)
		}
	}
	if n := f.rules["iptables SKYGUARD -s 1.2.3.4 -j DROP"]; n != 1 {
		t.Fatalf("rule count = %d, want 1 (rules=%v)", n, f.rules)
	}
	for _, c := range f.calls {
		if !strings.Contains(c, "-w 5") {
			t.Errorf("call without xtables lock wait: %s", c)
		}
	}
	if ok, _ := fw.IsBanned("1.2.3.4"); !ok {
		t.Error("IsBanned = false after Ban")
	}
}

func TestIPTablesIPv6AndUnban(t *testing.T) {
	fw, f := newFake()
	if err := fw.Ban("2001:db8::1"); err != nil {
		t.Fatal(err)
	}
	if f.rules["ip6tables SKYGUARD -s 2001:db8::1 -j DROP"] != 1 {
		t.Fatalf("IPv6 ban did not use ip6tables: %v", f.rules)
	}
	// Legacy rule from an older SkyGuard version, inserted straight into INPUT.
	f.rules["iptables INPUT -s 5.5.5.5 -j DROP"] = 2
	if err := fw.Unban("5.5.5.5"); err != nil {
		t.Fatal(err)
	}
	if f.rules["iptables INPUT -s 5.5.5.5 -j DROP"] != 0 {
		t.Errorf("legacy INPUT rules not removed: %v", f.rules)
	}
	if err := fw.Unban("9.9.9.9"); err != nil {
		t.Errorf("unban of unknown IP should be a no-op, got %v", err)
	}
	fw.v6 = ""
	if err := fw.Ban("2001:db8::2"); err == nil {
		t.Error("expected error banning IPv6 without ip6tables")
	}
	if err := fw.Ban("not-an-ip"); err == nil {
		t.Error("expected error for invalid IP")
	}
}

func TestUFWStatusParsing(t *testing.T) {
	status := `Status: active

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW       Anywhere
Anywhere                   DENY        1.2.3.40
Anywhere (v6)              DENY        2001:db8::1
`
	if ufwStatusHasDeny(status, "1.2.3.4") {
		t.Error("1.2.3.4 must not match 1.2.3.40")
	}
	if !ufwStatusHasDeny(status, "1.2.3.40") || !ufwStatusHasDeny(status, "2001:db8::1") {
		t.Error("expected exact DENY matches")
	}
}

func TestIPTablesBansCoverDockerPublishedPorts(t *testing.T) {
	fw, f := newFake()
	for _, ip := range []string{"203.0.113.7", "203.0.113.8"} {
		if err := fw.Ban(ip); err != nil {
			t.Fatal(err)
		}
	}
	if n := f.rules["iptables DOCKER-USER -j SKYGUARD"]; n != 1 {
		t.Errorf("DOCKER-USER jump inserted %d times, want once", n)
	}

	// Without Docker there is no DOCKER-USER chain and nothing is hooked.
	fw, f = newFake()
	fw.run = func(name string, args ...string) ([]byte, error) {
		if len(args) > 3 && args[2] == "-S" && args[3] == DockerChain {
			return []byte("iptables: No chain/target/match by that name."), exitErr(1)
		}
		return f.run(name, args...)
	}
	if err := fw.Ban("203.0.113.9"); err != nil {
		t.Fatal(err)
	}
	for _, c := range f.calls {
		if strings.Contains(c, "-I DOCKER-USER") {
			t.Errorf("hooked a chain that does not exist: %s", c)
		}
	}
}
