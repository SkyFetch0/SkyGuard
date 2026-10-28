package firewall

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Port access rules decide who may reach a port on this server: "only these
// sources" (everyone else is dropped) or "everyone except these". They work
// for every listener on the host, not only SkyGuard's own: a database
// published by Docker, an sshd, an Incus proxy.
//
// Two chains carry them, rebuilt atomically with iptables-restore:
//
//   - SKYGUARD-PORTS, jumped to from INPUT right after the ban chain, sees
//     traffic to programs on the host (and to Docker ports over IPv6, which
//     docker-proxy serves).
//   - SKYGUARD-PORTS-FWD, jumped to from FORWARD right after the ban chain
//     (so before the host's own "-d <IP> -j ACCEPT" rules and Docker's), sees
//     what the host passes on: ports Docker (or anyone) DNAT-ed to a
//     container, matched by the port the client asked for (conntrack's
//     original destination port) and only for DNAT-ed connections, so a
//     container's own outbound traffic is never touched; and addresses
//     routed through the host (an extra IP given to an Incus instance or a
//     VM), matched by destination address and port.
//
// An "only these" rule drops new connections only: a session that was open
// before the rule (the operator's SSH, say) keeps working. Loopback always
// passes, so the server can always reach its own services.
const (
	PortsChain    = "SKYGUARD-PORTS"
	PortsFwdChain = "SKYGUARD-PORTS-FWD"
)

// PortRule is one port access rule.
type PortRule struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`    // what runs there, for people: "MongoDB"
	Proto   string   `json:"proto"`   // tcp, udp or both
	Ports   string   `json:"ports"`   // "27017" or a range "9200-9300"
	Mode    string   `json:"mode"`    // allow: only Sources get in; deny: Sources are kept out
	Sources []string `json:"sources"` // IPs, CIDRs, or "private"
	// Addresses limits the rule to these addresses of the server (its own,
	// or ones it forwards); empty means the server-wide rule.
	Addresses []string `json:"addresses,omitempty"`
	Enabled   bool     `json:"enabled"`
	Note      string   `json:"note,omitempty"`
}

// PrivateKeyword stands for the private and container address ranges.
const PrivateKeyword = "private"

var privateRanges = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7", "fe80::/10"}

var ruleIDRE = regexp.MustCompile(`^[a-z0-9]{1,16}$`)

// PortRange parses "27017" or "9200-9300" (also "9200:9300").
func PortRange(s string) (lo, hi int, err error) {
	s = strings.TrimSpace(s)
	a, b, isRange := strings.Cut(strings.Replace(s, ":", "-", 1), "-")
	if lo, err = strconv.Atoi(strings.TrimSpace(a)); err != nil || lo < 1 || lo > 65535 {
		return 0, 0, fmt.Errorf("%q is not a port (1-65535) or a range like 9200-9300", s)
	}
	hi = lo
	if isRange {
		if hi, err = strconv.Atoi(strings.TrimSpace(b)); err != nil || hi < lo || hi > 65535 {
			return 0, 0, fmt.Errorf("%q is not a valid port range", s)
		}
	}
	return lo, hi, nil
}

// Validate checks and normalises a rule.
func (r *PortRule) Validate() error {
	if !ruleIDRE.MatchString(r.ID) {
		return fmt.Errorf("rule id %q must be 1-16 lowercase letters or digits", r.ID)
	}
	r.Name = strings.TrimSpace(r.Name)
	if len(r.Name) > 60 {
		r.Name = r.Name[:60]
	}
	if strings.ContainsAny(r.Name+r.Note, "\"\n\r") {
		return fmt.Errorf("the name and note cannot contain quotes or line breaks")
	}
	switch r.Proto = strings.ToLower(strings.TrimSpace(r.Proto)); r.Proto {
	case "":
		r.Proto = "tcp"
	case "tcp", "udp", "both":
	default:
		return fmt.Errorf("protocol must be tcp, udp or both, not %q", r.Proto)
	}
	lo, hi, err := PortRange(r.Ports)
	if err != nil {
		return err
	}
	if lo == hi {
		r.Ports = strconv.Itoa(lo)
	} else {
		r.Ports = fmt.Sprintf("%d-%d", lo, hi)
	}
	if r.Mode != "allow" && r.Mode != "deny" {
		return fmt.Errorf("mode must be allow (only these sources) or deny (everyone except these), not %q", r.Mode)
	}
	seen := map[string]bool{}
	var out []string
	for _, s := range r.Sources {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if s != PrivateKeyword {
			p, err := parsePrefix(s)
			if err != nil {
				return err
			}
			s = p.String()
			if p.Bits() == p.Addr().BitLen() {
				s = p.Addr().String()
			}
		}
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	if r.Mode == "deny" && len(out) == 0 {
		return fmt.Errorf("an \"everyone except\" rule needs at least one source to keep out")
	}
	if len(out) > 256 {
		return fmt.Errorf("at most 256 sources per rule")
	}
	r.Sources = out
	seen = map[string]bool{}
	var addrs []string
	for _, a := range r.Addresses {
		if a = strings.TrimSpace(a); a == "" {
			continue
		}
		p, err := parsePrefix(a)
		if err != nil {
			return fmt.Errorf("address %w", err)
		}
		a = p.String()
		if p.Bits() == p.Addr().BitLen() {
			a = p.Addr().String()
		}
		if !seen[a] {
			seen[a] = true
			addrs = append(addrs, a)
		}
	}
	if len(addrs) > 64 {
		return fmt.Errorf("at most 64 addresses per rule")
	}
	r.Addresses = addrs
	return nil
}

func parsePrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return p, fmt.Errorf("%q is not an IP address or CIDR range", s)
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%q is not an IP address or CIDR range", s)
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// sourcesFor expands a rule's sources (plus always-allowed extras) for one
// address family.
func sourcesFor(srcs []string, v6 bool) []string {
	var out []string
	for _, s := range srcs {
		list := []string{s}
		if s == PrivateKeyword {
			list = privateRanges
		}
		for _, x := range list {
			p, err := parsePrefix(x)
			if err == nil && p.Addr().Is6() == v6 {
				out = append(out, p.String())
			}
		}
	}
	return out
}

// Scope says which forwarded addresses take the server-wide rules (those
// without addresses of their own). A forwarded address is one this host
// passes on rather than owns: an extra IP routed to an Incus instance or a
// VM, or DNAT-ed somewhere by hand.
type Scope struct {
	Follow   []string // forwarded addresses the server-wide rules also cover
	NoFollow []string // forwarded addresses they leave alone
}

// target is one place a rule is matched: a chain and the match for it.
type target struct {
	chain, match string
	ct           bool // match already loads conntrack with --ctdir ORIGINAL
}

// Compile turns rules into the two chains' contents for one family, in
// iptables-restore syntax. extraAllow (the global whitelist) passes every
// "only these" rule as well.
//
// Rules for chosen addresses come first, then the server-wide ones: when an
// address rule lets a source in (RETURN), the server-wide rules no longer
// apply to that connection, so an address rule overrides them. Server-wide
// rules cover the host's own addresses, every port Docker (or anything)
// DNAT-s except to a NoFollow address, and the Follow addresses.
func Compile(rules []PortRule, extraAllow []string, v6 bool, sc Scope) string {
	var b strings.Builder
	fmt.Fprintf(&b, "*filter\n:%s - [0:0]\n:%s - [0:0]\n", PortsChain, PortsFwdChain)
	fmt.Fprintf(&b, "-A %s -i lo -j RETURN\n", PortsChain)
	extra := sourcesFor(extraAllow, v6)
	follow, noFollow := addrsFor(sc.Follow, v6), addrsFor(sc.NoFollow, v6)
	emit := func(r PortRule, targets []target) {
		tag := fmt.Sprintf(`-m comment --comment "sg:%s"`, r.ID)
		srcs := sourcesFor(r.Sources, v6)
		for _, t := range targets {
			if r.Mode == "allow" {
				for _, s := range append(append([]string{}, srcs...), extra...) {
					fmt.Fprintf(&b, "-A %s -s %s %s -j RETURN\n", t.chain, s, t.match)
				}
				fmt.Fprintf(&b, "-A %s %s -m conntrack --ctstate NEW %s -j DROP\n", t.chain, t.match, tag)
				continue
			}
			ct := " -m conntrack --ctdir ORIGINAL"
			if t.ct {
				ct = ""
			}
			for _, s := range srcs {
				fmt.Fprintf(&b, "-A %s -s %s %s%s %s -j DROP\n", t.chain, s, t.match, ct, tag)
			}
		}
	}
	targetsOf := func(r PortRule, addrs []string, general bool) []target {
		lo, hi, err := PortRange(r.Ports)
		if err != nil {
			return nil
		}
		port := strconv.Itoa(lo)
		if hi != lo {
			port += ":" + strconv.Itoa(hi)
		}
		protos := []string{r.Proto}
		if r.Proto == "both" {
			protos = []string{"tcp", "udp"}
		}
		var out []target
		for _, p := range protos {
			in := fmt.Sprintf("-p %s -m %s --dport %s", p, p, port)
			dnat := func(dst string) string {
				return fmt.Sprintf("-p %s -m conntrack --ctstate DNAT%s --ctorigdstport %s --ctdir ORIGINAL", p, dst, port)
			}
			// routed, not DNAT-ed: after DNAT the destination is the target,
			// and a rule is about the address the client asked for
			routed := func(a string) string {
				return fmt.Sprintf("-d %s -p %s -m %s --dport %s -m conntrack ! --ctstate DNAT", a, p, p, port)
			}
			if general {
				out = append(out, target{PortsChain, in, false}, target{PortsFwdChain, dnat(""), true})
				for _, a := range follow {
					out = append(out, target{PortsFwdChain, routed(a), false})
				}
				continue
			}
			for _, a := range addrs {
				out = append(out,
					target{PortsChain, "-d " + a + " " + in, false},
					target{PortsFwdChain, dnat(" --ctorigdst " + a), true},
					target{PortsFwdChain, routed(a), false})
			}
		}
		return out
	}
	for _, r := range rules {
		if !r.Enabled || len(r.Addresses) == 0 {
			continue
		}
		if addrs := addrsFor(r.Addresses, v6); len(addrs) > 0 {
			emit(r, targetsOf(r, addrs, false))
		}
	}
	// past the address rules: what goes to an address that keeps to its own
	// rules leaves the chain before the server-wide ones
	for _, a := range noFollow {
		fmt.Fprintf(&b, "-A %s -m conntrack --ctstate DNAT --ctorigdst %s -j RETURN\n", PortsFwdChain, a)
	}
	for _, r := range rules {
		if r.Enabled && len(r.Addresses) == 0 {
			emit(r, targetsOf(r, nil, true))
		}
	}
	b.WriteString("COMMIT\n")
	return b.String()
}

// addrsFor keeps the addresses (or networks) of one family, canonical.
func addrsFor(list []string, v6 bool) []string {
	var out []string
	for _, a := range list {
		p, err := parsePrefix(a)
		if err == nil && p.Addr().Is6() == v6 {
			if p.Bits() == p.Addr().BitLen() {
				out = append(out, p.Addr().String())
			} else {
				out = append(out, p.String())
			}
		}
	}
	return out
}

// PortGuard applies port rules with iptables (and ip6tables).
type PortGuard struct {
	logger  *slog.Logger
	run     runner
	restore func(bin string, input []byte) ([]byte, error)
	v4, v6  string

	mu sync.Mutex
}

// NewPortGuard finds iptables. Port rules need it even when bans use ufw or
// nothing; without it they are unavailable and an error says so.
func NewPortGuard(backend string, logger *slog.Logger) (*PortGuard, error) {
	g := &PortGuard{logger: logger, run: execRunner, restore: execRestore}
	g.v4, g.v6, _ = selectBinaries(backend, execRunner)
	if g.v4 == "" {
		return nil, fmt.Errorf("iptables is not installed, so port access rules cannot be enforced")
	}
	// A host (or container) without IPv6 has ip6tables but no kernel support;
	// the rules then cover IPv4 only instead of failing as a whole.
	if g.v6 != "" {
		if _, err := os.Stat("/proc/net/if_inet6"); err != nil {
			logger.Info("port rules: this kernel has no IPv6, the rules cover IPv4")
			g.v6 = ""
		} else if out, err := g.ipt(g.v6, "-S", "INPUT"); err != nil {
			logger.Warn("port rules: ip6tables is not usable, IPv6 is not covered", "error", err, "output", strings.TrimSpace(string(out)))
			g.v6 = ""
		}
	}
	return g, nil
}

func execRestore(bin string, input []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin+"-restore", "-w", "5", "--noflush")
	cmd.Stdin = bytes.NewReader(input)
	return cmd.CombinedOutput()
}

// IPv6 reports whether the rules also cover IPv6.
func (g *PortGuard) IPv6() bool { return g.v6 != "" }

// Apply replaces every port rule in one step per address family and makes
// sure the chains are hooked in.
func (g *PortGuard) Apply(rules []PortRule, extraAllow []string, sc Scope) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, fam := range []struct {
		bin string
		v6  bool
	}{{g.v4, false}, {g.v6, true}} {
		if fam.bin == "" {
			continue
		}
		if out, err := g.restore(fam.bin, []byte(Compile(rules, extraAllow, fam.v6, sc))); err != nil {
			return fmt.Errorf("%s-restore: %w (%s)", fam.bin, err, strings.TrimSpace(string(out)))
		}
		if err := g.hook(fam.bin, "INPUT", PortsChain); err != nil {
			return err
		}
		if err := g.hook(fam.bin, "FORWARD", PortsFwdChain); err != nil {
			return err
		}
		// Earlier builds hooked it into DOCKER-USER, behind the host's own
		// FORWARD rules; that hook is no longer needed.
		for i := 0; i < 4; i++ {
			if _, err := g.ipt(fam.bin, "-D", DockerChain, "-j", PortsFwdChain); err != nil {
				break
			}
		}
	}
	return nil
}

// Ensure puts the rules back if something removed them (a firewall reload,
// "iptables -F", Docker re-creating its chains) and otherwise only checks the
// hooks, so the drop counters keep counting.
func (g *PortGuard) Ensure(rules []PortRule, extraAllow []string, sc Scope) error {
	g.mu.Lock()
	intact := true
	for _, bin := range []string{g.v4, g.v6} {
		if bin == "" {
			continue
		}
		if _, err := g.ipt(bin, "-S", PortsChain); err != nil {
			intact = false
			continue
		}
		if _, err := g.ipt(bin, "-S", PortsFwdChain); err != nil {
			intact = false
			continue
		}
		for _, h := range [][2]string{{"INPUT", PortsChain}, {"FORWARD", PortsFwdChain}} {
			if err := g.hook(bin, h[0], h[1]); err != nil {
				g.mu.Unlock()
				return err
			}
		}
	}
	g.mu.Unlock()
	if intact {
		return nil
	}
	g.logger.Warn("port rules were missing from the firewall and have been put back")
	return g.Apply(rules, extraAllow, sc)
}

// NATPort is a port Docker publishes through its nat table. With Docker's
// userland proxy switched off nothing listens on such a port, so it is found
// here instead of among the sockets.
type NATPort struct {
	Proto  string
	Port   int
	HostIP string // "" when published on every address
	Dest   string // container address:port
}

var natRE = regexp.MustCompile(`-A DOCKER (?:-d (\S+) )?(?:! -i \S+ )?-p (tcp|udp) -m (?:tcp|udp) --dport (\d+) -j DNAT --to-destination (\S+)`)

// NATPorts lists Docker's published ports from both nat tables.
func (g *PortGuard) NATPorts() []NATPort {
	var out []NATPort
	for _, bin := range []string{g.v4, g.v6} {
		if bin == "" {
			continue
		}
		raw, err := g.ipt(bin, "-t", "nat", "-S", "DOCKER")
		if err != nil {
			continue
		}
		out = append(out, parseNAT(raw)...)
	}
	return out
}

func parseNAT(raw []byte) []NATPort {
	var out []NATPort
	for _, line := range strings.Split(string(raw), "\n") {
		m := natRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		port, _ := strconv.Atoi(m[3])
		host := strings.TrimSuffix(strings.TrimSuffix(m[1], "/32"), "/128")
		out = append(out, NATPort{Proto: m[2], Port: port, HostIP: host, Dest: m[4]})
	}
	return out
}

// DNATRule is a nat-table rule that sends one destination address
// somewhere else: how a hand-made setup forwards an extra IP.
type DNATRule struct {
	Dest  string // without the /32 or /128
	Proto string // "" for every protocol
	Port  int    // 0 for every port
	To    string // the --to-destination value
}

var (
	dnatDestRE = regexp.MustCompile(`(?:^| )-d (\S+?)(?:/(?:32|128))?(?: |$)`)
	dnatToRE   = regexp.MustCompile(`-j DNAT --to-destination (\S+)`)
	dnatProtRE = regexp.MustCompile(`(?:^| )-p (tcp|udp)(?: |$)`)
	dnatPortRE = regexp.MustCompile(`--dport (\d+)(?: |$)`)
)

// DNATRules lists the nat table's DNAT rules that name one destination
// address, in both families.
func (g *PortGuard) DNATRules() []DNATRule {
	var out []DNATRule
	for _, bin := range []string{g.v4, g.v6} {
		if bin == "" {
			continue
		}
		raw, err := g.ipt(bin, "-t", "nat", "-S")
		if err != nil {
			continue
		}
		out = append(out, parseDNAT(raw)...)
	}
	return out
}

func parseDNAT(raw []byte) []DNATRule {
	var out []DNATRule
	for _, line := range strings.Split(string(raw), "\n") {
		to := dnatToRE.FindStringSubmatch(line)
		dst := dnatDestRE.FindStringSubmatch(line)
		if to == nil || dst == nil || strings.Contains(dst[1], "/") || strings.HasPrefix(line, "-A DOCKER ") {
			continue // a network, not one address; Docker's own are its published ports
		}
		r := DNATRule{Dest: dst[1], To: to[1]}
		if m := dnatProtRE.FindStringSubmatch(line); m != nil {
			r.Proto = m[1]
		}
		if m := dnatPortRE.FindStringSubmatch(line); m != nil {
			r.Port, _ = strconv.Atoi(m[1])
		}
		out = append(out, r)
	}
	return out
}

func (g *PortGuard) ipt(bin string, args ...string) ([]byte, error) {
	return g.run(bin, append([]string{"-w", "5"}, args...)...)
}

// hook makes parent jump to chain right after SkyGuard's ban chain, so bans
// still win and port rules come before the host's own ACCEPT rules.
func (g *PortGuard) hook(bin, parent, chain string) error {
	out, err := g.ipt(bin, "-S", parent)
	if err != nil {
		return fmt.Errorf("%s -S %s: %w (%s)", bin, parent, err, strings.TrimSpace(string(out)))
	}
	pos, banPos := 0, 0
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.HasPrefix(line, "-A "+parent+" ") {
			continue
		}
		pos++
		if strings.HasSuffix(line, "-j "+Chain) && banPos == 0 {
			banPos = pos
		}
		if strings.HasSuffix(line, "-j "+chain) {
			return nil
		}
	}
	if out, err := g.ipt(bin, "-I", parent, strconv.Itoa(banPos+1), "-j", chain); err != nil {
		return fmt.Errorf("%s -I %s -j %s: %w (%s)", bin, parent, chain, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Remove takes the chains out (on uninstall or when every rule is deleted
// there is nothing to remove; an empty rule set simply compiles to nothing).
func (g *PortGuard) Remove() {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, bin := range []string{g.v4, g.v6} {
		if bin == "" {
			continue
		}
		for _, p := range [][2]string{{"INPUT", PortsChain}, {"FORWARD", PortsFwdChain}, {DockerChain, PortsFwdChain}} {
			_, _ = g.ipt(bin, "-D", p[0], "-j", p[1])
			_, _ = g.ipt(bin, "-F", p[1])
			_, _ = g.ipt(bin, "-X", p[1])
		}
	}
}

// Dropped counts the packets each rule dropped since its chains were last
// rebuilt, by rule ID, for both families and both chains together.
func (g *PortGuard) Dropped() map[string]uint64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := map[string]uint64{}
	for _, bin := range []string{g.v4, g.v6} {
		if bin == "" {
			continue
		}
		for _, chain := range []string{PortsChain, PortsFwdChain} {
			raw, err := g.ipt(bin, "-L", chain, "-n", "-v", "-x")
			if err != nil {
				continue
			}
			for id, n := range parseCounters(raw) {
				out[id] += n
			}
		}
	}
	return out
}

var counterRE = regexp.MustCompile(`/\* sg:([a-z0-9]+) \*/`)

func parseCounters(raw []byte) map[string]uint64 {
	out := map[string]uint64{}
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for sc.Scan() {
		line := sc.Text()
		m := counterRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if n, err := strconv.ParseUint(f[0], 10, 64); err == nil {
			out[m[1]] += n
		}
	}
	return out
}
