package portrules

import (
	"bufio"
	"encoding/hex"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// A server often has more than one address. Some are its own (on its
// interfaces). Others it only passes on: an extra IP routed to an Incus
// instance or a VM (Incus "routed" NICs, a hosting provider's additional IP),
// or one that a hand-written iptables rule DNAT-s somewhere. Traffic to those
// never reaches INPUT; it crosses FORWARD, and the programs that answer it
// live in another network namespace or another machine.

// Address is one address of this server.
type Address struct {
	IP        string `json:"ip"`
	Kind      string `json:"kind"` // host, routed or dnat
	Public    bool   `json:"public"`
	Device    string `json:"device,omitempty"`     // routed: the interface it is routed to
	Owner     string `json:"owner,omitempty"`      // the container, instance or program behind it
	OwnerKind string `json:"owner_kind,omitempty"` // docker, incus, vm or netns
	Target    string `json:"target,omitempty"`     // dnat: where it goes
	Follow    bool   `json:"follow"`               // forwarded: the server-wide rules cover it too
	Hidden    bool   `json:"hidden,omitempty"`     // its ports cannot be seen (a VM, another machine)

	pid int // a process in the namespace that holds it, 0 when unknown
}

// Forwarded reports whether the host passes this address on.
func (a Address) Forwarded() bool { return a.Kind != "host" }

// LocalAddrs lists the addresses of one network namespace, from the
// kernel's local routing table and the IPv6 address list. procNet is
// /proc/net or /proc/<pid>/net.
func LocalAddrs(procNet string) []netip.Addr {
	var out []netip.Addr
	seen := map[netip.Addr]bool{}
	add := func(a netip.Addr) {
		if a.IsValid() && !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	// fib_trie: an address line "|-- 192.0.2.2" followed by "/32 host LOCAL"
	if f, err := os.Open(filepath.Join(procNet, "fib_trie")); err == nil {
		sc := bufio.NewScanner(f)
		last := ""
		for sc.Scan() {
			l := strings.TrimSpace(sc.Text())
			if strings.HasPrefix(l, "|-- ") {
				last = strings.TrimPrefix(l, "|-- ")
				continue
			}
			if strings.HasPrefix(l, "/32 host LOCAL") && last != "" {
				if a, err := netip.ParseAddr(last); err == nil {
					add(a)
				}
			}
		}
		f.Close()
	}
	// if_inet6: "20010db8000000000000000000000001 02 40 00 80 eth0"
	if f, err := os.Open(filepath.Join(procNet, "if_inet6")); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			x := strings.Fields(sc.Text())
			if len(x) < 6 {
				continue
			}
			if b, err := hex.DecodeString(x[0]); err == nil && len(b) == 16 {
				a, _ := netip.AddrFromSlice(b)
				add(a)
			}
		}
		f.Close()
	}
	return out
}

// Route is a single address the host routes straight to an interface.
type Route struct {
	Addr netip.Addr
	Dev  string
}

// HostRoutes lists the host routes (/32 and /128, no gateway) to an
// interface other than loopback: how an extra IP reaches an Incus instance
// with a routed NIC, or a VM.
func HostRoutes(procNet string) []Route {
	var out []Route
	if f, err := os.Open(filepath.Join(procNet, "route")); err == nil {
		sc := bufio.NewScanner(f)
		sc.Scan() // header
		for sc.Scan() {
			x := strings.Fields(sc.Text())
			if len(x) < 8 || x[0] == "lo" || x[2] != "00000000" || x[7] != "FFFFFFFF" {
				continue
			}
			if a, err := procAddr(x[1]); err == nil {
				out = append(out, Route{a, x[0]})
			}
		}
		f.Close()
	}
	// ipv6_route: dest plen src splen nexthop metric ref use flags dev
	if f, err := os.Open(filepath.Join(procNet, "ipv6_route")); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			x := strings.Fields(sc.Text())
			if len(x) < 10 || x[1] != "80" || x[9] == "lo" || strings.Trim(x[4], "0") != "" {
				continue
			}
			b, err := hex.DecodeString(x[0])
			if err != nil || len(b) != 16 {
				continue
			}
			a, _ := netip.AddrFromSlice(b)
			if a.IsMulticast() || a.IsLinkLocalUnicast() {
				continue
			}
			out = append(out, Route{a, x[9]})
		}
		f.Close()
	}
	return out
}

// Netns is a network namespace other than the host's, with one process in it.
type Netns struct {
	PID   int
	Name  string // the container or instance, from the process's cgroup
	Kind  string // docker, incus or netns
	Addrs []netip.Addr
}

var (
	dockerCgroup = regexp.MustCompile(`docker[-/]([0-9a-f]{64})`)
	lxcCgroup    = regexp.MustCompile(`lxc\.payload\.([^/\s]+)|/lxc/([^/\s]+)`)
)

// Namespaces finds the other network namespaces and their addresses. It
// needs to see the host's processes: when SkyGuard runs in a container with
// its own PID namespace it finds none.
func Namespaces(proc string) []Netns {
	host, _ := os.Readlink(filepath.Join(proc, "self", "ns", "net"))
	pids, _ := filepath.Glob(filepath.Join(proc, "[0-9]*"))
	seen := map[string]bool{host: true}
	var out []Netns
	for _, p := range pids {
		ns, err := os.Readlink(filepath.Join(p, "ns", "net"))
		if err != nil || seen[ns] {
			continue
		}
		seen[ns] = true
		pid, _ := strconv.Atoi(filepath.Base(p))
		n := Netns{PID: pid, Kind: "netns", Addrs: LocalAddrs(filepath.Join(p, "net"))}
		cg, _ := os.ReadFile(filepath.Join(p, "cgroup"))
		switch {
		case dockerCgroup.Match(cg):
			n.Kind, n.Name = "docker", dockerCgroup.FindStringSubmatch(string(cg))[1]
		case lxcCgroup.Match(cg):
			m := lxcCgroup.FindStringSubmatch(string(cg))
			n.Kind, n.Name = "incus", m[1]+m[2]
		default:
			b, _ := os.ReadFile(filepath.Join(p, "comm"))
			n.Name = strings.TrimSpace(string(b))
		}
		out = append(out, n)
	}
	return out
}

// DNAT is an address a hand-written rule forwards somewhere.
type DNAT struct {
	Dest  string // the address clients connect to
	Proto string // "" for every protocol
	Port  int    // 0 for every port
	To    string // where it goes: an address, or address:port
}

// Discover puts the server's addresses together: its own, those routed to
// an interface, and DNAT-ed ones that are not its own (Docker's own DNAT to
// a host address is a host address publishing a port, not another address).
func Discover(local []netip.Addr, routes []Route, nss []Netns, dnat []DNAT) []Address {
	isLocal := map[netip.Addr]bool{}
	var out []Address
	for _, a := range local {
		isLocal[a] = true
		if a.IsLoopback() || a.IsLinkLocalUnicast() {
			continue
		}
		out = append(out, Address{IP: a.String(), Kind: "host", Public: isPublic(a)})
	}
	owner := func(a netip.Addr) *Netns {
		for i := range nss {
			for _, x := range nss[i].Addrs {
				if x == a {
					return &nss[i]
				}
			}
		}
		return nil
	}
	seen := map[string]bool{}
	for _, r := range routes {
		if isLocal[r.Addr] || seen[r.Addr.String()] {
			continue
		}
		seen[r.Addr.String()] = true
		ad := Address{IP: r.Addr.String(), Kind: "routed", Public: isPublic(r.Addr), Device: r.Dev}
		if n := owner(r.Addr); n != nil {
			ad.Owner, ad.OwnerKind, ad.pid = n.Name, n.Kind, n.PID
		} else {
			// a VM, or another machine behind this interface: its ports are its own
			ad.Hidden = true
			if strings.HasPrefix(r.Dev, "tap") || strings.HasPrefix(r.Dev, "vnet") || strings.HasPrefix(r.Dev, "macvtap") {
				ad.OwnerKind = "vm"
			}
		}
		out = append(out, ad)
	}
	for _, d := range dnat {
		a, err := netip.ParseAddr(d.Dest)
		if err != nil || isLocal[a] || a.IsLoopback() || seen[d.Dest] {
			continue
		}
		seen[d.Dest] = true
		ad := Address{IP: d.Dest, Kind: "dnat", Public: isPublic(a), Target: d.To}
		host := d.To
		if ap, err := netip.ParseAddrPort(d.To); err == nil {
			host = ap.Addr().String()
		} else if i := strings.LastIndex(d.To, ":"); i > 0 && !strings.Contains(d.To[:i], ":") {
			host = d.To[:i]
		}
		if t, err := netip.ParseAddr(host); err == nil {
			if n := owner(t); n != nil {
				ad.Owner, ad.OwnerKind, ad.pid = n.Name, n.Kind, n.PID
			}
		}
		if ad.pid == 0 && d.Port == 0 {
			ad.Hidden = true
		}
		out = append(out, ad)
	}
	rank := map[string]int{"host": 0, "routed": 1, "dnat": 2}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Public != out[j].Public {
			return out[i].Public
		}
		return rank[out[i].Kind] < rank[out[j].Kind]
	})
	return out
}

// ForwardedListeners lists what takes connections on the forwarded
// addresses: the sockets in the namespace behind each one that are bound to
// it (or to every address), or the port a DNAT rule names.
func ForwardedListeners(proc string, addrs []Address, owners map[string]string, dnat []DNAT) []Listener {
	var out []Listener
	for _, ad := range addrs {
		if !ad.Forwarded() {
			continue
		}
		ip, err := netip.ParseAddr(ad.IP)
		if err != nil {
			continue
		}
		byKey := map[string]*Listener{}
		whole := ad.Kind == "routed" // the whole address leads into the namespace
		for _, d := range dnat {
			if d.Dest == ad.IP && d.Port == 0 {
				whole = true
			}
		}
		if ad.pid > 0 && whole {
			for _, s := range ReadSockets(filepath.Join(proc, strconv.Itoa(ad.pid), "net")) {
				// for a DNAT address the socket is bound to the target, not to it
				if ad.Kind == "routed" && !(s.Addr == ip || s.Addr.IsUnspecified()) {
					continue
				}
				if s.Addr.IsLoopback() {
					continue
				}
				k := s.Proto + "/" + strconv.Itoa(s.Port)
				l := byKey[k]
				if l == nil {
					l = &Listener{Proto: s.Proto, Port: s.Port, Addrs: []string{ad.IP}, Address: ad.IP, Owner: ad.Owner, Kind: ad.OwnerKind}
					if wk, ok := WellKnown[s.Port]; ok {
						l.Service, l.Risk = wk.Name, wk.Risk
					}
					byKey[k] = l
				}
				if p := owners[s.Inode]; p != "" {
					l.Process = p
				}
			}
		}
		if ad.Kind == "dnat" {
			for _, d := range dnat {
				if d.Dest != ad.IP || d.Port == 0 {
					continue
				}
				protos := []string{d.Proto}
				if d.Proto == "" {
					protos = []string{"tcp", "udp"}
				}
				for _, p := range protos {
					k := p + "/" + strconv.Itoa(d.Port)
					if byKey[k] == nil {
						l := &Listener{Proto: p, Port: d.Port, Addrs: []string{ad.IP}, Address: ad.IP, Owner: cmpOr(ad.Owner, d.To), Kind: cmpOr(ad.OwnerKind, "dnat")}
						if wk, ok := WellKnown[d.Port]; ok {
							l.Service, l.Risk = wk.Name, wk.Risk
						}
						byKey[k] = l
					}
				}
			}
		}
		for _, l := range byKey {
			l.Scope = "private"
			if ad.Public {
				l.Scope = "public"
			}
			out = append(out, *l)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Address != out[j].Address {
			return out[i].Address < out[j].Address
		}
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		return out[i].Proto < out[j].Proto
	})
	return out
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func isPublic(a netip.Addr) bool {
	return !(a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || cgnat.Contains(a) || a.IsUnspecified())
}
