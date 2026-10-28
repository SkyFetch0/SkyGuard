package portrules

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/skyguard/skyguard/internal/firewall"
)

// Listener is one port that takes connections on this host.
type Listener struct {
	Proto   string   `json:"proto"`
	Port    int      `json:"port"`
	Addrs   []string `json:"addrs"`                  // bound addresses; 0.0.0.0 and :: mean every address
	Scope   string   `json:"scope"`                  // public, private (internal addresses only) or local (loopback only)
	Process string   `json:"process,omitempty"`      // the program holding the socket
	Owner   string   `json:"owner,omitempty"`        // container or SkyGuard service behind it
	Kind    string   `json:"kind,omitempty"`         // docker, incus, skyguard or host
	ID      string   `json:"container_id,omitempty"` // the container's ID, when the engine is managed
	Address string   `json:"address,omitempty"`      // a forwarded address this port is on; "" for the host's own
	Service string   `json:"service,omitempty"`      // what usually runs on this port
	Risk    string   `json:"risk,omitempty"`         // database, admin, remote or files: worth closing to the internet
}

// Known describes what usually listens on a port.
type Known struct {
	Name string
	Risk string
}

// WellKnown maps common ports to what usually runs there. Ports marked with
// a risk are the ones scanners look for first.
var WellKnown = map[int]Known{
	21: {"FTP", "files"}, 22: {"SSH", "remote"}, 23: {"Telnet", "remote"}, 25: {"SMTP", ""}, 53: {"DNS", ""},
	80: {"HTTP", ""}, 110: {"POP3", ""}, 111: {"rpcbind", "admin"}, 143: {"IMAP", ""}, 443: {"HTTPS", ""},
	445: {"SMB", "files"}, 465: {"SMTPS", ""}, 587: {"SMTP submission", ""}, 993: {"IMAPS", ""}, 995: {"POP3S", ""},
	1080: {"SOCKS proxy", "admin"}, 1433: {"SQL Server", "database"}, 1521: {"Oracle", "database"},
	2049: {"NFS", "files"}, 2181: {"ZooKeeper", "database"}, 2375: {"Docker API (plain)", "admin"},
	2376: {"Docker API", "admin"}, 2379: {"etcd", "database"}, 3000: {"Grafana / web app", ""},
	3306: {"MySQL / MariaDB", "database"}, 3389: {"RDP", "remote"}, 4369: {"Erlang port mapper", "admin"},
	5432: {"PostgreSQL", "database"}, 5601: {"Kibana", "admin"}, 5672: {"RabbitMQ", "database"},
	5900: {"VNC", "remote"}, 5984: {"CouchDB", "database"}, 6379: {"Redis", "database"},
	6443: {"Kubernetes API", "admin"}, 7000: {"Cassandra cluster", "database"}, 7001: {"Cassandra cluster (TLS)", "database"},
	7199: {"Cassandra JMX", "admin"}, 7474: {"Neo4j", "database"}, 8080: {"HTTP alt", ""}, 8086: {"InfluxDB", "database"},
	8123: {"ClickHouse HTTP", "database"}, 8443: {"HTTPS alt", ""}, 8500: {"Consul", "admin"},
	9000: {"ClickHouse native", "database"}, 9004: {"ClickHouse MySQL protocol", "database"},
	9005: {"ClickHouse PostgreSQL protocol", "database"}, 9009: {"ClickHouse replication", "database"},
	9042: {"Cassandra / ScyllaDB CQL", "database"}, 9090: {"Prometheus / SkyGuard", "admin"},
	9092: {"Kafka", "database"}, 9142: {"ScyllaDB CQL (TLS)", "database"}, 9160: {"Cassandra Thrift", "database"},
	9180: {"ScyllaDB metrics", "admin"}, 9200: {"Elasticsearch", "database"}, 9300: {"Elasticsearch cluster", "database"},
	9418: {"git daemon", ""}, 10000: {"ScyllaDB REST API", "admin"}, 10250: {"kubelet", "admin"},
	11211: {"Memcached", "database"}, 15672: {"RabbitMQ admin", "admin"}, 19042: {"ScyllaDB shard-aware CQL", "database"},
	25565: {"Minecraft", ""}, 27017: {"MongoDB", "database"}, 27018: {"MongoDB shard", "database"},
	28015: {"RethinkDB", "database"}, 50000: {"Jenkins agent", "admin"},
}

// Socket is one listening socket found in /proc.
type Socket struct {
	Proto string
	Addr  netip.Addr
	Port  int
	Inode string
}

// ReadSockets lists the listening TCP sockets and bound UDP sockets of this
// network namespace.
func ReadSockets(procNet string) []Socket {
	var out []Socket
	for _, f := range []struct{ file, proto, state string }{
		{"tcp", "tcp", "0A"}, {"tcp6", "tcp", "0A"}, {"udp", "udp", "07"}, {"udp6", "udp", "07"},
	} {
		fh, err := os.Open(filepath.Join(procNet, f.file))
		if err != nil {
			continue
		}
		out = append(out, parseSockets(fh, f.proto, f.state)...)
		fh.Close()
	}
	return out
}

func parseSockets(r interface{ Read([]byte) (int, error) }, proto, state string) []Socket {
	var out []Socket
	sc := bufio.NewScanner(r)
	sc.Scan() // header
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 10 || f[3] != state {
			continue
		}
		if proto == "udp" && !strings.HasSuffix(f[2], ":0000") {
			continue // a connected UDP socket is a client, not a service
		}
		host, port, ok := strings.Cut(f[1], ":")
		if !ok {
			continue
		}
		addr, err := procAddr(host)
		if err != nil {
			continue
		}
		p, err := strconv.ParseUint(port, 16, 16)
		if err != nil || p == 0 {
			continue
		}
		out = append(out, Socket{Proto: proto, Addr: addr, Port: int(p), Inode: f[9]})
	}
	return out
}

// procAddr decodes /proc/net's hex addresses: 32-bit words in host (little
// endian) byte order.
func procAddr(h string) (netip.Addr, error) {
	b, err := hex.DecodeString(h)
	if err != nil || (len(b) != 4 && len(b) != 16) {
		return netip.Addr{}, fmt.Errorf("bad address %q", h)
	}
	for i := 0; i < len(b); i += 4 {
		b[i], b[i+1], b[i+2], b[i+3] = b[i+3], b[i+2], b[i+1], b[i]
	}
	a, _ := netip.AddrFromSlice(b)
	return a.Unmap(), nil
}

// SocketOwners maps socket inodes to the name of the program holding them.
// It needs root to see other users' programs; unknown sockets are left out.
func SocketOwners(proc string) map[string]string {
	out := map[string]string{}
	pids, _ := filepath.Glob(filepath.Join(proc, "[0-9]*"))
	for _, pid := range pids {
		fds, err := os.ReadDir(filepath.Join(pid, "fd"))
		if err != nil {
			continue
		}
		name := ""
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(pid, "fd", fd.Name()))
			if err != nil || !strings.HasPrefix(link, "socket:[") {
				continue
			}
			if name == "" {
				b, _ := os.ReadFile(filepath.Join(pid, "comm"))
				if name = strings.TrimSpace(string(b)); name == "" {
					name = "?"
				}
			}
			out[strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")] = name
		}
	}
	return out
}

// Claim names who is behind a host port, from the container engines or
// SkyGuard itself.
type Claim struct {
	Proto  string
	Port   int
	HostIP string // "" for every address
	Owner  string
	Kind   string // docker, incus, skyguard
	ID     string // container ID
}

// Listeners merges the sockets, Docker's nat-only ports and the known
// claims into one list: public ports first, then by port.
func Listeners(socks []Socket, owners map[string]string, nat []firewall.NATPort, claims []Claim) []Listener {
	type key struct {
		proto string
		port  int
	}
	byKey := map[key]*Listener{}
	get := func(proto string, port int) *Listener {
		k := key{proto, port}
		if byKey[k] == nil {
			l := &Listener{Proto: proto, Port: port, Addrs: []string{}}
			if wk, ok := WellKnown[port]; ok {
				l.Service, l.Risk = wk.Name, wk.Risk
			}
			byKey[k] = l
		}
		return byKey[k]
	}
	addAddr := func(l *Listener, a string) {
		for _, x := range l.Addrs {
			if x == a {
				return
			}
		}
		l.Addrs = append(l.Addrs, a)
	}
	for _, s := range socks {
		l := get(s.Proto, s.Port)
		addAddr(l, s.Addr.String())
		if p := owners[s.Inode]; p != "" && (l.Process == "" || l.Process == "docker-proxy") {
			l.Process = p
		}
	}
	for _, n := range nat {
		l := get(n.Proto, n.Port)
		a := n.HostIP
		if a == "" {
			a = "0.0.0.0"
		}
		addAddr(l, a)
		if l.Owner == "" {
			l.Owner, l.Kind = n.Dest, "docker"
		}
	}
	for _, c := range claims {
		k := key{c.Proto, c.Port}
		l := byKey[k]
		if l == nil {
			continue // claimed but not listening: nothing to protect
		}
		if l.Kind == "" || (l.Kind == "docker" && strings.Contains(l.Owner, ":")) {
			l.Owner, l.Kind, l.ID = c.Owner, c.Kind, c.ID
		}
	}
	out := make([]Listener, 0, len(byKey))
	for _, l := range byKey {
		if l.Kind == "" {
			switch l.Process {
			case "docker-proxy":
				l.Kind = "docker"
			case "incusd", "lxd":
				l.Kind = "incus"
			default:
				l.Kind = "host"
			}
		}
		l.Scope = scope(l.Addrs)
		sort.Strings(l.Addrs)
		out = append(out, *l)
	}
	rank := map[string]int{"public": 0, "private": 1, "local": 2}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if rank[a.Scope] != rank[b.Scope] {
			return rank[a.Scope] < rank[b.Scope]
		}
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		return a.Proto < b.Proto
	})
	return out
}

// scope is "public" when any bound address takes traffic from anywhere,
// "private" when all are internal addresses (a container bridge, a LAN),
// "local" when all are loopback.
func scope(addrs []string) string {
	s := "local"
	for _, a := range addrs {
		ip, err := netip.ParseAddr(a)
		if err != nil {
			return "public"
		}
		switch {
		case ip.IsUnspecified():
			return "public"
		case ip.IsLoopback():
		case ip.IsPrivate() || ip.IsLinkLocalUnicast() || cgnat.Contains(ip):
			s = "private"
		default:
			return "public"
		}
	}
	return s
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")
