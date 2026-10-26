// Package netutil holds small IP helpers shared by the server and dashboard.
package netutil

import (
	"net"
	"strings"

	"github.com/skyguard/skyguard/internal/config"
)

// NormalizeIP returns the canonical text form of s, mapping IPv4-mapped IPv6
// addresses ("::ffff:1.2.3.4") to plain IPv4. Unparseable input is returned
// trimmed but otherwise unchanged.
func NormalizeIP(s string) string {
	s = strings.TrimSpace(s)
	ip := net.ParseIP(s)
	if ip == nil {
		return s
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}

// HostIP extracts and normalises the IP part of a "host:port" address.
func HostIP(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	return NormalizeIP(host)
}

// IPSet is an immutable set of IP networks (single IPs are stored as /32 or /128).
type IPSet struct {
	nets []*net.IPNet
}

// NewIPSet builds a set from IP / CIDR strings. Invalid entries are skipped
// (config validation rejects them before we get here).
func NewIPSet(entries []string) *IPSet {
	s := &IPSet{}
	for _, e := range entries {
		if n, err := config.ParseIPOrCIDR(e); err == nil {
			s.nets = append(s.nets, n)
		}
	}
	return s
}

// Contains reports whether ip (any textual form) falls into the set.
func (s *IPSet) Contains(ip string) bool {
	if s == nil || len(s.nets) == 0 {
		return false
	}
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return false
	}
	if v4 := parsed.To4(); v4 != nil {
		parsed = v4
	}
	for _, n := range s.nets {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}

// Len returns the number of networks in the set.
func (s *IPSet) Len() int {
	if s == nil {
		return 0
	}
	return len(s.nets)
}

// IsPrivateOrLocal reports whether ip is loopback, link-local or RFC1918/ULA —
// addresses that GeoIP databases cannot place in a country.
func IsPrivateOrLocal(ip string) bool {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return false
	}
	return parsed.IsLoopback() || parsed.IsPrivate() ||
		parsed.IsLinkLocalUnicast() || parsed.IsUnspecified()
}
