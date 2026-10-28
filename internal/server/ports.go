package server

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/skyguard/skyguard/internal/firewall"
	"github.com/skyguard/skyguard/internal/portrules"
)

// portRules builds the port access rules manager. Without a usable iptables
// the rules can still be read but not changed.
func (s *Server) portRules() *portrules.Manager {
	logger := s.logger.With("component", "port-rules")
	var guard portrules.Guard // a nil *PortGuard must stay a nil interface
	reason := ""
	if g, err := firewall.NewPortGuard(s.cfg.Analysis.AutoBan.IPTablesBackend, logger); err != nil {
		reason = err.Error()
	} else {
		guard, s.portGuard = g, g
	}
	m := portrules.New(guard, reason, s.db, s.cfg.Whitelist.IPs, logger)
	m.Protected = s.protectedPorts
	m.Addresses = s.portAddresses
	return m
}

// addrCache keeps the last address scan for a few seconds: a dashboard
// refresh asks for it several times.
type addrCache struct {
	mu   sync.Mutex
	at   time.Time
	list []portrules.Address
	dnat []portrules.DNAT
}

// portAddresses lists the server's addresses: its own, those routed to an
// instance or a VM, and DNAT-ed ones.
func (s *Server) portAddresses() []portrules.Address {
	addrs, _ := s.scanAddresses()
	return addrs
}

func (s *Server) scanAddresses() ([]portrules.Address, []portrules.DNAT) {
	c := &s.addrs
	c.mu.Lock()
	defer c.mu.Unlock()
	if time.Since(c.at) < 5*time.Second {
		return c.list, c.dnat
	}
	var dnat []portrules.DNAT
	if s.portGuard != nil {
		for _, r := range s.portGuard.DNATRules() {
			dnat = append(dnat, portrules.DNAT{Dest: r.Dest, Proto: r.Proto, Port: r.Port, To: r.To})
		}
	}
	nss := portrules.Namespaces("/proc")
	// Docker namespaces are named by container ID; the engine knows the name.
	names := map[string]string{}
	if s.ctr != nil && s.ctr.Enabled("docker") {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		for _, ct := range s.ctr.Snapshot(ctx).Containers {
			if ct.Engine == "docker" {
				names[ct.ID] = ct.Name
			}
		}
		cancel()
	}
	for i := range nss {
		if nss[i].Kind == "docker" {
			if n := names[nss[i].Name]; n != "" {
				nss[i].Name = n
			} else if len(nss[i].Name) > 12 {
				nss[i].Name = nss[i].Name[:12]
			}
		}
	}
	c.list = portrules.Discover(portrules.LocalAddrs("/proc/net"), portrules.HostRoutes("/proc/net"), nss, dnat)
	c.dnat, c.at = dnat, time.Now()
	return c.list, c.dnat
}

// protectedPorts are the ways back in: SSH (22 and wherever sshd listens),
// the stealth ports that front it, and the dashboard.
func (s *Server) protectedPorts() []portrules.Protected {
	out := []portrules.Protected{{Port: 22, Why: "SSH"}}
	seen := map[int]bool{22: true}
	add := func(port int, why string) {
		if port > 0 && !seen[port] {
			seen[port] = true
			out = append(out, portrules.Protected{Port: port, Why: why})
		}
	}
	owners := portrules.SocketOwners("/proc")
	for _, sk := range portrules.ReadSockets("/proc/net") {
		if sk.Proto == "tcp" && owners[sk.Inode] == "sshd" {
			add(sk.Port, "SSH")
		}
	}
	s.mu.Lock()
	for _, rt := range s.services {
		if rt.kind == kindStealth && rt.enabled {
			add(rt.port, fmt.Sprintf("the stealth port %q", rt.name))
		}
	}
	s.mu.Unlock()
	if s.cfg.Dashboard.Enabled {
		if _, p, err := net.SplitHostPort(s.cfg.Dashboard.Listen); err == nil {
			if n, err := strconv.Atoi(p); err == nil {
				add(n, "the dashboard")
			}
		}
	}
	return out
}

// PortListeners lists every port that takes connections on this host and
// who is behind it.
func (s *Server) PortListeners(ctx context.Context) []portrules.Listener {
	var nat []firewall.NATPort
	if s.portGuard != nil {
		nat = s.portGuard.NATPorts()
	}
	var claims []portrules.Claim
	for _, st := range s.Services() {
		if st.Running {
			claims = append(claims, portrules.Claim{Proto: "tcp", Port: st.Port, Owner: st.Kind + " " + st.Name, Kind: "skyguard"})
		}
	}
	if s.cfg.Dashboard.Enabled {
		if _, p, err := net.SplitHostPort(s.cfg.Dashboard.Listen); err == nil {
			if n, err := strconv.Atoi(p); err == nil {
				claims = append(claims, portrules.Claim{Proto: "tcp", Port: n, Owner: "dashboard", Kind: "skyguard"})
			}
		}
	}
	if s.ctr != nil && s.ctr.AnyEnabled() {
		for _, c := range s.ctr.Snapshot(ctx).Containers {
			for _, p := range c.Ports {
				if p.HostPort > 0 && c.Running {
					claims = append(claims, portrules.Claim{Proto: p.Proto, Port: p.HostPort, HostIP: p.HostIP, Owner: c.Name, Kind: c.Engine, ID: c.ID})
				}
			}
		}
	}
	owners := portrules.SocketOwners("/proc")
	addrs, dnat := s.scanAddresses()
	out := portrules.Listeners(portrules.ReadSockets("/proc/net"), owners, nat, claims)
	return append(out, portrules.ForwardedListeners("/proc", addrs, owners, dnat)...)
}
