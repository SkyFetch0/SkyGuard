package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"

	"github.com/skyguard/skyguard/internal/config"
	"github.com/skyguard/skyguard/internal/containers"
	"github.com/skyguard/skyguard/internal/dashboard"
	"github.com/skyguard/skyguard/internal/honeypot"
	"github.com/skyguard/skyguard/internal/stealth"
)

// svcRuntime is one configured service and its listener. Honeypots can be
// switched on and off at runtime from the dashboard; stealth and passthrough
// services are config-managed (switching the stealth port off from a panel
// that is usually reached through it would cut the operator's own session).
type svcRuntime struct {
	service
	htype      string // honeypot protocol, known even before the handler exists
	hcfg       config.HoneypotService
	cfgEnabled bool // what the config file says

	// guarded by Server.mu
	enabled bool
	ln      net.Listener
	conns   map[net.Conn]struct{}
	lastErr string
}

func (rt *svcRuntime) toggleable() bool { return rt.kind == kindHoneypot }

// buildServices creates a runtime entry for every configured service,
// enabled or not, and applies stored dashboard overrides to honeypots.
func (s *Server) buildServices() error {
	var out []*svcRuntime
	for _, svc := range s.cfg.Stealth {
		out = append(out, &svcRuntime{
			service: service{kind: kindStealth, name: svc.Name, port: svc.ListenPort,
				stealth: stealth.NewHandler(svc, s.proxy, s.logger.With("service", svc.Name))},
			cfgEnabled: svc.IsEnabled(), enabled: svc.IsEnabled(),
		})
	}
	for _, svc := range s.cfg.Honeypots {
		rt := &svcRuntime{
			service:    service{kind: kindHoneypot, name: svc.Name, port: svc.Port},
			htype:      svc.Type,
			hcfg:       svc,
			cfgEnabled: svc.IsEnabled(),
			enabled:    svc.IsEnabled(),
		}
		on, ok, err := s.db.ServiceOverride(svc.Name, rt.cfgEnabled)
		if err != nil {
			return fmt.Errorf("honeypot %q: reading dashboard override: %w", svc.Name, err)
		}
		if ok && on != rt.enabled {
			s.logger.Info("honeypot state set from the dashboard", "name", svc.Name, "enabled", on)
			rt.enabled = on
		}
		out = append(out, rt)
	}
	for _, svc := range s.cfg.Passthrough {
		out = append(out, &svcRuntime{
			service:    service{kind: kindPassthrough, name: svc.Name, port: svc.ListenPort, target: svc.RealTarget},
			cfgEnabled: svc.IsEnabled(), enabled: svc.IsEnabled(),
		})
	}
	s.services = out
	return nil
}

// ensureHandler builds a honeypot's handler the first time it is needed.
func (s *Server) ensureHandler(rt *svcRuntime) error {
	if rt.kind != kindHoneypot || rt.honeypot != nil {
		return nil
	}
	h, err := honeypot.NewHandler(rt.hcfg, s.eventLogger, s.cfg.General.DataDir)
	if err != nil {
		return fmt.Errorf("honeypot %q: %w", rt.name, err)
	}
	rt.honeypot = h
	return nil
}

// startListener opens rt's port and starts accepting. Caller holds s.mu.
func (s *Server) startListenerLocked(ctx context.Context, rt *svcRuntime) error {
	if rt.ln != nil {
		return nil
	}
	if err := s.ensureHandler(rt); err != nil {
		rt.lastErr = err.Error()
		return err
	}
	// ":port" listens on both IPv4 and IPv6 (the old "0.0.0.0:port" never
	// saw IPv6 attackers at all).
	addr := fmt.Sprintf(":%d", rt.port)
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", addr)
	if err != nil {
		err = fmt.Errorf("%s %q: listen %s: %w%s", rt.kind, rt.name, addr, err, listenHint(err, rt.port))
		rt.lastErr = err.Error()
		return err
	}
	rt.ln, rt.lastErr = ln, ""
	rt.conns = make(map[net.Conn]struct{})
	s.logger.Info("listener started", "kind", rt.kind, "name", rt.name, "addr", addr)

	svc := rt.service
	s.wg.Add(1)
	go s.acceptLoop(rt, ln, func(conn net.Conn) { s.handleConnection(conn, svc) })
	return nil
}

// stopListenerLocked closes rt's listener and its open connections. Caller holds s.mu.
func (s *Server) stopListenerLocked(rt *svcRuntime) {
	if rt.ln == nil {
		return
	}
	rt.ln.Close()
	rt.ln = nil
	for c := range rt.conns {
		c.Close()
	}
	s.logger.Info("listener stopped", "kind", rt.kind, "name", rt.name, "port", rt.port)
}

// Services implements dashboard.Controller.
func (s *Server) Services() []dashboard.ServiceStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]dashboard.ServiceStatus, 0, len(s.services))
	for _, rt := range s.services {
		typ := rt.kind
		if rt.kind == kindHoneypot {
			typ = rt.htype
		}
		out = append(out, dashboard.ServiceStatus{
			Name:          rt.name,
			Kind:          rt.kind,
			Type:          typ,
			Port:          rt.port,
			Target:        rt.target,
			Enabled:       rt.enabled,
			ConfigEnabled: rt.cfgEnabled,
			Running:       rt.ln != nil,
			Toggleable:    rt.toggleable(),
			Active:        len(rt.conns),
			Error:         rt.lastErr,
		})
	}
	order := map[string]int{kindHoneypot: 0, kindStealth: 1, kindPassthrough: 2}
	sort.SliceStable(out, func(i, j int) bool { return order[out[i].Kind] < order[out[j].Kind] })
	return out
}

// ErrNotToggleable is returned for services that are managed by the config file.
var ErrNotToggleable = errors.New("only honeypots can be switched from the dashboard; stealth and passthrough services are managed in the config file")

// SetServiceEnabled switches a honeypot on or off at runtime and remembers
// the choice across restarts (until the config file changes that service).
// It implements dashboard.Controller.
func (s *Server) SetServiceEnabled(name string, enabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopping {
		return errors.New("server is shutting down")
	}
	var rt *svcRuntime
	for _, x := range s.services {
		if x.name == name {
			rt = x
			break
		}
	}
	if rt == nil {
		return fmt.Errorf("unknown service %q", name)
	}
	if !rt.toggleable() {
		return ErrNotToggleable
	}

	if enabled {
		for _, other := range s.services {
			if other != rt && other.ln != nil && other.port == rt.port {
				return fmt.Errorf("port %d is already used by %s %q", rt.port, other.kind, other.name)
			}
		}
		if err := s.startListenerLocked(s.ctx, rt); err != nil {
			return err
		}
	} else {
		s.stopListenerLocked(rt)
		rt.lastErr = ""
	}
	rt.enabled = enabled
	if err := s.db.SetServiceOverride(rt.name, enabled, rt.cfgEnabled); err != nil {
		return fmt.Errorf("saving the switch: %w", err)
	}
	s.logger.Info("honeypot switched from the dashboard", "name", rt.name, "enabled", enabled)
	return nil
}

// containerManager builds the container manager whenever the dashboard
// runs, so its engines can be switched on from the panel. Each engine starts
// as the config file says, unless the dashboard switched it since (the file
// wins again once that engine is edited there). It is told which host ports
// SkyGuard's own listeners hold, so a container is never moved onto one.
func (s *Server) containerManager() *containers.Manager {
	cc := s.cfg.Containers
	engines := []containers.Engine{
		containers.NewDocker(cc.Docker.Socket, s.logger.With("engine", "docker")),
		containers.NewIncus(cc.Incus.Socket, cc.Incus.Project, s.logger.With("engine", "incus")),
	}
	cfgOn := map[string]bool{"docker": cc.Docker.Enabled, "incus": cc.Incus.Enabled}
	m := containers.NewManager(engines, cc.ReadOnly, s.logger.With("component", "containers"))
	for _, e := range engines {
		name := e.Name()
		on := cfgOn[name]
		if v, ok, err := s.db.ServiceOverride(engineKey(name), cfgOn[name]); err != nil {
			s.logger.Error("reading the dashboard's container engine switch", "engine", name, "error", err)
		} else if ok {
			on = v
		}
		m.SetInitial(name, on)
	}
	if m.AnyEnabled() {
		s.logger.Warn("container management is enabled: the dashboard can control the host's containers, so keep its password strong and its address private",
			"docker", m.Enabled("docker"), "incus", m.Enabled("incus"), "read_only", cc.ReadOnly)
	}
	m.Reserved = s.ReservedPorts
	m.OnSwitch = func(engine string, on bool) error {
		if on {
			if err := s.cfg.ContainersAllowed(); err != nil {
				return err
			}
		}
		return s.db.SetServiceOverride(engineKey(engine), on, cfgOn[engine])
	}
	return m
}

func engineKey(engine string) string { return "container-engine:" + engine }

// ReservedPorts lists the host ports SkyGuard's listeners hold or tried to
// take, and the dashboard's own port.
func (s *Server) ReservedPorts() []containers.Reserved {
	var out []containers.Reserved
	for _, st := range s.Services() {
		if !st.Enabled || (!st.Running && st.Error == "") {
			continue
		}
		out = append(out, containers.Reserved{Port: st.Port, Proto: "tcp", Owner: st.Kind + " " + st.Name, Failed: st.Error})
	}
	if s.cfg.Dashboard.Enabled {
		if _, p, err := net.SplitHostPort(s.cfg.Dashboard.Listen); err == nil {
			if n, err := strconv.Atoi(p); err == nil {
				out = append(out, containers.Reserved{Port: n, Proto: "tcp", Owner: "dashboard"})
			}
		}
	}
	return out
}
