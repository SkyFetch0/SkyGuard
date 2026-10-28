// Package portrules keeps the port access rules: who may reach which port on
// this server. It stores them, puts them into the firewall, and guards the
// ports an administrator needs to get back in (SSH, the dashboard) with a
// trial that undoes itself unless it is confirmed in time.
package portrules

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/skyguard/skyguard/internal/firewall"
)

// MaxRules caps the rule list; each rule becomes a few firewall lines.
const MaxRules = 200

// DefaultTrial is how long a change to a protected port waits for
// confirmation before it is undone.
const DefaultTrial = 2 * time.Minute

// Guard is the firewall side (firewall.PortGuard).
type Guard interface {
	Apply(rules []firewall.PortRule, extraAllow []string, sc firewall.Scope) error
	Ensure(rules []firewall.PortRule, extraAllow []string, sc firewall.Scope) error
	Remove()
	Dropped() map[string]uint64
	IPv6() bool
	NATPorts() []firewall.NATPort
}

// Store keeps the saved rules (storage.DB).
type Store interface {
	PortRules() (string, error)
	SavePortRules(string) error
}

// Protected is a port a rule could lock the administrator out of.
type Protected struct {
	Port int    `json:"port"`
	Why  string `json:"why"`
}

// Manager owns the rule set. Its zero value is not usable; call New.
type Manager struct {
	guard       Guard
	unavailable string // why rules cannot be enforced, when guard is nil
	store       Store
	logger      *slog.Logger
	extraAllow  []string
	trialFor    time.Duration

	// Protected lists the ports that need a trial; set before Start.
	Protected func() []Protected
	// Addresses lists the server's addresses (its own and the ones it
	// forwards); set before Start.
	Addresses func() []Address

	mu       sync.Mutex
	saved    []firewall.PortRule // what is stored and comes back after a restart
	active   []firewall.PortRule // what the firewall enforces now
	follow   map[string]bool     // forwarded addresses that take the server-wide rules
	scope    firewall.Scope      // what the firewall was given with active
	trial    *trial
	reverted time.Time // when a trial last ran out unconfirmed
}

type trial struct {
	deadline time.Time
	ports    []int
	timer    *time.Timer
}

// New makes a manager. guard may be nil (no iptables): the rules can then be
// seen but not changed, and unavailable says why. extraAllow (the global
// whitelist) may always reach every port that has an "only these" rule.
func New(guard Guard, unavailable string, store Store, extraAllow []string, logger *slog.Logger) *Manager {
	return &Manager{guard: guard, unavailable: unavailable, store: store, extraAllow: extraAllow, trialFor: DefaultTrial, logger: logger, follow: map[string]bool{}}
}

type stored struct {
	Rules     []firewall.PortRule `json:"rules"`
	Addresses []AddressSetting    `json:"addresses,omitempty"`
}

// AddressSetting is what is kept about one forwarded address.
type AddressSetting struct {
	IP     string `json:"ip"`
	Follow bool   `json:"follow"` // the server-wide rules cover it too
}

// Start loads the saved rules and enforces them. Nothing touches the
// firewall while there are none.
func (m *Manager) Start() error {
	raw, err := m.store.PortRules()
	if err != nil {
		return fmt.Errorf("reading the port rules: %w", err)
	}
	var st stored
	if raw != "" {
		if err := json.Unmarshal([]byte(raw), &st); err != nil {
			return fmt.Errorf("the saved port rules are unreadable: %w", err)
		}
	}
	for i := range st.Rules {
		if err := st.Rules[i].Validate(); err != nil {
			return fmt.Errorf("saved port rule %q: %w", st.Rules[i].ID, err)
		}
	}
	addrs := m.addresses()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.saved = st.Rules
	m.follow = map[string]bool{}
	for _, a := range st.Addresses {
		if a.Follow {
			m.follow[a.IP] = true
		}
	}
	if len(st.Rules) == 0 {
		return nil
	}
	if m.guard == nil {
		m.logger.Error("port access rules are saved but cannot be enforced", "reason", m.unavailable, "rules", len(st.Rules))
		return nil
	}
	sc := m.scopeOf(addrs)
	if err := m.guard.Apply(st.Rules, m.extraAllow, sc); err != nil {
		return fmt.Errorf("applying the port rules: %w", err)
	}
	m.active, m.scope = st.Rules, sc
	m.logger.Info("port access rules applied", "rules", len(st.Rules), "ipv6", m.guard.IPv6())
	return nil
}

// Maintain puts the rules back if something flushed them, and applies
// them again when the forwarded addresses changed (an instance got an IP,
// a DNAT rule came or went).
func (m *Manager) Maintain() {
	if m.guard == nil {
		return
	}
	addrs := m.addresses()
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.active) == 0 {
		return
	}
	if sc := m.scopeOf(addrs); !sameScope(sc, m.scope) {
		if err := m.guard.Apply(m.active, m.extraAllow, sc); err != nil {
			m.logger.Error("applying the port rules for the changed addresses", "error", err)
			return
		}
		m.scope = sc
		m.logger.Info("port rules applied again: the forwarded addresses changed", "follow", sc.Follow, "own_rules", sc.NoFollow)
		return
	}
	if err := m.guard.Ensure(m.active, m.extraAllow, m.scope); err != nil {
		m.logger.Error("checking the port rules in the firewall", "error", err)
	}
}

func (m *Manager) addresses() []Address {
	if m.Addresses == nil {
		return nil
	}
	return m.Addresses()
}

// scopeOf splits the forwarded addresses by whether the server-wide rules
// cover them. Call with m.mu held.
func (m *Manager) scopeOf(addrs []Address) firewall.Scope {
	var sc firewall.Scope
	for _, a := range addrs {
		if !a.Forwarded() {
			continue
		}
		if m.follow[a.IP] {
			sc.Follow = append(sc.Follow, a.IP)
		} else {
			sc.NoFollow = append(sc.NoFollow, a.IP)
		}
	}
	slices.Sort(sc.Follow)
	slices.Sort(sc.NoFollow)
	return sc
}

func sameScope(a, b firewall.Scope) bool {
	return slices.Equal(a.Follow, b.Follow) && slices.Equal(a.NoFollow, b.NoFollow)
}

// hostAddrs are the server's own addresses: only rules that reach one of
// them can lock the administrator out.
func hostAddrs(addrs []Address) []string {
	var out []string
	for _, a := range addrs {
		if !a.Forwarded() {
			out = append(out, a.IP)
		}
	}
	return out
}

// SetFollow decides whether the server-wide rules also cover a forwarded
// address.
func (m *Manager) SetFollow(ip string, follow bool) error {
	addrs := m.addresses()
	known := false
	for _, a := range addrs {
		if a.IP == ip && a.Forwarded() {
			known = true
		}
	}
	if !known {
		return fmt.Errorf("%s is not an address this server forwards", ip)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	prev := m.follow[ip]
	if follow {
		m.follow[ip] = true
	} else {
		delete(m.follow, ip)
	}
	if m.guard != nil && len(m.active) > 0 {
		sc := m.scopeOf(addrs)
		if err := m.guard.Apply(m.active, m.extraAllow, sc); err != nil {
			if prev {
				m.follow[ip] = true
			} else {
				delete(m.follow, ip)
			}
			return fmt.Errorf("the firewall refused the rules: %w", err)
		}
		m.scope = sc
	}
	if err := m.persist(m.saved); err != nil {
		return err
	}
	m.logger.Info("forwarded address changed", "ip", ip, "server_rules", follow)
	return nil
}

// Rule is a rule as the dashboard shows it.
type Rule struct {
	firewall.PortRule
	Dropped   uint64 `json:"dropped"`   // packets dropped since the rules were last applied
	Protected string `json:"protected"` // why a change here needs confirming, if it does
}

// View is the whole state for the dashboard.
type View struct {
	Available     bool        `json:"available"`
	Reason        string      `json:"reason,omitempty"`
	IPv6          bool        `json:"ipv6"`
	Rules         []Rule      `json:"rules"`
	Unsaved       bool        `json:"unsaved"` // a trial is running
	TrialDeadline *time.Time  `json:"trial_deadline,omitempty"`
	TrialPorts    []int       `json:"trial_ports,omitempty"`
	Reverted      *time.Time  `json:"reverted,omitempty"`
	Protected     []Protected `json:"protected"`
	AlwaysAllowed []string    `json:"always_allowed"`
	Addresses     []Address   `json:"addresses"`
}

// View reports the rules in force with their counters.
func (m *Manager) View() View {
	prot := m.protected()
	addrs := m.addresses()
	host := hostAddrs(addrs)
	m.mu.Lock()
	defer m.mu.Unlock()
	v := View{Available: m.guard != nil, Reason: m.unavailable, Rules: []Rule{}, Protected: prot,
		AlwaysAllowed: append([]string{"127.0.0.0/8", "::1"}, m.extraAllow...), Addresses: []Address{}}
	for _, a := range addrs {
		a.Follow = a.Forwarded() && m.follow[a.IP]
		v.Addresses = append(v.Addresses, a)
	}
	var dropped map[string]uint64
	if m.guard != nil {
		v.IPv6 = m.guard.IPv6()
		if len(m.active) > 0 {
			dropped = m.guard.Dropped()
		}
	}
	rules := m.active
	if m.guard == nil {
		rules = m.saved
	}
	for _, r := range rules {
		v.Rules = append(v.Rules, Rule{PortRule: r, Dropped: dropped[r.ID], Protected: protectedWhy(r, prot, host)})
	}
	if m.trial != nil {
		d := m.trial.deadline
		v.Unsaved, v.TrialDeadline, v.TrialPorts = true, &d, m.trial.ports
	}
	if !m.reverted.IsZero() {
		r := m.reverted
		v.Reverted = &r
	}
	return v
}

func (m *Manager) protected() []Protected {
	if m.Protected == nil {
		return []Protected{}
	}
	return m.Protected()
}

func protectedWhy(r firewall.PortRule, prot []Protected, host []string) string {
	lo, hi, err := firewall.PortRange(r.Ports)
	if err != nil || r.Proto == "udp" || !reachesHost(r, host) {
		return ""
	}
	for _, p := range prot {
		if p.Port >= lo && p.Port <= hi {
			return p.Why
		}
	}
	return ""
}

// Result tells the dashboard what a change did.
type Result struct {
	Trial    bool       `json:"trial"`
	Deadline *time.Time `json:"deadline,omitempty"`
	Ports    []int      `json:"ports,omitempty"`
}

// ErrUnavailable is returned by changes when there is no iptables.
var ErrUnavailable = errors.New("port rules cannot be enforced on this host")

// Set replaces the rule set. A change that can lock someone out of a
// protected port is enforced at once but saved only by Confirm; if Confirm
// does not come within the trial time, the saved rules come back.
func (m *Manager) Set(rules []firewall.PortRule) (Result, error) {
	if m.guard == nil {
		return Result{}, fmt.Errorf("%w: %s", ErrUnavailable, m.unavailable)
	}
	if len(rules) > MaxRules {
		return Result{}, fmt.Errorf("at most %d rules", MaxRules)
	}
	seen := map[string]bool{}
	for i := range rules {
		if err := rules[i].Validate(); err != nil {
			return Result{}, fmt.Errorf("rule %d (%s): %w", i+1, rules[i].Ports, err)
		}
		if seen[rules[i].ID] {
			return Result{}, fmt.Errorf("two rules share the id %q", rules[i].ID)
		}
		seen[rules[i].ID] = true
	}
	prot := m.protected()
	addrs := m.addresses()
	host := hostAddrs(addrs)

	m.mu.Lock()
	defer m.mu.Unlock()
	risky := riskyPorts(m.saved, rules, prot, host)
	if err := m.enforce(rules, addrs); err != nil {
		return Result{}, err
	}
	if len(risky) == 0 {
		m.stopTrial()
		if err := m.persist(rules); err != nil {
			return Result{}, err
		}
		m.saved = rules
		m.logger.Info("port access rules changed", "rules", len(rules))
		return Result{}, nil
	}
	if m.trial != nil {
		m.trial.timer.Stop()
	}
	deadline := time.Now().Add(m.trialFor)
	t := &trial{deadline: deadline, ports: risky}
	t.timer = time.AfterFunc(m.trialFor, func() { m.expire(t) })
	m.trial = t
	m.logger.Warn("port access rules changed on a protected port; they are undone unless confirmed",
		"ports", risky, "confirm_within", m.trialFor)
	return Result{Trial: true, Deadline: &deadline, Ports: risky}, nil
}

// enforce puts rules into the firewall, restoring the previous ones if that fails.
func (m *Manager) enforce(rules []firewall.PortRule, addrs []Address) error {
	if len(rules) == 0 {
		if len(m.active) > 0 {
			m.guard.Remove()
		}
		m.active = nil
		return nil
	}
	sc := m.scopeOf(addrs)
	if err := m.guard.Apply(rules, m.extraAllow, sc); err != nil {
		if len(m.active) > 0 {
			if rerr := m.guard.Apply(m.active, m.extraAllow, m.scope); rerr != nil {
				m.logger.Error("restoring the previous port rules failed", "error", rerr)
			}
		} else {
			m.guard.Remove()
		}
		return fmt.Errorf("the firewall refused the rules: %w", err)
	}
	m.active, m.scope = rules, sc
	return nil
}

// Confirm keeps the rules of a running trial.
func (m *Manager) Confirm() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.trial == nil {
		return errors.New("there is nothing to confirm")
	}
	if err := m.persist(m.active); err != nil {
		return err
	}
	m.stopTrial()
	m.saved = m.active
	m.logger.Info("port access rules confirmed", "rules", len(m.active))
	return nil
}

// Revert ends a running trial now and brings the saved rules back.
func (m *Manager) Revert() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.trial == nil {
		return errors.New("there is no unconfirmed change")
	}
	m.stopTrial()
	return m.enforce(m.saved, m.addresses())
}

func (m *Manager) expire(t *trial) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.trial != t {
		return // confirmed, reverted or replaced meanwhile
	}
	m.trial = nil
	m.reverted = time.Now()
	if err := m.enforce(m.saved, m.addresses()); err != nil {
		m.logger.Error("undoing the unconfirmed port rules failed", "error", err)
		return
	}
	m.logger.Warn("port access rules were not confirmed in time and have been undone", "rules", len(m.saved))
}

func (m *Manager) stopTrial() {
	if m.trial != nil {
		m.trial.timer.Stop()
		m.trial = nil
	}
}

func (m *Manager) persist(rules []firewall.PortRule) error {
	if rules == nil {
		rules = []firewall.PortRule{}
	}
	st := stored{Rules: rules}
	for _, ip := range slices.Sorted(maps.Keys(m.follow)) {
		st.Addresses = append(st.Addresses, AddressSetting{IP: ip, Follow: true})
	}
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	if err := m.store.SavePortRules(string(b)); err != nil {
		return fmt.Errorf("saving the port rules: %w", err)
	}
	return nil
}

// riskyPorts lists the protected ports whose enabled rules differ between
// the saved set and the new one, if the new set restricts them at all.
// Lifting a restriction cannot lock anyone out, so it needs no trial.
func riskyPorts(saved, next []firewall.PortRule, prot []Protected, host []string) []int {
	var out []int
	for _, p := range prot {
		after := covering(next, p.Port, host)
		if len(after) == 0 || slices.EqualFunc(covering(saved, p.Port, host), after, sameRule) {
			continue
		}
		if !slices.Contains(out, p.Port) {
			out = append(out, p.Port)
		}
	}
	slices.Sort(out)
	return out
}

func covering(rules []firewall.PortRule, port int, host []string) []firewall.PortRule {
	var out []firewall.PortRule
	for _, r := range rules {
		if !r.Enabled || r.Proto == "udp" || !reachesHost(r, host) {
			continue
		}
		if lo, hi, err := firewall.PortRange(r.Ports); err == nil && port >= lo && port <= hi {
			out = append(out, r)
		}
	}
	return out
}

func sameRule(a, b firewall.PortRule) bool {
	return a.Ports == b.Ports && a.Proto == b.Proto && a.Mode == b.Mode && slices.Equal(a.Sources, b.Sources) && slices.Equal(a.Addresses, b.Addresses)
}

// reachesHost reports whether a rule applies to one of the server's own
// addresses. A rule for forwarded addresses only cannot lock anyone out of
// this server. Without a list of host addresses every rule counts.
func reachesHost(r firewall.PortRule, host []string) bool {
	if len(r.Addresses) == 0 || len(host) == 0 {
		return true
	}
	for _, a := range r.Addresses {
		p, err := netip.ParsePrefix(a)
		if err != nil {
			if x, err := netip.ParseAddr(a); err == nil {
				p = netip.PrefixFrom(x, x.BitLen())
			} else {
				continue
			}
		}
		for _, h := range host {
			if x, err := netip.ParseAddr(h); err == nil && p.Contains(x) {
				return true
			}
		}
	}
	return false
}
