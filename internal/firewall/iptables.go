package firewall

import (
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
	"sync"
)

// Chain is the dedicated chain that holds SkyGuard's DROP rules. It is jumped
// to from the top of INPUT, so bans take precedence over ACCEPT rules and the
// whole set can be removed with a single flush (uninstall.sh does this).
const Chain = "SKYGUARD"

// IPTablesFirewall implements Firewall via iptables / ip6tables.
type IPTablesFirewall struct {
	logger  *slog.Logger
	run     runner
	v4, v6  string // binaries; v6 is "" when IPv6 is unavailable
	backend string // "legacy", "nft" or "default"

	// mu serialises invocations. iptables also takes the xtables lock (-w),
	// but serialising here keeps check-then-insert sequences atomic.
	mu sync.Mutex
}

func newIPTables(backend string, logger *slog.Logger, run runner) (*IPTablesFirewall, error) {
	f := &IPTablesFirewall{logger: logger, run: run}
	f.v4, f.v6, f.backend = selectBinaries(backend, run)
	if f.v4 == "" {
		return nil, fmt.Errorf("iptables binary not found (install the iptables package)")
	}
	if err := f.ensureChain(f.v4); err != nil {
		return nil, fmt.Errorf("iptables: %w (does the process have CAP_NET_ADMIN / run as root?)", err)
	}
	if f.v6 != "" {
		if err := f.ensureChain(f.v6); err != nil {
			logger.Warn("ip6tables unavailable, IPv6 addresses cannot be banned", "error", err)
			f.v6 = ""
		}
	}
	logger.Info("iptables firewall ready", "backend", f.backend, "iptables", f.v4, "ip6tables", f.v6, "chain", Chain)
	return f, nil
}

// selectBinaries picks the iptables flavour. Rules written with iptables-nft
// are invisible to iptables-legacy (and vice versa), so in "auto" mode we use
// whichever backend already holds the host's rules — the same heuristic
// Kubernetes' iptables-wrapper uses.
func selectBinaries(backend string, run runner) (v4, v6, chosen string) {
	have := func(bin string) bool { _, err := exec.LookPath(bin); return err == nil }
	pick := func(suffix string) (string, string) {
		a, b := "iptables"+suffix, "ip6tables"+suffix
		if !have(a) {
			return "", ""
		}
		if !have(b) {
			b = ""
		}
		return a, b
	}

	switch backend {
	case "legacy":
		if a, b := pick("-legacy"); a != "" {
			return a, b, "legacy"
		}
	case "nft":
		if a, b := pick("-nft"); a != "" {
			return a, b, "nft"
		}
	default: // auto
		if have("iptables-legacy") && have("iptables-nft") {
			if countRules(run, "iptables-legacy-save") > countRules(run, "iptables-nft-save") {
				a, b := pick("-legacy")
				return a, b, "legacy"
			}
			a, b := pick("-nft")
			return a, b, "nft"
		}
	}
	a, b := pick("")
	return a, b, "default"
}

func countRules(run runner, saveBin string) int {
	if _, err := exec.LookPath(saveBin); err != nil {
		return 0
	}
	out, err := run(saveBin)
	if err != nil {
		return 0
	}
	n := 0
	for _, l := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(l, "-A ") || strings.HasPrefix(l, ":") {
			n++
		}
	}
	return n
}

// ipt runs bin with the xtables lock wait flag prepended.
func (f *IPTablesFirewall) ipt(bin string, args ...string) ([]byte, error) {
	return f.run(bin, append([]string{"-w", "5"}, args...)...)
}

// exists runs an iptables -C check. Exit status 1 means "no such rule".
func (f *IPTablesFirewall) exists(bin string, rule ...string) (bool, error) {
	out, err := f.ipt(bin, append([]string{"-C"}, rule...)...)
	if err == nil {
		return true, nil
	}
	if exitCode(err) == 1 {
		return false, nil
	}
	return false, fmt.Errorf("%s -C %s: %w (%s)", bin, strings.Join(rule, " "), err, strings.TrimSpace(string(out)))
}

func (f *IPTablesFirewall) ensureChain(bin string) error {
	if _, err := f.ipt(bin, "-S", Chain); err != nil {
		if out, err := f.ipt(bin, "-N", Chain); err != nil {
			return fmt.Errorf("%s -N %s: %w (%s)", bin, Chain, err, strings.TrimSpace(string(out)))
		}
	}
	ok, err := f.exists(bin, "INPUT", "-j", Chain)
	if err != nil {
		return err
	}
	if !ok {
		if out, err := f.ipt(bin, "-I", "INPUT", "1", "-j", Chain); err != nil {
			return fmt.Errorf("%s -I INPUT -j %s: %w (%s)", bin, Chain, err, strings.TrimSpace(string(out)))
		}
	}
	f.hookDockerUser(bin)
	return nil
}

// DockerChain is where Docker leaves room for the operator's own rules.
const DockerChain = "DOCKER-USER"

// hookDockerUser makes bans cover the ports Docker publishes too: that
// traffic is DNAT-ed in PREROUTING and crosses FORWARD, never INPUT, so a
// banned IP could still reach every container. Docker jumps to DOCKER-USER
// before its own rules and never flushes it. The check repeats on every ban,
// because Docker may start after SkyGuard.
func (f *IPTablesFirewall) hookDockerUser(bin string) {
	if _, err := f.ipt(bin, "-S", DockerChain); err != nil {
		return // no Docker on this host (yet)
	}
	ok, err := f.exists(bin, DockerChain, "-j", Chain)
	if err != nil || ok {
		return
	}
	if out, err := f.ipt(bin, "-I", DockerChain, "1", "-j", Chain); err != nil {
		f.logger.Warn("could not hook bans into Docker's forwarding path; banned IPs can still reach published container ports",
			"binary", bin, "error", err, "output", strings.TrimSpace(string(out)))
		return
	}
	f.logger.Info("bans now also cover ports published by Docker containers", "binary", bin, "chain", DockerChain)
}

func (f *IPTablesFirewall) binFor(ip string) (string, string, error) {
	canon, v6, err := parseIP(ip)
	if err != nil {
		return "", "", err
	}
	if v6 {
		if f.v6 == "" {
			return "", "", fmt.Errorf("cannot ban IPv6 address %s: ip6tables unavailable", canon)
		}
		return f.v6, canon, nil
	}
	return f.v4, canon, nil
}

// Ban inserts a DROP rule for ip at the top of the SKYGUARD chain (idempotent).
func (f *IPTablesFirewall) Ban(ip string) error {
	bin, canon, err := f.binFor(ip)
	if err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()

	ok, err := f.exists(bin, Chain, "-s", canon, "-j", "DROP")
	if err != nil {
		return err
	}
	if ok {
		return nil
	}
	f.hookDockerUser(bin)
	if out, err := f.ipt(bin, "-I", Chain, "1", "-s", canon, "-j", "DROP"); err != nil {
		return fmt.Errorf("%s ban %s: %w (%s)", bin, canon, err, strings.TrimSpace(string(out)))
	}
	f.logger.Info("firewall ban applied", "ip", canon, "backend", bin)
	return nil
}

// Unban deletes every DROP rule for ip, including rules that older SkyGuard
// versions inserted directly into INPUT.
func (f *IPTablesFirewall) Unban(ip string) error {
	bin, canon, err := f.binFor(ip)
	if err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()

	removed := false
	for _, chain := range []string{Chain, "INPUT"} {
		for i := 0; i < 16; i++ { // bounded: duplicates are possible but never many
			ok, err := f.exists(bin, chain, "-s", canon, "-j", "DROP")
			if err != nil {
				return err
			}
			if !ok {
				break
			}
			if out, err := f.ipt(bin, "-D", chain, "-s", canon, "-j", "DROP"); err != nil {
				return fmt.Errorf("%s unban %s: %w (%s)", bin, canon, err, strings.TrimSpace(string(out)))
			}
			removed = true
		}
	}
	if removed {
		f.logger.Info("firewall ban removed", "ip", canon, "backend", bin)
	}
	return nil
}

// IsBanned reports whether ip has a DROP rule in the SKYGUARD chain.
func (f *IPTablesFirewall) IsBanned(ip string) (bool, error) {
	bin, canon, err := f.binFor(ip)
	if err != nil {
		return false, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.exists(bin, Chain, "-s", canon, "-j", "DROP")
}

// Method implements Firewall.
func (f *IPTablesFirewall) Method() string { return "iptables" }

// List returns the rules of the SKYGUARD chain for both address families.
func (f *IPTablesFirewall) List() ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	lines := []string{fmt.Sprintf("# backend: %s (%s)", f.backend, f.v4)}
	for _, bin := range []string{f.v4, f.v6} {
		if bin == "" {
			continue
		}
		out, err := f.ipt(bin, "-S", Chain)
		if err != nil {
			return nil, fmt.Errorf("%s -S %s: %w (%s)", bin, Chain, err, strings.TrimSpace(string(out)))
		}
		lines = append(lines, "# "+bin)
		lines = append(lines, splitNonEmptyLines(string(out))...)
	}
	return lines, nil
}

// CoversDocker reports whether bans reach the ports Docker publishes:
// docker is false when the host has no DOCKER-USER chain (no Docker), and
// covered says whether SkyGuard's chain is hooked into it.
func (f *IPTablesFirewall) CoversDocker() (docker, covered bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, err := f.ipt(f.v4, "-S", DockerChain); err != nil {
		return false, false
	}
	ok, err := f.exists(f.v4, DockerChain, "-j", Chain)
	return true, err == nil && ok
}
