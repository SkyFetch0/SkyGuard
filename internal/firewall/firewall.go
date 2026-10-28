package firewall

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// Firewall is the interface implemented by every firewall backend.
// Ban durations are tracked in the database; the server calls Unban when a
// ban expires, so backends only need to add and remove block rules.
type Firewall interface {
	// Ban blocks all traffic from ip. It is idempotent.
	Ban(ip string) error
	// Unban removes the block for ip. A missing rule is not an error.
	Unban(ip string) error
	// IsBanned reports whether ip is currently blocked at the firewall level.
	IsBanned(ip string) (bool, error)
	// List returns a human-readable snapshot of the backend's active rules.
	List() ([]string, error)
	// Method returns the backend identifier ("iptables", "ufw", "none").
	Method() string
}

// Options configures New.
type Options struct {
	// IPTablesBackend is "auto", "legacy" or "nft".
	IPTablesBackend string
	// NoForward keeps the ban chain out of FORWARD: bans then cover the
	// host itself and Docker's published ports only.
	NoForward bool
}

// New returns the Firewall implementation for method ("iptables", "ufw",
// "none"/"log"). An unusable ufw (not installed, inactive, or running inside
// a container where it cannot touch the host) falls back to iptables.
func New(method string, opts Options, logger *slog.Logger) (Firewall, error) {
	if logger == nil {
		logger = slog.Default()
	}
	method = strings.ToLower(strings.TrimSpace(method))

	if runtime.GOOS != "linux" && method != "none" && method != "log" && method != "" {
		logger.Warn("firewall: non-linux OS, bans are recorded but not enforced", "method", method)
		return &NoopFirewall{logger: logger, method: method}, nil
	}

	switch method {
	case "none", "log", "":
		return &NoopFirewall{logger: logger, method: "none"}, nil
	case "ufw":
		u, err := newUFW(logger, execRunner)
		if err == nil {
			return u, nil
		}
		logger.Warn("firewall: ufw is not usable, falling back to iptables", "reason", err)
		fallthrough
	case "iptables":
		return newIPTables(opts.IPTablesBackend, !opts.NoForward, logger, execRunner)
	default:
		return nil, fmt.Errorf("unknown firewall method %q (supported: iptables, ufw, none)", method)
	}
}

// runner executes a command and returns its combined output.
type runner func(name string, args ...string) ([]byte, error)

func execRunner(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

// exitCode returns the process exit code from a runner error, or -1.
func exitCode(err error) int {
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode()
	}
	return -1
}

// parseIP validates s and returns the canonical form plus whether it is IPv6.
func parseIP(s string) (string, bool, error) {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil {
		return "", false, fmt.Errorf("invalid IP address: %q", s)
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String(), false, nil
	}
	return ip.String(), true, nil
}

// splitNonEmptyLines splits s on newlines and drops blank lines.
func splitNonEmptyLines(s string) []string {
	var lines []string
	for _, l := range strings.Split(s, "\n") {
		if t := strings.TrimRight(l, "\r"); strings.TrimSpace(t) != "" {
			lines = append(lines, t)
		}
	}
	return lines
}
