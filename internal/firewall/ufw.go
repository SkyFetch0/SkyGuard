package firewall

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"sync"
)

// UFWFirewall implements Firewall via the ufw command-line tool.
type UFWFirewall struct {
	logger *slog.Logger
	run    runner
	mu     sync.Mutex
}

func newUFW(logger *slog.Logger, run runner) (*UFWFirewall, error) {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return nil, errors.New("running inside a container: ufw would only edit the container's own rules, not the host's")
	}
	if _, err := exec.LookPath("ufw"); err != nil {
		return nil, errors.New("ufw binary not found")
	}
	out, err := run("ufw", "status")
	if err != nil {
		return nil, fmt.Errorf("ufw status: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	if !strings.Contains(string(out), "Status: active") {
		return nil, errors.New("ufw is installed but not active (rules would have no effect)")
	}
	return &UFWFirewall{logger: logger, run: run}, nil
}

// Ban adds a deny rule for ip at the TOP of the ufw rule list. A plain
// "ufw deny" appends the rule after existing "allow" rules, so an attacker
// could still reach every explicitly allowed port (e.g. 22) — prepending
// makes the deny win.
func (u *UFWFirewall) Ban(ip string) error {
	canon, _, err := parseIP(ip)
	if err != nil {
		return err
	}
	u.mu.Lock()
	defer u.mu.Unlock()

	if banned, _ := u.isBannedLocked(canon); banned {
		return nil
	}
	out, err := u.run("ufw", "prepend", "deny", "from", canon, "to", "any")
	if err != nil {
		// ufw < 0.36 has no "prepend"; "insert 1" is the closest equivalent
		// (it fails on an empty rule list, where a plain deny is first anyway).
		if out2, err2 := u.run("ufw", "insert", "1", "deny", "from", canon, "to", "any"); err2 == nil {
			out, err = out2, nil
		} else if out3, err3 := u.run("ufw", "deny", "from", canon, "to", "any"); err3 == nil {
			out, err = out3, nil
		}
	}
	if err != nil {
		return fmt.Errorf("ufw ban %s: %w (%s)", canon, err, strings.TrimSpace(string(out)))
	}
	u.logger.Info("ufw ban applied", "ip", canon)
	return nil
}

// Unban removes the ufw deny rule for ip. A missing rule is not an error.
func (u *UFWFirewall) Unban(ip string) error {
	canon, _, err := parseIP(ip)
	if err != nil {
		return err
	}
	u.mu.Lock()
	defer u.mu.Unlock()

	out, err := u.run("ufw", "delete", "deny", "from", canon, "to", "any")
	if err != nil && !strings.Contains(strings.ToLower(string(out)), "non-existent") {
		return fmt.Errorf("ufw unban %s: %w (%s)", canon, err, strings.TrimSpace(string(out)))
	}
	u.logger.Info("ufw ban removed", "ip", canon)
	return nil
}

// IsBanned reports whether ufw has a DENY rule whose source is exactly ip.
func (u *UFWFirewall) IsBanned(ip string) (bool, error) {
	canon, _, err := parseIP(ip)
	if err != nil {
		return false, err
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.isBannedLocked(canon)
}

func (u *UFWFirewall) isBannedLocked(canon string) (bool, error) {
	out, err := u.run("ufw", "status")
	if err != nil {
		return false, fmt.Errorf("ufw status: %w", err)
	}
	return ufwStatusHasDeny(string(out), canon), nil
}

// ufwStatusHasDeny parses `ufw status` output. Rule lines look like
// "Anywhere                   DENY        1.2.3.4"; the source is the last
// field, so an exact match avoids "1.2.3.4" matching "1.2.3.40".
func ufwStatusHasDeny(status, ip string) bool {
	for _, line := range strings.Split(status, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		isDeny := false
		for _, f := range fields {
			if f == "DENY" {
				isDeny = true
				break
			}
		}
		if isDeny && fields[len(fields)-1] == ip {
			return true
		}
	}
	return false
}

// Method implements Firewall.
func (u *UFWFirewall) Method() string { return "ufw" }

// List returns the numbered ufw status output.
func (u *UFWFirewall) List() ([]string, error) {
	out, err := u.run("ufw", "status", "numbered")
	if err != nil {
		return nil, fmt.Errorf("ufw status: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}
	return splitNonEmptyLines(string(out)), nil
}
