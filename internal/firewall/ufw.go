package firewall

import (
	"bytes"
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"strings"
	"time"
)

// UFWFirewall implements Firewall via the ufw command-line tool.
type UFWFirewall struct {
	logger *slog.Logger
}

// BanIP adds a ufw deny rule for ip. Duration is not enforced by ufw itself;
// call UnbanIP to remove the rule when the ban expires.
func (u *UFWFirewall) BanIP(ip string, _ time.Duration) error {
	if err := validateIP(ip); err != nil {
		return err
	}
	if err := runCmd("ufw", "deny", "from", ip, "to", "any"); err != nil {
		return fmt.Errorf("ufw ban %s: %w", ip, err)
	}
	if u.logger != nil {
		u.logger.Info("ufw ban applied", "ip", ip)
	}
	return nil
}

// UnbanIP removes the ufw deny rule for ip.
func (u *UFWFirewall) UnbanIP(ip string) error {
	if err := validateIP(ip); err != nil {
		return err
	}
	if err := runCmd("ufw", "delete", "deny", "from", ip, "to", "any"); err != nil {
		return fmt.Errorf("ufw unban %s: %w", ip, err)
	}
	if u.logger != nil {
		u.logger.Info("ufw ban removed", "ip", ip)
	}
	return nil
}

// IsBanned reports whether ip appears in the current ufw status output.
func (u *UFWFirewall) IsBanned(ip string) (bool, error) {
	if err := validateIP(ip); err != nil {
		return false, err
	}
	out, err := exec.Command("ufw", "status").Output()
	if err != nil {
		return false, fmt.Errorf("ufw status: %w", err)
	}
	return bytes.Contains(out, []byte(ip)), nil
}

// BanIPPermanent is identical to BanIP; ufw rules are permanent by default.
func (u *UFWFirewall) BanIPPermanent(ip string) error {
	if err := u.BanIP(ip, 0); err != nil {
		return err
	}
	if u.logger != nil {
		u.logger.Info("ufw permanent ban applied", "ip", ip)
	}
	return nil
}

// Method implements Firewall.
func (u *UFWFirewall) Method() string { return "ufw" }

// List returns the numbered ufw status output.
func (u *UFWFirewall) List() ([]string, error) {
	out, err := exec.Command("ufw", "status", "numbered").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("ufw status: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}
	return splitNonEmptyLines(string(out)), nil
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

// validateIP returns an error if s is not a valid IP address.
func validateIP(s string) error {
	if net.ParseIP(strings.TrimSpace(s)) == nil {
		return fmt.Errorf("invalid IP address: %q", s)
	}
	return nil
}

// runCmd executes a command and wraps any error with stdout/stderr output.
func runCmd(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %w (output: %s)", name, args, err, strings.TrimSpace(string(out)))
	}
	return nil
}