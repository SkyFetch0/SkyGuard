package firewall

import (
	"bytes"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
	"time"
)

// IPTablesFirewall implements Firewall via the iptables command-line tool.
type IPTablesFirewall struct {
	logger *slog.Logger
}

// BanIP inserts a DROP rule for ip at the top of the INPUT chain.
// Idempotent: if a matching rule already exists it is not added again, so a
// banned IP that keeps reconnecting cannot grow the rule table unbounded.
func (i *IPTablesFirewall) BanIP(ip string, _ time.Duration) error {
	if err := validateIP(ip); err != nil {
		return err
	}
	// "-C" returns exit code 0 when the rule already exists.
	if exec.Command("iptables", "-C", "INPUT", "-s", ip, "-j", "DROP").Run() == nil {
		return nil
	}
	if err := runCmd("iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"); err != nil {
		return fmt.Errorf("iptables ban %s: %w", ip, err)
	}
	if i.logger != nil {
		i.logger.Info("iptables ban applied", "ip", ip)
	}
	return nil
}

// UnbanIP deletes the DROP rule for ip from the INPUT chain.
func (i *IPTablesFirewall) UnbanIP(ip string) error {
	if err := validateIP(ip); err != nil {
		return err
	}
	if err := runCmd("iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"); err != nil {
		return fmt.Errorf("iptables unban %s: %w", ip, err)
	}
	if i.logger != nil {
		i.logger.Info("iptables ban removed", "ip", ip)
	}
	return nil
}

// IsBanned reports whether ip appears in the INPUT chain's numeric listing.
func (i *IPTablesFirewall) IsBanned(ip string) (bool, error) {
	if err := validateIP(ip); err != nil {
		return false, err
	}
	out, err := exec.Command("iptables", "-L", "INPUT", "-n").Output()
	if err != nil {
		return false, fmt.Errorf("iptables -L INPUT -n: %w", err)
	}
	return bytes.Contains(out, []byte(ip)), nil
}

// BanIPPermanent is identical to BanIP for iptables.
func (i *IPTablesFirewall) BanIPPermanent(ip string) error {
	if err := i.BanIP(ip, 0); err != nil {
		return err
	}
	if i.logger != nil {
		i.logger.Info("iptables permanent ban applied", "ip", ip)
	}
	return nil
}

// Method implements Firewall.
func (i *IPTablesFirewall) Method() string { return "iptables" }

// List returns the numbered rules of the INPUT chain.
func (i *IPTablesFirewall) List() ([]string, error) {
	out, err := exec.Command("iptables", "-L", "INPUT", "-n", "--line-numbers").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("iptables -L INPUT: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}
	return splitNonEmptyLines(string(out)), nil
}