package firewall

import (
	"log/slog"
	"time"
)

// NoopFirewall is a no-op implementation for development / testing environments
// where actual firewall manipulation is not desired. All operations are logged
// and return nil.
type NoopFirewall struct {
	logger *slog.Logger
	method string
}

func (n *NoopFirewall) BanIP(ip string, _ time.Duration) error {
	if n.logger != nil {
		n.logger.Info("firewall ban (noop)", "ip", ip)
	}
	return nil
}

func (n *NoopFirewall) UnbanIP(ip string) error {
	if n.logger != nil {
		n.logger.Info("firewall unban (noop)", "ip", ip)
	}
	return nil
}

func (n *NoopFirewall) IsBanned(_ string) (bool, error) { return false, nil }

func (n *NoopFirewall) BanIPPermanent(ip string) error {
	if n.logger != nil {
		n.logger.Info("firewall permanent ban (noop)", "ip", ip)
	}
	return nil
}

// Method implements Firewall.
func (n *NoopFirewall) Method() string {
	if n.method == "" {
		return "none"
	}
	return n.method
}

// List implements Firewall. The noop backend enforces nothing at the kernel
// level, so it reports its status rather than real rules.
func (n *NoopFirewall) List() ([]string, error) {
	return []string{
		"firewall enforcement is DISABLED (method=" + n.Method() + ")",
		"bans are recorded in the database and shown here, but no kernel rule is applied",
		"set analysis.auto_ban.method to \"iptables\" (recommended for Docker) or \"ufw\" to enforce",
	}, nil
}