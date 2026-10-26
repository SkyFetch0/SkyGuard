package firewall

import "log/slog"

// NoopFirewall records nothing at the kernel level. Bans are still stored in
// the database and enforced by SkyGuard's own listeners (banned IPs are
// dropped on connect), but other ports on the host stay reachable.
type NoopFirewall struct {
	logger *slog.Logger
	method string
}

func (n *NoopFirewall) Ban(ip string) error {
	n.logger.Debug("firewall ban (noop)", "ip", ip)
	return nil
}

func (n *NoopFirewall) Unban(ip string) error {
	n.logger.Debug("firewall unban (noop)", "ip", ip)
	return nil
}

func (n *NoopFirewall) IsBanned(string) (bool, error) { return false, nil }

// Method implements Firewall.
func (n *NoopFirewall) Method() string {
	if n.method == "" {
		return "none"
	}
	return n.method
}

// List implements Firewall.
func (n *NoopFirewall) List() ([]string, error) {
	return []string{
		"firewall enforcement is DISABLED (method=" + n.Method() + ")",
		"bans are recorded in the database and SkyGuard's own ports drop banned IPs,",
		"but no kernel rule is applied, so other services on this host stay reachable.",
		"set analysis.auto_ban.method to \"iptables\" (recommended, also inside Docker) to enforce.",
	}, nil
}
