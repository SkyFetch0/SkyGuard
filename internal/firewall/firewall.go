package firewall

import (
	"fmt"
	"log/slog"
	"runtime"
	"time"
)

// Firewall is the interface implemented by every firewall backend.
type Firewall interface {
	// BanIP blocks the IP for the specified duration.
	BanIP(ip string, duration time.Duration) error

	// BanIPPermanent blocks the IP without an expiry.
	BanIPPermanent(ip string) error

	// UnbanIP removes an existing block for the IP.
	UnbanIP(ip string) error

	// IsBanned reports whether the IP is currently blocked at the firewall level.
	IsBanned(ip string) (bool, error)

	// List returns a human-readable snapshot of the backend's active rules.
	List() ([]string, error)

	// Method returns the backend identifier ("iptables", "ufw", "none").
	Method() string
}

// New returns the Firewall implementation for method.
// Supported values: "ufw", "iptables", "none", "log" (noop).
// On non-Linux hosts any method other than "none" / "log" falls back to noop.
func New(method string, logger *slog.Logger) (Firewall, error) {
	if runtime.GOOS != "linux" && method != "none" && method != "log" {
		if logger != nil {
			logger.Warn("firewall: non-linux OS, falling back to noop", "method", method)
		}
		return &NoopFirewall{logger: logger, method: method}, nil
	}

	switch method {
	case "ufw":
		return &UFWFirewall{logger: logger}, nil
	case "iptables":
		return &IPTablesFirewall{logger: logger}, nil
	case "none", "log", "":
		return &NoopFirewall{logger: logger, method: "none"}, nil
	default:
		return nil, fmt.Errorf("unknown firewall method %q (supported: ufw, iptables, none)", method)
	}
}