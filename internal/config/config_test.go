package config

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestParseDuration(t *testing.T) {
	cases := map[string]time.Duration{
		"90s":   90 * time.Second,
		"24h":   24 * time.Hour,
		"7d":    7 * 24 * time.Hour,
		"1d12h": 36 * time.Hour,
		"0s":    0,
		"0":     0,
	}
	for in, want := range cases {
		got, err := ParseDuration(in)
		if err != nil || got != want {
			t.Errorf("ParseDuration(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "xd", "-1d", "5x"} {
		if _, err := ParseDuration(bad); err == nil {
			t.Errorf("ParseDuration(%q) succeeded, want error", bad)
		}
	}
}

func TestDefaultsAndPermanentBan(t *testing.T) {
	cfg, err := Parse([]byte("general:\n  data_dir: /tmp/sg\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Analysis.AutoBan.BanDuration != 24*time.Hour {
		t.Errorf("omitted ban_duration = %v, want 24h", cfg.Analysis.AutoBan.BanDuration)
	}
	if cfg.Logging.DBPath != "/tmp/sg/skyguard.db" {
		t.Errorf("db_path default = %q", cfg.Logging.DBPath)
	}
	if cfg.Dashboard.Listen != DefaultDashboardListen {
		t.Errorf("dashboard listen default = %q", cfg.Dashboard.Listen)
	}

	cfg, err = Parse([]byte("analysis:\n  auto_ban:\n    ban_duration: \"0s\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Analysis.AutoBan.BanDuration != 0 {
		t.Errorf("explicit 0s ban_duration was replaced by %v", cfg.Analysis.AutoBan.BanDuration)
	}
}

func TestValidate(t *testing.T) {
	bad := `
honeypot_services:
  - {name: a, port: 2222, type: ssh}
  - {name: b, port: 2222, type: ftp}
  - {name: c, port: 70000, type: http}
  - {name: d, port: 2121, type: telnet}
  - {name: e, port: 2223, type: ssh, enabled: false}
  - {name: f, port: 2223, type: ssh}
stealth_services:
  - {name: s, listen_port: 9911, real_target: "nonsense"}
whitelist:
  ips: ["10.0.0.0/8", "not-an-ip"]
analysis:
  auto_ban:
    method: firewalld
`
	_, err := Parse([]byte(bad))
	if err == nil {
		t.Fatal("expected validation errors")
	}
	for _, want := range []string{"already used", "out of range", "unknown type", "real_target", "not-an-ip", "unknown method"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
	if strings.Contains(err.Error(), `"f"`) {
		t.Errorf("disabled honeypot should not claim its port: %v", err)
	}
}

func TestContainersNeedAnAuthenticatedDashboard(t *testing.T) {
	base := "dashboard: {enabled: true, listen: \"127.0.0.1:9090\"%s}\ncontainers: {docker: {enabled: true}}\n"
	if _, err := Parse([]byte(fmt.Sprintf(base, ""))); err == nil || !strings.Contains(err.Error(), "dashboard.auth") {
		t.Errorf("container management without a password: %v", err)
	}
	if _, err := Parse([]byte(fmt.Sprintf(base, ", auth: {username: admin, password: CHANGE_ME_NOW}"))); err == nil {
		t.Error("container management with the example password accepted")
	}
	cfg, err := Parse([]byte(fmt.Sprintf(base, ", auth: {username: admin, password: \"long enough pw\"}")))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Containers.Docker.Socket != DefaultDockerSocket || cfg.Containers.Incus.Socket != DefaultIncusSocket || cfg.Containers.Incus.Enabled {
		t.Errorf("defaults %+v", cfg.Containers)
	}
}
