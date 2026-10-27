<div align="center">

<img src="https://raw.githubusercontent.com/skyguard/skyguard/main/docs/logo.png" alt="SkyGuard" width="120" />

# SkyGuard

**Smart Linux Security Layer & Honeypot System**

*Protect your server by hiding real services, luring attackers into traps, and auto-banning threats — all in a single Go binary.*

---

[![Go](https://img.shields.io/badge/Go-1.27+-00ADD8?logo=go&logoColor=white)](https://go.dev/)
[![SQLite](https://img.shields.io/badge/SQLite-modernc%2Fsqlite-003B57?logo=sqlite&logoColor=white)](https://pkg.go.dev/modernc.org/sqlite)
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED?logo=docker&logoColor=white)](https://www.docker.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/skyguard/skyguard)](https://goreportcard.com/report/github.com/skyguard/skyguard)
[![Release](https://img.shields.io/github/v/release/skyguard/skyguard?color=green)](https://github.com/skyguard/skyguard/releases)

---

![GeoIP](https://img.shields.io/badge/GeoIP-MaxMind%20GeoLite2-00B4D8?logo=globe&logoColor=white)
![iptables](https://img.shields.io/badge/Firewall-iptables%20%7C%20ufw-EF233C?logo=linux&logoColor=white)
![Honeypots](https://img.shields.io/badge/Honeypots-SSH%20%7C%20FTP%20%7C%20MySQL%20%7C%20HTTP-6C3483?logo=security&logoColor=white)
![CGO](https://img.shields.io/badge/CGO-disabled%20(pure%20Go)-00ADD8?logo=go&logoColor=white)

</div>

---

## What is SkyGuard?

SkyGuard is a self-hosted, **zero-dependency** TCP security layer for Linux servers. Every incoming connection is intercepted, analysed, and routed based on a configurable decision engine:

- **Real services** (e.g. SSH) are hidden behind stealth ports — invisible to scanners, accessible only to clients sending the correct protocol signature.
- **Honeypot services** mimic common servers (SSH, FTP, MySQL, HTTP) to attract, log, and auto-ban attackers.
- **Passthrough services** forward traffic transparently to real backends while recording metadata.
- A **behavioural scoring engine** auto-bans IPs that exceed a configurable threat threshold via `iptables` or `ufw`.

All data is stored in a local **SQLite** database with a built-in **REST API + browser dashboard**.

---

## Traffic Decision Flow

```
Internet → Server (public IP) → SkyGuard (all ports)
                                       │
                    ┌──────────────────┼──────────────────┐
                    ▼                  ▼                   ▼
             Stealth Port        Honeypot Port      Passthrough Port
          (protocol check)     (fake + log + ban)   (analyse + proxy)
                    │
         ┌──────────┴──────────┐
         ▼                     ▼
   Correct signature       Wrong / no data
   → forward to real       → log & close
     service                 (no banner: nmap shows tcpwrapped)
```

**Per-connection pipeline:**

```
1. Whitelist (IP/CIDR, loopback always) → never scored or banned, routed directly
2. Active ban in DB     → drop, re-apply firewall rule
3. IP blacklist         → drop
4. GeoIP lookup         → stealth allowed_countries, country white/blacklist
5. Rate limit           → per-minute / per-hour exceeded? → drop + score
6. Port-scan detection  → N distinct ports in window? → drop + score (once per burst)
7. Honeypot routing     → score, log, capture credentials
8. Stealth detection    → protocol signature match? → forward : drop silently
9. Auto-ban             → score ≥ threshold → DB ban + iptables rule in the SKYGUARD chain
```

Bans are stored in SQLite and re-applied to the firewall at start-up; when a
temporary ban expires the kernel rule is removed and the IP's score is reset.
Passthrough services only apply steps 1–4 (real users must not be rate-limited).

---

## Features

| Category | Feature |
|---|---|
| 🕵️ **Stealth** | Real services hidden behind arbitrary ports; no banner is ever sent to non-matching clients |
| 🍯 **Honeypots** | SSH · FTP · MySQL · HTTP — configurable banners, individually toggled |
| 🔀 **Proxy** | Transparent TCP passthrough with connection logging |
| 📍 **GeoIP** | Country-level allow/block lists via MaxMind GeoLite2 |
| 📊 **Scoring** | Per-IP threat score; auto-ban on threshold breach |
| 🚫 **Auto-ban** | `iptables`/`ip6tables` (own `SKYGUARD` chain, legacy/nft auto-detected), `ufw` (bare metal), or dry-run (`none`) |
| 🔑 **Credentials** | Every username + password attempt harvested and ranked |
| ⏱️ **Rate limiting** | Per-IP sliding window (per-minute + per-hour) |
| 🛡️ **DoS guard** | Semaphore caps concurrent connections at 4 096 |
| 📦 **Storage** | Single-file SQLite, WAL mode, auto-purge old records |
| 🌐 **Dashboard** | Browser UI with live polling + JSON REST API |
| 🐳 **Docker** | Multi-stage image (`golang:1.27` → `debian:trixie-slim` with iptables-legacy + iptables-nft), built-in health check |
| ⚙️ **Config** | Single YAML file; hot-toggleable services (`enabled: false`) |
| 0️⃣ **Zero deps** | CGO disabled — pure Go binary, no shared libraries |

---

## Quick Start

### Docker (recommended)

```bash
# 1. Clone the repository
git clone https://github.com/skyguard/skyguard.git
cd skyguard

# 2. Copy and edit the config
cp configs/skyguard.example.yaml /etc/skyguard/skyguard.yaml
$EDITOR /etc/skyguard/skyguard.yaml          # set your whitelist IP + dashboard password

# 3. Build the image
docker build -t skyguard:latest .

# 4. Run
docker run --rm -v /etc/skyguard/skyguard.yaml:/etc/skyguard/skyguard.yaml:ro \
  skyguard:latest -check-config            # validate before starting
docker run -d \
  --name skyguard \
  --network host \
  --restart unless-stopped \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  -v /etc/skyguard/skyguard.yaml:/etc/skyguard/skyguard.yaml:ro \
  -v /var/lib/skyguard:/data \
  skyguard:latest

# 5. Access the dashboard (via SSH tunnel)
ssh -L 9090:127.0.0.1:9090 user@your-server
# → open http://localhost:9090
```

### docker compose

```bash
docker compose up -d
docker compose logs -f
```

### Automated install (Linux only)

The interactive install script auto-detects your OS, installs Docker, configures `iptables`, sets up a `systemd` service, and walks you through every option:

```bash
sudo bash install.sh
```

Supported distributions: **Ubuntu 20.04/22.04/24.04**, **Debian 11/12**, **CentOS 7/8/9**, **RHEL 8/9**, **Rocky Linux**, **AlmaLinux**, **Fedora 38+**

### Build from source

```bash
# Requires Go 1.27+ (go.mod pins toolchain go1.27.3)
make build                     # → ./bin/skyguard
make run                       # run with example config
make docker-build              # build Docker image
```

---

## Configuration

Full annotated reference: [`configs/skyguard.example.yaml`](configs/skyguard.example.yaml)

### Stealth SSH — the killer feature

Real SSH stays on `127.0.0.1:22`. SkyGuard listens on port `9911` publicly. A scanner can see that the TCP port is open, but it never receives a banner (nmap reports `tcpwrapped`/unknown) because SkyGuard waits for the client to speak first. An SSH client connecting to `9911` sends `SSH-2.0-` as its first bytes — SkyGuard recognises the signature and proxies the connection transparently.

```yaml
stealth_services:
  - name: "ssh"
    enabled: true
    listen_port: 9911             # public port clients connect to
    real_target: "127.0.0.1:22"  # where sshd actually listens
    protocol_signature: "SSH-2.0-"
    timeout: "5s"                 # no matching signature → drop
    allowed_countries: ["TR","US"] # optional country allowlist
```

```
nmap -sV -p 9911 your-server  →  9911/tcp  open  tcpwrapped
ssh -p 9911 user@server     →  connected (transparent proxy)
```

### Honeypot services

Each honeypot can be toggled independently **without restarting** anything else — just set `enabled: false` and send `SIGHUP` (or restart the container):

```yaml
honeypot_services:
  - name: "fake-ssh"
    enabled: true          # ← toggle here
    port: 22
    type: "ssh"
    banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
    max_auth_attempts: 3

  - name: "fake-mysql"
    enabled: false         # disabled without removing config
    port: 3306
    type: "mysql"
    banner: "5.7.42-0ubuntu0.18.04.1"
```

### Auto-ban scoring

```yaml
analysis:
  auto_ban:
    enabled: true
    score_threshold: 50    # ban when score reaches this value
    ban_duration: "24h"
    method: "iptables"     # "iptables" | "ufw" | "none"
    scoring:
      honeypot_connection: 10
      failed_credential:   15
      port_scan_detected:  25   # 5+ distinct ports within 60 s
      blacklisted_country:  5
      rate_limit_exceeded: 20
```

### Key configuration reference

| Section | Field | Default | Description |
|---|---|---|---|
| `general` | `log_level` | `info` | `debug` · `info` · `warn` · `error` |
| `stealth_services[*]` | `listen_port` | — | Public port clients connect to |
| `stealth_services[*]` | `protocol_signature` | — | First-bytes prefix to forward on |
| `stealth_services[*]` | `timeout` | `10s` | Close if no signature arrives |
| `stealth_services[*]` | `allowed_countries` | `[]` | Requires GeoIP; private/LAN IPs are always allowed |
| `honeypot_services[*]` | `enabled` | `true` | Toggle per honeypot (restart required) |
| `honeypot_services[*]` | `type` | — | `ssh` · `ftp` · `mysql` · `http` |
| `analysis.auto_ban` | `score_threshold` | `100` | Score that triggers a ban |
| `analysis.auto_ban` | `ban_duration` | `24h` | `"1h"` · `"24h"` · `"7d"` · `"0s"` = permanent |
| `analysis.auto_ban` | `method` | `none` | `iptables` (recommended, also in Docker) · `ufw` (bare metal only) · `none` |
| `analysis.auto_ban` | `iptables_backend` | `auto` | `auto` · `legacy` · `nft` |
| `whitelist` / `blacklist` | `ips` | `[]` | Single IPs or CIDR ranges |
| `analysis.rate_limit` | `max_per_minute` | `20` | Connections per IP per minute |
| `dashboard` | `listen` | `127.0.0.1:9090` | Non-loopback binds require a strong password |
| `logging` | `retention_days` | `90` | Auto-purge records older than N days |

---

## Dashboard & REST API

Access the dashboard via an SSH tunnel (never expose it directly):

```bash
ssh -L 9090:127.0.0.1:9090 user@your-server
# → http://localhost:9090
```

**Panels:** overview (stats + 24 h chart) · searchable connection log with CSV export · top attackers · captured credentials · bans (manual ban/unban) · firewall rules · auto-ban settings · per-IP detail view. Works on mobile.

All endpoints except `/healthz` require HTTP Basic Auth (`dashboard.auth`).
Failed logins are throttled per client IP. JSON fields are `snake_case`.
State-changing `POST` endpoints require the header `X-SkyGuard-Request: 1` (CSRF protection).

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/healthz` | Unauthenticated liveness probe (Docker health check) |
| `GET` | `/api/stats` | Totals, today, unique IPs/countries, credentials, active bans |
| `GET` | `/api/timeline?hours=N` | Per-hour counts (gaps filled with zeros) |
| `GET` | `/api/connections` | Connection log; filters `ip`, `country`, `service`, `action`, `since`, `until` (RFC3339), `limit`, `offset` |
| `GET` | `/api/export` | Same filters, CSV download (formula-injection safe) |
| `GET` | `/api/attackers?limit=N` | IPs ranked by threat score, with touched ports |
| `GET` | `/api/credentials?limit=N` | Most-attempted service/username/password combinations |
| `GET` | `/api/banned` | Active bans with expiry timestamps |
| `GET` | `/api/ip?ip=X` | Score, ban state, recent connections and credentials of one IP |
| `GET` | `/api/firewall` | Firewall backend and SKYGUARD chain rules |
| `GET`/`POST` | `/api/settings` | Auto-ban settings (partial updates) |
| `POST` | `/api/ban` | `ip`, `duration` (`24h`, `7d`, `0` = permanent), `permanent`, `reason` — whitelisted IPs are refused |
| `POST` | `/api/unban` | `ip` — also resets the IP's score |

```bash
curl -u admin:password http://localhost:9090/api/stats
curl -u admin:password -H 'X-SkyGuard-Request: 1' -d ip=203.0.113.5 -d duration=7d \
     http://localhost:9090/api/ban
```

---

## Project Structure

```
skyguard/
├── cmd/skyguard/          # main entry point (graceful shutdown, slog, env override)
├── internal/
│   ├── config/            # YAML parser + struct definitions
│   ├── server/            # TCP listeners, connection pipeline, semaphore DoS guard
│   ├── stealth/           # Protocol-aware forwarding (prefixedConn trick)
│   ├── honeypot/          # SSH · FTP · MySQL · HTTP handlers
│   ├── proxy/             # Bidirectional TCP proxy
│   ├── analysis/          # GeoIP · rate limiter · scorer · port-scan detector
│   ├── netutil/           # IP normalisation, IP/CIDR sets
│   ├── firewall/          # iptables · ufw · noop backends
│   ├── storage/           # SQLite (CGO-free) — connections · credentials · bans · scores
│   └── dashboard/         # HTTP server · REST API · embedded UI (static/index.html + app.js)
├── configs/
│   └── skyguard.example.yaml
├── install.sh             # Production installer (multi-distro, interactive wizard)
├── Dockerfile             # Multi-stage (golang:1.27 → debian:trixie-slim)
├── docker-compose.yml
├── Makefile
└── USAGE.md               # Full operational guide
```

---

## Security Notes

> SkyGuard is a **detection and logging** layer. It complements — but does not replace — a properly configured host firewall and a patched OS.

- **Never expose the dashboard publicly.** It binds to `127.0.0.1` by default. Use an SSH tunnel or an mTLS reverse proxy.
- **Add your own IP to `whitelist.ips`** before enabling auto-ban — you can lock yourself out.
- **Rotate the default password.** The example config ships with `CHANGE_ME_NOW`.
- **Secure the config file.** It contains credentials: `chmod 600 /etc/skyguard/skyguard.yaml`.
- **The stealth port is a secret.** Share it only over a secure channel. If an attacker learns it, the model is compromised.
- **GeoIP is advisory.** Determined attackers use VPNs. Pair it with score-based auto-ban.
- **SkyGuard stopping closes its ports.** Keep a whitelist-based `iptables` rescue rule for your own IP independent of SkyGuard, and keep port 22 reachable until you have verified the stealth port works (the installer only blocks 22 after testing it).

---

## Development

### Prerequisites

- **Go 1.27+** (CGO not required — `modernc.org/sqlite` is pure Go)
- **Docker** — for container builds and integration tests
- **make**

### Make targets

```
make build          Build binary  →  ./bin/skyguard
make run            Run with example config (localhost only)
make docker-build   Build Docker image
make docker-up      docker compose up -d
make docker-down    docker compose down
make test           go test ./...
make lint           golangci-lint run
make clean          Remove build artefacts
```

### Running tests manually

```bash
# Unit tests
go test ./...

# Race detector
go test -race ./...

# Vet
go vet ./...

# Quick smoke test with Docker
docker build -t skyguard:dev .
# (the dashboard binds 127.0.0.1, so use host networking, not -p)
docker run --rm --network host --cap-add NET_ADMIN \
  -v $(pwd)/configs/skyguard.example.yaml:/etc/skyguard/skyguard.yaml:ro \
  -v $(pwd)/data:/data \
  skyguard:dev
curl -u admin:CHANGE_ME_NOW http://localhost:9090/api/stats
```

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `SKYGUARD_CONFIG` | `/etc/skyguard/skyguard.yaml` | Config file path (used when `-config` is not given) |

### Command-line flags

| Flag | Description |
|---|---|
| `-config PATH` | Config file |
| `-check-config` | Validate the config (ports, addresses, durations, CIDRs) and exit |
| `-healthcheck` | Probe the running instance's `/healthz` (used by Docker) |
| `-version` | Print the version |

---

## Roadmap

- [ ] Fake interactive shell for SSH honeypot (`fake_shell` is accepted but ignored)
- [ ] WebSocket / SSE live-push for dashboard
- [ ] Prometheus metrics endpoint (`/metrics`)
- [ ] Geolocation map visualisation in dashboard
- [ ] JSON REST API for external SIEM integration
- [ ] IPv6 honeypot listeners
- [ ] Rate-limited SMTP honeypot

---

## Contributing

Pull requests are welcome. For major changes please open an issue first to discuss the approach.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes (`git commit -m 'add my feature'`)
4. Push to the branch (`git push origin feature/my-feature`)
5. Open a Pull Request

Please run `make lint` and `make test` before submitting.

---

## License

[MIT](LICENSE) © SkyGuard contributors

---

<div align="center">
<sub>Built with Go · Deployed with Docker · Runs on Linux</sub>
</div>