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
| 🧩 **Containers** | Opt-in Docker and Incus management: start/stop, published ports, restart policy, limits, and a patch bay to wire containers into each other's networks |
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

## Containers (Docker and Incus)

The dashboard can manage the containers that run next to SkyGuard. Both
engines are spoken to directly over their unix sockets (Docker Engine API,
Incus REST API), so no CLI is needed inside SkyGuard's container. Access to
either socket is equivalent to root on the host, so it is **off** until you
enable it, it requires `dashboard.auth`, and `read_only: true` limits it to
listing.

```yaml
containers:
  read_only: false
  docker: { enabled: true, socket: /var/run/docker.sock }
  incus:  { enabled: false, socket: /var/lib/incus/unix.socket, project: "" }
```

With docker compose, mount the sockets you enable (`docker-compose.yml` has
the lines commented out; the installer adds them when you say yes):

```yaml
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - /var/lib/incus:/var/lib/incus:ro   # the directory: Incus recreates its socket on restart
```

What each change does:

| Change | Docker | Incus |
|---|---|---|
| Start / stop / restart | in place (10 s stop timeout) | in place (30 s) |
| Join / leave a network | `network connect` / `disconnect`, live | a `nic` device added / removed live (a profile's nic is masked with `type: none`) |
| Published ports | **recreates the container** (Docker cannot change ports in place): same image ID, config, labels, networks with aliases and static IPs, named and anonymous volumes; the old one is renamed aside and removed only after the new one starts, otherwise it is put back unchanged | proxy devices (`listen tcp:0.0.0.0:8080`, `connect tcp:127.0.0.1:80`) added / removed live |
| Restart policy | live (`no`, `on-failure`, `unless-stopped`, `always`) | `boot.autostart` (`no`, `last-state`, `always`) |
| Memory / CPU limit | set or raise live; removing one recreates the container | `limits.memory` / `limits.cpu`, live |

A port is refused before anything changes when another running container
publishes it, a SkyGuard listener (or the dashboard) holds it, or a program on
the host is bound to it. SkyGuard's own container is protected: it can be
listed but not stopped, restarted or re-ported from the panel. A container
that belongs to a Compose project gets its compose file's ports back on the
next `docker compose up`, so change those there too; the sheet says so.

**Bans cover container ports.** Traffic to a port Docker publishes is DNAT-ed
and crosses `FORWARD`, never `INPUT`, so a ban in `INPUT` alone let a banned IP
keep reaching every container. SkyGuard now also jumps to its `SKYGUARD` chain
from the top of `DOCKER-USER` (checked again on every ban, since Docker may
start later); `uninstall.sh` removes the jump. Incus proxy devices accept on
the host and are covered through `INPUT`. With `method: ufw` Docker's ports
are not covered (ufw never sees forwarded traffic); use `iptables`.

### Sharing ports 80/443 with a reverse proxy (Nginx Proxy Manager, Traefik, Caddy)

Only one process can listen on a port. If a reverse proxy container publishes
80 and 443, SkyGuard's `fake-http` honeypot (port 80) and an HTTPS
`passthrough` (port 443) cannot have them, and SkyGuard refuses to start with
the owner named (`address already in use`). The installer detects this and
leaves those listeners off. Pick one of:

1. **The proxy keeps 80/443 (recommended).** Disable `fake-http` or move it
   to a port nothing real uses (`port: 8081`), and leave the passthrough off.
   The *Host ports* table shows who holds what; bans still protect the proxy
   through `DOCKER-USER`.
2. **SkyGuard in front.** Publish the proxy on loopback only
   (`127.0.0.1:8080:80`, `127.0.0.1:8443:443`) and let SkyGuard forward with
   two `passthrough_services` (80 → `127.0.0.1:8080`, 443 →
   `127.0.0.1:8443`). Every connection is then logged, scored and bannable
   before it reaches the proxy, but the proxy sees `127.0.0.1` as the client
   address (TCP passthrough has no PROXY protocol), so its own access lists
   and logs lose the real IP. Change the ports from the container's sheet in
   the dashboard, or in its compose file.

SkyGuard's listeners bind every address (`:80`), so the proxy cannot keep
`127.0.0.1:80` either: in option 2 it moves to other ports.

## Dashboard & REST API

Access the dashboard via an SSH tunnel (never expose it directly):

```bash
ssh -L 9090:127.0.0.1:9090 user@your-server
# → http://localhost:9090
```

**Screens** (dark "data terminal" design, every figure in IBM Plex Mono so digits line up; fonts are embedded, nothing is loaded from the internet):

- **Overview** — the busiest source and whether it is banned, KPIs that switch the main chart (connections, honeypot hits, logins tried, dropped) over 24 h / 7 d / 30 d with the change against the previous period, a *decision flow* showing where every connection ended (trapped, let through, or dropped by ban, blacklist, rate limit, port scan, stealth probe), busiest sources with a one-click ban, targeted services and countries (or ports without GeoIP), latest events.
- **Connections** — a day × hour heatmap of the last 7 days in your local time, filters (IP, service, country, outcome) kept in the URL, paging, CSV export.
- **Attackers and bans** — threat scores against the auto-ban threshold, active bans with confirmed unban, ban reasons, a ban dialog (1 h / 1 day / 7 days / permanent).
- **Captured credentials** — most tried usernames and passwords, attempts per honeypot and over time, the most frequent pairs.
- **Honeypots and services** — switch each honeypot on or off at runtime (the listener opens or closes at once; the choice survives restarts until you change that honeypot in the config file), with 24-hour activity per service. Stealth and passthrough services are shown read-only: turning them off from a panel you usually reach through them could cut your own session.
- **Containers** (opt-in, see [Containers](#containers-docker-and-incus)) — a *patch bay*: the server's Docker containers or Incus instances down the left, their networks across the top, a cable from each container to every network it is on. Click a container's socket and a cable follows the pointer; drop it on another container and the two get a network in common (join one of the other's, or a new one for the pair), drop it on a network to join it, click a lit jack to leave. Start, stop and restart; edit published ports, restart policy and memory/CPU limits in a side sheet. A host-port table names whoever holds each port (SkyGuard listeners included) and flags conflicts; *Open to the internet* lists every container port bound on all addresses and whether a ban stops traffic there.
- **Auto-ban and firewall** — switch, threshold stepper, ban length, and the SKYGUARD chain's current rules.
- **IP detail** — a side sheet with score, daily activity, credentials and connections for any address.

Works on phones (bottom navigation) and with the keyboard; screen state lives in the URL hash, so every view can be bookmarked.

All endpoints except `/healthz` require HTTP Basic Auth (`dashboard.auth`).
Failed logins are throttled per client IP. JSON fields are `snake_case`.
State-changing `POST` endpoints require the header `X-SkyGuard-Request: 1` (CSRF protection).

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/healthz` | Unauthenticated liveness probe (Docker health check) |
| `GET` | `/api/info` | Host name, version, firewall backend, auto-ban state |
| `GET` | `/api/stats` | All-time totals, today, unique IPs/countries, credentials, active bans |
| `GET` | `/api/summary?range=24h\|7d\|30d` | This and the previous period, decision-flow outcomes, top sources, services, countries, ports |
| `GET` | `/api/series?range=…&ip=…&port=…` | Hourly (24 h, 7 d) or daily (30 d) counts incl. credentials, optionally for one IP or port |
| `GET` | `/api/credentials/breakdown?range=…` | Most tried usernames, passwords and attempts per honeypot |
| `GET` | `/api/services` | Every configured service with its state and 24 h activity |
| `POST` | `/api/services` | `name`, `enabled` — switch a honeypot at runtime |
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
| `GET` | `/api/containers` | `enabled`, engines and their state, containers, networks, `host_ports` (every claimant per port, conflicts first), `ban_coverage` |
| `GET` | `/api/containers/inspect?engine=&id=` | One container with restart policy, limits, mounts |
| `POST` | `/api/containers/action` | `engine`, `id`, `action` = `start` \| `stop` \| `restart` |
| `POST` | `/api/containers/connect` | `engine`, `id`, `network`, `create=1` to create the network first |
| `POST` | `/api/containers/disconnect` | `engine`, `id`, `network` |
| `POST` | `/api/containers/ports` | `engine`, `id`, `ports` in `docker run -p` form, comma separated (`8080:80,127.0.0.1:8443:443/tcp`); empty unpublishes all |
| `POST` | `/api/containers/settings` | `engine`, `id`, `restart`, `memory_mb`, `cpus` (0 removes a limit) |
| `POST` | `/api/containers/networks` | `engine`, `name` — create a bridge network |

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

- **Container management is root on the host.** Enable `containers.docker` / `containers.incus` only with a strong dashboard password, keep the dashboard on loopback, and prefer `read_only: true` if you only want to look.
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