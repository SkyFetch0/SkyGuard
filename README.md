<div align="center">

<img src="docs/logo.svg" alt="SkyGuard" width="96" />

# SkyGuard

**Smart Linux Security Layer & Honeypot System**

*Protect your server by hiding real services, luring attackers into traps, and auto-banning threats — all in a single Go binary.*

---

[![Go](https://img.shields.io/badge/Go-1.27+-00ADD8?logo=go&logoColor=white)](https://go.dev/)
[![SQLite](https://img.shields.io/badge/SQLite-modernc%2Fsqlite-003B57?logo=sqlite&logoColor=white)](https://pkg.go.dev/modernc.org/sqlite)
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED?logo=docker&logoColor=white)](https://www.docker.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](#license)
[![Incus](https://img.shields.io/badge/Incus-managed-E95420?logo=linuxcontainers&logoColor=white)](https://linuxcontainers.org/incus/)

---

![GeoIP](https://img.shields.io/badge/GeoIP-MaxMind%20GeoLite2-00B4D8?logo=globe&logoColor=white)
![iptables](https://img.shields.io/badge/Firewall-iptables%20%7C%20ufw-EF233C?logo=linux&logoColor=white)
![Honeypots](https://img.shields.io/badge/Honeypots-SSH%20%7C%20FTP%20%7C%20MySQL%20%7C%20HTTP-6C3483?logo=security&logoColor=white)
![CGO](https://img.shields.io/badge/CGO-disabled%20(pure%20Go)-00ADD8?logo=go&logoColor=white)

**[Install](#installation)** · **[Screenshots](#screenshots)** · **[Configuration](#configuration)** · **[Containers](#containers-docker-and-incus)** · **[AI assistants (MCP)](#ai-assistants-mcp)** · **[API](#dashboard--rest-api)** · **[Operations guide](USAGE.md)** · **[Install guide for AI agents](LLM_INSTALL.md)**

</div>

---

## Screenshots

The dashboard on a server under a week of attack traffic, with 96 Docker containers next to it. Every address in these pictures is from the documentation ranges (RFC 5737).

<p align="center"><img src="docs/screenshots/overview.png" alt="Overview: connections per hour over 7 days with a spike annotated, where every connection ended (trapped by a honeypot, let through, or dropped and why), the busiest sources with their ban state, targeted services and countries" width="100%"></p>

<p align="center"><img src="docs/screenshots/containers-cable.png" alt="Network map: containers as devices and networks as switches; shop-web is selected, its two cables are lit and the rest of the map is dimmed while a new cable is pulled onto the monitoring switch" width="100%"></p>

| | |
|---|---|
| <img src="docs/screenshots/containers-map.png" alt="Network map of 96 containers grouped by Compose project, with numbered replicas folded into stacked devices and a minimap"> **Network map** — 96 containers, Compose projects kept together, replicas folded, minimap | <img src="docs/screenshots/container-sheet.png" alt="Container sheet with start, pause and stop, published ports with an explanation of the recreate, networks and restart policy"> **Container sheet** — ports, networks, restart policy, limits, logs, snapshots |
| <img src="docs/screenshots/attackers.png" alt="Highest threat scores against the auto-ban threshold and the active bans with their expiry"> **Attackers and bans** — scores against the auto-ban threshold, active bans | <img src="docs/screenshots/credentials.png" alt="Most tried usernames and passwords, attempts per honeypot over time and the most frequent pairs"> **Captured credentials** — what bots try, per honeypot and over time |
| <img src="docs/screenshots/connections.png" alt="A day by hour heatmap of the last week above the filterable connection log"> **Connections** — day × hour heatmap and the filterable log | <img src="docs/screenshots/honeypots.png" alt="Honeypots with on and off switches and 24-hour activity strips; stealth and passthrough services shown read-only"> **Honeypots** — switched on and off at runtime |
| <img src="docs/screenshots/containers-table.png" alt="The patch bay table view: containers in rows, networks in columns, cables from each container to its networks"> **Table view** — the patch bay for precise work | <img src="docs/screenshots/settings.png" alt="Auto-ban settings and the container engine switches with their sockets and versions"> **Settings** — auto-ban, container engines, firewall rules |

<p align="center"><img src="docs/screenshots/ports.png" alt="Ports and access: every port the server listens on with the container or program behind it, databases open to the internet flagged, and the access rules with their drop counters" width="100%"></p>

<p align="center"><img src="docs/screenshots/software.png" alt="Software and vulnerabilities: every place scanned (this server, Docker containers, Incus instances) with its system, the main software and versions found, and the known vulnerabilities by severity from OSV.dev" width="100%"></p>

<p align="center"><img src="docs/screenshots/phone-overview.png" alt="The overview on a phone" width="240">&nbsp;&nbsp;&nbsp;<img src="docs/screenshots/phone-containers.png" alt="The network map on a phone" width="240"></p>

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
| 🤖 **MCP** | A built-in Model Context Protocol server: Claude, ChatGPT, Cursor or any MCP client can read attacks, bans, credentials and containers, and act when you allow it |
| 🔒 **Port access** | Per-port rules for anything listening on the host (databases, admin panels, Docker and Incus ports): *only these sources* or *everyone except these*, IPv4 and IPv6, with a self-undoing trial on SSH and the dashboard |
| 🧬 **Software** | Finds what runs on the server and inside every Docker container and Incus instance (system packages, Next.js, Node, Go binaries, nginx, CyberPanel, WordPress and more) with its version, without running anything inside them; opt-in check against OSV.dev for known CVEs and the version that fixes each |
| 🧩 **Containers** | Opt-in Docker and Incus management, switched on from the panel: a network map to wire containers together, create / start / stop / pause / remove, published ports, restart policy, limits, logs, Incus snapshots |
| 🐳 **Docker** | Multi-stage image (`golang:1.27` → `debian:trixie-slim` with iptables-legacy + iptables-nft), built-in health check |
| ⚙️ **Config** | Single YAML file; hot-toggleable services (`enabled: false`) |
| 0️⃣ **Zero deps** | CGO disabled — pure Go binary, no shared libraries |

---

## Installation

SkyGuard runs as one Docker container on the host's network (recommended), or as a plain binary under systemd. Three ways to get there, from the most guided to the most manual. **AI agents installing SkyGuard on a server: follow [LLM_INSTALL.md](LLM_INSTALL.md)**, which is written to be executed step by step with checks and stop conditions.

### Before you start

| | |
|---|---|
| **System** | 64-bit Linux (x86_64 or arm64): Ubuntu 20.04–24.04, Debian 11–12, Rocky / AlmaLinux / RHEL 8–9, Fedora 38+ (what `install.sh` supports; other distributions work with Option B or C). 1 vCPU and 256 MB of RAM are plenty. |
| **Access** | Root (`sudo`). SkyGuard binds ports below 1024 and manages iptables. |
| **Software** | Docker Engine with the compose plugin (the installer installs both), `git`. |
| **Your IP** | Know the public IP you administer the server from: it goes on the whitelist so auto-ban can never lock you out. `echo $SSH_CLIENT` on the server prints it as the first field. |
| **Ports** | SkyGuard wants the ports of the honeypots you enable (21, 80, 3306, 8080; 22 only if you move sshd), the stealth port (9911 by default) and 127.0.0.1:9090 for the dashboard. Check what is taken with `sudo ss -tlnp`. A reverse proxy that already holds 80/443 (Nginx Proxy Manager, Traefik, Caddy) is fine: see [sharing 80/443](#sharing-ports-80443-with-a-reverse-proxy-nginx-proxy-manager-traefik-caddy). |

> **Keep your current SSH session open until the end.** Test every change (especially the stealth port) from a *second* terminal. Nothing in the installer blocks port 22 unless you confirm it after the stealth port has been proven to reach your sshd.

### Option A — the interactive installer (recommended)

```bash
git clone https://github.com/SkyFetch0/SkyGuard.git
cd SkyGuard
sudo bash install.sh            # English
sudo bash install.sh --lang tr  # Türkçe
```

The wizard asks, in order: whether to whitelist the public IP it detects for you (say yes), extra whitelist IPs and blocked countries; the stealth SSH port and where the real sshd listens; which honeypots to run (a port that is already taken is detected and that honeypot left off, naming the owner, e.g. `docker container nginx-proxy-manager`); an HTTPS passthrough; GeoIP; auto-ban threshold, ban length and firewall backend; the dashboard user and password (empty generates one); Docker / Incus management; log retention. Then it:

1. installs Docker if missing and the packages it needs (`curl`, `iptables`, `sqlite3`, `iproute2`, and `iptables-persistent` or `iptables-services` so rules survive a reboot);
2. copies the project to `/opt/skyguard` and writes `/etc/skyguard/skyguard.yaml` (mode 600);
3. snapshots your iptables rules (for `uninstall.sh --restore-iptables`), creates the `SKYGUARD` chain, hooks it into `INPUT`, `FORWARD` and `DOCKER-USER`, and opens exactly the ports you chose (recorded in `/etc/skyguard/firewall.state`);
4. writes `/opt/skyguard/docker-compose.yml`, builds the image, validates the config with `skyguard -check-config`, starts the container and waits until it is healthy;
5. dials the stealth port itself and, only if your sshd answers through it, offers to block direct access to port 22;
6. installs `skyguard.service` (starts the compose project at boot), log rotation and a daily database backup.

When it finishes, open a **new** terminal and log in through the stealth port before you close the old one:

```bash
ssh -p 9911 you@your-server
```

### Option B — Docker Compose by hand

```bash
git clone https://github.com/SkyFetch0/SkyGuard.git /opt/skyguard
cd /opt/skyguard
cp configs/skyguard.example.yaml configs/skyguard.yaml   # must exist before `up`, or Docker creates a directory
chmod 600 configs/skyguard.yaml
$EDITOR configs/skyguard.yaml     # whitelist.ips, dashboard.auth.password, the honeypots you want
docker compose build
docker compose run --rm skyguard -check-config -config /etc/skyguard/skyguard.yaml
docker compose up -d
docker compose ps                 # wait for "(healthy)"
```

`docker-compose.yml` uses host networking and `NET_ADMIN`/`NET_RAW`, so honeypots see real client addresses and bans land in the host's firewall. Data (SQLite database, SSH honeypot host key, GeoIP database) lives in `./data`. To let the dashboard manage containers, uncomment the socket lines in `docker-compose.yml` (see [Containers](#containers-docker-and-incus)).

The example config enables `fake-http` on port 80; turn it off (or move it) if a web server or reverse proxy already uses 80, otherwise SkyGuard refuses to start and names the port.

### Option C — native binary with systemd

```bash
git clone https://github.com/SkyFetch0/SkyGuard.git && cd SkyGuard
make build                                   # Go 1.27+ (go.mod pins go1.27.3; GOTOOLCHAIN downloads it)
sudo install -m 755 bin/skyguard /usr/local/bin/skyguard
sudo mkdir -p /etc/skyguard /var/lib/skyguard
sudo install -m 600 configs/skyguard.example.yaml /etc/skyguard/skyguard.yaml
sudoedit /etc/skyguard/skyguard.yaml         # also set general.data_dir and logging.db_path to /var/lib/skyguard
sudo skyguard -check-config -config /etc/skyguard/skyguard.yaml
```

Then install the unit from [USAGE.md › Running as a systemd Service](USAGE.md#running-as-a-systemd-service) and `sudo systemctl enable --now skyguard`. The binary needs `iptables` (or `ufw`) on the host.

### Check that it works

| Check | Command | Expect |
|---|---|---|
| Container is healthy | `docker ps --filter name=skyguard` | `Up … (healthy)` |
| Liveness | `curl -fsS http://127.0.0.1:9090/healthz` | `ok` |
| Listeners | `docker logs skyguard 2>&1 \| grep "listener started"` | one line per enabled service |
| Stealth port reaches sshd | `timeout 5 bash -c 'exec 3<>/dev/tcp/127.0.0.1/9911; printf "SSH-2.0-check\r\n" >&3; head -c 8 <&3'` | `SSH-2.0-` |
| Stealth login | from a second terminal: `ssh -p 9911 you@server` | a normal login |
| Firewall | `sudo iptables -S SKYGUARD; sudo iptables -S FORWARD \| head -3` | the chain exists; `-A FORWARD -j SKYGUARD` near the top |
| Dashboard | `ssh -L 9090:127.0.0.1:9090 you@server -p 9911`, then open http://localhost:9090 | the login prompt, then the overview |

### Turn on container management

Open **Settings → Container engines** in the dashboard and switch Docker or Incus on. SkyGuard checks that the socket answers and that the dashboard password is strong. With Docker Compose, mount the socket into the container first (uncomment the lines in `docker-compose.yml`, then `docker compose up -d`). Details and safety notes: [Containers](#containers-docker-and-incus).

### Update

**From the dashboard.** *Settings → Version and updates* shows the running
version, commit and build date, and the newest release on GitHub (checked a
minute after start and then every 6 hours; *Check now* asks at once). When
there is a newer one, its release notes are shown with *Update to x.y.z*. One
click then:

<p align="center"><img src="docs/screenshots/updates.png" alt="Version and updates: the running version, commit, build date and platform, the newest release with its notes and an Update button" width="100%"></p>


1. downloads `skyguard-linux-<arch>` from the release, with `SHA256SUMS` and
   its signature;
2. checks the checksum and, when SkyGuard knows the project's signing key,
   the signature; a damaged or foreign binary goes no further;
3. runs the new binary once with `-version` and `-check-config` on your
   config: a version that would refuse your settings goes no further;
4. backs up the database (a consistent copy while it runs) and the config to
   `<data_dir>/backups/pre-update-<from>-to-<to>-<time>.db|.yaml` (the last
   three are kept), and checks there is room for it;
5. restarts in place: same process, so Docker and systemd see no restart.
   The dashboard and honeypots are away for a few seconds; bans and port rules
   stay in the firewall throughout.

Nothing in the image or in `/usr/local/bin` is replaced: the new binary is
kept in `<data_dir>/updates/<version>/`, and the installed binary hands over
to it at every start. Until the new version has stayed up for 45 seconds,
every start counts; after three starts that did not stay up, the installed
binary puts the previous version back by itself and the dashboard says so.
*Go back* does the same on request. The database is never rolled back
automatically: a newer version only adds to it, and the copy from before the
update is in `backups/`.

If the installed binary is replaced later (`docker compose build` from a
newer checkout, a new package), the newer of the two choices wins: a release
installed in the image newer than the applied update, or a local build made
after the update was applied.

**By hand**, as before: the database, the config and the honeypot host keys
are kept, and dashboard choices survive until you change the same setting in
the config file.

```bash
cd /opt/skyguard && git pull && docker compose build && docker compose up -d
```

**Native (systemd) installs** restart through the service manager only when a
new version fails to start, so the unit needs `Restart=on-failure`:

```ini
[Service]
ExecStart=/usr/local/bin/skyguard -config /etc/skyguard/skyguard.yaml
Restart=on-failure
RestartSec=5
```

#### Publishing a release (for the repository owner)

Pushing a version tag builds the binaries, `SHA256SUMS` and its signature in
GitHub Actions (`.github/workflows/release.yml`) and publishes the release;
a tag with a hyphen (`v1.3.0-rc.1`) becomes a pre-release, offered only where
`update.channel: prerelease`.

```bash
git tag v1.2.0 && git push origin v1.2.0
```

Without a local clone, *Actions → release → Run workflow* with the version
(`1.2.0`) does the same: it tags the chosen branch's latest commit and
publishes it.

Sign releases, once:

1. `go run ./cmd/skyguard -update-keygen` on your own computer prints a key
   pair.
2. Repository → *Settings → Secrets and variables → Actions*: the private key
   as the secret `SKYGUARD_SIGNING_KEY`, the public key as the variable
   `SKYGUARD_UPDATE_PUBKEY` (compiled into release builds).
3. Put the public key into `TrustedKeys` in `internal/update/verify.go` (so
   builds from source trust it too), or into `update.public_key` on servers
   already running.

A build that trusts a key installs only releases signed with it. Until then
releases are unsigned and only their checksum is checked; the dashboard says
which applies.

### Uninstall

```bash
sudo bash /opt/skyguard/uninstall.sh                     # stop, remove the container and SkyGuard's firewall rules
sudo bash /opt/skyguard/uninstall.sh --purge             # also delete /etc/skyguard and the data
sudo bash /opt/skyguard/uninstall.sh --restore-iptables  # put back the iptables snapshot taken before install
```

### When something goes wrong

| Symptom | Cause and fix |
|---|---|
| `listen :80: … address already in use (another process already listens on this port; check with: ss -tlnp)` | Another program or container has the port (`ss -tlnp` names it; Docker's shows as `docker-proxy`). Turn that honeypot off or give it another `port`, then restart. |
| `skyguard.yaml: is a directory` | `docker compose up` ran before `configs/skyguard.yaml` existed. `rm -r configs/skyguard.yaml`, copy the example, start again. |
| Locked out of SSH | From the provider's console: `iptables -D INPUT ! -i lo -p tcp --dport 22 -j DROP` and `iptables -F SKYGUARD`, then whitelist your IP. |
| Dashboard does not open from your PC | It listens on 127.0.0.1 only, on purpose. Use the SSH tunnel above. |
| Container stays `unhealthy` | `docker logs skyguard` names the problem; `docker compose run --rm skyguard -check-config -config /etc/skyguard/skyguard.yaml` validates the file. |

More in [USAGE.md › Troubleshooting](USAGE.md#10-troubleshooting).

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
| `analysis.auto_ban` | `cover_forwarded` | `true` | bans also stop traffic the host forwards: routed IPs, VMs, DNAT |
| `update` | `check` | `true` | look for new releases every 6 hours (installing is always a click) |
| `update` | `repo` | `SkyFetch0/SkyGuard` | where releases come from (a fork's own) |
| `update` | `channel` | `stable` | `stable` · `prerelease` |
| `update` | `public_key` | — | base64 ed25519 key a release must be signed with |
| `update` | `github_token` | — | for a private repository (or env `SKYGUARD_GITHUB_TOKEN`) |
| `whitelist` / `blacklist` | `ips` | `[]` | Single IPs or CIDR ranges |
| `analysis.rate_limit` | `max_per_minute` | `20` | Connections per IP per minute |
| `dashboard` | `listen` | `127.0.0.1:9090` | Non-loopback binds require a strong password |
| `logging` | `retention_days` | `90` | Auto-purge records older than N days |

---

## Containers (Docker and Incus)

The dashboard can manage the containers that run next to SkyGuard: Docker,
and Incus (the community fork of LXD; system containers and virtual
machines). Both engines are spoken to directly over their unix sockets
(Docker Engine API, Incus REST API), so no CLI is needed inside SkyGuard's
container. Access to either socket is equivalent to root on the host, so it is
**off** until you switch it on, it requires a strong `dashboard.auth`
password, and `read_only: true` (config file only) limits it to listing.

Switch each engine on under **Settings → Container engines** (or with the
buttons on the empty Containers screen). SkyGuard checks that the socket
answers before it accepts, and remembers the choice across restarts; setting
`containers.docker.enabled` / `containers.incus.enabled` in the config file
works too, and once you change that value in the file, the file wins again.

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
| Pause / resume | `pause` / `unpause` | `freeze` / `unfreeze` |
| Create | pulls the image if missing, then create and start | from `images:<distro>/<release>` (images.linuxcontainers.org) or a local alias; container or VM |
| Remove | stop and delete; named and anonymous volumes are kept | stop and delete with its snapshots; custom volumes are kept |
| Logs | the last stdout/stderr lines | the console log (or the LXC log) |
| Snapshots | — (Docker has none) | take, roll back, delete |

A port is refused before anything changes when another running container
publishes it, a SkyGuard listener (or the dashboard) holds it, or a program on
the host is bound to it. SkyGuard's own container is protected: it can be
listed but not stopped, restarted or re-ported from the panel. A container
that belongs to a Compose project gets its compose file's ports back on the
next `docker compose up`, so change those there too; the sheet says so.

**Bans cover container ports.** Traffic to a port Docker publishes is DNAT-ed
and crosses `FORWARD`, never `INPUT`, so a ban in `INPUT` alone let a banned IP
keep reaching every container. SkyGuard also jumps to its `SKYGUARD` chain
from the top of `FORWARD` (which covers everything the host passes on, see
[Several addresses on one server](#several-addresses-on-one-server)) and from
the top of `DOCKER-USER`; the jumps are checked every minute and
`uninstall.sh` removes them. Incus proxy devices accept on the host and are
covered through `INPUT`. With `method: ufw` Docker's ports are not covered
(ufw never sees forwarded traffic); use `iptables`.

### Sharing ports 80/443 with a reverse proxy (Nginx Proxy Manager, Traefik, Caddy)

Only one process can listen on a port. If a reverse proxy container publishes
80 and 443, SkyGuard's `fake-http` honeypot (port 80) and an HTTPS
`passthrough` (port 443) cannot have them, and SkyGuard refuses to start with
the owner named (`address already in use`). The installer detects this and
leaves those listeners off. Pick one of:

1. **The proxy keeps 80/443 (recommended).** Disable `fake-http` or move it
   to a port nothing real uses (`port: 8081`), and leave the passthrough off.
   The *Host ports* table shows who holds what; bans still protect the proxy
   through `FORWARD`.
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

## Port access rules

A server usually listens on more than its web ports: a database published by
a Compose file, Elasticsearch and Kibana, an admin panel, a game server.
`ss -tulnp` shows them; anything on `0.0.0.0` or `[::]` is open to the whole
internet unless something stops it. The **Ports** screen lists each of them
with what is behind it and lets you put a rule in front of it:

- **Only these sources**: the listed addresses and networks get in, everyone
  else is dropped. `private` stands for every internal range (10/8,
  172.16/12, 192.168/16, 100.64/10, fc00::/7, fe80::/10): containers, the
  LAN, Tailscale and other VPNs. An empty list means *this server only*.
- **Everyone except these**: the listed sources are dropped, the rest get in.

The server itself (loopback) always gets in, and so does `whitelist.ips` from
the config on every *only these* rule. Rules drop new connections only, so a
session that is already open is never cut. A port can be one number or a
range (`9200-9300`), TCP, UDP or both.

**What a rule covers.** Host programs (sshd, pure-ftpd, a MySQL installed
with apt), Incus proxy devices (the default kind; one with `nat=true` is
forwarded by Incus's own nftables rules and is not covered), and Docker's
published ports, which never
pass through INPUT: Docker forwards them, so the rules also sit at the top of
`FORWARD` and match the port as it is published on the host
(`-p 27017:27017` → rule for 27017), before Docker rewrites it. Addresses the
server passes on to an instance or a VM are covered there too (next section). Containers that talk to each other over a Docker network are
not affected, and neither are a container's own outbound connections. Both
IPv4 and IPv6 are covered (a `[::]:27017` listener is reached over IPv6 too).

**You cannot lock yourself out for good.** Port 22, any other port sshd
listens on (when SkyGuard can see the host's processes), the stealth ports and the dashboard's port are *protected*: a
change that restricts one of them is put in force at once, but saved only
when you press *Keep these rules*. If you don't within two minutes, because
the change cut your own connection, the previous rules come back by
themselves. The saved rules are applied again at every start, and checked
every minute: if a `firewalld` reload or an `iptables -F` removed them, they
are put back.

Under the hood: two chains, `SKYGUARD-PORTS` (jumped to from `INPUT`) and
`SKYGUARD-PORTS-FWD` (from `FORWARD`), right after the ban chain, so a ban
still wins and a rule comes before the host's own ACCEPT rules (Docker's
included). Each
rule's DROP carries the comment `sg:<id>`, which is where the *dropped*
counters come from:

```bash
sudo iptables -S SKYGUARD-PORTS
sudo iptables -L SKYGUARD-PORTS-FWD -n -v      # packet counts per rule
```

Port rules need `iptables` on the host (any backend, also when bans go
through `ufw` or `auto_ban.method: none`); without it the screen says so and
refuses changes. SkyGuard in Docker needs `network_mode: host` and
`NET_ADMIN`, which the shipped compose file already has; it then sees the
host's ports but not the programs behind them (those are named when SkyGuard
runs natively, or for containers once container management is on).

### Several addresses on one server

A server rented with extra IPs often hands some of them on: Incus gives an
instance its own public IP with a `routed` NIC (the host gets a route
`157.90.0.79 dev veth…` and the instance answers on it), a VM gets one through
a tap device, or a hand-written `iptables -t nat … -j DNAT` sends an address
somewhere. Traffic to such an address never reaches the host's `INPUT`: it
crosses `FORWARD`, often accepted at the very top by a saved rule like
`-A FORWARD -d 157.90.0.79/32 -j ACCEPT`.

SkyGuard finds these addresses itself (the host's routing table, the nat
table, and the network namespaces of containers and instances) and lists them
on the Ports screen under **Addresses**, each with what is behind it, how many
ports listen there (read inside the instance's namespace; a VM's ports are its
own and are not listed), and whether bans reach it. SkyGuard in Docker needs `pid: host`
(commented in its `docker-compose.yml`) to look into other namespaces; without
it the addresses are still found and covered, but not what is behind them.

- **Bans cover them.** The ban chain sits at the top of `FORWARD`, before such
  ACCEPT rules, so a banned IP is cut off from every address the server
  forwards too (`analysis.auto_ban.cover_forwarded`, on by default). The
  honeypots and the port-scan detection see only the host's own addresses: an
  instance's traffic is not scored.
- **The same rules there, or its own.** Each forwarded address has a switch,
  *Server-wide rules*: *Own rules only* (the default, so nothing changes for an
  instance until you decide) or *Apply here too*, which puts every rule without
  addresses in front of that address as well.
- **Rules for one address.** *Applies to → Only these addresses* limits a rule
  to chosen addresses, the host's or forwarded ones (*Restrict…* on an
  instance's port and *Rule for it…* on an address fill it in). Address rules
  come first: a source they let in skips the server-wide rules there, so
  `3306 on 157.90.0.79: only 198.51.100.20` holds even if a server-wide rule
  says otherwise. A rule names the address the client connects to; traffic
  DNAT-ed from another address counts for that other address. A rule only for
  forwarded addresses cannot lock you out of the host, so it needs no trial.

```bash
sudo iptables -S FORWARD | head -4          # SKYGUARD, SKYGUARD-PORTS-FWD, then the host's own rules
sudo iptables -S SKYGUARD-PORTS-FWD | grep 157.90.0.79
```

### Locking down a busy server

1. **Open the Ports screen** (*Reachable from outside*). Everything there is
   reachable from the internet; the yellow tags mark databases and admin
   interfaces that anyone can reach.
2. **Close what nobody outside needs at the source.** If only programs and
   containers on the same server use a database, it does not need to be
   published on every address. *Close…* on its row (see
   [Closing a container port](#closing-a-container-port)) offers:
   - **This server only**: published on `127.0.0.1`, the way
     `"127.0.0.1:27017:27017"` in a Compose file does it;
   - **Not published**: other containers reach it over their shared network
     by service name (`mongodb://mongo:27017`), nothing else does.
3. **Put a rule on what must stay reachable from somewhere.** For example
   MongoDB used by an app on another server and by your office:
   *Restrict…* on 27017 → *Only these sources* → `198.51.100.20`,
   `203.0.113.0/24`, `private`. For Elasticsearch and its cluster port, one
   rule for `9200-9300`.
4. **Leave public what is meant to be public** (80/443 of a reverse proxy, a
   game server). Use *Everyone except these* there to keep known abusers out
   of one service without banning them everywhere.
5. **SSH**: leave 22 to the stealth port and the honeypot. If you do restrict
   it, keep your own address in the list and press *Keep these rules*.
6. **Check from outside** (another machine): `nc -vz your-server 27017` now
   times out, and the rule's *dropped* counter goes up.

### Closing a container port

A rule filters who reaches a port; often the port should not be open at all.
For a Docker container or an Incus instance (with container management on),
*Close…* on the Ports screen, in the container's sheet next to each published
port, or in the containers screen's *Open to the internet* list, changes the
publication itself:

| Choice | What changes | Who still connects |
|---|---|---|
| This server only | published on `127.0.0.1` | programs on the server (`127.0.0.1:27017`), containers by name |
| Not published | no host port | containers on its networks, as `service:port` |
| Everyone (for a port that is local only) | published on every address again | anyone, unless a rule says otherwise |

The dialog says beforehand which containers share a network with it and the
name they reach it by; on Docker's default `bridge` network names do not
resolve, and it tells you to put the containers on a shared network first.
Docker cannot change an existing container's ports, so the container is
recreated from the same image with the same settings, volumes and networks
(it restarts once; if the new one fails, the old one is put back). Incus
changes the proxy device on the running instance.

**Compose projects.** `docker compose up` recreates a container from its
compose file, which would bring the old port back. So for a container that
Compose made, the same change is made in the file it came from (Compose
records the path and the service in the container's labels): only that
port's line, with comments and formatting kept, quoted as Compose advises,
and the file as it was saved next to it as `docker-compose.yml.skyguard.bak`.
The dialog shows the exact lines before anything is written, and the box can
be unticked. Removing a service's last port removes its `ports:` key too.

```diff
     ports:
-      - "27017:27017"   # database
+      - "127.0.0.1:27017:27017"   # database
```

The file is left alone, and the dialog shows the line to write by hand,
when the edit cannot be made with certainty: the port comes from a variable
(`"${PORT}:27017"`), is part of a range, the list is written on one line
(`ports: ["27017:27017"]`), or the file is not visible to SkyGuard. Running
SkyGuard in Docker, it sees only what is mounted into it: mount the folder
your projects live in at the same path (`- /opt:/opt` in SkyGuard's
`docker-compose.yml`, commented there).

## Software and vulnerabilities

The **Software** screen lists what is installed on the server itself and inside
every Docker container and Incus instance SkyGuard manages, with versions:
the system packages (dpkg on Debian and Ubuntu, apk on Alpine), and by name the
things people ask about: Next.js and the other Node frameworks from
`package.json` and its lockfile, Node.js, Go (and the modules compiled into any
Go binary, read from its build info), Python packages, PHP, Java, nginx,
OpenResty, OpenLiteSpeed, CyberPanel, WordPress sites, databases, Docker,
containerd and Incus. It scans 3 minutes after start when the last results are
older than a day, then once a day; *Scan now* runs it at once.

**Known vulnerabilities.** Switch on *Check versions against OSV.dev* and every
package is compared with [OSV.dev](https://osv.dev), the open database that
gathers the advisories of Debian, Ubuntu, Alpine, GitHub (npm, PyPI) and the Go
project. Each finding shows its CVE and advisory, a CVSS score where there is
one, and the version that fixes it; *Only those with a fix* leaves the ones you
can act on today. Only package names, versions and ecosystems are sent (no
addresses, no file contents), and each advisory is cached until OSV.dev
changes it, so a daily check fetches only new or updated ones. Off (the default), nothing leaves the server; each
app still has an NVD link to look it up by hand.

**Safe against what it scans.** A container is someone else's file system,
and whoever controls it may plant traps for a scanner. SkyGuard assumes so:

- Nothing is ever run inside a container or instance (no `docker exec`, no
  `incus exec`, no package manager): files are only read.
- Every file is opened with `openat2(RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS)`
  under the container's own root (`/proc/<pid>/root`). The kernel resolves
  every symbolic link and `..` inside that root, so a link to `/etc/shadow`
  leads to the container's file, never the server's.
- A path is first opened without reading (`O_PATH`) and checked to be a
  regular file; only then is it read, non-blocking. A device, FIFO or socket
  planted in place of `/etc/os-release` is skipped and named in the
  container's notes.
- Sizes are capped (1 MiB for small files, 32 MiB for package databases), as
  are packages per place (20 000) and every string, which is stripped of
  control characters and shown escaped. Each place has 90 seconds; a file
  system that never answers is left behind, and after three of those scans
  stop until SkyGuard restarts.
- After opening a container's root, SkyGuard checks the process still belongs
  to that container, so a recycled PID cannot point it at another one.
- A stopped Docker container is read through the Docker API instead, which
  resolves paths inside the container; links are followed by path only.
- What is found is data, never instructions: the MCP tool says so to the
  model, like it does for logs.

Not read: virtual machines (their disks are not SkyGuard's to open), stopped
Incus instances, and RPM-based systems (Rocky, Alma, Fedora), whose package
database is a SQLite or Berkeley DB file. The OSV check uses each
distribution's own advisories, so a Debian or Ubuntu package is matched by its
source package and its exact Debian version.

**SkyGuard in Docker.** Inside a container SkyGuard sees only what is shared
with it. Mount the server's root read-only (`- /:/host:ro`) for its own
packages, and give it `pid: host` to read running containers and Incus
instances; both are in `docker-compose.yml`, commented. Without `pid: host`,
Docker containers are still read through the Docker API.

## AI assistants (MCP)

SkyGuard has a built-in [Model Context Protocol](https://modelcontextprotocol.io) server, so an AI assistant can answer "who attacked me last night?", "is anything on port 80 besides the reverse proxy?" or "ban the address that keeps trying root" from SkyGuard's own data. It is built on the official Go SDK and served at `/mcp` on the dashboard's address as stateless Streamable HTTP.

<p align="center"><img src="docs/screenshots/mcp-settings.png" alt="Settings: the switch that lets AI assistants connect, the switch for action tools, the token, a ready-to-copy Claude Code command, the tool list and the most recent calls" width="100%"></p>

**Turn it on:** Settings → *AI assistants (MCP)* → *Let AI assistants connect*. SkyGuard makes a token and shows it once; copy it. The panel then offers ready-to-paste setups with the token filled in:

- **Claude Code** (open the tunnel, then add the server once):
  ```bash
  ssh -N -L 9090:127.0.0.1:9090 -p 9911 you@your-server
  claude mcp add --transport http skyguard http://127.0.0.1:9090/mcp --header "Authorization: Bearer <token>"
  ```
- **Claude Desktop** and other stdio-only clients, through `mcp-remote` and the same tunnel:
  ```json
  {"mcpServers": {"skyguard": {"command": "npx", "args": ["-y", "mcp-remote", "http://127.0.0.1:9090/mcp", "--header", "Authorization:${SKYGUARD_AUTH}"],
    "env": {"SKYGUARD_AUTH": "Bearer <token>"}}}}
  ```
- **Over SSH, no tunnel:** the client starts SkyGuard's own stdio bridge on the server (`skyguard -mcp-stdio`):
  ```json
  {"mcpServers": {"skyguard": {"command": "ssh", "args": ["-p", "9911", "you@your-server",
    "docker", "exec", "-i", "-e", "SKYGUARD_MCP_TOKEN=<token>", "skyguard", "skyguard", "-mcp-stdio"]}}}
  ```
- **Anything else** that speaks Streamable HTTP: URL `http://127.0.0.1:9090/mcp`, header `Authorization: Bearer <token>`.

**Tools.** Reading is always available; the action tools exist only while *Allow actions* is on (off by default), so an assistant in read-only mode cannot even see them.

| Tool | What it does | |
|---|---|---|
| `skyguard_status` | Host, version, firewall backend and whether bans cover Docker's ports, auto-ban settings, totals, every service, container engines | read |
| `get_summary` | One window (24h / 7d / 30d) against the one before: counters, where connections ended, busiest sources, services, countries, ports | read |
| `list_connections` | The connection log, filtered by IP, country, service, outcome, last N hours | read |
| `list_attackers` | IPs by threat score with counters, ports and ban state | read |
| `get_ip` | One address: score, ban, whitelist, latest connections and logins | read |
| `list_bans` | Active bans and when they lift | read |
| `list_credentials` | Most tried usernames, passwords and pairs | read |
| `get_firewall` | The SKYGUARD chain's rules and Docker coverage | read |
| `list_ports` | Every listening port with its owner, reach and risk, and the port access rules with their drop counts | read |
| `list_software` | Every scanned place with its system, main software and known vulnerabilities; with `key`, one place's findings | read |
| `list_containers` / `get_container` / `get_container_logs` | Containers, networks, port conflicts; one container; its last log lines | read |
| `ban_ip` / `unban_ip` | Ban for a duration (default 24h, `0` permanent) or lift a ban | action |
| `set_honeypot` | Open or close a honeypot's port | action |
| `container_action` | Start, stop, restart, pause or resume a container | action |

Deliberately not offered to an assistant: removing or creating containers, changing ports, network wiring, and SkyGuard's own settings.

**Safety model.**
- The token is separate from the dashboard password and stored only as a SHA-256 hash. *Make a new token* locks the old one out at once; switching MCP off answers every call with 404.
- Wrong tokens are throttled per address (the same rule as the dashboard login), and all clients together are limited to about 240 calls a minute.
- Browsers cannot drive the endpoint: cross-site requests and DNS-rebinding attempts (a loopback connection with a foreign `Host`) are refused with 403.
- Bans requested over MCP go through the same rules as the dashboard: whitelisted and loopback addresses are refused. SkyGuard's own container cannot be stopped.
- Attacker-supplied text is trimmed. The server's instructions and the tool descriptions tell the model that this text, and container logs, are data and never instructions (a defence against prompt injection through, say, a crafted HTTP path).
- Every call is shown under *Recent calls* with its client address and result, and action calls are logged.

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
- **Containers** (opt-in, see [Containers](#containers-docker-and-incus)) — a *network map* in the manner of a network simulator: networks are switches, containers are devices, memberships are cables. Select a container and pull a cable from its plug: drop it on a switch to join that network, or on another container to give the two a network in common (join one of the other's, or a new one for the pair); clicking *Connect…* and then the target works too. Click a cable to unplug it. Built to stay readable with a hundred containers: a force layout that keeps each Compose project together on a soft outline, numbered replicas (`queue-worker-1…40`) folded into one stacked device until you expand them, labels that give way to each other as you zoom out, search that dims everything else and brings the first match into view, a minimap, focus on a node's own cables when selected, and dragged positions remembered per browser. A *Table* view keeps the patch bay for precise work. *New container* pulls an image (Docker) or downloads one from images.linuxcontainers.org (Incus) and starts it with ports, network, environment, restart policy and limits. The side sheet starts, stops, restarts, pauses and removes; edits ports, restart policy and memory/CPU limits; shows the last 200 log lines; and for Incus takes, rolls back and deletes snapshots. A host-port table names whoever holds each port (SkyGuard listeners included) and flags conflicts; *Open to the internet* lists every container port bound on all addresses and whether a ban stops traffic there.
- **Ports and access** — the server's addresses (its own, and those it passes on to Incus instances, VMs or DNAT) with whether bans reach them and a switch for the server-wide rules; every port that takes connections on the host and behind those addresses, who is behind it (program, container, SkyGuard service) and whether the internet can reach it, with databases and admin panels that anyone can reach flagged; *Close…* to publish a container's port on this server only or not at all (the compose file included), the access rules with their drop counters, a rule editor, and the trial banner that undoes a change to SSH or the dashboard unless you keep it. See [Port access rules](#port-access-rules).
- **Software** — every place scanned (this server, each container and instance) with its system, main software and versions, and its known vulnerabilities by severity; a sheet per place with each advisory, its CVE and the version that fixes it, and every package found. See [Software and vulnerabilities](#software-and-vulnerabilities).
- **Settings** — version and updates (the running build, the newest release with its notes, one-click update with automatic rollback, history), the auto-ban switch, threshold stepper and ban length, container engines, AI assistants, and the SKYGUARD chain's current rules.
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
| `GET` | `/api/ports` | Listening ports (`listeners`; an instance's carry `address`), the server's `addresses` (`kind` host, routed or dnat, `owner`, `follow`), the access rules with `dropped` counts, `protected` ports, a running trial (`unsaved`, `trial_deadline`), `always_allowed`, `client_ip`, ban coverage (`bans`) |
| `POST` | `/api/ports` | `rules` — the whole rule list as JSON (`id`, `name`, `ports` `27017` or `9200-9300`, `proto` `tcp`/`udp`/`both`, `mode` `allow`/`deny`, `sources`, `addresses` (empty: server-wide), `enabled`); returns `trial` and its `deadline` when a protected port changed |
| `POST` | `/api/ports/confirm` | Keep the rules of a running trial |
| `POST` | `/api/ports/address` | `ip`, `follow` — whether the server-wide rules also cover a forwarded address |
| `POST` | `/api/ports/revert` | End a running trial now and bring the saved rules back |
| `GET` | `/api/containers` | `enabled`, engines and their state, containers, networks, `host_ports` (every claimant per port, conflicts first), `ban_coverage` |
| `GET` | `/api/containers/port-plan?engine=&id=&host_port=&proto=&action=` | What a port action would do: the ports afterwards, who reaches it by name, and the `compose` edit (`file`, `line`, `before`, `after`, `ok`, `reason`, `manual`) |
| `POST` | `/api/containers/port` | `engine`, `id`, `host_port`, `proto`, `action` = `local` \| `public` \| `remove`, `compose=1` to edit the compose file too; returns `container` and `plan` |
| `GET` | `/api/containers/inspect?engine=&id=` | One container with restart policy, limits, mounts |
| `POST` | `/api/containers/action` | `engine`, `id`, `action` = `start` \| `stop` \| `restart` |
| `POST` | `/api/containers/connect` | `engine`, `id`, `network`, `create=1` to create the network first |
| `POST` | `/api/containers/disconnect` | `engine`, `id`, `network` |
| `POST` | `/api/containers/ports` | `engine`, `id`, `ports` in `docker run -p` form, comma separated (`8080:80,127.0.0.1:8443:443/tcp`); empty unpublishes all |
| `POST` | `/api/containers/settings` | `engine`, `id`, `restart`, `memory_mb`, `cpus` (0 removes a limit) |
| `POST` | `/api/containers/networks` | `engine`, `name` — create a bridge network |
| `POST` | `/api/containers/networks/delete` | `engine`, `name` — delete a network nothing is on |
| `POST` | `/api/containers/engines` | `engine`, `enabled` — switch Docker or Incus management from the panel |
| `POST` | `/api/containers/create` | `engine`, `name`, `image`, `ports`, `network`, `env` (KEY=value lines, Docker), `restart`, `memory_mb`, `cpus`, `vm` (Incus), `start` |
| `POST` | `/api/containers/remove` | `engine`, `id` — stop and delete; volumes are kept |
| `GET` | `/api/containers/logs?engine=&id=&lines=200` | The last lines of stdout/stderr (Docker) or the console log (Incus) |
| `GET`/`POST` | `/api/containers/snapshots` | Incus: list; `action` = `take` \| `restore` \| `delete`, `name` |
| `GET` | `/api/software` | Every scanned place (`targets`: `key`, `kind`, `os`, `apps`, `packages`, `severity`, `fixable`, `notes`), the scan `status` (`phase` idle, scanning or checking), `osv`, `host_reason` |
| `GET` | `/api/software/target?key=` | One place with every package (`packages`) and finding (`findings`: `id`, `cves`, `package`, `version`, `fixed`, `severity`, `score`) |
| `POST` | `/api/software/scan` | Scan now (and check, when OSV.dev is on) |
| `POST` | `/api/software/check` | Check what was found against OSV.dev again |
| `POST` | `/api/software/osv` | `enabled` — whether package names and versions may be sent to OSV.dev |
| `GET` | `/api/update` | Running version (`running`: `version`, `commit`, `date`), the newest release (`latest`, `available`), `status` of an update in progress, `state` (current, previous, `failure`, `history`), `can_rollback`, `backups` |
| `POST` | `/api/update/check` | Ask GitHub now |
| `POST` | `/api/update/apply` | `version` — install that release (the newest found); SkyGuard restarts at the end |
| `POST` | `/api/update/rollback` | Back to the previous version, or the installed one |
| `GET` | `/api/mcp` | MCP state: `enabled`, `allow_actions`, `token_set`, `token_created`, `tools`, recent `activity` |
| `POST` | `/api/mcp` | `enabled`, `allow_actions`; switching on the first time returns a new `token` once |
| `POST` | `/api/mcp/token` | Make a new token (returned once); the old one stops working |
| `POST` | `/mcp` | The MCP endpoint itself: `Authorization: Bearer <token>`, not Basic Auth |

```bash
curl -u admin:password http://localhost:9090/api/stats
curl -u admin:password -H 'X-SkyGuard-Request: 1' -d ip=203.0.113.5 -d duration=7d \
     http://localhost:9090/api/ban
```

---

## Project Structure

```
SkyGuard/
├── cmd/skyguard/            # entry point: flags, graceful shutdown, health check probe
├── internal/
│   ├── config/              # YAML parsing, defaults and validation
│   ├── server/              # listeners, the connection pipeline, runtime honeypot switches
│   ├── stealth/             # protocol-aware forwarding to the hidden real service
│   ├── honeypot/            # SSH (x/crypto/ssh) · FTP · MySQL · HTTP
│   ├── proxy/               # bidirectional TCP proxy
│   ├── analysis/            # GeoIP · rate limiter · scorer · port-scan detector
│   ├── firewall/            # iptables / ip6tables (SKYGUARD chain in INPUT, FORWARD, DOCKER-USER; port rule chains) · ufw · none
│   ├── containers/          # Docker Engine API and Incus REST API clients, the container manager, compose file edits
│   ├── inventory/           # software inventory: confined file reads, detectors, OSV.dev check
│   ├── portrules/           # port access rules: the server's addresses, listeners, trials
│   ├── update/              # releases from GitHub, verification, staging, the launcher and rollback
│   ├── storage/             # SQLite (pure Go): connections, credentials, bans, scores, settings
│   ├── netutil/             # IP normalisation, IP/CIDR sets
│   └── dashboard/           # HTTP server, REST API, MCP server (mcp.go), embedded UI (static/index.html, assets/*.js, *.css, fonts)
├── configs/skyguard.example.yaml
├── docs/                    # logo and screenshots
├── .github/workflows/       # release.yml: builds, checksums and signs a release for a v* tag
├── scripts/                 # install-plugin.sh, enable-ssh-honeypot.sh
├── install.sh / uninstall.sh
├── Dockerfile               # golang:1.27 → debian:trixie-slim
├── docker-compose.yml
├── Makefile
├── USAGE.md                 # full operational guide
└── LLM_INSTALL.md           # step-by-step install guide for AI agents
```

---

## Security Notes

> SkyGuard is a **detection and logging** layer. It complements — but does not replace — a properly configured host firewall and a patched OS.

- **Container management is root on the host.** Enable `containers.docker` / `containers.incus` only with a strong dashboard password, keep the dashboard on loopback, and prefer `read_only: true` if you only want to look.
- **An AI assistant with actions allowed can ban and stop things.** Leave *Allow actions* off unless you want that, and make a new MCP token if one may have leaked.
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
| `SKYGUARD_MCP_TOKEN` | — | The MCP token, for `-mcp-stdio` |
| `SKYGUARD_MCP_URL` | from `dashboard.listen` | The MCP endpoint `-mcp-stdio` relays to |

### Command-line flags

| Flag | Description |
|---|---|
| `-config PATH` | Config file |
| `-check-config` | Validate the config (ports, addresses, durations, CIDRs) and exit |
| `-healthcheck` | Probe the running instance's `/healthz` (used by Docker) |
| `-version` | Print the version |
| `-mcp-stdio` | Relay MCP between stdin/stdout and the running instance's `/mcp` (for stdio-only clients) |
| `-mcp-token-file PATH` | Read the MCP token for `-mcp-stdio` from a file instead of `SKYGUARD_MCP_TOKEN` |

---

## Roadmap

- [ ] Fake interactive shell for SSH honeypot (`fake_shell` is accepted but ignored)
- [ ] Notifications (Telegram, ntfy, Discord, e-mail, webhooks) for bans and honeypot logins
- [ ] Longer bans for repeat offenders
- [ ] Scheduled blocklist import (Spamhaus DROP, FireHOL level1) and nftables sets
- [ ] CrowdSec bouncer integration
- [ ] Reading sshd and reverse-proxy (Nginx Proxy Manager) logs
- [ ] HTTP lures for `/.git/config`, `/.env` and LLM API paths
- [ ] RPM-based systems in the software inventory
- [ ] TOTP two-factor login for the dashboard
- [ ] Prometheus metrics endpoint (`/metrics`)
- [ ] WebSocket / SSE live-push for the dashboard

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

MIT © SkyGuard contributors

---

<div align="center">
<sub>Built with Go · Deployed with Docker · Runs on Linux</sub>
</div>