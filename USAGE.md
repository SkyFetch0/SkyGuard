# SkyGuard Operational Guide

> SkyGuard is a lightweight, dependency-free intrusion detection and deception system written in Go.
> It combines stealth port forwarding, multi-protocol honeypots, behavioral scoring, and an automatic
> ban engine into a single static binary with no external runtime dependencies.

---

## Table of Contents

1. [Requirements](#1-requirements)
2. [Installation](#2-installation)
   - [2a. Docker (Recommended)](#2a-docker-recommended)
   - [2b. Build from Source](#2b-build-from-source)
   - [2c. Automated Install Script](#2c-automated-install-script)
3. [Configuration Guide](#3-configuration-guide)
   - [3a. General Settings](#3a-general-settings)
   - [3b. stealth_services](#3b-stealth_services)
   - [3c. honeypot_services](#3c-honeypot_services)
   - [3d. passthrough_services](#3d-passthrough_services)
   - [3e. analysis (GeoIP, Rate Limit, Auto-Ban)](#3e-analysis)
   - [3f. Whitelist and Blacklist](#3f-whitelist-and-blacklist)
   - [3g. Dashboard Authentication](#3g-dashboard-authentication)
   - [3h. Logging and Retention](#3h-logging-and-retention)
4. [Stealth SSH Setup](#4-stealth-ssh-setup)
5. [Honeypot Services](#5-honeypot-services)
6. [Dashboard Usage](#6-dashboard-usage)
7. [Auto-Ban System](#7-auto-ban-system)
8. [GeoIP Setup](#8-geoip-setup)
9. [Security Best Practices](#9-security-best-practices)
10. [Troubleshooting](#10-troubleshooting)
11. [API Reference](#11-api-reference)
12. [Environment Variables](#12-environment-variables)
13. [Production Checklist](#13-production-checklist)

---

## 1. Requirements

### System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| Operating System | Ubuntu 20.04 / Debian 11 / any Linux | Ubuntu 22.04 LTS |
| CPU | 1 vCPU | 2 vCPU |
| RAM | 128 MB | 256 MB |
| Disk | 500 MB (DB + logs) | 2 GB |
| Kernel | Linux 4.15+ | Linux 5.15+ |

SkyGuard compiles to a static binary and requires no external libraries at runtime.

### Software Requirements

**For Docker installation:**

| Software | Minimum Version | Notes |
|----------|----------------|-------|
| Docker | 20.10+ | Verify with `docker --version` |
| Docker Compose | v2.0+ | Verify with `docker compose version` |

**For building from source:**

| Software | Minimum Version | Notes |
|----------|----------------|-------|
| Go | 1.22+ | Verify with `go version` |
| make | any | Build automation |
| gcc / musl-dev | any | CGO dependencies (optional) |

**Optional (for auto-ban functionality):**

| Software | Description |
|----------|-------------|
| `iptables` | Kernel-level packet filtering (iptables method) |
| `ufw` | Ubuntu firewall (ufw method) |

### Network Requirements

- SkyGuard runs in `network_mode: host`; it does not use Docker NAT.
- Ports you want to listen on (e.g. 22, 21, 80, 3306, 9911) must be available on the host.
- The dashboard listens on `127.0.0.1:9090` by default; do not expose it to external interfaces.
- Requires `NET_ADMIN` and `NET_RAW` Linux capabilities for iptables/ufw integration.

---

## 2. Installation

### 2a. Docker (Recommended)

Docker installation is the fastest and most secure method. All dependencies are bundled in the image.

```bash
# 1. Clone the repository
git clone https://github.com/skyguard/skyguard
cd skyguard

# 2. Create the config directory and copy the example config
sudo mkdir -p /etc/skyguard
sudo cp configs/skyguard.example.yaml /etc/skyguard/skyguard.yaml

# 3. Edit the config — change the password and whitelist IPs before proceeding
sudo nano /etc/skyguard/skyguard.yaml

# 4. Create the data directory
sudo mkdir -p /data

# 5. Build the Docker image
docker build -t skyguard:latest .

# 6. Start the container
docker run -d \
  --name skyguard \
  --network host \
  --restart unless-stopped \
  --cap-add NET_ADMIN \
  --cap-add NET_RAW \
  -v /etc/skyguard/skyguard.yaml:/etc/skyguard/skyguard.yaml:ro \
  -v /data:/data \
  skyguard:latest

# 7. Verify the logs
docker logs -f skyguard

# 8. Test the dashboard (in a separate terminal)
curl -u admin:changeme_strong_password http://127.0.0.1:9090/api/stats
```

#### Starting with Docker Compose

The project includes a ready-to-use `docker-compose.yml` in the project root:

```bash
# Copy the example config into the project directory (used by the compose bind mount)
cp configs/skyguard.example.yaml configs/skyguard.yaml
nano configs/skyguard.yaml

# Start
make docker-up
# or
docker compose up -d

# Stop
make docker-down

# Follow logs
docker compose logs -f skyguard
```

#### Health Check

When the container is running correctly, `docker ps` shows `(healthy)` in the status column:

```bash
docker ps --format "table {{.Names}}\t{{.Status}}"
# skyguard   Up 2 minutes (healthy)

# Manual health check
nc -z localhost 9090 && echo "Dashboard OK" || echo "Dashboard DOWN"
```

---

### 2b. Build from Source

```bash
# 1. Clone the repository
git clone https://github.com/skyguard/skyguard
cd skyguard

# 2. Download dependencies
go mod download

# 3. Compile the binary (CGO_ENABLED=0 produces a fully static binary)
make build
# or manually:
CGO_ENABLED=0 go build \
  -ldflags="-w -s -X main.Version=1.0.0" \
  -o bin/skyguard ./cmd/skyguard

# 4. Install the binary to the system path
sudo cp bin/skyguard /usr/local/bin/skyguard
sudo chmod 755 /usr/local/bin/skyguard

# 5. Prepare config and data directories
sudo mkdir -p /etc/skyguard /data
sudo cp configs/skyguard.example.yaml /etc/skyguard/skyguard.yaml
sudo chmod 600 /etc/skyguard/skyguard.yaml

# 6. Run
sudo skyguard -config /etc/skyguard/skyguard.yaml
```

#### Running as a systemd Service

```bash
# Create the unit file
sudo tee /etc/systemd/system/skyguard.service > /dev/null <<'EOF'
[Unit]
Description=SkyGuard Intrusion Detection System
After=network.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/skyguard -config /etc/skyguard/skyguard.yaml
Restart=always
RestartSec=5
User=root
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable skyguard
sudo systemctl start skyguard
sudo systemctl status skyguard
```

#### Developer Mode (example config)

```bash
make run
# → go run ./cmd/skyguard -config configs/skyguard.example.yaml
```

---

### 2c. Automated Install Script

`scripts/install-plugin.sh` automates Docker setup, interactive config wizard, and systemd integration:

```bash
# Full installation (Docker + config + systemd)
sudo ./scripts/install-plugin.sh

# Create config file only, do not start the container
sudo ./scripts/install-plugin.sh --config-only

# Standalone mode (bypasses the server-guard plugin framework)
sudo ./scripts/install-plugin.sh --standalone
```

---

## 3. Configuration Guide

The configuration file uses YAML format. Default location: `/etc/skyguard/skyguard.yaml`
Example file: `configs/skyguard.example.yaml`

---

### 3a. General Settings

```yaml
general:
  log_level: "info"   # debug | info | warn | error
  data_dir: "/data"   # SQLite DB and GeoIP files are stored here
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `log_level` | string | `info` | Log verbosity. `debug` produces high output volume; use `info` or `warn` in production. |
| `data_dir` | string | `/var/lib/skyguard` | Directory for `skyguard.db` and `GeoLite2-City.mmdb`. |

---

### 3b. `stealth_services`

Stealth services act as a protocol-aware proxy bridge to a real backend service (e.g. sshd). Only clients that send the correct protocol signature in their first bytes are forwarded; all other connections are silently dropped.

```yaml
stealth_services:
  - name: "ssh"
    listen_port: 9911             # The publicly exposed hidden port
    real_target: "127.0.0.1:22"  # Address of the real sshd
    protocol_signature: "SSH-2.0-"  # First bytes must begin with this prefix
    timeout: 5s                   # Timeout waiting for the protocol signature
    allowed_countries: ["TR"]     # Leave empty to allow all countries
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | string | — | Service name (appears in logs). |
| `listen_port` | int | — | Port number SkyGuard will bind to. |
| `real_target` | string | — | Backend address to proxy traffic to (`host:port`). |
| `protocol_signature` | string | `""` | If empty, no signature check is performed and all connections are forwarded. Use `SSH-2.0-` for SSH or `GET ` for HTTP. |
| `timeout` | duration | `30s` | How long to wait for the client to send the signature. SYN-only scanners are dropped after this timeout. |
| `allowed_countries` | []string | `[]` | When GeoIP is enabled, only connections from these country codes are forwarded. Empty means all countries are allowed. |

**How it works:** SkyGuard binds to the port and reads the first bytes from each connecting client. If the bytes match `protocol_signature`, the connection is proxied to `real_target`. If they do not match, the connection is silently closed. As a result, port scanners see the port as `filtered`.

---

### 3c. `honeypot_services`

Honeypot services emulate real network protocols to attract and log attacker behavior. Each service can be individually enabled or disabled using the `enabled` field.

```yaml
honeypot_services:
  - name: "fake-ssh"
    port: 22
    type: "ssh"
    enabled: true
    banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
    max_auth_attempts: 3
    fake_shell: false

  - name: "fake-ftp"
    port: 21
    type: "ftp"
    enabled: true
    banner: "ProFTPD 1.3.5e Server (Debian) ready."

  - name: "fake-mysql"
    port: 3306
    type: "mysql"
    enabled: true
    banner: "5.7.42-0ubuntu0.18.04.1"

  - name: "fake-http"
    port: 80
    type: "http"
    enabled: true
    server_header: "Apache/2.4.41 (Ubuntu)"
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | string | — | Service name. |
| `port` | int | — | Port to listen on. |
| `type` | string | — | One of: `ssh`, `ftp`, `mysql`, `http`. |
| `enabled` | bool | `true` | Set to `false` to disable this honeypot without removing it from the config. |
| `banner` | string | Protocol default | The banner/version string shown to the attacker. A realistic banner keeps attackers engaged longer. |
| `max_auth_attempts` | int | `3` | Maximum authentication attempts for FTP/SSH honeypots before the connection is closed. |
| `fake_shell` | bool | `false` | Simulates a fake interactive shell in the SSH honeypot. **Do not enable in production.** |
| `server_header` | string | `"Apache/2.4.41 (Ubuntu)"` | Value of the `Server:` response header for the HTTP honeypot. |

> **Note:** To temporarily disable a single honeypot, set `enabled: false` on that entry. The service will not bind to its port and no logs will be generated for it until it is re-enabled.

---

### 3d. `passthrough_services`

Passthrough services transparently proxy any TCP port while simultaneously applying GeoIP lookups, rate limiting, and behavioral scoring. Use this for services you want to monitor without deception.

```yaml
passthrough_services:
  - name: "web"
    listen_port: 443
    real_target: "127.0.0.1:8443"
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | string | — | Service name. |
| `listen_port` | int | — | Port SkyGuard listens on. |
| `real_target` | string | — | Backend address (`host:port`) to forward traffic to. |

---

### 3e. `analysis`

The `analysis` block controls GeoIP enrichment, per-IP rate limiting, and the automatic ban engine.

```yaml
analysis:
  geoip:
    enabled: false
    db_path: "/data/GeoLite2-City.mmdb"

  rate_limit:
    max_per_minute: 20
    max_per_hour: 200

  auto_ban:
    enabled: true
    score_threshold: 50
    ban_duration: "24h"
    method: "none"   # none | iptables | ufw

    scoring:
      honeypot_connection: 10
      failed_credential: 15
      port_scan_detected: 25
      blacklisted_country: 5
      rate_limit_exceeded: 20
```

**GeoIP:**

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `geoip.enabled` | bool | `false` | Enables GeoIP lookups. If `db_path` does not exist, the service will not start. |
| `geoip.db_path` | string | `/data/GeoLite2-City.mmdb` | Path to the MaxMind GeoLite2 City database file. |

**Rate Limit:**

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `rate_limit.max_per_minute` | int | — | Maximum connections per IP per minute. |
| `rate_limit.max_per_hour` | int | — | Maximum connections per IP per hour. |

**Auto-Ban:**

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `auto_ban.enabled` | bool | — | Enables the auto-ban engine. |
| `auto_ban.score_threshold` | int | `100` | An IP reaching this score is automatically banned. |
| `auto_ban.ban_duration` | duration | `24h` | Duration of the ban. Accepts formats like `1h`, `48h`, `720h`. |
| `auto_ban.method` | string | `none` | `none` (writes to DB only), `iptables` (adds a kernel DROP rule), `ufw` (adds a UFW deny rule). |

---

### 3f. Whitelist and Blacklist

```yaml
whitelist:
  ips:
    - "127.0.0.1"
    - "::1"
    - "YOUR_HOME_IP"   # Always add your own IP here!
  countries: []        # e.g. ["US", "DE"] — these countries bypass scoring

blacklist:
  countries:
    - "CN"
    - "RU"
    - "KP"
  ips:
    - "192.0.2.1"      # Known malicious IP
```

| Field | Type | Description |
|-------|------|-------------|
| `whitelist.ips` | []string | Connections from these IPs bypass all checks and are forwarded directly. |
| `whitelist.countries` | []string | Connections from these countries skip scoring and ban checks. |
| `blacklist.countries` | []string | Connections from these countries are dropped and receive the `blacklisted_country` score. Requires GeoIP to be enabled. |
| `blacklist.ips` | []string | These IPs are always dropped regardless of other settings. |

> **Warning:** If you forget to add your own IP address to `whitelist.ips` before enabling auto-ban, you risk locking yourself out of your own server. This is especially critical in production environments.

---

### 3g. Dashboard Authentication

```yaml
dashboard:
  enabled: true
  listen: "127.0.0.1:9090"   # Never change to 0.0.0.0
  auth:
    username: "admin"
    password: "changeme_strong_password"   # Change this immediately!
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `dashboard.enabled` | bool | — | Set to `false` to disable the dashboard entirely. |
| `dashboard.listen` | string | `127.0.0.1:8080` | Bind address. Always listen on localhost only. |
| `dashboard.auth.username` | string | — | HTTP Basic Auth username. |
| `dashboard.auth.password` | string | — | HTTP Basic Auth password. Use a strong, randomly generated value. |

---

### 3h. Logging and Retention

```yaml
logging:
  database: "sqlite"
  db_path: "/data/skyguard.db"
  retention_days: 90
  log_first_bytes: 512
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `logging.database` | string | `sqlite` | Only `sqlite` is currently supported. |
| `logging.db_path` | string | — | Path to the SQLite database file. |
| `logging.retention_days` | int | `30` | Connection records older than this many days are deleted automatically. |
| `logging.log_first_bytes` | int | `512` | Number of bytes to capture from the beginning of each connection payload. |

---

## 4. Stealth SSH Setup

This section walks through a real-world scenario: moving SSH off port 22 and serving it through SkyGuard on a hidden port (9911). Attackers who connect to port 22 fall into the SSH honeypot.

### Step 1 — Bind sshd to Localhost Only

```bash
# Edit sshd_config
sudo nano /etc/ssh/sshd_config

# Add or change this line:
ListenAddress 127.0.0.1

# Apply the change
sudo systemctl restart sshd

# Verify: 127.0.0.1:22 should appear, NOT 0.0.0.0:22
ss -tlnp | grep sshd
```

> **Important:** Do not close your current SSH session before completing this step.
> Work from a second terminal or tmux pane to avoid locking yourself out.

### Step 2 — Configure UFW Rules

```bash
# Block port 22 from external access
sudo ufw deny 22/tcp

# Open the stealth port
sudo ufw allow 9911/tcp

# The dashboard listens on 127.0.0.1 — no external firewall rule is needed
# Verify UFW rules
sudo ufw status numbered
```

### Step 3 — Configure SkyGuard

Edit `/etc/skyguard/skyguard.yaml`:

```yaml
general:
  log_level: "info"
  data_dir: "/data"

stealth_services:
  - name: "ssh"
    listen_port: 9911             # The hidden port
    real_target: "127.0.0.1:22"  # sshd is now localhost-only
    protocol_signature: "SSH-2.0-"
    timeout: 5s
    allowed_countries: []         # or restrict to ["US"] etc.

honeypot_services:
  - name: "fake-ssh"
    port: 22                      # Attackers land here
    type: "ssh"
    enabled: true
    banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
    max_auth_attempts: 3
    fake_shell: false

whitelist:
  ips:
    - "127.0.0.1"
    - "::1"
    - "YOUR_REAL_HOME_IP"

dashboard:
  enabled: true
  listen: "127.0.0.1:9090"
  auth:
    username: "admin"
    password: "choose_a_strong_password_here"

analysis:
  auto_ban:
    enabled: true
    score_threshold: 50
    ban_duration: "24h"
    method: "ufw"
```

### Step 4 — Start SkyGuard and Verify

```bash
# Start with Docker Compose
docker compose up -d

# Watch the logs
docker logs -f skyguard

# From another terminal, test the stealth port
ssh -p 9911 user@YOUR_SERVER_IP
# Expected: connects successfully to the real SSH server

# Test port 22 (should hit the honeypot)
ssh -p 22 user@YOUR_SERVER_IP
# Expected: connection received, then "Authentication failed" (honeypot)
```

### Step 5 — Verify External Appearance with nmap

Run these commands from a **different machine** (not the server itself):

```bash
# Scan the stealth port
nmap -p 9911 YOUR_SERVER_IP
# Expected output:
# PORT     STATE    SERVICE
# 9911/tcp filtered unknown
#
# Explanation: Without a valid SSH client handshake, SkyGuard drops
# the connection after the timeout → nmap sees the port as filtered.

# Scan the honeypot port
nmap -sV -p 22 YOUR_SERVER_IP
# Expected output:
# PORT   STATE SERVICE VERSION
# 22/tcp open  ssh     OpenSSH 8.9p1
#
# Explanation: The honeypot responds with a realistic banner,
# making it indistinguishable from a real OpenSSH server.
```

This confirms the stealth port is invisible to scanners while the honeypot looks like a legitimate target.

---

## 5. Honeypot Services

### SSH Honeypot

**What it does:** Sends a realistic SSH banner, reads the client's banner and key-exchange packet, introduces a 3-second delay to simulate a real handshake, then returns `Authentication failed` and closes the connection.

**Data logged:** Source IP, client SSH banner string (reveals the attacker's SSH client version), bytes read.

**How it appears to an attacker:** Identical to a real OpenSSH server. Automated scanners will attempt username/password combinations without suspicion.

**How to enable/disable:** Set `enabled: false` on the entry to stop this honeypot without removing it from the config.

**Example log output:**

```json
{
  "time": "2024-01-15T10:23:45Z",
  "level": "INFO",
  "msg": "ssh connection",
  "source_ip": "185.220.101.5",
  "client_banner": "SSH-2.0-libssh_0.9.6",
  "bytes_read": 48
}
```

---

### FTP Honeypot

**What it does:** Sends a `220 ProFTPD ... ready.` banner, reads `USER` and `PASS` commands, logs the credentials, and replies with `530 Login incorrect` every time. After `max_auth_attempts` failed attempts the connection is closed.

**Data logged:** Source IP, username, password (plaintext as submitted), attempt number.

**How it appears to an attacker:** Indistinguishable from a real ProFTPD server. Brute-force tools and credential stuffers will try common password lists.

**How to enable/disable:** Set `enabled: false` to disable this honeypot independently.

**Example log output:**

```json
{
  "time": "2024-01-15T10:24:12Z",
  "level": "INFO",
  "msg": "ftp credential attempt",
  "source_ip": "185.220.101.5",
  "user": "admin",
  "pass": "admin123",
  "attempt": 1
}
```

---

### MySQL Honeypot

**What it does:** Sends a MySQL Protocol v10 Initial Handshake packet with a randomly generated `auth-plugin-data` field. Reads the client's `HandshakeResponse` packet, extracts the username, then replies with a standard `Access denied` error packet.

**Data logged:** Source IP, username. (Passwords are hashed client-side before transmission and cannot be recovered.)

**How it appears to an attacker:** A MySQL 5.7.x server. The `mysql` CLI client and automated database scanners treat it as a genuine MySQL instance.

**How to enable/disable:** Set `enabled: false` to disable this honeypot independently.

**Example log output:**

```json
{
  "time": "2024-01-15T10:25:33Z",
  "level": "INFO",
  "msg": "mysql login attempt",
  "source_ip": "45.155.205.233",
  "user": "root"
}
```

---

### HTTP Honeypot

**What it does:** Reads the first line of the HTTP request (method and path) and returns a context-appropriate fake HTML page based on the requested path:

| Requested Path | Fake Response Page |
|----------------|--------------------|
| `/admin`, `/wp-admin`, `/wp-login.php` | WordPress login form |
| `/phpmyadmin*` | phpMyAdmin login page |
| All other paths | Apache 2 default "It works!" page |

**Data logged:** Source IP, HTTP method, requested path.

**How it appears to an attacker:** A standard Apache or nginx web server. Automated web scanners routinely probe for `/wp-admin`, `/phpmyadmin`, `/admin`, and similar paths.

**How to enable/disable:** Set `enabled: false` to disable this honeypot independently.

**Example log output:**

```json
{
  "time": "2024-01-15T10:26:01Z",
  "level": "INFO",
  "msg": "http request",
  "source_ip": "91.108.4.1",
  "method": "GET",
  "path": "/wp-login.php"
}
```

---

## 6. Dashboard Usage

### Accessing the Dashboard

The dashboard binds exclusively to `127.0.0.1:9090`. If SkyGuard is running on a remote server, access it through an SSH tunnel:

```bash
# Run this on your local machine:
ssh -L 9090:127.0.0.1:9090 user@YOUR_SERVER_IP -N

# Then open in your browser:
# http://127.0.0.1:9090
```

Authenticate using the `username` and `password` values from `dashboard.auth` in your config.

### Dashboard Features

The web UI provides:

- **Summary statistics** — total connections, honeypot hits, forwarded, dropped
- **Recent connections** — live connection feed, refreshed every 15 seconds
- **Top attackers** — the 20 IPs with the highest threat scores
- **Top credentials** — the 50 most-attempted username/password pairs

### API Endpoints

All endpoints require HTTP Basic Authentication and return `application/json`.

#### `GET /api/stats`

Returns aggregate connection statistics.

```bash
curl -u admin:PASSWORD http://127.0.0.1:9090/api/stats
```

```json
{
  "total": 1423,
  "honeypot_hits": 1187,
  "forwarded": 34,
  "dropped": 202
}
```

#### `GET /api/connections?limit=N`

Returns the most recent `N` connection records. Default: 100.

```bash
curl -u admin:PASSWORD "http://127.0.0.1:9090/api/connections?limit=20"
```

```json
[
  {
    "Timestamp": "2024-01-15T10:23:45Z",
    "SourceIP": "185.220.101.5",
    "DestPort": 22,
    "Country": "DE",
    "City": "Frankfurt",
    "ServiceType": "honeypot",
    "Action": "honeypot",
    "Data": ""
  }
]
```

#### `GET /api/attackers`

Returns the top 20 attackers sorted by threat score (descending).

```bash
curl -u admin:PASSWORD http://127.0.0.1:9090/api/attackers
```

```json
[
  {
    "IP": "185.220.101.5",
    "Country": "DE",
    "Score": 85,
    "HoneypotHits": 7,
    "LastSeen": "2024-01-15T10:24:00Z"
  }
]
```

#### `GET /api/credentials`

Returns the top 50 most-attempted username/password pairs across all honeypots.

```bash
curl -u admin:PASSWORD http://127.0.0.1:9090/api/credentials
```

```json
[
  {"username": "root",  "password": "123456",   "count": 342},
  {"username": "admin", "password": "admin",    "count": 218},
  {"username": "root",  "password": "password", "count": 156}
]
```

#### `GET /api/banned`

Returns the list of currently active bans.

```bash
curl -u admin:PASSWORD http://127.0.0.1:9090/api/banned
```

```json
[
  {
    "IP": "185.220.101.5",
    "Reason": "honeypot_threshold",
    "BannedAt": "2024-01-15T10:24:00Z",
    "ExpiresAt": "2024-01-16T10:24:00Z",
    "Permanent": false
  }
]
```

---

## 7. Auto-Ban System

### How Scoring Works

SkyGuard maintains a cumulative threat score for each unique source IP. The score increases when specific events are observed:

| Event | Default Score | Description |
|-------|---------------|-------------|
| `honeypot_connection` | +10 | The IP connected to any honeypot port |
| `failed_credential` | +15 | Authentication attempt failed on FTP or SSH honeypot |
| `port_scan_detected` | +25 | The IP connected to multiple distinct ports in a short window |
| `blacklisted_country` | +5 | GeoIP resolved the IP to a blacklisted country |
| `rate_limit_exceeded` | +20 | The IP exceeded the per-minute or per-hour connection limit |

Scores are configurable in the `analysis.auto_ban.scoring` block. Adjust them to match your threat model.

### Score Threshold and Ban Trigger

When an IP's cumulative score reaches `score_threshold`, the following actions occur:

1. A record is written to the `bans` table in the SQLite database.
2. All subsequent connections from that IP are dropped for the duration of `ban_duration`.
3. If `method` is `iptables` or `ufw`, a firewall rule is added at the kernel or UFW layer.

### UFW vs. iptables

| Method | Advantages | Disadvantages |
|--------|------------|---------------|
| `none` | No root privilege required for banning; writes to DB only | No kernel-level block; if SkyGuard restarts, the ban persists in DB but the traffic continues until SkyGuard is back up |
| `iptables` | Adds a `-j DROP` rule to the kernel INPUT chain; blocks at the packet level regardless of port | Requires root; rules are lost on server reboot unless `iptables-persistent` is installed |
| `ufw` | Ubuntu's standard firewall; rules survive reboots | `ufw` must be installed; slight latency as the `ufw deny` command is executed as a subprocess |

> **Recommendation:** Use `ufw` on Ubuntu servers. Use `iptables` on other distributions. Always install `iptables-persistent` (`sudo apt install iptables-persistent`) if you choose `iptables` to ensure rules survive reboots.

### Manual Ban and Unban

```bash
# Manually ban an IP with iptables
sudo iptables -I INPUT -s 185.220.101.5 -j DROP

# Unban with iptables
sudo iptables -D INPUT -s 185.220.101.5 -j DROP

# Manually ban an IP with UFW
sudo ufw deny from 185.220.101.5 to any

# Unban with UFW
sudo ufw delete deny from 185.220.101.5 to any

# View active bans from the database via the API
curl -u admin:PASSWORD http://127.0.0.1:9090/api/banned
```

### Viewing Active Firewall Rules

```bash
# UFW
sudo ufw status numbered

# iptables — show INPUT chain
sudo iptables -L INPUT -n --line-numbers

# iptables — show all DROP rules
sudo iptables-save | grep DROP
```

### When a Ban Expires

SkyGuard periodically checks the `bans` table and removes expired entries. However, if `method: iptables` was used, the corresponding kernel rules are **not removed automatically**. Use a cron job or `iptables-persistent` to manage rule cleanup:

```bash
# Example cron entry: /etc/cron.d/skyguard-unban
*/5 * * * * root /usr/local/bin/skyguard-unban.sh
```

---

## 8. GeoIP Setup

SkyGuard uses the MaxMind GeoLite2 City database for IP geolocation. A free MaxMind account is required.

### Step 1 — Create a MaxMind Account

1. Go to [https://www.maxmind.com/en/geolite2/signup](https://www.maxmind.com/en/geolite2/signup)
2. Create a free account.
3. Navigate to **Account → Manage License Keys → Generate new license key**.
4. Save the **Account ID** and **License Key** — you will need both below.

### Step 2 — Download and Install the Database

**Using the `geoipupdate` tool (recommended):**

```bash
# Install geoipupdate
sudo apt-get install geoipupdate   # Debian/Ubuntu

# Edit the GeoIP configuration file
sudo nano /etc/GeoIP.conf

# Add or update these lines:
AccountID YOUR_ACCOUNT_ID
LicenseKey YOUR_LICENSE_KEY
EditionIDs GeoLite2-City

# Download the database
sudo geoipupdate

# Copy the database to SkyGuard's data directory
sudo cp /usr/share/GeoIP/GeoLite2-City.mmdb /data/GeoLite2-City.mmdb
sudo chmod 644 /data/GeoLite2-City.mmdb
```

**Manual download (without `geoipupdate`):**

```bash
LICENSE_KEY="YOUR_LICENSE_KEY"
ACCOUNT_ID="YOUR_ACCOUNT_ID"

curl -o /tmp/GeoLite2-City.tar.gz \
  "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=${LICENSE_KEY}&suffix=tar.gz"

tar -xzf /tmp/GeoLite2-City.tar.gz -C /tmp/
sudo cp /tmp/GeoLite2-City_*/GeoLite2-City.mmdb /data/GeoLite2-City.mmdb
sudo chmod 644 /data/GeoLite2-City.mmdb
```

### Step 3 — Enable GeoIP in Config

```yaml
analysis:
  geoip:
    enabled: true
    db_path: "/data/GeoLite2-City.mmdb"
```

Restart SkyGuard after enabling GeoIP for the change to take effect.

### Step 4 — Monthly Automatic Updates (Cron)

MaxMind updates the GeoLite2 database on the first Tuesday of each month. Set up a cron job to keep the database current:

```bash
# Create: /etc/cron.d/geoip-update
0 3 2 * * root geoipupdate && cp /usr/share/GeoIP/GeoLite2-City.mmdb /data/GeoLite2-City.mmdb && docker restart skyguard
```

> **Note:** The cron above runs on the 2nd of each month at 03:00. Adjust the day and time to suit your schedule. If you are running SkyGuard as a systemd service instead of Docker, replace `docker restart skyguard` with `systemctl restart skyguard`.

---

## 9. Security Best Practices

### Always Whitelist Your Own IP Before Enabling Auto-Ban

```yaml
whitelist:
  ips:
    - "127.0.0.1"
    - "::1"
    - "YOUR_HOME_STATIC_IP"
    - "YOUR_OFFICE_IP"
```

If your IP is not whitelisted and you trigger a honeypot or rate limit (for example, during testing), auto-ban will lock you out. Always add your IP first, verify you can still connect, then enable auto-ban.

### Dashboard Must Only Bind to Localhost

```yaml
dashboard:
  listen: "127.0.0.1:9090"   # DO NOT change to 0.0.0.0
```

Exposing the dashboard on a public interface leaks sensitive threat intelligence data. For remote access, use an SSH tunnel:

```bash
ssh -L 9090:127.0.0.1:9090 user@YOUR_SERVER_IP -N &
# Open http://127.0.0.1:9090 in your browser
```

### Config File Permissions

The config file contains your dashboard password in plaintext. Restrict access to root only:

```bash
sudo chmod 600 /etc/skyguard/skyguard.yaml
sudo chown root:root /etc/skyguard/skyguard.yaml
```

### Use a Strong Dashboard Password

```yaml
dashboard:
  auth:
    username: "admin"
    password: "AtLeast16CharStrongPassword!2024"
```

Generate a cryptographically random password:

```bash
openssl rand -base64 24
```

### What Happens If SkyGuard Crashes

If SkyGuard goes down, no process listens on the stealth or honeypot ports. If sshd is bound to `127.0.0.1:22` and UFW blocks port 22 externally, both you and attackers lose access to port 22. Your stealth port (9911) will also be unreachable until SkyGuard restarts.

Mitigations:

```bash
# Docker: automatic restart policy
docker run --restart unless-stopped ...

# systemd: automatic restart
# In the unit file:
# Restart=always
# RestartSec=5

# Out-of-band access options (always have one ready):
# - VPS provider web console (DigitalOcean, Hetzner, Vultr, etc.)
# - IPMI / KVM over IP
# - A second sshd instance on a separate port as an emergency fallback
```

### Backup and Log Rotation

```bash
# Daily SQLite backup via cron
0 4 * * * root sqlite3 /data/skyguard.db ".backup /backup/skyguard-$(date +\%Y\%m\%d).db"

# Remove backups older than 30 days
find /backup -name "skyguard-*.db" -mtime +30 -delete

# Docker log rotation is pre-configured in docker-compose.yml:
# options:
#   max-size: "50m"
#   max-file: "5"
```

---

## 10. Troubleshooting

### Port Already in Use

```
Error: stealth "ssh": listen 0.0.0.0:9911: bind: address already in use
```

**Resolution:**

```bash
# Identify which process is holding the port
sudo ss -tlnp | grep 9911
# or
sudo lsof -i :9911

# Stop the conflicting process if necessary
sudo kill -9 <PID>
```

---

### Permission Denied — Root Required for Firewall Rules

```
firewall ban error: iptables -I INPUT -s 1.2.3.4 -j DROP: exit status 1 (output: xtables lock)
```

**Resolution:** SkyGuard must run as root or with the `NET_ADMIN` capability to modify firewall rules.

```bash
# Docker: add the required capabilities
docker run --cap-add NET_ADMIN --cap-add NET_RAW ...

# Binary: run as root
sudo skyguard -config /etc/skyguard/skyguard.yaml

# systemd unit file: add ambient capabilities
# AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE
```

---

### GeoIP Database Not Found

```
geoip: open /data/GeoLite2-City.mmdb: no such file or directory
```

**Resolution:**

```bash
# Check whether the file exists
ls -la /data/GeoLite2-City.mmdb

# If missing, download it (see Section 8)

# To run without GeoIP temporarily, disable it in config:
# analysis:
#   geoip:
#     enabled: false
```

---

### Dashboard Returns 401 Unauthorized

```bash
curl http://127.0.0.1:9090/api/stats
# HTTP/1.1 401 Unauthorized
```

**Resolution:** All API endpoints require HTTP Basic Authentication:

```bash
curl -u admin:YOUR_PASSWORD http://127.0.0.1:9090/api/stats
```

If the credentials are correct but authentication still fails, verify `dashboard.auth.username` and `dashboard.auth.password` in your config file, then restart SkyGuard.

---

### Container Not Starting

```bash
docker logs skyguard
```

Common causes and fixes:

- **Config file not found at mount path:** Verify the bind mount path in `docker-compose.yml` matches the actual file location.
- **YAML syntax error in config:** Validate the file with `yamllint /etc/skyguard/skyguard.yaml`.
- **Port conflict:** Another process is already listening on one of SkyGuard's configured ports (see "Port Already in Use" above).
- **GeoIP enabled but database missing:** Either download the database (see Section 8) or set `geoip.enabled: false`.

```bash
# Test config syntax without starting the full service
docker run --rm \
  -v /etc/skyguard/skyguard.yaml:/etc/skyguard/skyguard.yaml:ro \
  skyguard:latest -config /etc/skyguard/skyguard.yaml -validate
```

---

### Honeypot Logs Not Appearing

Enable debug logging to increase output verbosity:

```yaml
general:
  log_level: "debug"
```

```bash
docker restart skyguard
docker logs -f skyguard
```

Also verify the honeypot entry has `enabled: true` (or the field is absent, which defaults to enabled) and that the port is not blocked by UFW before reaching SkyGuard.

---

## 11. API Reference

All endpoints require HTTP Basic Authentication. All responses are `Content-Type: application/json`.

| Endpoint | Method | Auth Required | Parameters | Returns |
|----------|--------|:-------------:|------------|---------|
| `GET /` | GET | Yes | — | HTML dashboard page |
| `GET /api/stats` | GET | Yes | — | `{total, honeypot_hits, forwarded, dropped}` |
| `GET /api/connections` | GET | Yes | `limit` (int, default 100) | Array of connection records |
| `GET /api/banned` | GET | Yes | — | Array of active ban records |
| `GET /api/attackers` | GET | Yes | — | Top 20 attackers by score |
| `GET /api/credentials` | GET | Yes | — | Top 50 credential pairs |

### Connection Record Fields

| Field | Type | Description |
|-------|------|-------------|
| `Timestamp` | string (ISO 8601) | Time of the connection |
| `SourceIP` | string | Source IP address |
| `DestPort` | int | Destination port |
| `Country` | string | ISO 3166-1 alpha-2 country code (requires GeoIP) |
| `City` | string | City name (requires GeoIP) |
| `ServiceType` | string | One of: `stealth`, `honeypot`, `passthrough` |
| `Action` | string | One of: `forwarded`, `honeypot`, `dropped`, `passthrough` |
| `Data` | string | Additional payload data (banner string, HTTP path, etc.) |

### Attacker Record Fields

| Field | Type | Description |
|-------|------|-------------|
| `IP` | string | IP address |
| `Country` | string | Country code |
| `Score` | int | Cumulative threat score |
| `HoneypotHits` | int | Number of honeypot connections |
| `LastSeen` | string (ISO 8601) | Timestamp of most recent activity |

### Ban Record Fields

| Field | Type | Description |
|-------|------|-------------|
| `IP` | string | Banned IP address |
| `Reason` | string | Reason for the ban (e.g. `honeypot_threshold`) |
| `BannedAt` | string (ISO 8601) | Time the ban was applied |
| `ExpiresAt` | string (ISO 8601) | Time the ban expires |
| `Permanent` | bool | Whether the ban is permanent |

---

## 12. Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SKYGUARD_CONFIG` | Path to the config file. Overrides the `-config` command-line flag. | `/etc/skyguard/skyguard.yaml` |
| `TZ` | Timezone used for log timestamps. | `UTC` |

**Example — binary:**

```bash
export SKYGUARD_CONFIG=/opt/skyguard/config.yaml
export TZ=America/New_York
skyguard
```

**Example — Docker Compose:**

```yaml
environment:
  - SKYGUARD_CONFIG=/etc/skyguard/skyguard.yaml
  - TZ=America/New_York
```

---

## 13. Production Checklist

Complete all items below before deploying SkyGuard to a production environment.

### Security

- [ ] Your IP address has been added to `whitelist.ips`
- [ ] `dashboard.auth.password` has been changed from the default (`changeme_strong_password`)
- [ ] Config file permissions are restricted: `chmod 600 /etc/skyguard/skyguard.yaml`
- [ ] Dashboard is bound to `127.0.0.1:9090` only (not `0.0.0.0`)
- [ ] `fake_shell: false` on all SSH honeypot entries
- [ ] Stealth SSH port is protected by UFW or iptables

### GeoIP

- [ ] MaxMind account created and license key obtained
- [ ] `GeoLite2-City.mmdb` downloaded to `/data/`
- [ ] `analysis.geoip.enabled: true` set in config
- [ ] Monthly auto-update cron job configured

### Auto-Ban

- [ ] `analysis.auto_ban.method` selected: `iptables` or `ufw`
- [ ] `analysis.auto_ban.enabled: true`
- [ ] Country and IP blacklists reviewed
- [ ] Verified your own IP is not triggering a ban during testing

### Backup and Monitoring

- [ ] Data directory (`/data`) is included in a scheduled backup (cron or snapshot)
- [ ] Docker `--restart unless-stopped` or systemd `Restart=always` is active
- [ ] `logging.retention_days` is set to a value appropriate for your storage capacity
- [ ] Docker log rotation is configured (`max-size` and `max-file` in compose)

### Accessibility

- [ ] Stealth SSH port tested: `ssh -p 9911 user@SERVER_IP`
- [ ] Honeypot port tested: `nc SERVER_IP 22` shows the banner
- [ ] Dashboard accessible via SSH tunnel
- [ ] Out-of-band access method is available and tested (VPS console, IPMI, etc.)

### Monitoring and Alerting

- [ ] Container or service logs are being collected (`docker logs` or systemd journal)
- [ ] Dashboard `/api/stats` is integrated with an external monitoring system (Uptime Kuma, Grafana, etc.)

---

*SkyGuard is a detection and logging tool. It is not a replacement for a properly configured host firewall. Always keep your host OS up to date and apply defence-in-depth practices alongside SkyGuard.*