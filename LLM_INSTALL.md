# Installing SkyGuard: a runbook for AI agents

This file is written for an AI agent (an LLM with shell access) that has been asked to install SkyGuard
on a Linux server. Follow it top to bottom. Every step says what to run, what you should see, and what
to do when you see something else. Humans can follow it too; the [README](README.md#installation) is
the shorter version.

SkyGuard sits in front of the server's network ports: it hides the real SSH behind a stealth port,
runs honeypots on common ports, scores attackers and bans them in the firewall. **A mistake here can
lock the operator out of their own server.** The rules below exist to prevent that.

---

## 0. Rules you must follow

1. **Never close, restart or reconfigure `sshd`, and never block port 22**, unless the human has logged
   in through the stealth port in a *new* session and told you so (step 9).
2. **Never run `install.sh` unattended.** It is an interactive wizard. Use the manual steps below; they
   produce the same result and can be checked one by one.
3. **Ask the human** for every value in section 1 that you cannot read from the server. Do not invent a
   password they cannot see later: generate one and show it to them.
4. **Stop and report** (do not improvise) when a step's check fails twice, when the server is not
   Linux x86_64/arm64, when you are not root and cannot `sudo`, or when the human's own IP is unknown and
   auto-ban would be on.
5. **Do not expose the dashboard.** It listens on `127.0.0.1:9090`. Never change that to `0.0.0.0` and
   never publish it through a reverse proxy without the human asking for it explicitly.
6. Run commands as root (`sudo -i` or prefix with `sudo`). Quote paths. Do not pipe remote scripts into
   a shell except Docker's official installer in step 3, and say that you are doing it.

---

## 1. Values to collect

Collect these before touching anything. Defaults in brackets.

| Value | How to get it | Used in |
|---|---|---|
| `ADMIN_IP` | First field of `echo $SSH_CLIENT` in the human's SSH session, or ask. A list is fine. | whitelist (auto-ban never touches it) |
| `STEALTH_PORT` | Ask. [`9911`] Any free TCP port above 1024. | stealth SSH |
| `REAL_SSH` | `ss -tlnp \| grep sshd` → usually `0.0.0.0:22`. Use `127.0.0.1:<port>`. [`127.0.0.1:22`] | stealth target |
| Honeypots | Ask which: FTP 21, MySQL 3306, HTTP 80, HTTP-alt 8080. [FTP + MySQL + HTTP] Drop any whose port is taken (step 2). | honeypot_services |
| `DASH_USER` / `DASH_PASS` | Ask, or generate: `openssl rand -base64 18`. 8+ characters, never `CHANGE_ME_NOW`. | dashboard.auth |
| Auto-ban | Ask. [on, threshold 50, 24h] | analysis.auto_ban |
| Container management | Ask: "Should the dashboard manage this server's Docker containers / Incus instances? It gets root-equivalent access." [no] | containers |
| Language of the reply | Match the human's language. | — |

---

## 2. Pre-flight checks

Run each command and compare.

```bash
id -u                                   # → 0  (else use sudo; stop if neither works)
uname -sm                               # → Linux x86_64  or  Linux aarch64
. /etc/os-release; echo "$ID $VERSION_ID"   # ubuntu/debian/rocky/almalinux/rhel/fedora are tested
systemctl is-system-running             # running or degraded is fine
echo "$SSH_CLIENT"                      # first field = ADMIN_IP candidate
ss -tlnp | awk 'NR>1{print $4, $6}'     # every listening TCP port and its owner
command -v docker && docker version --format '{{.Server.Version}}'
docker compose version                  # the compose plugin (v2)
command -v iptables ufw firewall-cmd    # which firewall front end exists
```

**Port decisions.** For each port SkyGuard would use, look at the `ss` output:

| Port | If it is taken by… | Do |
|---|---|---|
| `STEALTH_PORT` | anything | pick another stealth port |
| 21, 3306, 8080 | anything | leave that honeypot off |
| 80 / 443 | a web server or reverse proxy (`docker-proxy`, `nginx`, `caddy`, `traefik`, Nginx Proxy Manager) | leave `fake-http` off and the HTTPS passthrough off; tell the human. Find the container with `docker ps --filter publish=80`. |
| 22 | `sshd` (normal) | keep `fake-ssh` **off** (the default) |
| 9090 on 127.0.0.1 | anything | set `dashboard.listen` to another loopback port, e.g. `127.0.0.1:9191` |

---

## 3. Install Docker (only if step 2 found none)

```bash
curl -fsSL https://get.docker.com -o /tmp/get-docker.sh   # Docker's official convenience script
sh /tmp/get-docker.sh
systemctl enable --now docker
docker version --format '{{.Server.Version}}' && docker compose version
```

Expect a version for both. On RHEL-family systems with SELinux enforcing this still works; do not
disable SELinux.

Also make sure these exist: `apt-get install -y git iptables` (Debian/Ubuntu) or
`dnf install -y git iptables` (RHEL/Fedora).

---

## 4. Get the code

```bash
git clone https://github.com/SkyFetch0/SkyGuard.git /opt/skyguard
cd /opt/skyguard
git log --oneline -1          # note the commit for your report
```

---

## 5. Write the configuration

Write `/opt/skyguard/configs/skyguard.yaml` (this is the path `docker-compose.yml` mounts). Replace every
`<…>`. Keep or delete honeypot entries according to step 2: an entry with `enabled: false` is fine.

```yaml
general:
  log_level: "info"
  data_dir: "/data"

stealth_services:
  - name: "ssh"
    enabled: true
    listen_port: <STEALTH_PORT>          # e.g. 9911
    real_target: "<REAL_SSH>"            # e.g. "127.0.0.1:22"
    protocol_signature: "SSH-2.0-"
    timeout: "5s"

honeypot_services:
  - name: "fake-ftp"
    enabled: true
    port: 21
    type: "ftp"
  - name: "fake-mysql"
    enabled: true
    port: 3306
    type: "mysql"
  - name: "fake-http"
    enabled: true                        # false when a web server / reverse proxy owns port 80
    port: 80
    type: "http"
    server_header: "Apache/2.4.41 (Ubuntu)"

analysis:
  auto_ban:
    enabled: true
    score_threshold: 50
    ban_duration: "24h"
    method: "iptables"                   # "ufw" if the host is managed with ufw; "none" to only log
    iptables_backend: "auto"

whitelist:
  ips:
    - "127.0.0.1"
    - "::1"
    - "<ADMIN_IP>"                       # one line per address or CIDR

dashboard:
  enabled: true
  listen: "127.0.0.1:9090"
  auth:
    username: "<DASH_USER>"
    password: "<DASH_PASS>"

containers:                              # only if the human said yes in section 1
  docker:
    enabled: false
  incus:
    enabled: false

logging:
  db_path: "/data/skyguard.db"
  retention_days: 90
```

Then:

```bash
chmod 600 /opt/skyguard/configs/skyguard.yaml
test -f /opt/skyguard/configs/skyguard.yaml && echo file-ok   # must be a FILE: if it is missing,
                                                              # `docker compose up` creates a directory
```

If the human wants container management, also uncomment the socket line(s) in
`/opt/skyguard/docker-compose.yml`:

```yaml
      - /var/run/docker.sock:/var/run/docker.sock      # Docker
      - /var/lib/incus:/var/lib/incus:ro               # Incus (only if /var/lib/incus/unix.socket exists)
```

and set `containers.docker.enabled: true` (and/or `incus`). The engines can also be switched on later
from the dashboard (Settings → Container engines).

---

## 6. Build and validate

```bash
cd /opt/skyguard
docker compose build                                  # 2–5 minutes the first time
docker compose run --rm skyguard -check-config -config /etc/skyguard/skyguard.yaml
```

Expect one line ending in `is valid`. Otherwise the message names the field: fix the file and run the
check again. Typical messages:

| Message contains | Fix |
|---|---|
| `port N already used by …` | two services share a port; change or disable one |
| `container management needs dashboard.auth with a strong password` | set an 8+ character password |
| `invalid real_target` | use `host:port`, e.g. `127.0.0.1:22` |
| `unknown method` | `method` is one of `iptables`, `ufw`, `none` |

---

## 7. Open the firewall for SkyGuard's ports (only if a firewall front end is active)

SkyGuard creates its own `SKYGUARD` chain for bans. Whether the *ports* are reachable is the host
firewall's business:

```bash
ufw status 2>/dev/null | head -1          # "Status: active" → use ufw
firewall-cmd --state 2>/dev/null          # "running" → use firewalld
```

- **ufw active:** `ufw allow <STEALTH_PORT>/tcp` and one `ufw allow <port>/tcp` per enabled honeypot.
- **firewalld running:** `firewall-cmd --permanent --add-port=<port>/tcp` for each, then `firewall-cmd --reload`.
- **neither:** nothing to do (iptables `INPUT` policy is usually ACCEPT; check with `iptables -S INPUT | head -1`;
  if it is `-P INPUT DROP`, add `iptables -A INPUT -p tcp --dport <port> -j ACCEPT` for each port).
- Also open the stealth port in the **cloud provider's firewall / security group** if the server has one.
  You usually cannot do this from the shell: tell the human.

Do **not** add any rule for port 22.

---

## 8. Start and verify

```bash
cd /opt/skyguard
docker compose up -d
for i in $(seq 1 30); do s=$(docker inspect -f '{{.State.Health.Status}}' skyguard 2>/dev/null); [ "$s" = healthy ] && break; sleep 2; done; echo "$s"
```

Expect `healthy`. Then all of these:

```bash
curl -fsS http://127.0.0.1:9090/healthz                                   # → ok
docker logs skyguard 2>&1 | grep -E '"listener started"|"dashboard started"|"SkyGuard running"'
timeout 5 bash -c 'exec 3<>/dev/tcp/127.0.0.1/<STEALTH_PORT>; printf "SSH-2.0-agent-check\r\n" >&3; head -c 8 <&3'; echo
                                                                           # → SSH-2.0-  (the real sshd answered through the stealth port)
iptables -S SKYGUARD                                                       # → -N SKYGUARD
iptables -S INPUT | grep -c SKYGUARD                                       # → 1
iptables -S DOCKER-USER 2>/dev/null | grep SKYGUARD                        # → -A DOCKER-USER -j SKYGUARD (when Docker runs)
iptables -S FORWARD | head -3                                              # → -A FORWARD -j SKYGUARD near the top
curl -fsS -u '<DASH_USER>:<DASH_PASS>' http://127.0.0.1:9090/api/info      # → JSON with "host", "firewall_method"
```

| If | Then |
|---|---|
| status `unhealthy` or the container restarts | `docker logs --tail 50 skyguard`; the last error names the cause |
| `address already in use` | a port from step 2 was taken after all: disable that service in the config, `docker compose up -d` |
| the stealth check prints nothing | `REAL_SSH` is wrong (sshd not on that address), or sshd only listens on a public IP: use that IP in `real_target` |
| `iptables: command not found` inside the logs | the host has no iptables kernel support; set `method: "none"` and tell the human |

---

## 9. Hand over to the human (required)

Ask the human to do this **in a new terminal, keeping the old session open**:

```bash
ssh -p <STEALTH_PORT> <their-user>@<server>
```

Only after they confirm that this login works:

- Offer (do not do it unasked) to block direct SSH on port 22 for everyone but loopback:
  `iptables -I INPUT 2 ! -i lo -p tcp --dport 22 -j DROP`, then persist the rules
  (`netfilter-persistent save` on Debian/Ubuntu, `service iptables save` on RHEL with iptables-services).
  With ufw: `ufw deny 22/tcp`.
- Show them how to reach the dashboard: `ssh -L 9090:127.0.0.1:9090 -p <STEALTH_PORT> <user>@<server>`,
  then http://localhost:9090 with `DASH_USER` / `DASH_PASS`.

---

## 10. Start on boot

`docker-compose.yml` sets `restart: unless-stopped`, so the container comes back after a reboot as long as
Docker starts. Confirm: `systemctl is-enabled docker` → `enabled`.

---

## 10b. Optional: let an AI assistant watch SkyGuard (MCP)

Only if the human asked for it. This switches on SkyGuard's MCP endpoint in **read-only** mode and
returns a token once:

```bash
curl -s -u '<DASH_USER>:<DASH_PASS>' -H 'X-SkyGuard-Request: 1' -d enabled=1 http://127.0.0.1:9090/api/mcp
# → {"enabled":true,"allow_actions":false,"token":"sgmcp_…", …}
```

Give the token to the human (do not store it anywhere else). Do **not** turn on `allow_actions` unless
the human asks for it explicitly: it lets an assistant ban IPs and stop containers. Client setups are
in the README, section "AI assistants (MCP)"; the dashboard's Settings screen shows them with the token
filled in.

## 11. Report back

Give the human a short summary in their language, with these facts filled in:

```
SkyGuard <commit> is running (healthy) on <hostname>.
- Real SSH: hidden behind port <STEALTH_PORT> → <REAL_SSH>. Port 22: <still open | blocked after your test>.
- Honeypots: <list with ports>; left off because the port was taken: <list or none>.
- Auto-ban: <on, threshold 50, 24h | off>. Whitelisted: <ADMIN_IP list>.
- Dashboard: ssh -L 9090:127.0.0.1:9090 -p <STEALTH_PORT> <user>@<server> → http://localhost:9090
  user <DASH_USER>, password <shown once here / where you stored it>.
- Container management: <off | Docker | Incus>.
- AI assistants (MCP): <off | on, read-only | on, actions allowed>.
- Config: /opt/skyguard/configs/skyguard.yaml (mode 600). Data: /opt/skyguard/data.
- Open in the cloud firewall if the server has one: <ports>.
```

---

## Undo

```bash
cd /opt/skyguard && docker compose down
iptables -D INPUT -j SKYGUARD; iptables -D FORWARD -j SKYGUARD; iptables -D DOCKER-USER -j SKYGUARD 2>/dev/null; iptables -F SKYGUARD; iptables -X SKYGUARD
# port access rules (the Ports screen), if any were made:
iptables -D INPUT -j SKYGUARD-PORTS; iptables -D FORWARD -j SKYGUARD-PORTS-FWD
iptables -F SKYGUARD-PORTS; iptables -X SKYGUARD-PORTS; iptables -F SKYGUARD-PORTS-FWD; iptables -X SKYGUARD-PORTS-FWD
# if you blocked 22 in step 9:
iptables -D INPUT ! -i lo -p tcp --dport 22 -j DROP
```

Or run `bash /opt/skyguard/uninstall.sh` (add `--purge` to delete the config and data as well).

## Facts you may need

- Image: built locally from `Dockerfile` (`golang:1.27` → `debian:trixie-slim`), runs as root with
  `NET_ADMIN`/`NET_RAW` on the host network. Health check: `skyguard -healthcheck` (no password needed).
- Flags: `-config PATH`, `-check-config`, `-healthcheck`, `-version`. Env: `SKYGUARD_CONFIG`.
- The full annotated config is `configs/skyguard.example.yaml`; every option is explained in
  [USAGE.md](USAGE.md#3-configuration-guide).
- Moving the real sshd off port 22 so the fake SSH honeypot can take it: `scripts/enable-ssh-honeypot.sh`.
  Do not do this unless the human asks; it restarts sshd.
