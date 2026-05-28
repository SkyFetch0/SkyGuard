#!/usr/bin/env bash
# SkyGuard installation script
# Usage: ./scripts/install-plugin.sh [--standalone] [--config-only]
#
# Options:
#   --standalone   Install without server-guard plugin framework
#   --config-only  Only write/update config, do not start containers

set -euo pipefail

# ── Colours ─────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}[INFO]${RESET}  $*"; }
success() { echo -e "${GREEN}[OK]${RESET}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
die()     { echo -e "${RED}[ERROR]${RESET} $*" >&2; exit 1; }

# ── Defaults ────────────────────────────────────────────────────────────────
SKYGUARD_DIR="${SKYGUARD_DIR:-/opt/skyguard}"
CONFIG_DIR="/etc/skyguard"
DATA_DIR="/data"
COMPOSE_FILE="docker-compose.yml"
IMAGE_NAME="skyguard:latest"
SERVICE_NAME="skyguard"
STANDALONE=false
CONFIG_ONLY=false

# ── Argument parsing ─────────────────────────────────────────────────────────
for arg in "$@"; do
  case $arg in
    --standalone)  STANDALONE=true ;;
    --config-only) CONFIG_ONLY=true ;;
    *)             die "Unknown option: $arg" ;;
  esac
done

# ── Root check ───────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
  die "This script must be run as root. Try: sudo $0 $*"
fi

echo -e ""
echo -e "${BOLD}╔══════════════════════════════════════╗${RESET}"
echo -e "${BOLD}║        SkyGuard  Installer           ║${RESET}"
echo -e "${BOLD}╚══════════════════════════════════════╝${RESET}"
echo -e ""

# ── Docker availability check ────────────────────────────────────────────────
check_docker() {
  if ! command -v docker &>/dev/null; then
    warn "Docker not found. Installing..."
    if command -v apt-get &>/dev/null; then
      apt-get update -qq
      apt-get install -y -qq ca-certificates curl gnupg lsb-release
      mkdir -p /etc/apt/keyrings
      curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
        | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
      echo \
        "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
        https://download.docker.com/linux/ubuntu \
        $(lsb_release -cs) stable" \
        | tee /etc/apt/sources.list.d/docker.list > /dev/null
      apt-get update -qq
      apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin
    elif command -v yum &>/dev/null; then
      yum install -y -q yum-utils
      yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
      yum install -y -q docker-ce docker-ce-cli containerd.io docker-compose-plugin
    else
      die "Cannot install Docker automatically. Please install Docker manually: https://docs.docker.com/get-docker/"
    fi
    systemctl enable --now docker
    success "Docker installed."
  else
    success "Docker $(docker --version | awk '{print $3}' | tr -d ',') found."
  fi

  # Verify docker compose (v2 plugin or standalone)
  if docker compose version &>/dev/null 2>&1; then
    DOCKER_COMPOSE="docker compose"
  elif command -v docker-compose &>/dev/null; then
    DOCKER_COMPOSE="docker-compose"
  else
    warn "docker compose plugin not found. Installing..."
    DOCKER_CONFIG="${DOCKER_CONFIG:-$HOME/.docker}"
    mkdir -p "$DOCKER_CONFIG/cli-plugins"
    COMPOSE_VERSION=$(curl -s https://api.github.com/repos/docker/compose/releases/latest \
      | grep -oP '"tag_name": "\K[^"]+' | head -1 || echo "v2.27.0")
    curl -SL "https://github.com/docker/compose/releases/download/${COMPOSE_VERSION}/docker-compose-$(uname -s)-$(uname -m)" \
      -o "$DOCKER_CONFIG/cli-plugins/docker-compose"
    chmod +x "$DOCKER_CONFIG/cli-plugins/docker-compose"
    DOCKER_COMPOSE="docker compose"
    success "docker compose plugin installed."
  fi
  export DOCKER_COMPOSE
}

# ── Directory setup ──────────────────────────────────────────────────────────
setup_dirs() {
  info "Creating directories..."
  mkdir -p "$SKYGUARD_DIR" "$CONFIG_DIR" "$DATA_DIR"
  chmod 750 "$CONFIG_DIR" "$DATA_DIR"
  success "Directories ready: $SKYGUARD_DIR, $CONFIG_DIR, $DATA_DIR"
}

# ── Copy project files ───────────────────────────────────────────────────────
copy_files() {
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

  info "Copying project files to $SKYGUARD_DIR..."
  cp -r "$PROJECT_ROOT/." "$SKYGUARD_DIR/"
  success "Files copied."
}

# ── Interactive config creation ──────────────────────────────────────────────
create_config() {
  CONFIG_FILE="$CONFIG_DIR/skyguard.yaml"

  if [[ -f "$CONFIG_FILE" ]]; then
    read -rp "$(echo -e "${YELLOW}Config already exists at $CONFIG_FILE. Overwrite? [y/N]: ${RESET}")" OVERWRITE
    [[ "${OVERWRITE,,}" == "y" ]] || { info "Keeping existing config."; return 0; }
  fi

  echo -e ""
  echo -e "${BOLD}── Configuration Wizard ──────────────────${RESET}"

  # Dashboard credentials
  read -rp "$(echo -e "${CYAN}Dashboard username [admin]: ${RESET}")"   DASH_USER
  DASH_USER="${DASH_USER:-admin}"

  while true; do
    read -rsp "$(echo -e "${CYAN}Dashboard password: ${RESET}")" DASH_PASS; echo
    [[ ${#DASH_PASS} -ge 8 ]] && break
    warn "Password must be at least 8 characters."
  done

  # Whitelist IPs
  read -rp "$(echo -e "${CYAN}Your trusted IP(s) to whitelist (comma-separated, or blank): ${RESET}")" TRUSTED_IPS

  # Stealth SSH port
  read -rp "$(echo -e "${CYAN}Stealth SSH listen port [9911]: ${RESET}")" STEALTH_PORT
  STEALTH_PORT="${STEALTH_PORT:-9911}"

  # GeoIP
  read -rp "$(echo -e "${CYAN}Enable GeoIP filtering? [y/N]: ${RESET}")" ENABLE_GEOIP
  GEOIP_ENABLED="false"
  [[ "${ENABLE_GEOIP,,}" == "y" ]] && GEOIP_ENABLED="true"

  # Build whitelist YAML block
  WHITELIST_IPS="    - \"127.0.0.1\"\n    - \"::1\""
  if [[ -n "$TRUSTED_IPS" ]]; then
    IFS=',' read -ra IP_ARR <<< "$TRUSTED_IPS"
    for ip in "${IP_ARR[@]}"; do
      ip="$(echo "$ip" | xargs)"
      WHITELIST_IPS+="\\n    - \"$ip\""
    done
  fi

  info "Writing config to $CONFIG_FILE..."
  cat > "$CONFIG_FILE" <<YAML
# SkyGuard Configuration — generated by install-plugin.sh
# https://github.com/skyguard/skyguard

general:
  log_level: "info"
  data_dir: "$DATA_DIR"

stealth_services:
  - name: "ssh"
    listen_port: $STEALTH_PORT
    real_target: "127.0.0.1:22"
    protocol_signature: "SSH-2.0-"
    timeout: 10s
    allowed_countries: []

honeypot_services:
  - name: "fake-ssh"
    port: 22
    type: "ssh"
    banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
    max_auth_attempts: 3
    fake_shell: false

  - name: "fake-ftp"
    port: 21
    type: "ftp"
    banner: "ProFTPD 1.3.5e Server (Debian) ready."

  - name: "fake-mysql"
    port: 3306
    type: "mysql"
    banner: "5.7.42-0ubuntu0.18.04.1"

  - name: "fake-http"
    port: 80
    type: "http"
    server_header: "Apache/2.4.41 (Ubuntu)"

passthrough_services:
  - name: "web"
    listen_port: 443
    real_target: "127.0.0.1:8443"

analysis:
  geoip:
    enabled: $GEOIP_ENABLED
    db_path: "$DATA_DIR/GeoLite2-City.mmdb"
  rate_limit:
    max_per_minute: 20
    max_per_hour: 200
  auto_ban:
    enabled: true
    score_threshold: 50
    ban_duration: "24h"
    method: "none"
    scoring:
      honeypot_connection: 10
      failed_credential: 15
      port_scan_detected: 25
      blacklisted_country: 5
      rate_limit_exceeded: 20

whitelist:
  ips:
$(echo -e "$WHITELIST_IPS")
  countries: []

blacklist:
  countries: []
  ips: []

dashboard:
  enabled: true
  listen: "127.0.0.1:9090"
  auth:
    username: "$DASH_USER"
    password: "$DASH_PASS"

logging:
  database: "sqlite"
  db_path: "$DATA_DIR/skyguard.db"
  retention_days: 90
  log_first_bytes: 512
YAML

  chmod 640 "$CONFIG_FILE"
  success "Config written to $CONFIG_FILE"
}

# ── Build Docker image ────────────────────────────────────────────────────────
build_image() {
  info "Building Docker image $IMAGE_NAME..."
  docker build -t "$IMAGE_NAME" "$SKYGUARD_DIR" \
    --build-arg BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --build-arg VCS_REF="$(git -C "$SKYGUARD_DIR" rev-parse --short HEAD 2>/dev/null || echo 'unknown')"
  success "Image built: $IMAGE_NAME"
}

# ── Write compose file ────────────────────────────────────────────────────────
write_compose() {
  COMPOSE_PATH="$SKYGUARD_DIR/$COMPOSE_FILE"
  info "Writing $COMPOSE_PATH..."
  cat > "$COMPOSE_PATH" <<COMPOSE
version: "3.9"
services:
  skyguard:
    image: $IMAGE_NAME
    container_name: $SERVICE_NAME
    restart: unless-stopped
    network_mode: host
    volumes:
      - $CONFIG_DIR/skyguard.yaml:/etc/skyguard/skyguard.yaml:ro
      - $DATA_DIR:/data
    environment:
      - SKYGUARD_CONFIG=/etc/skyguard/skyguard.yaml
    logging:
      driver: "json-file"
      options:
        max-size: "50m"
        max-file: "5"
COMPOSE
  success "docker-compose.yml written."
}

# ── systemd service ───────────────────────────────────────────────────────────
install_systemd() {
  UNIT_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
  info "Installing systemd unit $UNIT_FILE..."
  cat > "$UNIT_FILE" <<UNIT
[Unit]
Description=SkyGuard Security System
Documentation=https://github.com/skyguard/skyguard
After=docker.service network-online.target
Requires=docker.service
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=$SKYGUARD_DIR
ExecStart=/usr/bin/env bash -c '${DOCKER_COMPOSE} -f $SKYGUARD_DIR/$COMPOSE_FILE up -d'
ExecStop=/usr/bin/env bash -c '${DOCKER_COMPOSE} -f $SKYGUARD_DIR/$COMPOSE_FILE down'
ExecReload=/usr/bin/env bash -c '${DOCKER_COMPOSE} -f $SKYGUARD_DIR/$COMPOSE_FILE pull && ${DOCKER_COMPOSE} -f $SKYGUARD_DIR/$COMPOSE_FILE up -d'
TimeoutStartSec=120
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
UNIT

  systemctl daemon-reload
  systemctl enable "$SERVICE_NAME"
  success "systemd unit installed and enabled."
}

# ── Start container ───────────────────────────────────────────────────────────
start_container() {
  info "Starting SkyGuard container..."
  cd "$SKYGUARD_DIR"
  $DOCKER_COMPOSE -f "$COMPOSE_FILE" up -d
  success "Container started."
}

# ── Healthcheck ───────────────────────────────────────────────────────────────
healthcheck() {
  info "Waiting for SkyGuard to become healthy..."
  local retries=15 wait=2
  for ((i=1; i<=retries; i++)); do
    if docker inspect --format='{{.State.Health.Status}}' "$SERVICE_NAME" 2>/dev/null | grep -q "healthy"; then
      success "SkyGuard is healthy."
      return 0
    fi
    # Fallback: check if process is running
    if docker ps --filter "name=$SERVICE_NAME" --filter "status=running" | grep -q "$SERVICE_NAME"; then
      # Give it a few more seconds then check dashboard
      sleep 3
      if curl -sf --max-time 5 "http://127.0.0.1:9090/api/stats" -o /dev/null 2>/dev/null; then
        success "SkyGuard dashboard responding at http://127.0.0.1:9090"
        return 0
      fi
    fi
    sleep "$wait"
  done
  warn "Health check inconclusive. Check logs: docker logs $SERVICE_NAME"
}

# ── Print summary ─────────────────────────────────────────────────────────────
print_summary() {
  echo -e ""
  echo -e "${BOLD}${GREEN}╔══════════════════════════════════════╗${RESET}"
  echo -e "${BOLD}${GREEN}║    SkyGuard installed successfully!  ║${RESET}"
  echo -e "${BOLD}${GREEN}╚══════════════════════════════════════╝${RESET}"
  echo -e ""
  echo -e "  ${BOLD}Dashboard:${RESET}  http://127.0.0.1:9090"
  echo -e "  ${BOLD}Config:${RESET}     $CONFIG_DIR/skyguard.yaml"
  echo -e "  ${BOLD}Data:${RESET}       $DATA_DIR"
  echo -e "  ${BOLD}Logs:${RESET}       docker logs -f $SERVICE_NAME"
  echo -e ""
  echo -e "  ${BOLD}Manage:${RESET}"
  echo -e "    systemctl start|stop|restart $SERVICE_NAME"
  echo -e "    docker logs -f $SERVICE_NAME"
  echo -e ""
}

# ── Main ─────────────────────────────────────────────────────────────────────
main() {
  check_docker
  setup_dirs
  copy_files
  create_config

  if $CONFIG_ONLY; then
    success "Config-only mode: skipping build and start."
    exit 0
  fi

  build_image
  write_compose
  install_systemd
  start_container
  healthcheck
  print_summary
}

main