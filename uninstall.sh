#!/usr/bin/env bash
# =============================================================================
#  SkyGuard — Uninstaller
#
#  Removes the container, image, systemd unit, cron jobs and logrotate config,
#  restores sshd_config from the SkyGuard backup (so SSH returns to its original
#  port), and cleans up the firewall rules SkyGuard added. Config/data are kept
#  unless you confirm removal (or pass --purge).
#
#  Usage:
#     sudo bash uninstall.sh [--yes] [--purge]
#       --yes     do not prompt for confirmation
#       --purge   also delete config, database and logs
# =============================================================================
set -euo pipefail
IFS=$'\n\t'

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
info(){ echo -e "${CYAN}[INFO]${RESET}  $*"; }
ok(){   echo -e "${GREEN}[OK]${RESET}    $*"; }
warn(){ echo -e "${YELLOW}[WARN]${RESET}  $*"; }
die(){  echo -e "${RED}[ERROR]${RESET} $*" >&2; exit 1; }

ASSUME_YES=false; PURGE=false
for arg in "$@"; do
    case "$arg" in
        --yes|-y) ASSUME_YES=true ;;
        --purge)  PURGE=true ;;
    esac
done

confirm() {
    local prompt="$1" default="${2:-y}"
    $ASSUME_YES && return 0
    local yn
    if [[ "$default" == "y" ]]; then
        read -rp "$(echo -e "${YELLOW}[?]${RESET}    ${prompt} [Y/n]: ")" yn
        [[ -z "$yn" || "$yn" =~ ^[Yy]$ ]]
    else
        read -rp "$(echo -e "${YELLOW}[?]${RESET}    ${prompt} [y/N]: ")" yn
        [[ "$yn" =~ ^[Yy]$ ]]
    fi
}

[[ $EUID -eq 0 ]] || die "Bu script root ile çalıştırılmalı (sudo)."

INSTALL_DIR="${SKYGUARD_DIR:-/opt/skyguard}"
CONFIG_DIR="/etc/skyguard"
DATA_DIR="/var/lib/skyguard"
LOG_DIR="/var/log/skyguard"
IPTABLES_RULES_FILE="/etc/iptables/rules.v4"
IPTABLES_PREBACKUP="${CONFIG_DIR}/iptables.pre-skyguard.bak"

echo -e "${BOLD}SkyGuard kaldırılacak.${RESET}"
confirm "Devam edilsin mi?" || { info "İptal edildi."; exit 0; }

# ── 1. systemd servisi ────────────────────────────────────────────────────────
info "Systemd servisi kaldırılıyor..."
systemctl stop skyguard 2>/dev/null || true
systemctl disable skyguard 2>/dev/null || true
rm -f /etc/systemd/system/skyguard.service
systemctl daemon-reload 2>/dev/null || true
ok "Systemd servisi kaldırıldı."

# ── 2. Container + imaj ───────────────────────────────────────────────────────
info "Container ve imaj kaldırılıyor..."
if [[ -f "${INSTALL_DIR}/docker-compose.yml" ]] && command -v docker &>/dev/null; then
    (cd "${INSTALL_DIR}" && docker compose down 2>/dev/null) || true
fi
docker rm -f skyguard 2>/dev/null || true
docker rmi skyguard:latest 2>/dev/null || true
docker rmi skyguard-skyguard 2>/dev/null || true
ok "Container ve imaj kaldırıldı."

# ── 3. cron + logrotate ───────────────────────────────────────────────────────
rm -f /etc/cron.monthly/skyguard-geoip-update
rm -f /etc/cron.d/skyguard-backup
rm -f /etc/logrotate.d/skyguard
ok "Cron ve logrotate yapılandırması kaldırıldı."

# ── 4. sshd_config'i yedekten geri yükle ──────────────────────────────────────
# enable-ssh-honeypot.sh, port taşımadan önce zaman damgalı yedek bırakır.
# En ESKİ yedek pristine orijinaldir; onu tercih ederiz.
OLDEST_BK=$(ls -1tr /etc/ssh/sshd_config.skyguard.*.bak 2>/dev/null | head -1 || true)
if [[ -n "$OLDEST_BK" ]]; then
    info "sshd_config yedekten geri yükleniyor: ${OLDEST_BK}"
    cp -a /etc/ssh/sshd_config "/etc/ssh/sshd_config.before-uninstall.$(date +%Y%m%d%H%M%S).bak"
    cp -a "$OLDEST_BK" /etc/ssh/sshd_config
    if sshd -t 2>/dev/null; then
        systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true
        ok "sshd eski haline döndü (mevcut oturumun düşmez)."
    else
        warn "Geri yüklenen sshd_config geçersiz! sshd yeniden başlatılmadı; elle kontrol et."
    fi
else
    info "sshd yedeği yok — SSH portu zaten değiştirilmemiş, dokunulmadı."
fi

# ── 5. Firewall temizliği ─────────────────────────────────────────────────────
if command -v iptables &>/dev/null; then
    if [[ -f "$IPTABLES_PREBACKUP" ]]; then
        info "iptables kurulum-öncesi yedekten geri yükleniyor..."
        iptables-restore < "$IPTABLES_PREBACKUP" && ok "iptables tamamen eski haline döndü." \
            || warn "iptables-restore başarısız; aşağıdaki tabloyu elle gözden geçir."
    else
        warn "Kurulum-öncesi iptables yedeği yok — en iyi çaba ile temizleniyor."
        # SKYGUARD zincirini kaldır.
        iptables -D INPUT -j SKYGUARD 2>/dev/null || true
        iptables -F SKYGUARD 2>/dev/null || true
        iptables -X SKYGUARD 2>/dev/null || true
        # SSH erişimini geri açmak için 22 DROP'u kaldır.
        while iptables -C INPUT -p tcp --dport 22 -j DROP 2>/dev/null; do
            iptables -D INPUT -p tcp --dport 22 -j DROP
        done
        # SkyGuard'ın açtığı bilinen honeypot/stealth port ACCEPT kurallarını kaldır.
        for p in 9911 21 3306 8080; do
            while iptables -C INPUT -p tcp --dport "$p" -j ACCEPT 2>/dev/null; do
                iptables -D INPUT -p tcp --dport "$p" -j ACCEPT
            done
        done
        warn "Kalan ban (-s IP -j DROP) kuralları otomatik silinmedi; aşağıdan gözden geçir."
    fi
    iptables-save > "$IPTABLES_RULES_FILE" 2>/dev/null || true
    command -v netfilter-persistent &>/dev/null && netfilter-persistent save >/dev/null 2>&1 || true
    echo
    info "Güncel INPUT zinciri (elle gözden geçir):"
    iptables -L INPUT -n --line-numbers || true
    echo
fi

# ── 6. Dosyalar ───────────────────────────────────────────────────────────────
rm -rf "${INSTALL_DIR}"
ok "Kurulum dizini silindi: ${INSTALL_DIR}"

if $PURGE || confirm "Yapılandırma + veritabanı + logları da SİL? (geri alınamaz)" "n"; then
    rm -rf "${CONFIG_DIR}" "${DATA_DIR}" "${LOG_DIR}"
    ok "Config, veritabanı ve loglar silindi."
else
    info "Korundu: ${CONFIG_DIR}, ${DATA_DIR}, ${LOG_DIR}"
fi

echo
ok "SkyGuard kaldırıldı."
warn "ÖNEMLİ: Çıkmadan önce ikinci bir terminalde SSH erişimini doğrula:"
echo "    ssh -p 22 kullanici@SUNUCU"
