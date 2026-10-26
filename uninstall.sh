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
#     sudo bash uninstall.sh [--yes] [--purge] [--restore-iptables]
#       --yes               do not prompt for confirmation
#       --purge             also delete config, database and logs
#       --restore-iptables  restore the full pre-install iptables snapshot
#                           (also drops rules added later by Docker/ufw!)
# =============================================================================
set -euo pipefail
IFS=$'\n\t'

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
info(){ echo -e "${CYAN}[INFO]${RESET}  $*"; }
ok(){   echo -e "${GREEN}[OK]${RESET}    $*"; }
warn(){ echo -e "${YELLOW}[WARN]${RESET}  $*"; }
die(){  echo -e "${RED}[ERROR]${RESET} $*" >&2; exit 1; }

ASSUME_YES=false; PURGE=false; RESTORE_IPTABLES=false
for arg in "$@"; do
    case "$arg" in
        --yes|-y)           ASSUME_YES=true ;;
        --purge)            PURGE=true ;;
        --restore-iptables) RESTORE_IPTABLES=true ;;
        *) die "Bilinmeyen seçenek: $arg" ;;
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
        systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || true
        ok "sshd eski haline döndü (mevcut oturumun düşmez)."
    else
        warn "Geri yüklenen sshd_config geçersiz! sshd yeniden başlatılmadı; elle kontrol et."
    fi
else
    info "sshd yedeği yok — SSH portu zaten değiştirilmemiş, dokunulmadı."
fi

# ── 5. Firewall temizliği ─────────────────────────────────────────────────────
# Yalnızca SkyGuard'ın eklediklerini geri alıyoruz. Kurulum-öncesi yedeği
# körlemesine geri yüklemek, o tarihten sonra Docker/ufw/firewalld'ın eklediği
# kuralları da silip diğer container'ların ağını bozabilir; bu yüzden sadece
# --restore-iptables ile istenirse yapılır.
FW_STATE="${CONFIG_DIR}/firewall.state"
FRONTEND="iptables"
[[ -f "$FW_STATE" ]] && FRONTEND=$(grep '^frontend=' "$FW_STATE" | tail -1 | cut -d= -f2 || true)
[[ -n "$FRONTEND" ]] || FRONTEND="iptables"

if $RESTORE_IPTABLES && [[ -f "$IPTABLES_PREBACKUP" ]]; then
    info "iptables kurulum-öncesi yedekten geri yükleniyor (--restore-iptables)..."
    iptables-restore < "$IPTABLES_PREBACKUP" && ok "iptables eski haline döndü." \
        || warn "iptables-restore başarısız; tabloyu elle gözden geçir."
else
    # SKYGUARD zinciri (tüm ban kuralları burada) — hem IPv4/IPv6 hem legacy/nft.
    for bin in iptables ip6tables iptables-legacy ip6tables-legacy iptables-nft ip6tables-nft; do
        command -v "$bin" &>/dev/null || continue
        while "$bin" -w 5 -D INPUT -j SKYGUARD 2>/dev/null; do :; done
        "$bin" -w 5 -F SKYGUARD 2>/dev/null || true
        "$bin" -w 5 -X SKYGUARD 2>/dev/null || true
    done
    ok "SKYGUARD zinciri ve ban kuralları kaldırıldı."

    # Port 22 engeli (varsa) — SSH erişimini geri aç.
    if command -v iptables &>/dev/null; then
        while iptables -C INPUT ! -i lo -p tcp --dport 22 -j DROP 2>/dev/null; do iptables -D INPUT ! -i lo -p tcp --dport 22 -j DROP; done
        while iptables -C INPUT -p tcp --dport 22 -j DROP 2>/dev/null; do iptables -D INPUT -p tcp --dport 22 -j DROP; done
    fi
    if grep -q '^block22=1' "$FW_STATE" 2>/dev/null; then
        case "$FRONTEND" in
            ufw)       ufw delete deny 22/tcp >/dev/null 2>&1 || true; ufw allow 22/tcp >/dev/null 2>&1 || true ;;
            firewalld) firewall-cmd --quiet --permanent --add-service=ssh 2>/dev/null || true ;;
        esac
    fi

    # Kurulumun açtığı portlar.
    if [[ -f "$FW_STATE" ]]; then
        for spec in $(grep '^port=' "$FW_STATE" | cut -d= -f2 | sort -u || true); do
            port="${spec%/*}"; proto="${spec#*/}"
            case "$FRONTEND" in
                ufw)       ufw delete allow "${port}/${proto}" >/dev/null 2>&1 || true ;;
                firewalld) firewall-cmd --quiet --permanent --remove-port="${port}/${proto}" 2>/dev/null || true ;;
                *)         while iptables -C INPUT -p "$proto" --dport "$port" -j ACCEPT 2>/dev/null; do
                               iptables -D INPUT -p "$proto" --dport "$port" -j ACCEPT
                           done ;;
            esac
        done
        [[ "$FRONTEND" == "firewalld" ]] && firewall-cmd --quiet --reload 2>/dev/null || true
        ok "Kurulumun açtığı portlar kapatıldı."
    else
        warn "firewall.state bulunamadı; açılan portları elle gözden geçir."
    fi
fi

# Kalıcı kural dosyasını güncelle (dağıtıma göre yol değişir).
if [[ "$FRONTEND" == "iptables" ]] && command -v iptables-save &>/dev/null; then
    if [[ -d /etc/iptables ]]; then
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
        command -v ip6tables-save &>/dev/null && ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true
    fi
    [[ -f /etc/sysconfig/iptables ]] && iptables-save > /etc/sysconfig/iptables 2>/dev/null || true
    [[ -f /etc/iptables/iptables.rules ]] && iptables-save > /etc/iptables/iptables.rules 2>/dev/null || true
    command -v netfilter-persistent &>/dev/null && netfilter-persistent save >/dev/null 2>&1 || true
fi
if command -v iptables &>/dev/null; then
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
