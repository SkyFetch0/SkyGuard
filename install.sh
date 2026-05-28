#!/usr/bin/env bash
# =============================================================================
#  SkyGuard — Production Installation Script
#  Supports: Ubuntu 20.04/22.04/24.04, Debian 11/12, CentOS 7/8/9, RHEL 8/9,
#            Rocky Linux 8/9, AlmaLinux 8/9, Fedora 38+
#
#  Usage:
#    sudo bash install.sh              # English (default)
#    sudo bash install.sh --lang tr    # Turkish
#    SKYGUARD_LANG=tr sudo bash install.sh
# =============================================================================
set -euo pipefail
IFS=$'\n\t'

# Interactive vs unattended apt behaviour:
#   - On a real terminal we leave debconf interactive so package prompts (e.g.
#     iptables-persistent's "Save current IPv4 rules?") are SHOWN and you can
#     answer them. Output is never redirected, so nothing hangs invisibly.
#   - When piped (e.g. curl ... | bash) there is no TTY to answer prompts, so we
#     fall back to noninteractive defaults to avoid a silent hang.
if [ -t 0 ]; then
    export DEBIAN_FRONTEND=readline
else
    export DEBIAN_FRONTEND=noninteractive
fi

# ── colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

# ── parse --lang flag (must happen before any i18n call) ─────────────────────
SKYGUARD_LANG="${SKYGUARD_LANG:-en}"
for arg in "$@"; do
    case "$arg" in
        --lang=*) SKYGUARD_LANG="${arg#--lang=}" ;;
        --lang)   shift; SKYGUARD_LANG="${1:-en}" ;;
    esac
done
# Normalise: accept "tr", "TR", "turkish", "türkçe"
case "${SKYGUARD_LANG,,}" in
    tr|tur|turkish|türkçe) SKYGUARD_LANG="tr" ;;
    *)                     SKYGUARD_LANG="en" ;;
esac

# =============================================================================
#  I18N — String tables
#  Usage: t KEY   →  prints the localised string
# =============================================================================

# ── English strings ───────────────────────────────────────────────────────────
declare -A I18N_EN=(
    # generic
    [must_run_as_root]="This script must be run as root (use sudo)."
    [lang_active]="Language: English"
    [lang_switch_hint]="Run with --lang tr for Turkish  |  --lang tr ile Türkçe"

    # sections
    [sec_detecting_os]="Detecting Operating System"
    [sec_config_wizard]="Configuration Wizard"
    [sec_summary]="Configuration Summary"
    [sec_proceed]="Proceed with installation?"
    [sec_phase1]="Phase 1: Installing System Packages"
    [sec_phase2]="Phase 2: Docker"
    [sec_phase3]="Phase 3: Directory Structure"
    [sec_phase4]="Phase 4: Generating Configuration"
    [sec_phase5]="Phase 5: Configuring iptables"
    [sec_phase6]="Phase 6: Generating docker-compose.yml"
    [sec_phase7]="Phase 7: Building and Starting SkyGuard"
    [sec_phase8]="Phase 8: Systemd Watchdog"
    [sec_phase9]="Phase 9: GeoIP Setup"
    [sec_phase10]="Phase 10: Log Rotation & Maintenance Cron"
    [sec_done]="Installation Complete"

    # wizard prompts
    [wizard_intro]="Answer the following questions to configure SkyGuard."
    [wizard_enter_hint]="Press ENTER to accept the default value shown in brackets."
    [q_whitelist_own_ip]="Add your current public IP (%s) to the whitelist?"
    [q_extra_ips]="Add additional whitelist IPs (e.g. office/home IPs)?"
    [q_extra_ips_enter]="Enter IPs separated by commas"
    [q_blacklist_countries]="Enable country blacklisting?"
    [q_blacklist_codes]="Country codes (space-separated)"
    [q_country_hint]="Common codes: CN RU KP IR BY VN ID"
    [sec_stealth_ssh]="Stealth SSH"
    [stealth_desc1]="Stealth SSH hides your real SSH behind a random port."
    [stealth_desc2]="Nmap sees the port as 'filtered'. Only real SSH clients are forwarded."
    [q_enable_stealth]="Enable Stealth SSH?"
    [q_stealth_port]="Public port for stealth SSH (clients connect here)"
    [q_real_ssh_port]="Actual SSH daemon port (currently listening on)"
    [stealth_note]="After setup, SSH access: ssh -p %s user@%s"
    [sec_honeypots]="Honeypot Services"
    [honeypot_desc]="Honeypots attract attackers, log their activity, and auto-ban them."
    [q_hp_ssh]="Enable Fake SSH honeypot (port 22)?"
    [q_hp_ftp]="Enable Fake FTP honeypot (port 21)?"
    [q_hp_mysql]="Enable Fake MySQL honeypot (port 3306)?"
    [q_hp_http]="Enable Fake HTTP honeypot (port 80)?"
    [q_hp_http_alt]="Enable Fake HTTP-Alt honeypot (port 8080)?"
    [sec_passthrough]="Passthrough Services"
    [q_passthrough_https]="Forward HTTPS (port 443) to a backend service?"
    [q_passthrough_target]="Backend target address"
    [sec_geoip]="GeoIP"
    [geoip_desc]="GeoIP requires a free MaxMind GeoLite2 database (~60MB)."
    [geoip_signup]="Sign up at https://www.maxmind.com/en/geolite2/signup"
    [q_enable_geoip]="Enable GeoIP country detection?"
    [sec_autoban]="Auto-Ban"
    [q_enable_autoban]="Enable automatic IP banning based on threat score?"
    [q_ban_method]="Firewall method"
    [q_ban_threshold]="Threat score threshold to trigger ban"
    [q_ban_duration]="Ban duration (e.g. 1h, 24h, 7d)"
    [sec_dashboard]="Dashboard"
    [q_enable_dashboard]="Enable web dashboard (localhost:%s)?"
    [q_dash_user]="Dashboard username"
    [q_dash_pass]="Dashboard password"
    [q_dash_pass_confirm]="Confirm password"
    [dash_pass_mismatch]="Passwords do not match. Try again."
    [dash_pass_generated]="Empty password not allowed. Generated: %s"
    [q_log_retention]="Log retention in days"

    # summary
    [sum_install_dir]="Install directory"
    [sum_config_file]="Config file"
    [sum_data_dir]="Data directory"
    [sum_stealth]="Stealth SSH"
    [sum_stealth_val]="port %s → %s:%s"
    [sum_stealth_disabled]="disabled"
    [sum_honeypots]="Honeypots enabled"
    [sum_autoban]="Auto-ban"
    [sum_autoban_val]="enabled (%s, threshold=%s)"
    [sum_autoban_disabled]="disabled"
    [sum_dashboard]="Dashboard"
    [sum_dash_val]="enabled (127.0.0.1:%s)"
    [sum_dash_disabled]="disabled"
    [sum_geoip]="GeoIP"
    [sum_geoip_enabled]="enabled"
    [sum_geoip_disabled]="disabled (can enable later)"

    # phases
    [pkg_updating]="Updating package cache..."
    [pkg_ok]="System packages installed."
    [docker_found]="Docker already installed (version: %s)"
    [docker_installing]="Docker not found. Installing..."
    [docker_ok]="Docker installed and started."
    [compose_ok]="Docker Compose available."
    [dirs_ok]="Directories created."
    [config_written]="Configuration written to %s"
    [iptables_open]="Opened port %s/%s"
    [iptables_block22]="Port 22 is now BLOCKED (use port %s to connect)."
    [iptables_dash_safe]="Dashboard port %s is bound to 127.0.0.1 only (safe)."
    [iptables_saved]="iptables rules saved to %s"
    [ip6_applied]="Basic ip6tables rules applied."
    [compose_generated]="docker-compose.yml generated at %s"
    [docker_building]="Building Docker image (this may take 2-5 minutes on first run)..."
    [docker_build_ok]="Docker image built successfully."
    [docker_build_fail]="Docker build failed. Check /tmp/skyguard-build.log for details."
    [docker_starting]="Starting SkyGuard container..."
    [docker_waiting]="Waiting for SkyGuard to become healthy..."
    [docker_running]="SkyGuard container is running."
    [docker_fail]="Container failed to start. Run: docker logs skyguard"
    [systemd_ok]="Systemd service installed and enabled (skyguard.service)."
    [logrotate_ok]="Log rotation and backup cron configured."
    [aborted]="Aborted."

    # geoip
    [geoip_place_file]="GeoIP enabled. Download GeoLite2-City.mmdb from MaxMind and place it at:"
    [geoip_quick_dl]="Quick download (requires free MaxMind account):"
    [geoip_cron_note]="Monthly auto-update cron (replace YOUR_LICENSE_KEY):"

    # final
    [final_title]="SkyGuard Installed Successfully!"
    [final_service_mgmt]="Service management:"
    [final_dashboard]="Dashboard (via SSH tunnel):"
    [final_dash_open]="→ open http://localhost:%s  (%s / <your password>)"
    [final_ssh_access]="SSH access (NEW port):"
    [final_ssh_warn]="Save this! Port 22 may now be blocked."
    [final_config]="Configuration:"
    [final_data]="Data & logs:"
    [final_iptables]="iptables rules:"
    [final_useful]="Useful commands:"
    [final_geoip_warn]="GeoIP: Download GeoLite2-City.mmdb to %s/"
    [final_listeners]="Active listeners:"
    [final_done]="Done. SkyGuard is protecting your server."

    # errors
    [err_no_pkg_mgr]="No supported package manager found (apt/dnf/yum)."
    [err_unknown_os]="Unrecognised OS: '%s'. Attempting generic setup (apt/yum auto-detect)."
    [err_no_docker_auto]="Cannot auto-install Docker on this system. Please install manually: https://docs.docker.com/engine/install/"
)

# ── Turkish strings ───────────────────────────────────────────────────────────
declare -A I18N_TR=(
    # generic
    [must_run_as_root]="Bu script root olarak çalıştırılmalıdır (sudo kullanın)."
    [lang_active]="Dil: Türkçe"
    [lang_switch_hint]="İngilizce için --lang en ile çalıştırın  |  English: --lang en"

    # sections
    [sec_detecting_os]="İşletim Sistemi Tespit Ediliyor"
    [sec_config_wizard]="Yapılandırma Sihirbazı"
    [sec_summary]="Yapılandırma Özeti"
    [sec_proceed]="Kuruluma devam edilsin mi?"
    [sec_phase1]="Aşama 1: Sistem Paketleri Kuruluyor"
    [sec_phase2]="Aşama 2: Docker"
    [sec_phase3]="Aşama 3: Dizin Yapısı"
    [sec_phase4]="Aşama 4: Yapılandırma Dosyası Oluşturuluyor"
    [sec_phase5]="Aşama 5: iptables Yapılandırması"
    [sec_phase6]="Aşama 6: docker-compose.yml Oluşturuluyor"
    [sec_phase7]="Aşama 7: SkyGuard Derleniyor ve Başlatılıyor"
    [sec_phase8]="Aşama 8: Systemd İzleyici"
    [sec_phase9]="Aşama 9: GeoIP Kurulumu"
    [sec_phase10]="Aşama 10: Log Rotasyonu ve Bakım Cron"
    [sec_done]="Kurulum Tamamlandı"

    # wizard prompts
    [wizard_intro]="SkyGuard'ı yapılandırmak için aşağıdaki soruları yanıtlayın."
    [wizard_enter_hint]="Varsayılan değeri kabul etmek için ENTER'a basın."
    [q_whitelist_own_ip]="Mevcut genel IP'niz (%s) whitelist'e eklensin mi?"
    [q_extra_ips]="Ekstra whitelist IP'leri eklemek ister misiniz? (ev/ofis IP'leri)"
    [q_extra_ips_enter]="IP'leri virgülle ayırarak girin"
    [q_blacklist_countries]="Ülke kara listesi etkinleştirilsin mi?"
    [q_blacklist_codes]="Ülke kodları (boşlukla ayırın)"
    [q_country_hint]="Yaygın kodlar: CN RU KP IR BY VN ID"
    [sec_stealth_ssh]="Stealth SSH"
    [stealth_desc1]="Stealth SSH, gerçek SSH'ınızı rastgele bir port arkasına gizler."
    [stealth_desc2]="Nmap portu 'filtered' olarak görür. Yalnızca gerçek SSH istemcileri yönlendirilir."
    [q_enable_stealth]="Stealth SSH etkinleştirilsin mi?"
    [q_stealth_port]="Stealth SSH için genel port (istemciler buraya bağlanır)"
    [q_real_ssh_port]="Gerçek SSH daemon portu (şu an dinleniyor)"
    [stealth_note]="Kurulumdan sonra SSH erişimi: ssh -p %s kullanici@%s"
    [sec_honeypots]="Honeypot Servisleri"
    [honeypot_desc]="Honeypot'lar saldırganları çeker, aktivitelerini loglar ve otomatik olarak banlar."
    [q_hp_ssh]="Sahte SSH honeypot (port 22) etkinleştirilsin mi?"
    [q_hp_ftp]="Sahte FTP honeypot (port 21) etkinleştirilsin mi?"
    [q_hp_mysql]="Sahte MySQL honeypot (port 3306) etkinleştirilsin mi?"
    [q_hp_http]="Sahte HTTP honeypot (port 80) etkinleştirilsin mi?"
    [q_hp_http_alt]="Sahte HTTP-Alt honeypot (port 8080) etkinleştirilsin mi?"
    [sec_passthrough]="Passthrough Servisleri"
    [q_passthrough_https]="HTTPS (port 443) bir backend servise yönlendirilsin mi?"
    [q_passthrough_target]="Backend hedef adresi"
    [sec_geoip]="GeoIP"
    [geoip_desc]="GeoIP, ücretsiz MaxMind GeoLite2 veritabanı gerektirir (~60MB)."
    [geoip_signup]="Kayıt: https://www.maxmind.com/en/geolite2/signup"
    [q_enable_geoip]="GeoIP ülke tespiti etkinleştirilsin mi?"
    [sec_autoban]="Otomatik Ban"
    [q_enable_autoban]="Tehdit skoruna göre otomatik IP banlama etkinleştirilsin mi?"
    [q_ban_method]="Güvenlik duvarı yöntemi"
    [q_ban_threshold]="Banı tetikleyecek tehdit skoru eşiği"
    [q_ban_duration]="Ban süresi (örn. 1h, 24h, 7d)"
    [sec_dashboard]="Dashboard"
    [q_enable_dashboard]="Web dashboard etkinleştirilsin mi (localhost:%s)?"
    [q_dash_user]="Dashboard kullanıcı adı"
    [q_dash_pass]="Dashboard parolası"
    [q_dash_pass_confirm]="Parolayı doğrulayın"
    [dash_pass_mismatch]="Parolalar eşleşmiyor. Tekrar deneyin."
    [dash_pass_generated]="Boş parola kullanılamaz. Oluşturulan: %s"
    [q_log_retention]="Log saklama süresi (gün)"

    # summary
    [sum_install_dir]="Kurulum dizini"
    [sum_config_file]="Yapılandırma dosyası"
    [sum_data_dir]="Veri dizini"
    [sum_stealth]="Stealth SSH"
    [sum_stealth_val]="port %s → %s:%s"
    [sum_stealth_disabled]="devre dışı"
    [sum_honeypots]="Aktif honeypot'lar"
    [sum_autoban]="Otomatik ban"
    [sum_autoban_val]="etkin (%s, eşik=%s)"
    [sum_autoban_disabled]="devre dışı"
    [sum_dashboard]="Dashboard"
    [sum_dash_val]="etkin (127.0.0.1:%s)"
    [sum_dash_disabled]="devre dışı"
    [sum_geoip]="GeoIP"
    [sum_geoip_enabled]="etkin"
    [sum_geoip_disabled]="devre dışı (sonradan etkinleştirilebilir)"

    # phases
    [pkg_updating]="Paket önbelleği güncelleniyor..."
    [pkg_ok]="Sistem paketleri kuruldu."
    [docker_found]="Docker zaten kurulu (sürüm: %s)"
    [docker_installing]="Docker bulunamadı. Kuruluyor..."
    [docker_ok]="Docker kuruldu ve başlatıldı."
    [compose_ok]="Docker Compose kullanılabilir."
    [dirs_ok]="Dizinler oluşturuldu."
    [config_written]="Yapılandırma %s konumuna yazıldı"
    [iptables_open]="Port açıldı: %s/%s"
    [iptables_block22]="Port 22 artık KAPALI (bağlanmak için port %s kullanın)."
    [iptables_dash_safe]="Dashboard portu %s yalnızca 127.0.0.1'e bağlı (güvenli)."
    [iptables_saved]="iptables kuralları %s konumuna kaydedildi"
    [ip6_applied]="Temel ip6tables kuralları uygulandı."
    [compose_generated]="docker-compose.yml %s konumuna oluşturuldu"
    [docker_building]="Docker image derleniyor (ilk çalıştırmada 2-5 dakika sürebilir)..."
    [docker_build_ok]="Docker image başarıyla derlendi."
    [docker_build_fail]="Docker derlemesi başarısız. Ayrıntılar: /tmp/skyguard-build.log"
    [docker_starting]="SkyGuard container'ı başlatılıyor..."
    [docker_waiting]="SkyGuard'ın sağlıklı duruma geçmesi bekleniyor..."
    [docker_running]="SkyGuard container'ı çalışıyor."
    [docker_fail]="Container başlatılamadı. Çalıştırın: docker logs skyguard"
    [systemd_ok]="Systemd servisi kuruldu ve etkinleştirildi (skyguard.service)."
    [logrotate_ok]="Log rotasyonu ve yedek cron yapılandırıldı."
    [aborted]="İptal edildi."

    # geoip
    [geoip_place_file]="GeoIP etkin. GeoLite2-City.mmdb'yi MaxMind'dan indirin ve şu konuma yerleştirin:"
    [geoip_quick_dl]="Hızlı indirme (ücretsiz MaxMind hesabı gerekli):"
    [geoip_cron_note]="Aylık otomatik güncelleme cron'u (YOUR_LICENSE_KEY ile değiştirin):"

    # final
    [final_title]="SkyGuard Başarıyla Kuruldu!"
    [final_service_mgmt]="Servis yönetimi:"
    [final_dashboard]="Dashboard (SSH tüneli üzerinden):"
    [final_dash_open]="→ aç http://localhost:%s  (%s / <parolanız>)"
    [final_ssh_access]="SSH erişimi (YENİ port):"
    [final_ssh_warn]="Bunu kaydedin! Port 22 artık kapalı olabilir."
    [final_config]="Yapılandırma:"
    [final_data]="Veri & loglar:"
    [final_iptables]="iptables kuralları:"
    [final_useful]="Yararlı komutlar:"
    [final_geoip_warn]="GeoIP: GeoLite2-City.mmdb'yi %s/ konumuna indirin"
    [final_listeners]="Aktif dinleyiciler:"
    [final_done]="Tamamlandı. SkyGuard sunucunuzu koruyor."

    # errors
    [err_no_pkg_mgr]="Desteklenen paket yöneticisi bulunamadı (apt/dnf/yum)."
    [err_unknown_os]="Tanımlanamayan OS: '%s'. Genel kurulum deneniyor (apt/yum otomatik tespit)."
    [err_no_docker_auto]="Bu sistemde Docker otomatik kurulamaz. Lütfen manuel kurun: https://docs.docker.com/engine/install/"
)

# ── Translation function ───────────────────────────────────────────────────────
t() {
    local key="$1"; shift
    local str=""
    if [[ "$SKYGUARD_LANG" == "tr" ]]; then
        str="${I18N_TR[$key]:-${I18N_EN[$key]:-$key}}"
    else
        str="${I18N_EN[$key]:-$key}"
    fi
    # If extra args provided, use printf formatting
    if [[ $# -gt 0 ]]; then
        # shellcheck disable=SC2059
        printf "$str" "$@"
    else
        echo "$str"
    fi
}

# ── helpers ───────────────────────────────────────────────────────────────────
info()    { echo -e "${CYAN}[INFO]${RESET}  $*"; }
ok()      { echo -e "${GREEN}[OK]${RESET}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
die()     { echo -e "${RED}[ERROR]${RESET} $*" >&2; exit 1; }
section() { echo -e "\n${BOLD}━━━  $*  ━━━${RESET}"; }

confirm() {
    local prompt="$1" default="${2:-y}"
    local yn
    if [[ "$default" == "y" ]]; then
        read -rp "$(echo -e "${YELLOW}[?]${RESET}    ${prompt} [Y/n]: ")" yn
        [[ -z "$yn" || "$yn" =~ ^[Yy]$ ]]
    else
        read -rp "$(echo -e "${YELLOW}[?]${RESET}    ${prompt} [y/N]: ")" yn
        [[ "$yn" =~ ^[Yy]$ ]]
    fi
}

prompt() {
    local msg="$1" default="$2"
    local val
    read -rp "$(echo -e "${YELLOW}[?]${RESET}    ${msg} [${default}]: ")" val
    echo "${val:-$default}"
}

prompt_secret() {
    local msg="$1"
    local val
    read -rsp "$(echo -e "${YELLOW}[?]${RESET}    ${msg}: ")" val
    echo
    echo "$val"
}

# ── root check ────────────────────────────────────────────────────────────────
[[ $EUID -eq 0 ]] || die "$(t must_run_as_root)"

# ── banner ────────────────────────────────────────────────────────────────────
clear
cat <<'BANNER'
  _____ _          ____                     _
 / ____| |        / ___|_   _  __ _ _ __ __| |
 \___ \| | ___  | |  _| | | |/ _` | '__/ _` |
  ___) | |/ / _ \| |_| | |_| | (_| | | | (_| |
 |____/|_|\_\___/ \____|\_,_|\__,_|_|  \__,_|

   Smart Linux Security Layer & Honeypot System
   Production Installation Script v1.0
BANNER
echo
info "$(t lang_active)"
info "$(t lang_switch_hint)"
echo

# ── detect OS ─────────────────────────────────────────────────────────────────
section "$(t sec_detecting_os)"

OS_ID="" OS_VERSION="" PKG_MGR="" PKG_INSTALL="" PKG_UPDATE=""
IPTABLES_RULES_FILE="" IPTABLES_SERVICE=""

if [[ -f /etc/os-release ]]; then
    # shellcheck source=/dev/null
    source /etc/os-release
    OS_ID="${ID:-unknown}"
    OS_VERSION="${VERSION_ID:-0}"
fi

case "$OS_ID" in
    ubuntu|debian|linuxmint|pop)
        PKG_MGR="apt"; PKG_UPDATE="apt-get update"; PKG_INSTALL="apt-get install -y"
        IPTABLES_RULES_FILE="/etc/iptables/rules.v4"; IPTABLES_SERVICE="netfilter-persistent"
        ;;
    centos|rhel|rocky|almalinux|ol)
        PKG_MGR="yum"; PKG_UPDATE="yum makecache"; PKG_INSTALL="yum install -y"
        IPTABLES_RULES_FILE="/etc/sysconfig/iptables"; IPTABLES_SERVICE="iptables"
        command -v dnf &>/dev/null && { PKG_MGR="dnf"; PKG_UPDATE="dnf makecache"; PKG_INSTALL="dnf install -y"; }
        ;;
    fedora)
        PKG_MGR="dnf"; PKG_UPDATE="dnf makecache"; PKG_INSTALL="dnf install -y"
        IPTABLES_RULES_FILE="/etc/sysconfig/iptables"; IPTABLES_SERVICE="iptables"
        ;;
    arch|manjaro)
        PKG_MGR="pacman"; PKG_UPDATE="pacman -Sy --noconfirm"; PKG_INSTALL="pacman -S --noconfirm --needed"
        IPTABLES_RULES_FILE="/etc/iptables/iptables.rules"; IPTABLES_SERVICE="iptables"
        ;;
    *)
        warn "$(t err_unknown_os "$OS_ID")"
        if   command -v apt-get &>/dev/null; then PKG_MGR="apt";   PKG_UPDATE="apt-get update";  PKG_INSTALL="apt-get install -y"; IPTABLES_RULES_FILE="/etc/iptables/rules.v4";    IPTABLES_SERVICE="netfilter-persistent"
        elif command -v dnf     &>/dev/null; then PKG_MGR="dnf";   PKG_UPDATE="dnf makecache";    PKG_INSTALL="dnf install -y";       IPTABLES_RULES_FILE="/etc/sysconfig/iptables";  IPTABLES_SERVICE="iptables"
        elif command -v yum     &>/dev/null; then PKG_MGR="yum";   PKG_UPDATE="yum makecache";    PKG_INSTALL="yum install -y";       IPTABLES_RULES_FILE="/etc/sysconfig/iptables";  IPTABLES_SERVICE="iptables"
        else die "$(t err_no_pkg_mgr)"; fi
        ;;
esac

ARCH=$(uname -m)
HOSTNAME_FQDN=$(hostname -f 2>/dev/null || hostname)
PUBLIC_IP=$(curl -fsSL --max-time 5 https://api.ipify.org 2>/dev/null || echo "unknown")

info "OS       : ${OS_ID} ${OS_VERSION}"
info "Arch     : ${ARCH}"
info "Hostname : ${HOSTNAME_FQDN}"
info "Public IP: ${PUBLIC_IP}"
info "Pkg mgr  : ${PKG_MGR}"

# ── paths ─────────────────────────────────────────────────────────────────────
INSTALL_DIR="${SKYGUARD_DIR:-/opt/skyguard}"
CONFIG_DIR="/etc/skyguard"
DATA_DIR="/var/lib/skyguard"
LOG_DIR="/var/log/skyguard"
CONFIG_FILE="${CONFIG_DIR}/skyguard.yaml"

# ═════════════════════════════════════════════════════════════════════════════
#  INTERACTIVE WIZARD
# ═════════════════════════════════════════════════════════════════════════════
section "$(t sec_config_wizard)"
echo
warn "$(t wizard_intro)"
warn "$(t wizard_enter_hint)"
echo

# -- whitelist own IP --
OWN_IP=""
if [[ "$PUBLIC_IP" != "unknown" ]]; then
    confirm "$(t q_whitelist_own_ip "$PUBLIC_IP")" && OWN_IP="$PUBLIC_IP"
fi

EXTRA_WHITELIST_IPS=""
if confirm "$(t q_extra_ips)" "n"; then
    read -rp "$(echo -e "${YELLOW}[?]${RESET}    $(t q_extra_ips_enter): ")" EXTRA_WHITELIST_IPS
fi

# -- blacklist countries --
echo
info "$(t q_country_hint)"
BLACKLIST_COUNTRIES=""
if confirm "$(t q_blacklist_countries)" "n"; then
    BLACKLIST_COUNTRIES=$(prompt "$(t q_blacklist_codes)" "CN RU KP")
fi

# -- stealth SSH --
echo
section "$(t sec_stealth_ssh)"
info "$(t stealth_desc1)"
info "$(t stealth_desc2)"
ENABLE_STEALTH_SSH=false
STEALTH_SSH_PORT="9911"
REAL_SSH_HOST="127.0.0.1"
REAL_SSH_PORT="22"
if confirm "$(t q_enable_stealth)"; then
    ENABLE_STEALTH_SSH=true
    STEALTH_SSH_PORT=$(prompt "$(t q_stealth_port)" "9911")
    REAL_SSH_PORT=$(prompt "$(t q_real_ssh_port)" "22")
    info "$(t stealth_note "$STEALTH_SSH_PORT" "$PUBLIC_IP")"
fi

# -- honeypot services --
section "$(t sec_honeypots)"
info "$(t honeypot_desc)"
echo
HONEYPOT_SSH=false;     confirm "$(t q_hp_ssh)"      && HONEYPOT_SSH=true
HONEYPOT_FTP=false;     confirm "$(t q_hp_ftp)"      && HONEYPOT_FTP=true
HONEYPOT_MYSQL=false;   confirm "$(t q_hp_mysql)"    && HONEYPOT_MYSQL=true
HONEYPOT_HTTP=false;    confirm "$(t q_hp_http)"     && HONEYPOT_HTTP=true
HONEYPOT_HTTP_ALT=false;confirm "$(t q_hp_http_alt)" && HONEYPOT_HTTP_ALT=true

# -- passthrough --
section "$(t sec_passthrough)"
PASSTHROUGH_HTTPS=false
PASSTHROUGH_HTTPS_TARGET="127.0.0.1:8443"
if confirm "$(t q_passthrough_https)" "n"; then
    PASSTHROUGH_HTTPS=true
    PASSTHROUGH_HTTPS_TARGET=$(prompt "$(t q_passthrough_target)" "127.0.0.1:8443")
fi

# -- GeoIP --
section "$(t sec_geoip)"
GEOIP_ENABLED=false
info "$(t geoip_desc)"
info "$(t geoip_signup)"
confirm "$(t q_enable_geoip)" "n" && GEOIP_ENABLED=true

# -- auto-ban --
section "$(t sec_autoban)"
AUTO_BAN_ENABLED=false
AUTO_BAN_METHOD="iptables"
AUTO_BAN_THRESHOLD=50
AUTO_BAN_DURATION="24h"
if confirm "$(t q_enable_autoban)"; then
    AUTO_BAN_ENABLED=true
    if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
        AUTO_BAN_METHOD=$(prompt "$(t q_ban_method) (ufw/iptables)" "ufw")
    else
        AUTO_BAN_METHOD=$(prompt "$(t q_ban_method) (iptables/ufw)" "iptables")
    fi
    AUTO_BAN_THRESHOLD=$(prompt "$(t q_ban_threshold)" "50")
    AUTO_BAN_DURATION=$(prompt "$(t q_ban_duration)" "24h")
fi

# -- dashboard --
section "$(t sec_dashboard)"
DASHBOARD_ENABLED=false
DASHBOARD_PORT="9090"
DASHBOARD_USER="admin"
DASHBOARD_PASS=""
if confirm "$(t q_enable_dashboard "$DASHBOARD_PORT")"; then
    DASHBOARD_ENABLED=true
    DASHBOARD_USER=$(prompt "$(t q_dash_user)" "admin")
    while true; do
        DASHBOARD_PASS=$(prompt_secret "$(t q_dash_pass)")
        CONFIRM_PASS=$(prompt_secret "$(t q_dash_pass_confirm)")
        [[ "$DASHBOARD_PASS" == "$CONFIRM_PASS" ]] && break
        warn "$(t dash_pass_mismatch)"
    done
    if [[ -z "$DASHBOARD_PASS" ]]; then
        DASHBOARD_PASS=$(openssl rand -hex 16)
        warn "$(t dash_pass_generated "$DASHBOARD_PASS")"
    fi
fi

LOG_RETENTION=$(prompt "$(t q_log_retention)" "90")
RATE_LIMIT_PER_MINUTE=20
RATE_LIMIT_PER_HOUR=200

# ── summary ───────────────────────────────────────────────────────────────────
section "$(t sec_summary)"
echo
echo -e "  $(t sum_install_dir) : ${BOLD}${INSTALL_DIR}${RESET}"
echo -e "  $(t sum_config_file) : ${BOLD}${CONFIG_FILE}${RESET}"
echo -e "  $(t sum_data_dir)    : ${BOLD}${DATA_DIR}${RESET}"

STEALTH_VAL=$( $ENABLE_STEALTH_SSH && t sum_stealth_val "$STEALTH_SSH_PORT" "$REAL_SSH_HOST" "$REAL_SSH_PORT" || t sum_stealth_disabled)
echo -e "  $(t sum_stealth)     : ${BOLD}${STEALTH_VAL}${RESET}"

echo -e "  $(t sum_honeypots)   :"
hp_icon() { $1 && echo -e "    ${GREEN}✔${RESET} $2" || echo -e "    ${RED}✘${RESET} $2"; }
hp_icon $HONEYPOT_SSH     "Fake SSH   (port 22)"
hp_icon $HONEYPOT_FTP     "Fake FTP   (port 21)"
hp_icon $HONEYPOT_MYSQL   "Fake MySQL (port 3306)"
hp_icon $HONEYPOT_HTTP    "Fake HTTP  (port 80)"
hp_icon $HONEYPOT_HTTP_ALT "Fake HTTP  (port 8080)"

BAN_VAL=$( $AUTO_BAN_ENABLED && t sum_autoban_val "$AUTO_BAN_METHOD" "$AUTO_BAN_THRESHOLD" || t sum_autoban_disabled)
echo -e "  $(t sum_autoban)     : ${BOLD}${BAN_VAL}${RESET}"

DASH_VAL=$( $DASHBOARD_ENABLED && t sum_dash_val "$DASHBOARD_PORT" || t sum_dash_disabled)
echo -e "  $(t sum_dashboard)   : ${BOLD}${DASH_VAL}${RESET}"

GEO_VAL=$( $GEOIP_ENABLED && t sum_geoip_enabled || t sum_geoip_disabled)
echo -e "  $(t sum_geoip)       : ${BOLD}${GEO_VAL}${RESET}"
echo

# Warn about the port-22 bind conflict: if stealth forwards to the real sshd on
# :22 AND a honeypot is told to bind :22, the honeypot listener cannot start
# while the real sshd still holds 0.0.0.0:22 — SkyGuard would crash-loop.
if $ENABLE_STEALTH_SSH && $HONEYPOT_SSH; then
    echo
    if [[ "$SKYGUARD_LANG" == "tr" ]]; then
        warn "DİKKAT: Stealth SSH + port 22 honeypot birlikte seçili."
        warn "Gerçek sshd 0.0.0.0:22'yi tutuyorsa honeypot 22'yi bağlayamaz; SkyGuard başlamaz."
        warn "Çözüm: /etc/ssh/sshd_config içine 'ListenAddress 127.0.0.1' ekleyip 'systemctl restart ssh'."
        warn "Önce 'ssh -p ${STEALTH_SSH_PORT}' ile bağlanabildiğinizi DOĞRULAYIN, yoksa kilitlenirsiniz."
    else
        warn "WARNING: Both Stealth SSH and the port-22 honeypot are enabled."
        warn "If the real sshd holds 0.0.0.0:22, the honeypot cannot bind :22 and SkyGuard won't start."
        warn "Fix: add 'ListenAddress 127.0.0.1' to /etc/ssh/sshd_config, then 'systemctl restart ssh'."
        warn "Verify 'ssh -p ${STEALTH_SSH_PORT}' works BEFORE relying on it, or you may lock yourself out."
    fi
    echo
fi

confirm "$(t sec_proceed)" || { info "$(t aborted)"; exit 0; }

# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 1 — System Packages
# ═════════════════════════════════════════════════════════════════════════════
section "$(t sec_phase1)"
info "$(t pkg_updating)"
# Output is shown (not redirected) so you can watch progress and answer any
# prompts; a failure aborts the script instead of being silently swallowed.
eval "$PKG_UPDATE" || die "package cache update failed — check the output above"

case "$PKG_MGR" in
    apt)     eval "$PKG_INSTALL curl wget ca-certificates gnupg lsb-release openssl iptables iptables-persistent netfilter-persistent" || die "package installation failed" ;;
    yum|dnf) eval "$PKG_INSTALL curl wget ca-certificates openssl iptables iptables-services" || die "package installation failed" ;;
    pacman)  eval "$PKG_INSTALL curl wget ca-certificates openssl iptables" || die "package installation failed" ;;
esac
ok "$(t pkg_ok)"

# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 2 — Docker
# ═════════════════════════════════════════════════════════════════════════════
section "$(t sec_phase2)"

install_docker_apt() {
    apt-get remove -y docker docker-engine docker.io containerd runc 2>/dev/null || true
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL "https://download.docker.com/linux/${OS_ID}/gpg" | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/${OS_ID} $(. /etc/os-release && echo "${VERSION_CODENAME}") stable" \
        | tee /etc/apt/sources.list.d/docker.list > /dev/null
    apt-get update
    apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
}
install_docker_rhel() {
    eval "$PKG_INSTALL yum-utils" || true
    if command -v dnf &>/dev/null; then
        dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
        dnf install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    else
        yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
        yum install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    fi
}
install_docker_arch() { pacman -S --noconfirm --needed docker docker-compose; }

if command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
    DOCKER_VER=$(docker version --format '{{.Server.Version}}' 2>/dev/null || echo "unknown")
    ok "$(t docker_found "$DOCKER_VER")"
else
    info "$(t docker_installing)"
    case "$PKG_MGR" in
        apt)     install_docker_apt  ;;
        yum|dnf) install_docker_rhel ;;
        pacman)  install_docker_arch ;;
        *) die "$(t err_no_docker_auto)" ;;
    esac
    systemctl enable --now docker
    ok "$(t docker_ok)"
fi

if ! docker compose version &>/dev/null 2>&1; then
    if ! command -v docker-compose &>/dev/null; then
        COMPOSE_VER="v2.27.1"
        curl -fsSL "https://github.com/docker/compose/releases/download/${COMPOSE_VER}/docker-compose-$(uname -s)-$(uname -m)" \
            -o /usr/local/bin/docker-compose
        chmod +x /usr/local/bin/docker-compose
    fi
fi
ok "$(t compose_ok)"

# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 3 — Directory Structure
# ═════════════════════════════════════════════════════════════════════════════
section "$(t sec_phase3)"
mkdir -p "${INSTALL_DIR}" "${CONFIG_DIR}" "${DATA_DIR}" "${LOG_DIR}"
chmod 750 "${CONFIG_DIR}" "${DATA_DIR}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# install.sh lives at the project root; fall back to the parent directory in
# case it was relocated into a scripts/ subfolder.
SRC_DIR=""
if   [[ -f "${SCRIPT_DIR}/docker-compose.yml" ]]; then SRC_DIR="${SCRIPT_DIR}"
elif [[ -f "$(dirname "${SCRIPT_DIR}")/docker-compose.yml" ]]; then SRC_DIR="$(dirname "${SCRIPT_DIR}")"; fi

if [[ -n "$SRC_DIR" && "$SRC_DIR" != "$INSTALL_DIR" ]]; then
    cp -r "${SRC_DIR}/"* "${INSTALL_DIR}/" 2>/dev/null || true
elif [[ -z "$SRC_DIR" ]]; then
    warn "Could not find docker-compose.yml. Ensure project files are in ${INSTALL_DIR}"
fi
ok "$(t dirs_ok)"

# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 4 — Generate Configuration
# ═════════════════════════════════════════════════════════════════════════════
section "$(t sec_phase4)"

_whitelist_yaml() {
    echo "  ips:"
    echo "    - \"127.0.0.1\""; echo "    - \"::1\""
    [[ -n "$OWN_IP" ]] && echo "    - \"${OWN_IP}\"  # your public IP"
    if [[ -n "$EXTRA_WHITELIST_IPS" ]]; then
        IFS=',' read -ra EX <<< "$EXTRA_WHITELIST_IPS"
        for ip in "${EX[@]}"; do ip_c=$(echo "$ip"|tr -d ' '); [[ -n "$ip_c" ]] && echo "    - \"${ip_c}\""; done
    fi
    echo "  countries: []"
}

_blacklist_yaml() {
    echo "  ips: []"
    if [[ -n "$BLACKLIST_COUNTRIES" ]]; then
        echo "  countries:"
        read -ra CCS <<< "$BLACKLIST_COUNTRIES"
        for cc in "${CCS[@]}"; do echo "    - \"${cc}\""; done
    else echo "  countries: []"; fi
}

_honeypot_yaml() {
    $HONEYPOT_SSH     && printf "  - name: \"fake-ssh\"\n    enabled: true\n    port: 22\n    type: \"ssh\"\n    banner: \"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\"\n    max_auth_attempts: 3\n    fake_shell: false\n\n"
    $HONEYPOT_FTP     && printf "  - name: \"fake-ftp\"\n    enabled: true\n    port: 21\n    type: \"ftp\"\n    banner: \"ProFTPD 1.3.5e Server (Debian) ready.\"\n\n"
    $HONEYPOT_MYSQL   && printf "  - name: \"fake-mysql\"\n    enabled: true\n    port: 3306\n    type: \"mysql\"\n    banner: \"5.7.42-0ubuntu0.18.04.1\"\n\n"
    $HONEYPOT_HTTP    && printf "  - name: \"fake-http\"\n    enabled: true\n    port: 80\n    type: \"http\"\n    server_header: \"Apache/2.4.41 (Ubuntu)\"\n\n"
    $HONEYPOT_HTTP_ALT && printf "  - name: \"fake-http-alt\"\n    enabled: true\n    port: 8080\n    type: \"http\"\n    server_header: \"nginx/1.18.0\"\n\n"
    return 0
}

_stealth_yaml() {
    $ENABLE_STEALTH_SSH && printf "  - name: \"ssh\"\n    enabled: true\n    listen_port: %s\n    real_target: \"%s:%s\"\n    protocol_signature: \"SSH-2.0-\"\n    timeout: \"5s\"\n    allowed_countries: []\n\n" "$STEALTH_SSH_PORT" "$REAL_SSH_HOST" "$REAL_SSH_PORT"
    return 0
}

_passthrough_yaml() {
    $PASSTHROUGH_HTTPS && printf "  - name: \"web\"\n    listen_port: 443\n    real_target: \"%s\"\n\n" "$PASSTHROUGH_HTTPS_TARGET"
    return 0
}

cat > "${CONFIG_FILE}" <<YAML
# SkyGuard Configuration
# Generated by install.sh on $(date -u '+%Y-%m-%d %H:%M:%S UTC')
# Host: ${HOSTNAME_FQDN}  |  Language: ${SKYGUARD_LANG}

general:
  log_level: "info"
  # In-container path: the host's ${DATA_DIR} is bind-mounted to /data (see
  # docker-compose.yml), so all runtime paths below must reference /data.
  data_dir: "/data"

stealth_services:
$(_stealth_yaml)
honeypot_services:
$(_honeypot_yaml)
passthrough_services:
$(_passthrough_yaml)
analysis:
  geoip:
    enabled: ${GEOIP_ENABLED}
    db_path: "/data/GeoLite2-City.mmdb"
  rate_limit:
    max_per_minute: ${RATE_LIMIT_PER_MINUTE}
    max_per_hour: ${RATE_LIMIT_PER_HOUR}
  auto_ban:
    enabled: ${AUTO_BAN_ENABLED}
    score_threshold: ${AUTO_BAN_THRESHOLD}
    ban_duration: "${AUTO_BAN_DURATION}"
    method: "${AUTO_BAN_METHOD}"
    scoring:
      honeypot_connection: 10
      failed_credential: 15
      port_scan_detected: 25
      blacklisted_country: 5
      rate_limit_exceeded: 20

whitelist:
$(_whitelist_yaml)

blacklist:
$(_blacklist_yaml)

dashboard:
  enabled: ${DASHBOARD_ENABLED}
  listen: "127.0.0.1:${DASHBOARD_PORT}"
  auth:
    username: "${DASHBOARD_USER}"
    password: "${DASHBOARD_PASS}"

logging:
  database: "sqlite"
  db_path: "/data/skyguard.db"
  retention_days: ${LOG_RETENTION}
  log_first_bytes: 512
YAML
chmod 600 "${CONFIG_FILE}"
ok "$(t config_written "$CONFIG_FILE")"

# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 5 — iptables
# ═════════════════════════════════════════════════════════════════════════════
section "$(t sec_phase5)"

iptables -N SKYGUARD 2>/dev/null || iptables -F SKYGUARD
iptables -C INPUT -j SKYGUARD 2>/dev/null || iptables -I INPUT 1 -j SKYGUARD
iptables -C INPUT -i lo -j ACCEPT 2>/dev/null || iptables -A INPUT -i lo -j ACCEPT
iptables -C INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

[[ -n "$OWN_IP" ]] && {
    iptables -C INPUT -s "${OWN_IP}" -j ACCEPT 2>/dev/null || iptables -I INPUT 2 -s "${OWN_IP}" -j ACCEPT
}

open_port() {
    local port="$1" proto="${2:-tcp}"
    iptables -C INPUT -p "${proto}" --dport "${port}" -j ACCEPT 2>/dev/null || \
        iptables -A INPUT -p "${proto}" --dport "${port}" -j ACCEPT
    info "$(t iptables_open "$port" "$proto")"
}

# Reconcile the port-22 rule deterministically. Repeated installs — or flipping
# the SSH-honeypot choice between runs — must never leave a stale ACCEPT
# shadowing a DROP (or vice versa), which would silently keep real SSH exposed.
# Strip both first, then add exactly what this config needs.
while iptables -C INPUT -p tcp --dport 22 -j ACCEPT 2>/dev/null; do iptables -D INPUT -p tcp --dport 22 -j ACCEPT; done
while iptables -C INPUT -p tcp --dport 22 -j DROP   2>/dev/null; do iptables -D INPUT -p tcp --dport 22 -j DROP;   done

$ENABLE_STEALTH_SSH && open_port "${STEALTH_SSH_PORT}"

if $HONEYPOT_SSH; then
    open_port 22                                       # fake SSH must be reachable
elif $ENABLE_STEALTH_SSH; then
    iptables -A INPUT -p tcp --dport 22 -j DROP        # hide real SSH; use stealth port
    warn "$(t iptables_block22 "$STEALTH_SSH_PORT")"
fi

$HONEYPOT_FTP      && open_port 21
$HONEYPOT_MYSQL    && open_port 3306
$HONEYPOT_HTTP     && open_port 80
$HONEYPOT_HTTP_ALT && open_port 8080
$PASSTHROUGH_HTTPS && open_port 443
info "$(t iptables_dash_safe "$DASHBOARD_PORT")"
iptables -C INPUT -p icmp --icmp-type echo-request -j ACCEPT 2>/dev/null || \
    iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT

mkdir -p "$(dirname "${IPTABLES_RULES_FILE}")"
iptables-save > "${IPTABLES_RULES_FILE}"
case "$PKG_MGR" in
    apt)     command -v netfilter-persistent &>/dev/null && netfilter-persistent save &>/dev/null || true ;;
    yum|dnf) systemctl enable iptables &>/dev/null || true; service iptables save &>/dev/null || true ;;
    pacman)  systemctl enable iptables &>/dev/null || true ;;
esac
ok "$(t iptables_saved "$IPTABLES_RULES_FILE")"

command -v ip6tables &>/dev/null && {
    ip6tables -C INPUT -i lo -j ACCEPT 2>/dev/null || ip6tables -A INPUT -i lo -j ACCEPT
    ip6tables -C INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
        ip6tables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    info "$(t ip6_applied)"
}

# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 6 — docker-compose.yml
# ═════════════════════════════════════════════════════════════════════════════
section "$(t sec_phase6)"
TZ_VAL=$(cat /etc/timezone 2>/dev/null || timedatectl show --value -p Timezone 2>/dev/null || echo "UTC")

# The healthcheck depends on the dashboard. When the dashboard is disabled,
# probing it would always fail and mark the container unhealthy, so fall back to
# a liveness check on PID 1.
if $DASHBOARD_ENABLED; then
    HEALTH_TEST="wget -qO- 'http://${DASHBOARD_USER}:${DASHBOARD_PASS}@127.0.0.1:${DASHBOARD_PORT}/api/stats' >/dev/null 2>&1 || exit 1"
else
    HEALTH_TEST="kill -0 1 >/dev/null 2>&1 || exit 1"
fi

cat > "${INSTALL_DIR}/docker-compose.yml" <<COMPOSE
version: '3.8'
services:
  skyguard:
    build: .
    image: skyguard:latest
    container_name: skyguard
    restart: unless-stopped
    network_mode: host
    cap_add:
      - NET_ADMIN
      - NET_RAW
    volumes:
      - ${DATA_DIR}:/data
      - ${CONFIG_FILE}:/etc/skyguard/skyguard.yaml:ro
    environment:
      - SKYGUARD_CONFIG=/etc/skyguard/skyguard.yaml
      - TZ=${TZ_VAL}
    logging:
      driver: "json-file"
      options:
        max-size: "50m"
        max-file: "5"
    healthcheck:
      test: ["CMD-SHELL", "${HEALTH_TEST}"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 15s
COMPOSE
# The compose file embeds the dashboard password (healthcheck) — restrict it.
chmod 600 "${INSTALL_DIR}/docker-compose.yml"
ok "$(t compose_generated "${INSTALL_DIR}/docker-compose.yml")"

# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 7 — Build & Start
# ═════════════════════════════════════════════════════════════════════════════
section "$(t sec_phase7)"
cd "${INSTALL_DIR}"
info "$(t docker_building)"
# Show full build output live (so downloads/steps are visible) and keep a log.
# Note: pipefail makes the previous grep-filtered form fail spuriously when the
# build succeeds but no line matches the filter, so we stream the raw output.
if docker compose build --no-cache 2>&1 | tee /tmp/skyguard-build.log; then
    ok "$(t docker_build_ok)"
else
    echo
    warn "Build failed — last 40 lines of /tmp/skyguard-build.log:"
    tail -n 40 /tmp/skyguard-build.log
    die "$(t docker_build_fail)"
fi

info "$(t docker_starting)"
docker compose up -d

info "$(t docker_waiting)"
MAX_WAIT=60; WAITED=0
while [[ $WAITED -lt $MAX_WAIT ]]; do
    STATUS=$(docker inspect --format='{{.State.Health.Status}}' skyguard 2>/dev/null || echo "unknown")
    [[ "$STATUS" == "healthy" ]]   && break
    [[ "$STATUS" == "unhealthy" ]] && { warn "Container unhealthy:"; docker logs --tail=20 skyguard; break; }
    sleep 2; ((WAITED+=2))
done

docker ps | grep -q "skyguard" && ok "$(t docker_running)" || die "$(t docker_fail)"

# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 8 — Systemd Watchdog
# ═════════════════════════════════════════════════════════════════════════════
section "$(t sec_phase8)"
cat > /etc/systemd/system/skyguard.service <<UNIT
[Unit]
Description=SkyGuard Security Layer
Documentation=https://github.com/skyguard/skyguard
Requires=docker.service
After=docker.service network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=${INSTALL_DIR}
ExecStart=/usr/bin/docker compose up -d --remove-orphans
ExecStop=/usr/bin/docker compose down
ExecReload=/usr/bin/docker compose restart
TimeoutStartSec=120
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable skyguard.service
ok "$(t systemd_ok)"

# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 9 — GeoIP (optional)
# ═════════════════════════════════════════════════════════════════════════════
if $GEOIP_ENABLED; then
    section "$(t sec_phase9)"
    info "$(t geoip_place_file)"
    info "  ${DATA_DIR}/GeoLite2-City.mmdb"
    echo
    info "$(t geoip_quick_dl)"
    echo "  wget -O /tmp/GeoLite2-City.tar.gz \\"
    echo "    'https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=YOUR_KEY&suffix=tar.gz'"
    echo "  tar -xzf /tmp/GeoLite2-City.tar.gz --wildcards '*.mmdb' --strip-components=1 -C ${DATA_DIR}/"
    echo
    info "$(t geoip_cron_note)"
    cat > /etc/cron.monthly/skyguard-geoip-update <<CRON
#!/usr/bin/env bash
LICENSE_KEY="YOUR_MAXMIND_LICENSE_KEY"
DATA_DIR="${DATA_DIR}"
wget -qO /tmp/GeoLite2-City.tar.gz \
  "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=\${LICENSE_KEY}&suffix=tar.gz" \
  && tar -xzf /tmp/GeoLite2-City.tar.gz --wildcards '*.mmdb' --strip-components=1 -C "\${DATA_DIR}/" \
  && docker restart skyguard >/dev/null 2>&1 || true
rm -f /tmp/GeoLite2-City.tar.gz
CRON
    chmod +x /etc/cron.monthly/skyguard-geoip-update
fi

# ═════════════════════════════════════════════════════════════════════════════
#  PHASE 10 — Log Rotation & Backup
# ═════════════════════════════════════════════════════════════════════════════
section "$(t sec_phase10)"
cat > /etc/logrotate.d/skyguard <<LOGROTATE
${LOG_DIR}/*.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
}
LOGROTATE
echo "0 3 * * * root sqlite3 ${DATA_DIR}/skyguard.db \".backup '${DATA_DIR}/skyguard.db.bak'\" 2>/dev/null || true" \
    > /etc/cron.d/skyguard-backup
ok "$(t logrotate_ok)"

# ═════════════════════════════════════════════════════════════════════════════
#  FINAL SUMMARY
# ═════════════════════════════════════════════════════════════════════════════
section "$(t sec_done)"
echo
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════════════════╗"
echo -e "║       $(t final_title)        ║"
echo -e "╚══════════════════════════════════════════════════════════════╝${RESET}"
echo
echo -e "  ${CYAN}$(t final_service_mgmt)${RESET}"
echo -e "    systemctl start|stop|restart skyguard"
echo -e "    docker compose -f ${INSTALL_DIR}/docker-compose.yml logs -f"
echo
if $DASHBOARD_ENABLED; then
echo -e "  ${CYAN}$(t final_dashboard)${RESET}"
echo -e "    ssh -L ${DASHBOARD_PORT}:127.0.0.1:${DASHBOARD_PORT} user@${PUBLIC_IP}"
echo -e "    $(t final_dash_open "$DASHBOARD_PORT" "$DASHBOARD_USER")"
echo
fi
if $ENABLE_STEALTH_SSH; then
echo -e "  ${CYAN}$(t final_ssh_access)${RESET}"
echo -e "    ssh -p ${STEALTH_SSH_PORT} user@${PUBLIC_IP}"
echo -e "    ${YELLOW}⚠  $(t final_ssh_warn)${RESET}"
echo
fi
echo -e "  ${CYAN}$(t final_config)${RESET}    ${CONFIG_FILE}"
echo -e "  ${CYAN}$(t final_data)${RESET}     ${DATA_DIR}"
echo -e "  ${CYAN}$(t final_iptables)${RESET} ${IPTABLES_RULES_FILE}"
echo
echo -e "  ${CYAN}$(t final_useful)${RESET}"
echo -e "    docker logs skyguard -f"
echo -e "    docker exec -it skyguard sh"
echo -e "    iptables -L SKYGUARD -n --line-numbers"
echo
$GEOIP_ENABLED && { echo -e "  ${YELLOW}⚠  $(t final_geoip_warn "$DATA_DIR")${RESET}"; echo; }
echo -e "  ${CYAN}$(t final_listeners)${RESET}"
docker exec skyguard sh -c "wget -qO- 'http://${DASHBOARD_USER}:${DASHBOARD_PASS}@127.0.0.1:${DASHBOARD_PORT}/api/stats' 2>/dev/null" || true
echo
ok "$(t final_done)"