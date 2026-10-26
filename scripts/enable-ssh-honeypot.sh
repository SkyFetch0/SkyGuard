#!/usr/bin/env bash
# =============================================================================
#  SkyGuard — Enable the SSH honeypot on port 22
#
#  Frees port 22 for the fake-SSH honeypot by moving the REAL sshd to another
#  port, then reconfigures SkyGuard so:
#     attacker → 0.0.0.0:22      → fake SSH (honeypot: logged + scored + banned)
#     you      → 9911 (stealth)  → SkyGuard → 127.0.0.1:<new-port> (real sshd)
#
#  Safe by design: backs up sshd_config, validates with `sshd -t` and reverts on
#  error, opens the new port in the firewall BEFORE restarting sshd, and never
#  kills your current session.
#
#  Usage (run on the server, as root, AFTER SkyGuard is installed & 9911 works):
#     sudo bash scripts/enable-ssh-honeypot.sh [NEW_SSH_PORT]   # default 2222
# =============================================================================
set -euo pipefail

NEW_PORT="${1:-2222}"
SSHD_CONFIG="/etc/ssh/sshd_config"
SKY_CONFIG="${SKYGUARD_CONFIG:-/etc/skyguard/skyguard.yaml}"
SSH_BANNER="SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; RESET='\033[0m'
info(){ echo -e "${CYAN}[INFO]${RESET}  $*"; }
ok(){   echo -e "${GREEN}[OK]${RESET}    $*"; }
warn(){ echo -e "${YELLOW}[WARN]${RESET}  $*"; }
die(){  echo -e "${RED}[ERROR]${RESET} $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "Bu script root ile çalıştırılmalı (sudo)."
[[ "$NEW_PORT" =~ ^[0-9]+$ ]] && (( NEW_PORT >= 1 && NEW_PORT <= 65535 && NEW_PORT != 22 )) \
    || die "Geçersiz yeni SSH portu: '$NEW_PORT' (1-65535, 22 olamaz)."
[[ -f "$SSHD_CONFIG" ]] || die "sshd config bulunamadı: $SSHD_CONFIG"
[[ -f "$SKY_CONFIG"  ]] || die "SkyGuard config bulunamadı: $SKY_CONFIG (SKYGUARD_CONFIG ile yol verebilirsin)"

# ── 1. Socket activation kontrolü (Debian/Ubuntu ssh.socket) ─────────────────
# ssh.socket aktifse port sshd_config'te değil socket unit'inde tanımlıdır.
if systemctl is-active --quiet ssh.socket 2>/dev/null; then
    die "ssh.socket (socket activation) aktif — port socket unit'inde tutuluyor.
Önce şunu çalıştır, sonra bu script'i tekrar dene:
  systemctl disable --now ssh.socket && systemctl enable --now ssh.service"
fi

# Güvenlik duvarı arayüzü (install.sh ile aynı mantık).
FW_FRONTEND="iptables"
if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
    FW_FRONTEND="ufw"
elif systemctl is-active --quiet firewalld 2>/dev/null; then
    FW_FRONTEND="firewalld"
fi
open_port() {
    case "$FW_FRONTEND" in
        ufw)       ufw allow "$1/tcp" >/dev/null ;;
        firewalld) firewall-cmd --quiet --permanent --add-port="$1/tcp" && firewall-cmd --quiet --reload ;;
        *)         iptables -C INPUT -p tcp --dport "$1" -j ACCEPT 2>/dev/null \
                       || iptables -I INPUT -p tcp --dport "$1" -j ACCEPT ;;
    esac
}
save_rules() {
    [[ "$FW_FRONTEND" == "iptables" ]] || return 0
    if [[ -d /etc/iptables ]]; then iptables-save > /etc/iptables/rules.v4; fi
    if [[ -f /etc/sysconfig/iptables ]]; then iptables-save > /etc/sysconfig/iptables; fi
    command -v netfilter-persistent &>/dev/null && netfilter-persistent save >/dev/null 2>&1 || true
}

# Servis adını tespit et (Debian/Ubuntu: ssh, RHEL: sshd).
SSH_SVC="ssh"
systemctl list-unit-files 2>/dev/null | grep -q '^sshd\.service' && SSH_SVC="sshd"

info "Yeni gerçek SSH portu : ${NEW_PORT}"
info "SSH servisi           : ${SSH_SVC}.service"
info "SkyGuard config       : ${SKY_CONFIG}"
echo
warn "DİKKAT: Bu işlem gerçek SSH'ı ${NEW_PORT} portuna taşır ve 22'yi honeypot'a bırakır."
warn "Mevcut SSH oturumun AÇIK kalacak. Bitince 9911 veya ${NEW_PORT} üzerinden gir."
echo

# ── 2. sshd_config yedekle ───────────────────────────────────────────────────
BK="${SSHD_CONFIG}.skyguard.$(date +%Y%m%d%H%M%S).bak"
cp -a "$SSHD_CONFIG" "$BK"
ok "sshd_config yedeklendi → ${BK}"

# ── 3. Port satırını ayarla ──────────────────────────────────────────────────
# Mevcut (yorumsuz) Port satırlarını yorum yap, sonra kendi portumuzu ekle.
sed -i -E 's/^[[:space:]]*Port[[:space:]]+[0-9]+.*/# &  (SkyGuard tarafından taşındı)/' "$SSHD_CONFIG"
printf '\n# SkyGuard: gerçek SSH 22 dışına taşındı (22 = honeypot). Stealth portu: 9911.\nPort %s\n' "$NEW_PORT" >> "$SSHD_CONFIG"

# ── 3b. SELinux: RHEL/Rocky/Alma/Fedora'da sshd yalnızca ssh_port_t portlarına
# bağlanabilir; etiketlenmezse sshd yeni portta açılmaz.
if command -v getenforce &>/dev/null && [[ "$(getenforce 2>/dev/null)" == "Enforcing" ]]; then
    if ! command -v semanage &>/dev/null; then
        cp -a "$BK" "$SSHD_CONFIG"
        die "SELinux Enforcing ama 'semanage' yok. Kur: dnf install -y policycoreutils-python-utils — sonra tekrar çalıştır."
    fi
    semanage port -a -t ssh_port_t -p tcp "$NEW_PORT" 2>/dev/null \
        || semanage port -m -t ssh_port_t -p tcp "$NEW_PORT"
    ok "SELinux: ${NEW_PORT}/tcp ssh_port_t olarak etiketlendi"
fi

# ── 4. Riskli adımdan ÖNCE config'i doğrula; bozuksa geri al ──────────────────
if ! sshd -t 2>/tmp/skyguard-sshd-test.err; then
    cp -a "$BK" "$SSHD_CONFIG"
    cat /tmp/skyguard-sshd-test.err >&2
    die "sshd config geçersiz — değişiklik geri alındı, hiçbir şey bozulmadı."
fi
ok "sshd config geçerli (Port ${NEW_PORT})"

# ── 5. Yeni portu firewall'da AÇ (yeniden başlatmadan önce → yedek erişim) ────
open_port "$NEW_PORT"
ok "Firewall (${FW_FRONTEND}): ${NEW_PORT}/tcp açıldı (yedek doğrudan erişim)"

# ── 6. sshd'yi yeniden başlat (mevcut oturumlar düşmez) ──────────────────────
systemctl restart "$SSH_SVC"
sleep 1
if [[ -n "$(ss -Htln "sport = :${NEW_PORT}" 2>/dev/null)" ]]; then
    ok "sshd ${NEW_PORT} portunda dinliyor (mevcut oturumun hâlâ bağlı)"
else
    warn "sshd ${NEW_PORT} portunda görünmüyor — geri alıyorum."
    cp -a "$BK" "$SSHD_CONFIG"; systemctl restart "$SSH_SVC"
    die "sshd yeni portta açılmadı; eski config geri yüklendi."
fi

# ── 7. SkyGuard config: stealth hedefini güncelle + fake-ssh honeypot ekle ────
# Stealth real_target portunu yeni gerçek SSH portuna çevir.
sed -i -E 's#(real_target:[[:space:]]*"127\.0\.0\.1):22"#\1:'"${NEW_PORT}"'"#' "$SKY_CONFIG"

# 22 portlu bir honeypot varsa (örnek config'te enabled: false ile gelir)
# onu etkinleştir; yoksa fake-ssh ekle.
cp -a "$SKY_CONFIG" "${SKY_CONFIG}.skyguard.$(date +%Y%m%d%H%M%S).bak"
if grep -Eq '^[[:space:]]+port:[[:space:]]*22[[:space:]]*(#.*)?$' "$SKY_CONFIG"; then
    # Liste öğelerini tek tek tamponla; "port: 22" içeren öğede enabled'ı true yap.
    awk '
        function flush() {
            if (n == 0) return
            if (has22) {
                for (i = 1; i <= n; i++) {
                    if (buf[i] ~ /^[[:space:]]+enabled:[[:space:]]*false/) { sub(/false/, "true", buf[i]); fixed = 1 }
                }
            }
            for (i = 1; i <= n; i++) print buf[i]
            n = 0; has22 = 0
        }
        /^[^[:space:]#]/ { flush(); print; next }          # top-level key
        /^  - / { flush() }                                # new list item
        { buf[++n] = $0; if ($0 ~ /^[[:space:]]+port:[[:space:]]*22[[:space:]]*(#.*)?$/) has22 = 1 }
        END { flush() }
    ' "$SKY_CONFIG" > "${SKY_CONFIG}.tmp" && mv "${SKY_CONFIG}.tmp" "$SKY_CONFIG"
    ok "22 portundaki honeypot etkinleştirildi"
else
    # "honeypot_services: []" boş liste ise önce blok biçimine çevir.
    sed -i -E 's/^honeypot_services:[[:space:]]*\[\][[:space:]]*$/honeypot_services:/' "$SKY_CONFIG"
    awk -v banner="$SSH_BANNER" '
        { print }
        /^honeypot_services:/ && !done {
            print "  - name: \"fake-ssh\""
            print "    enabled: true"
            print "    port: 22"
            print "    type: \"ssh\""
            print "    banner: \"" banner "\""
            print "    max_auth_attempts: 3"
            done = 1
        }
    ' "$SKY_CONFIG" > "${SKY_CONFIG}.tmp" && mv "${SKY_CONFIG}.tmp" "$SKY_CONFIG"
    ok "fake-ssh honeypot (port 22) config'e eklendi"
fi
chmod 600 "$SKY_CONFIG"

# Yeni config'i başlatmadan önce doğrula (bozuk config = çöken container).
if command -v docker &>/dev/null && docker image inspect skyguard:latest &>/dev/null; then
    if ! docker run --rm --entrypoint /usr/local/bin/skyguard -v "${SKY_CONFIG}:/c.yaml:ro" skyguard:latest -check-config -config /c.yaml; then
        warn "SkyGuard yeni config'i reddetti; sshd 2222'de çalışmaya devam ediyor, config yedeği: ${SKY_CONFIG}.skyguard.*.bak"
        die "Config'i düzeltip 'systemctl restart skyguard' çalıştır."
    fi
fi

# ── 8. iptables: 22'deki DROP'u kaldır, honeypot için ACCEPT bırak ───────────
while iptables -C INPUT -p tcp --dport 22 -j DROP 2>/dev/null; do
    iptables -D INPUT -p tcp --dport 22 -j DROP
done
while iptables -C INPUT ! -i lo -p tcp --dport 22 -j DROP 2>/dev/null; do
    iptables -D INPUT ! -i lo -p tcp --dport 22 -j DROP
done
[[ "$FW_FRONTEND" == "ufw" ]] && ufw delete deny 22/tcp >/dev/null 2>&1 || true
open_port 22
ok "Firewall: 22/tcp honeypot için açık (DROP kaldırıldı)"

# ── 9. SkyGuard'ı yeniden başlat → honeypot artık boş 22'yi bağlar ───────────
if systemctl is-enabled --quiet skyguard 2>/dev/null; then
    systemctl restart skyguard
elif [[ -f /opt/skyguard/docker-compose.yml ]]; then
    (cd /opt/skyguard && docker compose restart)
else
    warn "skyguard servisi bulunamadı — elle yeniden başlat: systemctl restart skyguard"
fi
sleep 2

# ── 10. Kuralları kalıcılaştır ────────────────────────────────────────────────
save_rules
ok "Firewall kuralları kalıcılaştırıldı (${FW_FRONTEND})"

# ── 11. Özet + doğrulama ─────────────────────────────────────────────────────
echo
ok "Tamamlandı. Yeni düzen:"
echo "    • Gerçek SSH : port ${NEW_PORT}  (ssh -p ${NEW_PORT} kullanici@SUNUCU)"
echo "    • Stealth    : 9911 → 127.0.0.1:${NEW_PORT}  (ssh -p 9911 ...)"
echo "    • Honeypot   : 0.0.0.0:22  (saldırganlar buraya düşer)"
echo
info "Dinleyiciler:"
ss -Htlnp 2>/dev/null | grep -E ":(22|${NEW_PORT}|9911) " || true
echo
warn "ŞİMDİ test et (mevcut oturumu KAPATMADAN, ikinci terminalde):"
echo "    ssh -p ${NEW_PORT} kullanici@SUNUCU      # doğrudan, yedek"
echo "    ssh -p 9911 kullanici@SUNUCU             # stealth"
echo "İkisi de çalışıyorsa mevcut oturumu kapatabilirsin."
echo
info "İsteğe bağlı sertleştirme: gerçek SSH'ı tamamen gizlemek için sshd_config'e"
info "'ListenAddress 127.0.0.1' ekleyip ${NEW_PORT}/tcp firewall kuralını kaldırabilirsin"
info "(o zaman SADECE 9911 stealth üzerinden girilir)."
