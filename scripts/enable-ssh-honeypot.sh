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
IPTABLES_RULES_FILE="${IPTABLES_RULES_FILE:-/etc/iptables/rules.v4}"
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

# ── 4. Riskli adımdan ÖNCE config'i doğrula; bozuksa geri al ──────────────────
if ! sshd -t 2>/tmp/skyguard-sshd-test.err; then
    cp -a "$BK" "$SSHD_CONFIG"
    cat /tmp/skyguard-sshd-test.err >&2
    die "sshd config geçersiz — değişiklik geri alındı, hiçbir şey bozulmadı."
fi
ok "sshd config geçerli (Port ${NEW_PORT})"

# ── 5. Yeni portu firewall'da AÇ (yeniden başlatmadan önce → yedek erişim) ────
iptables -C INPUT -p tcp --dport "$NEW_PORT" -j ACCEPT 2>/dev/null \
    || iptables -I INPUT -p tcp --dport "$NEW_PORT" -j ACCEPT
ok "Firewall: ${NEW_PORT}/tcp açıldı (yedek doğrudan erişim)"

# ── 6. sshd'yi yeniden başlat (mevcut oturumlar düşmez) ──────────────────────
systemctl restart "$SSH_SVC"
sleep 1
if ss -tlnp 2>/dev/null | grep -q ":${NEW_PORT} "; then
    ok "sshd ${NEW_PORT} portunda dinliyor (mevcut oturumun hâlâ bağlı)"
else
    warn "sshd ${NEW_PORT} portunda görünmüyor — geri alıyorum."
    cp -a "$BK" "$SSHD_CONFIG"; systemctl restart "$SSH_SVC"
    die "sshd yeni portta açılmadı; eski config geri yüklendi."
fi

# ── 7. SkyGuard config: stealth hedefini güncelle + fake-ssh honeypot ekle ────
# Stealth real_target portunu yeni gerçek SSH portuna çevir.
sed -i -E 's#(real_target:[[:space:]]*"127\.0\.0\.1):22"#\1:'"${NEW_PORT}"'"#' "$SKY_CONFIG"

# Zaten 22'de bir honeypot var mı? Yoksa fake-ssh ekle.
if grep -Eq 'port:[[:space:]]*22\b' "$SKY_CONFIG"; then
    info "Config'de zaten 22 portunda bir honeypot tanımlı — eklemiyorum."
else
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
    chmod 600 "$SKY_CONFIG"
    ok "fake-ssh honeypot (port 22) config'e eklendi"
fi

# ── 8. iptables: 22'deki DROP'u kaldır, honeypot için ACCEPT bırak ───────────
while iptables -C INPUT -p tcp --dport 22 -j DROP 2>/dev/null; do
    iptables -D INPUT -p tcp --dport 22 -j DROP
done
iptables -C INPUT -p tcp --dport 22 -j ACCEPT 2>/dev/null \
    || iptables -A INPUT -p tcp --dport 22 -j ACCEPT
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
mkdir -p "$(dirname "$IPTABLES_RULES_FILE")"
iptables-save > "$IPTABLES_RULES_FILE"
command -v netfilter-persistent &>/dev/null && netfilter-persistent save >/dev/null 2>&1 || true
ok "iptables kuralları kaydedildi → ${IPTABLES_RULES_FILE}"

# ── 11. Özet + doğrulama ─────────────────────────────────────────────────────
echo
ok "Tamamlandı. Yeni düzen:"
echo "    • Gerçek SSH : port ${NEW_PORT}  (ssh -p ${NEW_PORT} kullanici@SUNUCU)"
echo "    • Stealth    : 9911 → 127.0.0.1:${NEW_PORT}  (ssh -p 9911 ...)"
echo "    • Honeypot   : 0.0.0.0:22  (saldırganlar buraya düşer)"
echo
info "Dinleyiciler:"
ss -tlnp 2>/dev/null | grep -E ":(22|${NEW_PORT}|9911) " || true
echo
warn "ŞİMDİ test et (mevcut oturumu KAPATMADAN, ikinci terminalde):"
echo "    ssh -p ${NEW_PORT} kullanici@SUNUCU      # doğrudan, yedek"
echo "    ssh -p 9911 kullanici@SUNUCU             # stealth"
echo "İkisi de çalışıyorsa mevcut oturumu kapatabilirsin."
echo
info "İsteğe bağlı sertleştirme: gerçek SSH'ı tamamen gizlemek için sshd_config'e"
info "'ListenAddress 127.0.0.1' ekleyip ${NEW_PORT}/tcp firewall kuralını kaldırabilirsin"
info "(o zaman SADECE 9911 stealth üzerinden girilir)."
