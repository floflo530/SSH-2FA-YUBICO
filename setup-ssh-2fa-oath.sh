#!/usr/bin/env bash
# Gestion 2FA SSH (mot de passe + OTP OATH via Yubico Authenticator) - Debian 12+
# Menu :
#   1) Installer/activer le 2FA
#   2) Supprimer/revenir à la config de base
#   3) Diagnostic (heure NTP, TOTP serveur, conf PAM/SSH, vérifs)
# A lancer en root. Sauvegardes automatiques *.bak.YYYYmmdd-HHMMSS

set -euo pipefail

# ---------- UI ----------
CE="\033[0;36m"; GR="\033[0;32m"; YE="\033[1;33m"; RD="\033[0;31m"; NC="\033[0m"
info(){ echo -e "${CE}==>${NC} $*"; }
ok(){   echo -e "${GR}[OK]${NC} $*"; }
warn(){ echo -e "${YE}[! ]${NC} $*"; }
err(){  echo -e "${RD}[ERREUR]${NC} $*"; }
ask(){  read -r -p "$(echo -e "${YE}?${NC} $*") " REPLY_ASK; }

require_root(){ [[ "${EUID:-$(id -u)}" -eq 0 ]] || { err "Lance ce script en root."; exit 1; }; }

backup_file(){
  local f="$1"; [[ -f "$f" ]] || return 0
  local ts; ts="$(date +%Y%m%d-%H%M%S)"
  cp -a "$f" "${f}.bak.${ts}"
  ok "Sauvegarde : ${f}.bak.${ts}"
}

latest_backup(){ ls -1t "$1".bak.* 2>/dev/null | head -n1 || true; }

set_conf_value(){
  local file="$1" key="$2" val="$3"
  if grep -Eq "^[#\s]*${key}\b" "$file"; then
    sed -i "s|^[#\s]*${key}\b.*|${key} ${val}|" "$file"
  else
    printf "%s %s\n" "$key" "$val" >> "$file"
  fi
}

# ---------- 1) Installer / activer 2FA ----------
install_2fa(){
  info "Installation des paquets nécessaires"
  apt update -y
  apt install -y libpam-oath oathtool systemd-timesyncd openssl python3

  info "Activation/synchro NTP (important pour TOTP)"
  timedatectl set-ntp true || true
  systemctl restart systemd-timesyncd 2>/dev/null || true
  timedatectl

  info "Utilisateur à protéger (ex : debian)"
  read -r -p "Nom d'utilisateur : " SSH_USER
  id "$SSH_USER" >/dev/null 2>&1 || { err "Utilisateur introuvable."; exit 1; }

  local WINDOW="30" DIGITS="6" SECRET_HEX="" SECRET_B32=""

  info "Souhaitez-vous générer un nouveau secret (recommandé) ?"
  ask "[Entrée=oui / n=non, j'ai déjà un secret Base32] "
  if [[ ! "${REPLY_ASK:-}" =~ ^[nN]$ ]]; then
    SECRET_HEX="$(openssl rand -hex 20)"; ok "Secret HEX (serveur) : ${SECRET_HEX}"
    SECRET_B32="$(oathtool --totp --verbose "$SECRET_HEX" | awk '/Base32 secret/{print $3}')"
    ok "Secret Base32 (Yubico Authenticator) : ${SECRET_B32}"
  else
    read -r -p "Collez le secret Base32 (depuis Yubico Authenticator) : " SECRET_B32
    SECRET_HEX="$(python3 - <<'PY'
import sys,base64,binascii
b32=sys.stdin.read().strip().replace(' ','').upper()
pad='='*((8-len(b32)%8)%8)
raw=base64.b32decode(b32+pad)
print(binascii.hexlify(raw).decode())
PY
<<<"$SECRET_B32")"
    ok "Secret HEX (converti) : ${SECRET_HEX}"
  fi

  info "Mise à jour /etc/users.oath"
  touch /etc/users.oath && chmod 600 /etc/users.oath && chown root:root /etc/users.oath
  backup_file /etc/users.oath
  sed -i "\|^[[:space:]]*HOTP/T30/${DIGITS}[[:space:]]\+${SSH_USER}[[:space:]]\+-[[:space:]]\+[0-9a-fA-F]\+|d" /etc/users.oath
  echo "HOTP/T30/${DIGITS} ${SSH_USER} - ${SECRET_HEX}" >> /etc/users.oath
  ok "Ajouté pour ${SSH_USER}"

  cat <<'TXT'

\033[1;33m=== Étape à faire dans Yubico Authenticator ===\033[0m
  1) Ouvrez \033[0;32mYubico Authenticator\033[0m.
  2) Cliquez sur \033[0;32m+\033[0m → \033[0;32mTOTP\033[0m.
  3) Nom : \033[0;32mSSH <votre_user>@<serveur>\033[0m
  4) Secret : \033[0;32m(Base32 affiché ci-dessus si généré ici)\033[0m
  5) Chiffres : \033[0;32m6\033[0m | Période : \033[0;32m30s\033[0m
Puis enregistrez, et revenez ici.
TXT
  read -r -p "Appuyez sur Entrée quand c'est fait..." _

  info "Vérification TOTP côté serveur"
  local CODE_SERV; CODE_SERV="$(oathtool --totp -d ${DIGITS} "${SECRET_HEX}")"
  echo -e "Code serveur (maintenant) : ${GR}${CODE_SERV}${NC}"
  ask "Correspond-il au code dans Yubico Authenticator ? (o/N) "
  [[ "${REPLY_ASK:-}" =~ ^[oOyY]$ ]] || { err "Codes différents. Abandon pour éviter un lockout."; exit 1; }
  ok "TOTP OK"

  info "Configuration PAM (/etc/pam.d/sshd)"
  backup_file /etc/pam.d/sshd
  sed -i '/pam_oath\.so/d' /etc/pam.d/sshd
  {
    echo "@include common-auth"
    echo "auth required pam_oath.so usersfile=/etc/users.oath window=${WINDOW} digits=${DIGITS}"
    nl -ba /etc/pam.d/sshd | awk 'NR>=5{print substr($0,index($0,$2))}'
  } > /etc/pam.d/sshd.new && mv /etc/pam.d/sshd.new /etc/pam.d/sshd
  ok "PAM : mot de passe puis OTP."

  info "Configuration SSH (/etc/ssh/sshd_config)"
  backup_file /etc/ssh/sshd_config
  set_conf_value /etc/ssh/sshd_config UsePAM yes
  set_conf_value /etc/ssh/sshd_config KbdInteractiveAuthentication yes
  set_conf_value /etc/ssh/sshd_config ChallengeResponseAuthentication yes
  set_conf_value /etc/ssh/sshd_config PasswordAuthentication no
  grep -Eq '^AuthenticationMethods\b' /etc/ssh/sshd_config \
    && sed -i 's|^AuthenticationMethods.*|AuthenticationMethods keyboard-interactive:pam|' /etc/ssh/sshd_config \
    || echo 'AuthenticationMethods keyboard-interactive:pam' >> /etc/ssh/sshd_config
  ok "sshd_config prêt."

  warn "Gardez cette session ouverte pour tester."
  systemctl restart ssh
  ok "SSH redémarré."
  echo -e "${YE}Testez depuis un autre terminal : Password → One-time password (OATH).${NC}"
}

# ---------- 2) Revert ----------
revert_2fa(){
  info "Restauration de la configuration d'origine"
  local pam="/etc/pam.d/sshd" sshc="/etc/ssh/sshd_config"
  local pam_bak ssh_bak; pam_bak="$(latest_backup "$pam" || true)"; ssh_bak="$(latest_backup "$sshc" || true)"

  if [[ -n "$pam_bak" ]]; then
    cp -a "$pam_bak" "$pam"; ok "PAM restauré depuis : $pam_bak"
  else
    sed -i '/pam_oath\.so/d' "$pam"
    grep -q '^[[:space:]]*@include[[:space:]]\+common-auth' "$pam" || sed -i '1i @include common-auth' "$pam"
    ok "PAM nettoyé."
  fi

  if [[ -n "$ssh_bak" ]]; then
    cp -a "$ssh_bak" "$sshc"; ok "sshd_config restauré depuis : $ssh_bak"
  else
    set_conf_value "$sshc" UsePAM yes
    set_conf_value "$sshc" KbdInteractiveAuthentication yes
    set_conf_value "$sshc" PasswordAuthentication yes
    sed -i '/^AuthenticationMethods\b/d' "$sshc"
    set_conf_value "$sshc" ChallengeResponseAuthentication yes
    ok "sshd_config nettoyé (mot de passe actif)."
  fi

  systemctl restart ssh
  ok "2FA désactivé, mot de passe seul actif."
}

# ---------- 3) Diagnostic ----------
diag_2fa(){
  info "Diagnostic 2FA (lecture seule, aucune modif)"
  echo

  info "Heure / NTP"
  timedatectl || true
  echo

  info "Vérification des fichiers/permissions"
  ls -l /etc/pam.d/sshd 2>/dev/null || true
  ls -l /etc/ssh/sshd_config 2>/dev/null || true
  ls -l /etc/users.oath 2>/dev/null || true
  [[ -f /etc/users.oath ]] && stat -c 'users.oath perms: %A owner:%U group:%G' /etc/users.oath || true
  echo

  info "Entrée /etc/users.oath détectée (1ère ligne utile)"
  if [[ -f /etc/users.oath ]] && awk '!/^($|#)/{exit 0} END{exit 1}' /etc/users.oath; then
    awk '!/^($|#)/{print "Format:",$1,"| User:",$2,"| Secret(HEX):",$4; exit}' /etc/users.oath
    USER_DIAG="$(awk '!/^($|#)/{print $2; exit}' /etc/users.oath)"
    SECRET_HEX="$(awk '!/^($|#)/{print $4; exit}' /etc/users.oath)"
  else
    warn "Aucune entrée utile trouvée."
    USER_DIAG=""
    SECRET_HEX=""
  fi
  echo

  info "Aperçu TOTP côté serveur (si secret dispo)"
  if [[ -n "${SECRET_HEX:-}" ]]; then
    echo -n "Code TOTP (6d/30s, maintenant) : "
    oathtool --totp -d 6 "${SECRET_HEX}" || warn "oathtool indisponible ?"
  else
    warn "Secret indisponible, saut de cette étape."
  fi
  echo

  info "sshd -T (extraits Auth)"
  sshd -T 2>/dev/null | egrep -i 'authenticationmethods|usepam|kbd|challenge|passwordauthentication' || true
  echo

  info "Début de /etc/pam.d/sshd"
  sed -n '1,20p' /etc/pam.d/sshd 2>/dev/null || true
  echo

  info "Recherche de doublons pam_oath/common-auth"
  { grep -n 'pam_oath\.so' /etc/pam.d/sshd || true; } | sed 's/^/  /'
  { grep -n '^[[:space:]]*@include[[:space:]]\+common-auth' /etc/pam.d/sshd || true; } | sed 's/^/  /'
  echo

  info "Validation de la conf SSH"
  if sshd -t 2>/tmp/sshd_t_err; then
    ok "sshd -t : OK"
  else
    err "sshd -t : erreurs détectées :"
    sed -n '1,120p' /tmp/sshd_t_err
  fi
  echo

  info "Derniers logs SSH (5 min)"
  journalctl -u ssh --since "5 minutes ago" --no-pager || true

  echo
  ok "Diagnostic terminé."
}

# ---------- Main ----------
require_root
echo -e "${CE}Gestion du 2FA SSH (mot de passe + OTP OATH via Yubico Authenticator)${NC}"
echo -e "1) Installer/activer le 2FA"
echo -e "2) Supprimer/revenir à la config de base"
echo -e "3) Diagnostic"
read -r -p "Choisissez [1/2/3] : " CHOIX
case "${CHOIX:-}" in
  1) install_2fa ;;
  2) revert_2fa ;;
  3) diag_2fa ;;
  *) err "Choix invalide." ; exit 1 ;;
esac
