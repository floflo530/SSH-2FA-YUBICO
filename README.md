# 🔐 2FA SSH (mot de passe + OTP OATH via Yubico Authenticator) – Debian 12+

Script Bash interactif pour installer, diagnostiquer et supprimer le 2FA SSH **mot de passe + OTP TOTP** sur Debian 12+.  
Il s’appuie sur **libpam-oath** et un code TOTP généré dans **Yubico Authenticator**.

> ✅ Le script reconstruit `/etc/pam.d/sshd` de façon **sûre**, sans numérotation parasite, et **garantit l’ordre** _mot de passe → OTP_ pour **tous** les comptes (y compris `root`).

---

## ✨ Fonctionnalités

- Installation guidée du 2FA (mot de passe + OTP TOTP)
- Génération **HEX** (serveur) + conversion **Base32** (Yubico Authenticator)
- Vérification en direct du TOTP côté serveur
- Sauvegardes automatiques :  
  - `/etc/pam.d/sshd`  
  - `/etc/ssh/sshd_config`  
  - `/etc/users.oath`
- **Revert** propre vers la conf de base (mot de passe seul)
- **Diagnostic** détaillé (NTP, TOTP, conf PAM/SSH, logs)
- **Option 4 : Activer/Désactiver le debug `pam_oath`** pour enquête rapide
- Correctifs robustes contre les **“lignes numériques orphelines”** et les **doublons** `pam_oath`

---

## 📥 Installation

```bash
wget https://raw.githubusercontent.com/<VOTRE_USER>/<VOTRE_REPO>/main/setup-ssh-2fa-oath.sh -O /root/setup-ssh-2fa-oath.sh
chmod +x /root/setup-ssh-2fa-oath.sh
/root/setup-ssh-2fa-oath.sh
