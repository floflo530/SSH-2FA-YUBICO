# 🔐 Gestion 2FA SSH (mot de passe + OTP OATH via Yubico Authenticator) - Debian 12+

Ce script Bash permet d’installer, de configurer ou de désinstaller facilement l’authentification à deux facteurs (**mot de passe + OTP TOTP**) pour SSH sur un serveur **Debian 12+**.  
Il utilise **`libpam-oath`** et un code TOTP généré depuis **Yubico Authenticator**.  
Les sauvegardes des fichiers de configuration sont automatiques, avec possibilité de **revenir à la configuration d’origine**.

---

## ✨ Fonctionnalités

- **Installation interactive** du 2FA SSH (mot de passe + OTP TOTP)
- **Compatibilité Yubico Authenticator** (ajout manuel du secret Base32)
- Génération automatique du secret HEX et conversion en Base32
- Vérification du code TOTP en temps réel côté serveur
- Sauvegarde automatique de :
  - `/etc/pam.d/sshd`
  - `/etc/ssh/sshd_config`
  - `/etc/users.oath`
- **Revert complet** vers la configuration SSH initiale
- **Diagnostic** pour vérifier la configuration, l’heure NTP, et les logs SSH

---

## 📦 Installation

1. **Télécharger le script :**
   ```bash
   wget https://raw.githubusercontent.com/floflo530/SSH-2FA-YUBICO/refs/heads/main/setup-ssh-2fa-oath.sh -O /root/setup-ssh-2fa-oath.sh
   chmod +x /root/setup-ssh-2fa-oath.sh
