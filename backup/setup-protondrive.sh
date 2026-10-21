#!/usr/bin/env bash
# One-time setup (run as yourself, not sudo): log rclone into Proton Drive,
# create the encrypted restic repository, and turn on the weekly timer.
set -euo pipefail
[[ $EUID -ne 0 ]] || { echo "Run this WITHOUT sudo: bash $0"; exit 1; }
command -v /usr/local/bin/rclone >/dev/null || { echo "Run 'sudo bash ~/laptop-setup/setup.sh proton' first."; exit 1; }

if ! /usr/local/bin/rclone listremotes | grep -qx 'proton:'; then
  read -rp  "Proton username/email: " user
  read -rsp "Proton password: " pass; echo
  read -rp  "2FA code (blank if 2FA is off): " code
  args=(username "$user" password "$pass")
  [[ -n "$code" ]] && args+=(2fa "$code")
  /usr/local/bin/rclone config create proton protondrive "${args[@]}" --obscure >/dev/null
  chmod 600 "$HOME/.config/rclone/rclone.conf"
fi
/usr/local/bin/rclone mkdir proton:Backups
echo "Connected to Proton Drive:"; /usr/local/bin/rclone about proton: || true

install -d -m 700 "$HOME/.config/restic"
if [[ ! -f "$HOME/.config/restic/password" ]]; then
  ( umask 077; head -c 32 /dev/urandom | base64 > "$HOME/.config/restic/password" )
  echo
  echo "==> Backup encryption password (SAVE THIS IN PROTON PASS - without it the backup can't be restored):"
  cat "$HOME/.config/restic/password"
  echo
fi
export RESTIC_PASSWORD_FILE="$HOME/.config/restic/password"
restic -o rclone.program=/usr/local/bin/rclone -r rclone:proton:Backups/jack-home cat config >/dev/null 2>&1 \
  || restic -o rclone.program=/usr/local/bin/rclone -r rclone:proton:Backups/jack-home init

systemctl --user daemon-reload
systemctl --user enable --now proton-backup.timer
echo "Weekly backup enabled. Run one now with: systemctl --user start proton-backup.service"
