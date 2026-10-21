#!/usr/bin/env bash
# Weekly encrypted backup of ~ to Proton Drive (restic repo via rclone's protondrive backend).
set -euo pipefail

export RESTIC_REPOSITORY="rclone:proton:Backups/jack-home"
export RESTIC_PASSWORD_FILE="$HOME/.config/restic/password"
RESTIC=(restic -o rclone.program=/usr/local/bin/rclone)

"${RESTIC[@]}" backup "$HOME" --one-file-system --exclude-caches \
  --exclude "$HOME/.cache" \
  --exclude "$HOME/laptop-setup/dl" \
  --exclude "$HOME/.local/share/Trash" \
  --exclude "$HOME/.local/share/nvim/lazy" \
  --exclude "$HOME/.local/share/containers" \
  --exclude "$HOME/.local/state/nvim" \
  --exclude "node_modules" \
  --exclude ".venv" \
  --exclude "*.qcow2" \
  --exclude "*.iso" \
  --exclude "*.vmdk" \
  --exclude "*.vmem" \
  --exclude "*.vmss" \
  --exclude "*.nvram"

"${RESTIC[@]}" forget --keep-last 2 --prune
"${RESTIC[@]}" check --read-data-subset=2%
notify-send "Backup" "Weekly Proton Drive backup finished" 2>/dev/null || true
