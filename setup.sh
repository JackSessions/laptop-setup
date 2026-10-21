#!/usr/bin/env bash
# Laptop setup: dev tools + LazyVim deps, TigerVNC, Tailscale, firewall, hardening,
# virt-manager, LXC + Velociraptor (DFIR), Zeek, GRUB theme, login screen, Lynis.
#
# Usage:  sudo bash ~/laptop-setup/setup.sh            (everything, in order)
#         sudo bash ~/laptop-setup/setup.sh lxc zeek   (just those sections)
# Every section is safe to re-run.

set -Eeuo pipefail

[[ $EUID -eq 0 ]] || { echo "Run with sudo: sudo bash $0 $*"; exit 1; }
USER_NAME="${SUDO_USER:-void}"
USER_HOME="$(getent passwd "$USER_NAME" | cut -d: -f6)"
HERE="$(cd "$(dirname "$0")" && pwd)"
VR_BIN="$HERE/dl/velociraptor-v0.77.3-linux-amd64"
VR_CONF_DIR="$HERE/velociraptor"
CT=velociraptor
CT_IP=10.0.3.10
export DEBIAN_FRONTEND=noninteractive

# Keep a log and say exactly which section/line failed (set -e otherwise exits silently).
LOG="$HERE/setup.log"
exec > >(tee -a "$LOG") 2>&1
CURRENT=""
trap 'echo -e "\n\033[1;31m!! Section \"$CURRENT\" failed at line $LINENO (exit $?). Log: $LOG\033[0m"' ERR

# needrestart pops a dialog after installs; with no TTY that hangs apt (and holds its lock) forever.
mkdir -p /etc/needrestart/conf.d
printf "\$nrconf{restart} = 'l';\n\$nrconf{kernelhints} = -1;\n\$nrconf{ucodehints} = 0;\n" > /etc/needrestart/conf.d/90-nonint.conf

log() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
apt_install() { apt-get -o DPkg::Lock::Timeout=600 install -y --no-install-recommends "$@"; }

packages() {
  log "Dev tools + LazyVim dependencies"
  apt-get -o DPkg::Lock::Timeout=600 update
  apt_install git curl wget ca-certificates gnupg build-essential pkg-config \
    python3-pip python3-venv pipx jq ripgrep fd-find tmux htop tcpdump unzip \
    neovim lazygit tree-sitter-cli nodejs npm shellcheck wl-clipboard
}

remove-vscode() {
  log "Removing VS Code and its repo"
  apt-get purge -y code 2>/dev/null || true
  rm -f /etc/apt/sources.list.d/vscode.sources /etc/apt/keyrings/microsoft.gpg
}

ssh() {
  log "OpenSSH server"
  apt_install openssh-server
  cat > /etc/ssh/sshd_config.d/10-hardening.conf <<'EOF'
PermitRootLogin no
MaxAuthTries 3
X11Forwarding no
# Once your key is in ~/.ssh/authorized_keys, set this to "no":
PasswordAuthentication yes
EOF
  sshd -t
  systemctl enable --now ssh
  systemctl restart ssh
}

vnc() {
  log "TigerVNC server (XFCE desktop on :1, port 5901) + viewer"
  # --no-install-recommends keeps xfce4 from pulling in a new display manager.
  apt_install tigervnc-standalone-server tigervnc-common tigervnc-tools tigervnc-viewer \
    xfce4 xfce4-terminal dbus-x11 xfonts-base
  # Own D-Bus for the VNC desktop: sharing the Hyprland session's bus made XFCE exit ~10s after start.
  cat > /usr/share/xsessions/xfce-vnc.desktop <<'EOF2'
[Desktop Entry]
Name=Xfce (VNC)
Exec=dbus-run-session -- startxfce4
Type=Application
EOF2
  local cfg="$USER_HOME/.config/tigervnc"
  install -d -o "$USER_NAME" -g "$USER_NAME" -m 700 "$cfg"
  # Listens on the network; the firewall only lets it in over Tailscale.
  cat > "$cfg/config" <<'EOF'
session=xfce-vnc
geometry=1920x1080
localhost=no
alwaysshared
EOF
  chown "$USER_NAME:" "$cfg/config"
  grep -q "^:1=$USER_NAME" /etc/tigervnc/vncserver.users 2>/dev/null \
    || echo ":1=$USER_NAME" >> /etc/tigervnc/vncserver.users
  if [[ ! -f "$cfg/passwd" && ! -f "$USER_HOME/.vnc/passwd" ]]; then
    echo "Set a VNC password for $USER_NAME (answer 'n' to view-only):"
    sudo -u "$USER_NAME" vncpasswd "$cfg/passwd"
  fi
  systemctl enable tigervncserver@:1.service
  systemctl restart tigervncserver@:1.service
}

tailscale() {
  log "Tailscale"
  . /etc/os-release
  curl -fsSL "https://pkgs.tailscale.com/stable/ubuntu/${VERSION_CODENAME}.noarmor.gpg" \
    -o /usr/share/keyrings/tailscale-archive-keyring.gpg
  curl -fsSL "https://pkgs.tailscale.com/stable/ubuntu/${VERSION_CODENAME}.tailscale-keyring.list" \
    -o /etc/apt/sources.list.d/tailscale.list
  apt-get -o DPkg::Lock::Timeout=600 update
  apt_install tailscale
  systemctl enable --now tailscaled
}

firewall() {
  log "UFW: deny inbound; SSH + VNC only over Tailscale; allow container/VM bridges"
  ufw default deny incoming
  ufw default allow outgoing
  ufw default deny routed
  ufw delete limit OpenSSH 2>/dev/null || true
  ufw limit in on tailscale0 to any port 22 proto tcp
  ufw allow in on tailscale0 to any port 5901 proto tcp
  for br in lxcbr0 virbr0; do
    ufw allow in on "$br" to any port 53
    ufw allow in on "$br" to any port 67 proto udp
    ufw route allow in on "$br"
    ufw route allow out on "$br"
  done
  ufw --force enable
  ufw status verbose
}

harden() {
  log "Hardening: fail2ban, kernel sysctls, automatic security updates"
  apt_install fail2ban python3-systemd unattended-upgrades apparmor-utils
  cat > /etc/fail2ban/jail.d/sshd.local <<'EOF'
[sshd]
enabled  = true
backend  = systemd
maxretry = 5
findtime = 10m
bantime  = 1h
EOF
  systemctl enable --now fail2ban
  systemctl restart fail2ban

  cat > /etc/sysctl.d/90-hardening.conf <<'EOF'
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2
kernel.kexec_load_disabled = 1
kernel.sysrq = 0
fs.suid_dumpable = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
EOF
  sysctl --system >/dev/null

  cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
}

virt() {
  log "virt-manager (QEMU/KVM)"
  apt_install virt-manager qemu-system-x86 qemu-utils libvirt-daemon-system libvirt-clients \
    ovmf swtpm swtpm-tools dnsmasq-base
  usermod -aG libvirt,kvm "$USER_NAME"
  systemctl enable --now libvirtd
  virsh net-autostart default 2>/dev/null || true
  virsh net-start default 2>/dev/null || true
}

lxc() {
  log "LXC with an unprivileged container '$CT' at $CT_IP"
  apt_install lxc uidmap debootstrap rsync xz-utils

  # Unprivileged: container root maps to an unused host uid range.
  grep -q '^root:1000000:65536' /etc/subuid || usermod --add-subuids 1000000-1065535 root
  grep -q '^root:1000000:65536' /etc/subgid || usermod --add-subgids 1000000-1065535 root

  if ! lxc-info -n "$CT" &>/dev/null; then
    cat > /etc/lxc/$CT.conf <<'EOF'
lxc.include = /etc/lxc/default.conf
lxc.idmap = u 0 1000000 65536
lxc.idmap = g 0 1000000 65536
lxc.start.auto = 1
EOF
    # images.linuxcontainers.org no longer ships Ubuntu, so the container runs Debian.
    lxc-create -n "$CT" -f /etc/lxc/$CT.conf -t download -- -d debian -r trixie -a amd64
  fi

  # Reserve the IP by MAC address, so it doesn't depend on the DHCP hostname.
  local mac
  mac="$(awk -F' *= *' '$1=="lxc.net.0.hwaddr"{print $2}' /var/lib/lxc/$CT/config)"
  if [[ -z "$mac" ]]; then
    mac="00:16:3e:$(openssl rand -hex 3 | sed 's/../&:/g;s/:$//')"
    echo "lxc.net.0.hwaddr = $mac" >> /var/lib/lxc/$CT/config
  fi
  echo "dhcp-host=$mac,$CT_IP" > /etc/lxc/dnsmasq.conf
  # An address set by LXC gets wiped by networkd inside the container, so the
  # static IP is configured inside the container instead (below).
  sed -i '/^lxc.net.0.ipv4.address/d; /^lxc.net.0.ipv4.gateway/d' /var/lib/lxc/$CT/config
  sed -i "/ $mac /d" /var/lib/misc/dnsmasq.lxcbr0.leases 2>/dev/null || true
  touch /etc/default/lxc-net
  grep -q '^USE_LXC_BRIDGE=' /etc/default/lxc-net || echo 'USE_LXC_BRIDGE="true"' >> /etc/default/lxc-net
  sed -i '/^#\?LXC_DHCP_CONFILE=/d' /etc/default/lxc-net
  echo 'LXC_DHCP_CONFILE=/etc/lxc/dnsmasq.conf' >> /etc/default/lxc-net

  # Let DHCP/DNS through on the bridge in case UFW is already on.
  if command -v ufw >/dev/null && ufw status | grep -q 'Status: active'; then
    ufw allow in on lxcbr0 to any port 53 >/dev/null
    ufw allow in on lxcbr0 to any port 67 proto udp >/dev/null
    ufw route allow in on lxcbr0 >/dev/null
    ufw route allow out on lxcbr0 >/dev/null
  fi

  lxc-stop -n "$CT" 2>/dev/null || true
  systemctl restart lxc-net
  lxc-start -n "$CT"
  for _ in $(seq 30); do lxc-attach -n "$CT" -- true 2>/dev/null && break; sleep 1; done
  sleep 3
  lxc-attach -n "$CT" --clear-env --set-var PATH=/usr/sbin:/usr/bin:/sbin:/bin -- sh -s "$CT_IP" <<'EOS'
ip="$1"
if [ -d /etc/systemd/network ]; then
  rm -f /etc/systemd/network/*.network
  printf '[Match]\nName=eth0\n\n[Network]\nAddress=%s/24\nGateway=10.0.3.1\nDNS=10.0.3.1\n' "$ip" \
    > /etc/systemd/network/eth0.network
  systemctl restart systemd-networkd 2>/dev/null || true
fi
if [ -f /etc/network/interfaces ] && grep -q 'eth0 inet dhcp' /etc/network/interfaces; then
  sed -i "s|iface eth0 inet dhcp|iface eth0 inet static\n    address $ip/24\n    gateway 10.0.3.1|" /etc/network/interfaces
  ifdown eth0 2>/dev/null; ifup eth0 2>/dev/null || true
fi
[ -L /etc/resolv.conf ] || echo 'nameserver 10.0.3.1' > /etc/resolv.conf
EOS
  for _ in $(seq 60); do
    lxc-info -n "$CT" -iH 2>/dev/null | grep -qx "$CT_IP" && break; sleep 1
  done
  if ! lxc-info -n "$CT" -iH | grep -qx "$CT_IP"; then
    echo "Container did not get $CT_IP. Diagnostics:"
    lxc-info -n "$CT" || true
    ip -br addr show lxcbr0 || true
    systemctl status lxc-net --no-pager | tail -5 || true
    exit 1
  fi
}

velociraptor() {
  log "Velociraptor server inside '$CT'"
  local A=(lxc-attach -n "$CT" --clear-env --set-var PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin --)
  "${A[@]}" sh -c 'id velociraptor >/dev/null 2>&1 || useradd --system --home /var/lib/velociraptor --shell /usr/sbin/nologin velociraptor'
  "${A[@]}" install -d -o velociraptor -g velociraptor -m 750 /var/lib/velociraptor /var/lib/velociraptor/logs
  "${A[@]}" install -d -m 750 -g velociraptor /etc/velociraptor
  "${A[@]}" sh -c 'cat > /usr/local/bin/velociraptor.new && chmod 755 /usr/local/bin/velociraptor.new && mv -f /usr/local/bin/velociraptor.new /usr/local/bin/velociraptor' < "$VR_BIN"
  "${A[@]}" sh -c 'cat > /etc/velociraptor/server.config.yaml && chgrp velociraptor /etc/velociraptor/server.config.yaml && chmod 640 /etc/velociraptor/server.config.yaml' \
    < "$VR_CONF_DIR/server.config.yaml"
  "${A[@]}" sh -c 'cat > /etc/systemd/system/velociraptor.service' <<'EOF'
[Unit]
Description=Velociraptor server
After=network-online.target

[Service]
User=velociraptor
Group=velociraptor
ExecStart=/usr/local/bin/velociraptor --config /etc/velociraptor/server.config.yaml frontend
Restart=on-failure
NoNewPrivileges=yes
ProtectSystem=full
ProtectHome=yes

[Install]
WantedBy=multi-user.target
EOF
  if ! "${A[@]}" sh -c 'ls /var/lib/velociraptor/users 2>/dev/null | grep -q .'; then
    echo "Create the Velociraptor GUI admin password:"
    "${A[@]}" su -s /bin/sh velociraptor -c \
      '/usr/local/bin/velociraptor --config /etc/velociraptor/server.config.yaml user add admin --role administrator'
  fi
  "${A[@]}" systemctl daemon-reload
  "${A[@]}" systemctl enable velociraptor.service
  "${A[@]}" systemctl restart velociraptor.service
}

velo-client() {
  log "Velociraptor client on this laptop (reports to the container)"
  install -m 755 "$VR_BIN" /usr/local/bin/velociraptor.new
  mv -f /usr/local/bin/velociraptor.new /usr/local/bin/velociraptor
  install -d -m 700 /etc/velociraptor
  install -m 600 "$VR_CONF_DIR/client.config.yaml" /etc/velociraptor/client.config.yaml
  cat > /etc/systemd/system/velociraptor-client.service <<'EOF'
[Unit]
Description=Velociraptor client
After=network-online.target lxc.service

[Service]
ExecStart=/usr/local/bin/velociraptor --config /etc/velociraptor/client.config.yaml client
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now velociraptor-client.service
}

zeek() {
  log "Zeek network monitor (openSUSE build service repo)"
  . /etc/os-release
  local repo="https://download.opensuse.org/repositories/security:/zeek/xUbuntu_${VERSION_ID}"
  install -d -m 755 /etc/apt/keyrings
  curl -fsSL "$repo/Release.key" | gpg --dearmor --yes -o /etc/apt/keyrings/zeek.gpg
  echo "deb [signed-by=/etc/apt/keyrings/zeek.gpg] $repo/ /" > /etc/apt/sources.list.d/zeek.list
  apt-get -o DPkg::Lock::Timeout=600 update
  apt_install zeek
  local iface
  iface="$(ip route show default | awk '{print $5; exit}')"
  sed -i "s/^interface=.*/interface=$iface/" /opt/zeek/etc/node.cfg
  cat > /etc/systemd/system/zeek.service <<'EOF'
[Unit]
Description=Zeek network security monitor
After=network-online.target
Wants=network-online.target

[Service]
Type=forking
ExecStart=/opt/zeek/bin/zeekctl deploy
ExecStop=/opt/zeek/bin/zeekctl stop
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
  echo '*/5 * * * * root /opt/zeek/bin/zeekctl cron' > /etc/cron.d/zeek
  echo 'export PATH="$PATH:/opt/zeek/bin"' > /etc/profile.d/zeek.sh
  systemctl daemon-reload
  systemctl enable --now zeek.service
  echo "Zeek logs: /opt/zeek/logs/current/  (interface: $iface)"
}

grub() {
  log "GRUB theme"
  [[ -d "$HERE/grub-theme/kool" ]] || { echo "No grub-theme/kool in the repo (third-party assets are not included) - skipping."; return; }
  rm -rf /boot/grub/themes/kool
  install -d /boot/grub/themes
  cp -r "$HERE/grub-theme/kool" /boot/grub/themes/kool
  cat > /etc/default/grub.d/99-kool-theme.cfg <<'EOF'
GRUB_TIMEOUT_STYLE=menu
GRUB_TIMEOUT=5
GRUB_GFXMODE=1920x1200,auto
GRUB_THEME=/boot/grub/themes/kool/theme.txt
EOF
  update-grub
}

login-screen() {
  log "Login screen (GDM): background + dark style"
  [[ -f "$HERE/login/login.png" ]] || { echo "No login/login.png in the repo (bring your own wallpaper) - skipping."; return; }
  install -d /usr/share/backgrounds/kool
  install -m 644 "$HERE/login/login.png" /usr/share/backgrounds/kool/login.png
  install -d /etc/dconf/db/gdm.d
  cat > /etc/dconf/db/gdm.d/10-kool <<'EOF'
[com/ubuntu/login-screen]
background-picture-uri='file:///usr/share/backgrounds/kool/login.png'
background-size='cover'
background-color='#000000'

[org/gnome/desktop/interface]
color-scheme='prefer-dark'
EOF
  [[ -f /etc/dconf/profile/gdm ]] || printf 'user-db:user\nsystem-db:gdm\nfile-db:/usr/share/gdm/greeter-dconf-defaults\n' > /etc/dconf/profile/gdm
  dconf update
  echo "Takes effect on the next login screen (log out or reboot)."
}

lynis() {
  log "Lynis security audit"
  apt_install lynis
  command lynis audit system --quick --no-colors > "$HERE/lynis-audit.txt" 2>&1 || true
  cp /var/log/lynis-report.dat "$HERE/lynis-report.dat"
  chown "$USER_NAME:" "$HERE/lynis-audit.txt" "$HERE/lynis-report.dat"
  grep -E 'Hardening index' "$HERE/lynis-audit.txt" || true
  echo "Full report: $HERE/lynis-audit.txt"
}

tools() {
  log "Extra tools: GitHub CLI, delta, Wireshark, nmap, Podman, Flameshot, Signal, Obsidian, terminal helpers"
  echo "wireshark-common wireshark-common/install-setuid boolean true" | debconf-set-selections
  apt_install gh git-delta wireshark nmap bat fzf zoxide 7zip
  usermod -aG wireshark "$USER_NAME"
  apt-get purge -y keepassxc keepassxc-full 2>/dev/null || true   # Proton Pass replaces it

  # Podman (rootless), flameshot for report screenshots (grim is its Wayland backend)
  apt_install podman podman-compose uidmap slirp4netns flameshot grim slurp

  # Signal Desktop from Signal's own apt repo
  curl -fsSL https://updates.signal.org/desktop/apt/keys.asc | gpg --dearmor --yes -o /usr/share/keyrings/signal-desktop-keyring.gpg
  echo 'deb [arch=amd64 signed-by=/usr/share/keyrings/signal-desktop-keyring.gpg] https://updates.signal.org/desktop/apt xenial main' \
    > /etc/apt/sources.list.d/signal-desktop.list
  apt-get -o DPkg::Lock::Timeout=600 update
  apt_install signal-desktop

  # Obsidian (publisher-built snap, needs classic confinement)
  snap list obsidian &>/dev/null || snap install obsidian --classic
}

ssh-key() {
  log "SSH key for GitHub and Git commit signing"
  local key="$USER_HOME/.ssh/id_ed25519"
  if [[ ! -f "$key" ]]; then
    echo "Choose a passphrase for your SSH key (recommended):"
    sudo -u "$USER_NAME" ssh-keygen -t ed25519 -C "$(sudo -u "$USER_NAME" git config user.email)" -f "$key"
  fi
  # Lets `git log --show-signature` verify your own signed commits.
  printf '%s %s\n' "$(sudo -u "$USER_NAME" git config user.email)" "$(cut -d' ' -f1,2 "$key.pub")" \
    > "$USER_HOME/.ssh/allowed_signers"
  chown "$USER_NAME:" "$USER_HOME/.ssh/allowed_signers"
  sudo -u "$USER_NAME" git config --global gpg.ssh.allowedSignersFile "$USER_HOME/.ssh/allowed_signers"
  echo "Public key (add it to GitHub as both an Authentication and a Signing key):"
  cat "$key.pub"
}

security-extra() {
  log "auditd, rkhunter, chkrootkit, ClamAV, debsums, needrestart, password quality"
  apt_install auditd audispd-plugins rkhunter chkrootkit clamav clamav-freshclam \
    debsums needrestart libpam-pwquality

  cat > /etc/audit/rules.d/50-kool.rules <<'EOF'
# Changes to accounts, sudo, SSH and login config
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers
-w /etc/ssh/sshd_config -p wa -k sshd
-w /etc/ssh/sshd_config.d/ -p wa -k sshd
-w /etc/pam.d/ -p wa -k pam
# Persistence locations
-w /etc/systemd/system/ -p wa -k systemd
-w /etc/cron.d/ -p wa -k cron
-w /etc/crontab -p wa -k cron
-w /var/spool/cron/ -p wa -k cron
# Kernel modules and privilege use
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k modules
-w /usr/bin/sudo -p x -k priv
-w /usr/bin/su -p x -k priv
EOF
  # Filebeat's auditd module expects RAW logs; the Ubuntu default (ENRICHED) corrupts the rule key field.
  sed -i 's/^log_format *=.*/log_format = RAW/' /etc/audit/auditd.conf
  systemctl enable --now auditd
  service auditd restart || true
  augenrules --load

  sed -i 's/^CRON_DAILY_RUN=.*/CRON_DAILY_RUN="true"/; s/^APT_AUTOGEN=.*/APT_AUTOGEN="true"/' /etc/default/rkhunter
  systemctl enable --now clamav-freshclam

  cat > /etc/systemd/system/clamav-weekly-scan.service <<EOF
[Unit]
Description=Weekly ClamAV scan of home folders

[Service]
Type=oneshot
Nice=19
IOSchedulingClass=idle
ExecStart=/bin/sh -c 'clamscan -r -i --exclude-dir="^$USER_HOME/laptop-setup/dl" --exclude-dir="^$USER_HOME/.cache" --log=/var/log/clamav/weekly-scan.log /home; [ \$? -le 1 ]'
EOF
  cat > /etc/systemd/system/clamav-weekly-scan.timer <<'EOF'
[Unit]
Description=Weekly ClamAV scan

[Timer]
OnCalendar=Sun 13:00
Persistent=true

[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload
  systemctl enable --now clamav-weekly-scan.timer
}

secureboot() {
  log "Secure Boot / firmware status"
  mokutil --sb-state
  echo "Kernel lockdown: $(cat /sys/kernel/security/lockdown)"
  apt_install fwupd
  fwupdmgr refresh --force >/dev/null 2>&1 || true
  echo "Firmware / Secure Boot revocation (dbx) updates available:"
  fwupdmgr get-updates 2>&1 || true
  echo "Apply them later with: sudo fwupdmgr update  (may reboot)"
}

kali() {
  log "Kali Linux VM in QEMU/KVM"
  local src="$HERE/dl/kali/kali-linux-2026.3-qemu-amd64.7z"
  local img=/var/lib/libvirt/images/kali.qcow2
  if virsh dominfo kali &>/dev/null; then echo "VM 'kali' already exists."; return; fi
  [[ -f "$src" ]] || { echo "Kali image not downloaded yet - skipping. Re-run: sudo bash $0 kali"; return; }
  if ! ( cd "$HERE/dl/kali" && grep " ${src##*/}\$" SHA256SUMS | sha256sum -c - ); then
    echo "Kali image incomplete or corrupt (still downloading?) - skipping. Re-run: sudo bash $0 kali"
    return
  fi
  if [[ ! -f "$img" ]]; then
    local tmp; tmp="$(mktemp -d /var/lib/libvirt/images/kali-extract.XXXX)"
    "$(command -v 7z || command -v 7zz)" x -o"$tmp" "$src"
    mv "$(find "$tmp" -name '*.qcow2' | head -1)" "$img"
    rm -rf "$tmp"
  fi
  virt-install --name kali --memory 4096 --vcpus 4 --cpu host-passthrough \
    --import --disk path="$img",bus=virtio \
    --osinfo detect=on,require=off \
    --network network=default,model=virtio \
    --graphics vnc,listen=127.0.0.1 --video virtio \
    --noautoconsole
  virsh shutdown kali >/dev/null 2>&1 || true
  echo "Kali VM ready in virt-manager. Login kali / kali - change it with 'passwd' on first boot."
}

backups() {
  log "Timeshift system snapshots (one daily snapshot, only the latest kept); home goes to Proton Drive via restic"
  apt_install timeshift
  local uuid; uuid="$(findmnt -no UUID /)"
  install -d /etc/timeshift
  cat > /etc/timeshift/timeshift.json <<EOF
{
  "backup_device_uuid" : "$uuid",
  "parent_device_uuid" : "",
  "do_first_run" : "false",
  "btrfs_mode" : "false",
  "include_btrfs_home_for_backup" : "false",
  "include_btrfs_home_for_restore" : "false",
  "stop_cron_emails" : "true",
  "schedule_monthly" : "false",
  "schedule_weekly" : "false",
  "schedule_daily" : "true",
  "schedule_hourly" : "false",
  "schedule_boot" : "false",
  "count_monthly" : "1",
  "count_weekly" : "1",
  "count_daily" : "1",
  "count_hourly" : "1",
  "count_boot" : "1",
  "date_format" : "%Y-%m-%d %H:%M:%S",
  "exclude" : [
    "/home/**",
    "/root/**",
    "/var/lib/libvirt/images/**",
    "/opt/zeek/logs/**",
    "/var/cache/**",
    "/swap.img"
  ],
  "exclude-apps" : []
}
EOF
  echo '0 * * * * root timeshift --check --scripted >/dev/null 2>&1' > /etc/cron.d/timeshift-hourly
  if ! timeshift --list 2>/dev/null | grep -q 'initial setup'; then
    echo "Creating the first snapshot (several minutes)..."
    timeshift --create --comments "initial setup" --tags O --scripted
  fi
}

proton() {
  log "Proton VPN, Pass, Mail (includes Calendar) + rclone/restic for Proton Drive backups"
  local d="$HERE/dl/proton"
  apt_install "$d/protonvpn-stable-release_1.0.10_all.deb"
  apt-get -o DPkg::Lock::Timeout=600 update
  # With recommends: pulls in the tray-icon libraries Waybar needs.
  apt-get -o DPkg::Lock::Timeout=600 install -y proton-vpn-gnome-desktop
  apt-get -o DPkg::Lock::Timeout=600 install -y "$d/proton-pass.deb" "$d/proton-mail.deb"

  apt_install restic libsecret-1-0
  local tmp; tmp="$(mktemp -d)"
  unzip -q "$HERE/dl/rclone/rclone-v1.75.1-linux-amd64.zip" -d "$tmp"
  install -m 755 "$tmp"/rclone-v1.75.1-linux-amd64/rclone /usr/local/bin/rclone
  rm -rf "$tmp"
  /usr/local/bin/rclone version | head -1
  echo "Next (as yourself, no sudo): bash ~/laptop-setup/backup/setup-protondrive.sh"
}

dock() {
  log "macOS-style dock (nwg-dock-hyprland v0.4.11, built from source)"
  apt_install libgtk-3-dev libgtk-layer-shell-dev libgirepository1.0-dev golang-go
  local src="$HERE/src/nwg-dock-hyprland"
  sudo -u "$USER_NAME" sh -c "cd '$src' && go build -o bin/nwg-dock-hyprland ."
  install -m 755 "$src/bin/nwg-dock-hyprland" /usr/local/bin/nwg-dock-hyprland
  install -d /usr/share/nwg-dock-hyprland
  cp -r "$src/images" /usr/share/nwg-dock-hyprland/
  cp "$src"/config/* /usr/share/nwg-dock-hyprland/

  # The snap Firefox .desktop lives in /var/lib/snapd/desktop, which the dock doesn't search,
  # so its icon was blank. A copy in ~/.local/share/applications fixes that (same id as the window class).
  install -d -o "$USER_NAME" -g "$USER_NAME" "$USER_HOME/.local/share/applications"
  local sd
  for sd in firefox_firefox:firefox_firefox obsidian_obsidian:obsidian; do
    [[ -f /var/lib/snapd/desktop/applications/${sd%%:*}.desktop ]] || continue
    install -o "$USER_NAME" -g "$USER_NAME" -m 644 /var/lib/snapd/desktop/applications/${sd%%:*}.desktop \
      "$USER_HOME/.local/share/applications/${sd##*:}.desktop"
  done

  # Starting apps in the dock (only those actually installed).
  local pinned="$USER_HOME/.cache/nwg-dock-pinned" app
  if [[ ! -s "$pinned" ]]; then
    : > "$pinned"
    for app in kitty firefox_firefox org.gnome.Nautilus nvim proton-mail proton-pass signal-desktop obsidian \
               proton.vpn.app.gtk org.gnome.Settings virt-manager org.wireshark.Wireshark; do
      if [[ -e /usr/share/applications/$app.desktop || -e /var/lib/snapd/desktop/applications/$app.desktop \
            || -e "$USER_HOME/.local/share/applications/$app.desktop" ]]; then
        echo "$app" >> "$pinned"
      fi
    done
    chown "$USER_NAME:" "$pinned"
  fi
  echo "Pinned: $(paste -sd' ' "$pinned")"
  sudo -u "$USER_NAME" XDG_RUNTIME_DIR="/run/user/$(id -u "$USER_NAME")" \
    HYPRLAND_INSTANCE_SIGNATURE="$(ls -t /run/user/$(id -u "$USER_NAME")/hypr 2>/dev/null | head -1)" \
    WAYLAND_DISPLAY=wayland-1 "$USER_HOME/.config/hypr/scripts/Dock.sh" restart || true
}

backup-fix() {
  log "Move Proton Drive backup settings from root to $USER_NAME"
  local f
  for f in rclone/rclone.conf restic/password; do
    if [[ -f /root/.config/$f ]]; then
      install -d -o "$USER_NAME" -g "$USER_NAME" -m 700 "$USER_HOME/.config/${f%/*}"
      install -o "$USER_NAME" -g "$USER_NAME" -m 600 "/root/.config/$f" "$USER_HOME/.config/$f"
      rm -f "/root/.config/$f"
      echo "Moved $f"
    fi
  done
  echo "Now run (no sudo): bash ~/laptop-setup/backup/setup-protondrive.sh"
}

vmware() {
  log "VMware Workstation (for SANS labs) + Secure Boot module signing"
  local bundle; bundle="$(ls "$USER_HOME"/VMware-Workstation-Full-*.bundle 2>/dev/null | sort | tail -1 || true)"
  [[ -n "$bundle" ]] || { echo "No VMware-Workstation-Full-*.bundle in $USER_HOME - skipping."; return; }
  apt_install build-essential "linux-headers-$(uname -r)" dkms mokutil openssl

  if [[ ! -x /usr/bin/vmware ]]; then
    bash "$bundle" --eulas-agreed --required --console
  fi

  # Secure Boot only loads signed modules: make a MOK key, sign vmmon/vmnet with it.
  local keydir=/var/lib/shim-signed/mok
  if mokutil --sb-state 2>/dev/null | grep -q enabled; then
    install -d -m 700 "$keydir"
    if [[ ! -f $keydir/MOK.priv ]]; then
      openssl req -new -x509 -newkey rsa:2048 -nodes -days 3650 -sha256 \
        -subj "/CN=$(hostname) VMware module signing/" \
        -keyout "$keydir/MOK.priv" -outform DER -out "$keydir/MOK.der"
      chmod 600 "$keydir/MOK.priv"
    fi
    if ! mokutil --test-key "$keydir/MOK.der" 2>&1 | grep -q 'already enrolled'; then
      echo "Pick a one-time password (you'll type it on the blue MOK screen at next boot):"
      mokutil --import "$keydir/MOK.der"
      NEED_MOK=1
    fi
  fi

  vmware-modconfig --console --install-all || true
  if [[ -f $keydir/MOK.priv ]]; then
    local ko
    for ko in "/lib/modules/$(uname -r)"/misc/vmmon.ko* "/lib/modules/$(uname -r)"/misc/vmnet.ko*; do
      [[ -e $ko ]] || continue
      case "$ko" in
        *.ko) /usr/src/linux-headers-"$(uname -r)"/scripts/sign-file sha256 "$keydir/MOK.priv" "$keydir/MOK.der" "$ko" ;;
        *) echo "Compressed module $ko: sign it manually (decompress, sign-file, recompress)." ;;
      esac
    done
    depmod -a
  fi
  # VMware and KVM both want VT-x; VMware 17+ can share it, but not while a KVM guest is running.
  modprobe vmmon 2>/dev/null && echo "vmmon loaded." || echo "vmmon not loaded yet - reboot and enrol the MOK key if prompted."
  [[ -z "${NEED_MOK:-}" ]] || echo "REBOOT, then on the blue 'MOK management' screen choose Enroll MOK -> Continue -> Yes -> enter the password."
}

power() {
  log "Power: powertop + 'powermode' command; performance on AC, power-saver on battery"
  apt_install powertop power-profiles-daemon thermald
  install -m 755 "$HERE/bin/powermode" /usr/local/bin/powermode
  cat > /etc/udev/rules.d/99-power-profile.rules <<'EOF2'
# Plug in -> performance, unplug -> power-saver (manual 'powermode' changes stick until the next plug/unplug)
SUBSYSTEM=="power_supply", ATTR{type}=="Mains", ATTR{online}=="1", RUN+="/usr/bin/systemd-run --no-block /usr/bin/powerprofilesctl set performance"
SUBSYSTEM=="power_supply", ATTR{type}=="Mains", ATTR{online}=="0", RUN+="/usr/bin/systemd-run --no-block /usr/bin/powerprofilesctl set power-saver"
EOF2
  udevadm control --reload
  systemctl enable --now power-profiles-daemon thermald
  if [[ "$(cat /sys/class/power_supply/AC/online 2>/dev/null)" == 1 ]]; then
    powerprofilesctl set performance || true
  else
    powerprofilesctl set power-saver || true
  fi
  echo "Now: $(powerprofilesctl get). Change by hand: powermode saver|balanced|performance|cycle"
}

desktop-tweaks() {
  log "Caffeine command, Settings app launcher"
  install -m 755 "$HERE/bin/caffeine" /usr/local/bin/caffeine
  apt_install gnome-control-center nwg-look pavucontrol
  # gnome-control-center hides most panels unless it thinks it's on GNOME.
  local apps="$USER_HOME/.local/share/applications"
  install -d -o "$USER_NAME" -g "$USER_NAME" "$apps"
  sed 's|^Exec=gnome-control-center|Exec=env XDG_CURRENT_DESKTOP=GNOME gnome-control-center|' \
    /usr/share/applications/org.gnome.Settings.desktop > "$apps/org.gnome.Settings.desktop"
  chown "$USER_NAME:" "$apps/org.gnome.Settings.desktop"
  # The dock doesn't open a terminal for Terminal=true apps, so nvim did nothing when clicked.
  sed -e 's|^Exec=nvim %F|Exec=kitty --class nvim -e nvim %F|' -e 's|^Terminal=true|Terminal=false|' \
    /usr/share/applications/nvim.desktop > "$apps/nvim.desktop"
  chown "$USER_NAME:" "$apps/nvim.desktop"
  echo "Toggle caffeine with: caffeine   (Super+Shift+I once Hyprland is reloaded)"
}

dev() {
  log "Dev extras: direnv, clangd, shfmt, sqlite, httpie, git-lfs, hyperfine, uv, ruff"
  apt_install direnv clangd shfmt sqlite3 httpie git-lfs hyperfine universal-ctags yq cmake gdb
  # Python tools are per-user (pipx), so they don't touch system Python.
  sudo -u "$USER_NAME" env PATH="$USER_HOME/.local/bin:$PATH" sh -c 'pipx install uv || true; pipx install ruff || true'
  sudo -u "$USER_NAME" git lfs install >/dev/null || true
  grep -q 'direnv hook zsh' "$USER_HOME/.zshrc" 2>/dev/null \
    || echo 'eval "$(direnv hook zsh)"' >> "$USER_HOME/.zshrc"
  systemctl --user --machine="$USER_NAME@.host" enable --now podman.socket 2>/dev/null || true
  echo "LSPs/formatters for Neovim: open nvim and run :Mason (LazyVim installs most on demand)."
}

harden2() {
  log "Extra hardening from the Lynis report (dev-friendly: SSH forwarding and ptrace stay usable)"
  apt_install apt-listchanges libpam-tmpdir apt-show-versions aide

  # SSH: tighter limits; password login is only turned off once a key is installed.
  local pw="yes"
  [[ -s "$USER_HOME/.ssh/authorized_keys" ]] && pw="no"
  cat > /etc/ssh/sshd_config.d/20-hardening2.conf <<EOF2
LogLevel VERBOSE
MaxSessions 4
ClientAliveCountMax 2
ClientAliveInterval 300
TCPKeepAlive no
AllowAgentForwarding no
PasswordAuthentication $pw
EOF2
  sshd -t && systemctl reload ssh
  echo "SSH password login: $pw (becomes 'no' automatically on re-run once ~/.ssh/authorized_keys has a key)"

  [[ -f /etc/fail2ban/jail.local ]] || cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local

  # Rare network protocols that have had many kernel CVEs.
  local p
  : > /etc/modprobe.d/90-rare-protocols.conf
  for p in dccp sctp rds tipc; do echo "install $p /bin/false" >> /etc/modprobe.d/90-rare-protocols.conf; done

  if grep -q '^UMASK' /etc/login.defs; then sed -i 's/^UMASK.*/UMASK\t\t027/' /etc/login.defs
  else printf 'UMASK\t\t027\n' >> /etc/login.defs; fi

  cat > /etc/sysctl.d/91-hardening2.conf <<'EOF2'
kernel.yama.ptrace_scope = 1
kernel.randomize_va_space = 2
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv4.icmp_ignore_bogus_error_responses = 1
EOF2
  sysctl --system >/dev/null

  sed -i 's/^CRON_CHECK=.*/CRON_CHECK=weekly/' /etc/default/debsums 2>/dev/null || true
  dpkg -l | awk '/^rc/{print $2}' | xargs -r dpkg --purge

  # AIDE watches /home only (a whole-disk scan took ~an hour and fought apt for its lock).
  # System-level changes are covered by auditd, debsums, rkhunter and the SIEM.
  [[ -f /etc/aide/aide.conf.orig ]] || cp /etc/aide/aide.conf /etc/aide/aide.conf.orig
  install -m 644 "$HERE/dotfiles/aide-home.conf" /etc/aide/aide.conf
  if [[ ! -f /var/lib/aide/aide.db ]]; then
    aide --config /etc/aide/aide.conf --init >/dev/null 2>&1 || true
    if [[ -f /var/lib/aide/aide.db.new ]]; then cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db; fi
  fi
}

usb() {
  log "USBGuard: block unknown USB devices (current ones are allowed)"
  apt_install usbguard
  # Only (re)generate the allow-list when it is empty, so re-runs never lock out new trusted devices.
  if [[ ! -s /etc/usbguard/rules.conf ]]; then
    usbguard generate-policy > /etc/usbguard/rules.conf
    chmod 600 /etc/usbguard/rules.conf
  fi
  sed -i 's/^IPCAllowedUsers=.*/IPCAllowedUsers=root '"$USER_NAME"'/' /etc/usbguard/usbguard-daemon.conf
  systemctl enable --now usbguard
  systemctl restart usbguard
  # Allow/deny popup for new devices (user service); needs yad for the dialog.
  apt_install yad
  sudo -u "$USER_NAME" install -d "$USER_HOME/.local/bin" "$USER_HOME/.config/systemd/user"
  sudo -u "$USER_NAME" install -m 755 "$HERE/bin/usbguard-prompt" "$USER_HOME/.local/bin/usbguard-prompt"
  sudo -u "$USER_NAME" install -m 644 "$HERE/dotfiles/usbguard-prompt.service" "$USER_HOME/.config/systemd/user/usbguard-prompt.service"
  loginctl enable-linger "$USER_NAME" >/dev/null 2>&1 || true
  sudo -u "$USER_NAME" XDG_RUNTIME_DIR="/run/user/$(id -u "$USER_NAME")" systemctl --user daemon-reload || true
  sudo -u "$USER_NAME" XDG_RUNTIME_DIR="/run/user/$(id -u "$USER_NAME")" systemctl --user enable --now usbguard-prompt.service \
    || echo "Enable it from your desktop session: systemctl --user enable --now usbguard-prompt"
  echo "Allow a new device:  sudo usbguard list-devices -b ; sudo usbguard allow-device <id> -p"
}

cdev() {
  log "C toolchain + shell/dev CLI tools + secret scanning"
  apt_install clang valgrind cppcheck bear cgdb manpages-dev manpages-posix-dev make \
    atuin eza tealdeer duf just gitleaks pre-commit
  local t; t="$(mktemp -d)"
  # yazi (file manager) and zellij (multiplexer) from their official GitHub releases
  curl -fsSL -o "$t/y.zip" https://github.com/sxyazi/yazi/releases/download/v26.9.1/yazi-x86_64-unknown-linux-musl.zip
  unzip -qo "$t/y.zip" -d "$t"; install -m 755 "$t"/yazi-x86_64-unknown-linux-musl/{yazi,ya} /usr/local/bin/
  curl -fsSL -o "$t/z.tgz" https://github.com/zellij-org/zellij/releases/download/v0.45.1/zellij-x86_64-unknown-linux-musl.tar.gz
  curl -fsSL -o "$t/z.sha" https://github.com/zellij-org/zellij/releases/download/v0.45.1/zellij-x86_64-unknown-linux-musl.sha256sum
  tar xzf "$t/z.tgz" -C "$t"
  [[ "$(sha256sum "$t/zellij" | cut -d' ' -f1)" == "$(cut -d' ' -f1 "$t/z.sha")" ]] || { echo "zellij checksum mismatch"; rm -rf "$t"; return 1; }
  install -m 755 "$t/zellij" /usr/local/bin/zellij
  rm -rf "$t"
  # Per-user: starter C project, global gitleaks pre-commit hook
  sudo -u "$USER_NAME" mkdir -p "$USER_HOME/c-lab" "$USER_HOME/.config/git/hooks"
  [[ -f "$USER_HOME/c-lab/Makefile" ]] || sudo -u "$USER_NAME" cp -r "$HERE/dotfiles/c-lab/." "$USER_HOME/c-lab/"
  install -o "$USER_NAME" -g "$USER_NAME" -m 755 "$HERE/dotfiles/git-pre-commit" "$USER_HOME/.config/git/hooks/pre-commit"
  sudo -u "$USER_NAME" git config --global core.hooksPath "$USER_HOME/.config/git/hooks"
}

memtools() {
  log "Memory forensics: Volatility 3 + LiME capture ('sudo memdump')"
  sudo -u "$USER_NAME" env PATH="$USER_HOME/.local/bin:$PATH" pipx install volatility3 || true
  apt_install lime-forensics-dkms
  install -m 755 "$HERE/bin/memdump" /usr/local/bin/memdump
  echo "LiME loads only after the Secure Boot MOK key is enrolled. See $HERE/MEMORY-FORENSICS.md"
}

rice() {
  log "Look and feel: random fastfetch art, readable terminal colours, power draw in Waybar"
  local H="$USER_HOME/.config/hypr" F="$USER_HOME/.config/fastfetch"
  sudo -u "$USER_NAME" mkdir -p "$F/art" "$USER_HOME/.local/bin" "$H/UserScripts"
  sudo -u "$USER_NAME" cp -r "$HERE/dotfiles/fastfetch-art/." "$F/art/"
  sudo -u "$USER_NAME" install -m 755 "$HERE/bin/ff" "$USER_HOME/.local/bin/ff"
  sudo -u "$USER_NAME" install -m 755 "$HERE/bin/KittyContrast.py" "$H/UserScripts/KittyContrast.py"
  sudo -u "$USER_NAME" install -m 755 "$HERE/bin/PowerDraw.sh" "$H/UserScripts/PowerDraw.sh"
  sudo -u "$USER_NAME" install -m 755 "$HERE/bin/SiemStats.sh" "$H/UserScripts/SiemStats.sh"
  sudo -u "$USER_NAME" install -m 755 "$HERE/bin/soc" "$HERE/bin/avd" "$HERE/bin/barpin" "$HERE/bin/dockpin" "$USER_HOME/.local/bin/"
  # Login screen follows the wallpaper: root helper, called from WallustSwww.sh via sudo.
  install -m 755 "$HERE/bin/sync-login-wallpaper" /usr/local/sbin/sync-login-wallpaper
  sudo -u "$USER_NAME" install -m 755 "$HERE/bin/caffeine" "$HERE/bin/powermode" "$USER_HOME/.local/bin/"
  echo "Keybinds, Waybar module and .zshrc edits are in $HERE/dotfiles/README-rice.md (apply by hand or ask Claude)."
}

siem() {
  log "SIEM: Elasticsearch + Kibana + Filebeat (Zeek, auditd, syslog) in rootful Podman, localhost only"
  apt_install podman podman-compose curl openssl
  bash "$HERE/siem/install.sh"
}

zram() {
  log "Memory: compressed swap in RAM (zram) + earlyoom"
  apt_install systemd-zram-generator earlyoom
  cat > /etc/systemd/zram-generator.conf <<'EOF2'
[zram0]
zram-size = ram / 2
compression-algorithm = zstd
swap-priority = 100
EOF2
  cat > /etc/sysctl.d/92-zram.conf <<'EOF2'
vm.swappiness = 100
vm.page-cluster = 0
EOF2
  cat > /etc/default/earlyoom <<'EOF2'
EARLYOOM_ARGS="-r 3600 -m 5 -s 10 --avoid '(^|/)(Hyprland|sshd|Xtigervnc|tailscaled|auditd|dockerd|podman|conmon|elasticsearch|java)$' --prefer '(^|/)(chrome|firefox|electron|node)$'"
EOF2
  sysctl --system >/dev/null
  systemctl daemon-reload
  # The package starts zram0 with its own defaults; restart so ours (7 GB, zstd) take effect.
  systemctl stop systemd-zram-setup@zram0.service 2>/dev/null || true
  systemctl start systemd-zram-setup@zram0.service
  systemctl enable earlyoom
  systemctl restart earlyoom
  swapon --show
}

baseline() {
  log "rkhunter baseline of system files (run after installs)"
  rkhunter --propupd --quiet || true
}

ALL=(backup-fix packages remove-vscode tools ssh ssh-key vnc tailscale firewall harden security-extra secureboot virt kali lxc velociraptor velo-client zeek proton backups vmware power desktop-tweaks zram dev harden2 usb cdev memtools rice dock grub login-screen siem baseline lynis)
# Everything not yet done after the first runs (short, so it doesn't wrap when pasted).
FINISH=(dock kali grub login-screen siem baseline lynis)
[[ $# -eq 0 || "$1" == all ]] && set -- "${ALL[@]}"
[[ "${1:-}" == finish ]] && set -- "${FINISH[@]}"
for s in "$@"; do
  [[ " ${ALL[*]} " == *" $s "* ]] || { echo "Unknown section: $s"; exit 1; }
  CURRENT="$s"
  "$s"
done
log "Done: $*"
[[ " $* " == *" tailscale "* ]] && echo "Next: run 'sudo tailscale up' and log in with the link it prints."
true
