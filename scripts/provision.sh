#!/usr/bin/env bash
#
# provision.sh
# Run once, as root, on a fresh Linux VM (intended for a Proxmox guest)
# before "docker compose up -d --build".
#
# What it does:
#   1. Installs Docker Engine + Compose plugin (if missing)
#   2. Creates /opt/admin/logs (bind-mounted into the app container)
#   3. Creates the Blue Team SSH user (analyst / blue_team_rocks) and
#      exposes SSH on the custom port 2275, alongside the existing sshd
#      on 22 (so you don't lock yourself out of admin access)
#
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Please run as root (sudo ./provision.sh)" >&2
  exit 1
fi

echo "[1/3] Installing Docker (if needed)..."
if ! command -v docker &> /dev/null; then
  curl -fsSL https://get.docker.com | sh
  systemctl enable --now docker
else
  echo "  Docker already installed, skipping."
fi

echo "[2/3] Creating /opt/admin/logs ..."
mkdir -p /opt/admin/logs
chmod 755 /opt/admin/logs

echo "[3/3] Creating Blue Team SSH user on port 2275 ..."
BLUE_USER="analyst"
BLUE_PASS="blue_team_rocks"

if ! id -u "$BLUE_USER" &> /dev/null; then
  useradd -m -s /bin/bash "$BLUE_USER"
fi
echo "${BLUE_USER}:${BLUE_PASS}" | chpasswd

# Read-only access to the shared log directory for the Blue Team account
setfacl -R -m u:"${BLUE_USER}":rx /opt/admin/logs 2>/dev/null || \
  chmod -R o+rx /opt/admin/logs

SSHD_CONFIG="/etc/ssh/sshd_config"
if ! grep -qE "^Port 2275$" "$SSHD_CONFIG"; then
  cp "$SSHD_CONFIG" "${SSHD_CONFIG}.bak.$(date +%s)"
  # Keep the existing Port line(s) intact and just add 2275 alongside it,
  # so you don't lose your normal admin SSH access on 22.
  echo "Port 2275" >> "$SSHD_CONFIG"
  echo "PasswordAuthentication yes" >> "$SSHD_CONFIG"
fi

systemctl restart sshd || systemctl restart ssh

echo ""
echo "Done. Blue Team can now: ssh ${BLUE_USER}@<vm-ip> -p 2275"
echo "Next: cd into this repo and run: docker compose up -d --build"
