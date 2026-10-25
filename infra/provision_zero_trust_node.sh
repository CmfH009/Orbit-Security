#!/usr/bin/env bash
# ==============================================================================
# provision_zero_trust_node.sh: Standalone Zero-Trust Provisioner for Project Orbit
# ==============================================================================
# Sets up a 24/7 hardened Linux node (Oracle Cloud ARM64 / Ubuntu):
# - Enforces UFW zero public ingress (all ports closed, Tailscale mesh only)
# - Creates isolated non-root 'orbit' system account
# - Installs Tailscale and registers daemon
# - Sets up Python 3 venv and hardened systemd service unit
# ==============================================================================

set -euo pipefail

CYAN='\033[0;36m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() { echo -e "${CYAN}[INFO]${NC} $1"; }
log_ok()   { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_err()  { echo -e "${RED}[ERROR]${NC} $1" >&2; }

# Guard: Must be run as root
if [[ "$EUID" -ne 0 ]]; then
    log_err "This script must be run as root (use sudo)."
    exit 1
fi

ARCH=$(uname -m)
log_info "Detected Host Architecture: ${ARCH}"
if [[ "${ARCH}" != "aarch64" && "${ARCH}" != "x86_64" ]]; then
    log_warn "Untested architecture: ${ARCH}. Proceeding with standard wheels."
fi

# Step 1: System Package Updates
log_info "Updating system packages..."
apt-get update -qq
apt-get install -y -qq ufw curl git ca-certificates python3-venv python3-pip unattended-upgrades

# Step 2: Zero-Trust UFW Firewall Configuration
log_info "Enforcing Zero Ingress UFW Firewall..."
ufw default deny incoming
ufw default allow outgoing
# Allow traffic on Tailscale mesh VPN only
ufw allow in on tailscale0 comment "Orbit Private Tailscale Mesh"
ufw --force enable
log_ok "Firewall active: All public internet ports blocked. Only Tailscale mesh allowed."

# Step 3: Install Tailscale if not present
if ! command -v tailscale &> /dev/null; then
    log_info "Installing Tailscale..."
    curl -fsSL https://tailscale.com/install.sh | sh
    log_ok "Tailscale installed successfully."
else
    log_ok "Tailscale already present on host."
fi

# Step 4: Create isolated 'orbit' system user
if ! id "orbit" &>/dev/null; then
    log_info "Creating system user 'orbit'..."
    useradd --system --shell /bin/bash --home-dir /home/orbit --create-home orbit
    log_ok "User 'orbit' created."
fi

# Step 5: Install Orbit Security Codebase
ORBIT_INSTALL_DIR="/opt/orbit-security"
if [[ ! -d "${ORBIT_INSTALL_DIR}" ]]; then
    log_info "Cloning Orbit Security repository..."
    git clone https://github.com/CmfH009/Orbit-Security.git "${ORBIT_INSTALL_DIR}"
else
    log_info "Orbit repository exists at ${ORBIT_INSTALL_DIR}, pulling latest main..."
    git -C "${ORBIT_INSTALL_DIR}" pull origin main
fi

# Step 6: Virtualenv and Dependencies
log_info "Setting up Python virtual environment..."
python3 -m venv "${ORBIT_INSTALL_DIR}/.venv"
"${ORBIT_INSTALL_DIR}/.venv/bin/pip" install --upgrade pip -q
"${ORBIT_INSTALL_DIR}/.venv/bin/pip" install dnspython httpx pydantic psutil -q
"${ORBIT_INSTALL_DIR}/.venv/bin/pip" install -e "${ORBIT_INSTALL_DIR}" -q

# Set permissions
mkdir -p "${ORBIT_INSTALL_DIR}/data" "${ORBIT_INSTALL_DIR}/logs"
chown -R orbit:orbit "${ORBIT_INSTALL_DIR}"
log_ok "Python environment and filesystem ownership configured."

# Step 7: Install Hardened Systemd Service Unit
SERVICE_FILE="/etc/systemd/system/orbit-security.service"
log_info "Installing hardened systemd service unit..."
cat << 'EOF' > "${SERVICE_FILE}"
[Unit]
Description=Orbit Security 24/7 Autonomous Threat Radar & Sentinel
After=network.target tailscaled.service
Wants=tailscaled.service

[Service]
Type=simple
User=orbit
Group=orbit
WorkingDirectory=/opt/orbit-security
Environment=PYTHONUNBUFFERED=1
Environment=PYTHONDONTWRITEBYTECODE=1
Environment=PYTHONPATH=/opt/orbit-security/src
Environment=ORBIT_WORKSPACE_ROOT=/opt/orbit-security
ExecStart=/opt/orbit-security/.venv/bin/python src/orbit_security/bounty_rolling_daemon.py
Restart=always
RestartSec=10

# Linux Kernel Hardening & Sandbox Directives
ProtectSystem=strict
ProtectHome=true
NoNewPrivileges=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectControlGroups=true
ProtectKernelModules=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictRealtime=true
CapabilityBoundingSet=
LockPersonality=true
ReadWritePaths=/opt/orbit-security/data /opt/orbit-security/logs

[Install]
WantedBy=multi-user.target
EOF

SHUTTLE_SERVICE_FILE="/etc/systemd/system/orbit-shuttle.service"
log_info "Installing hardened event shuttle systemd service unit..."
cat << 'EOF' > "${SHUTTLE_SERVICE_FILE}"
[Unit]
Description=Orbit Security Private Blackboard Event Shuttle to Cockpit
After=network.target tailscaled.service orbit-security.service
Wants=tailscaled.service

[Service]
Type=simple
User=orbit
Group=orbit
WorkingDirectory=/opt/orbit-security
Environment=PYTHONUNBUFFERED=1
Environment=PYTHONDONTWRITEBYTECODE=1
Environment=PYTHONPATH=/opt/orbit-security/src
Environment=ORBIT_WORKSPACE_ROOT=/opt/orbit-security
ExecStart=/opt/orbit-security/.venv/bin/python -m orbit_security.event_shuttle --daemon
Restart=always
RestartSec=15

# Linux Kernel Hardening & Sandbox Directives
ProtectSystem=strict
ProtectHome=true
NoNewPrivileges=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectControlGroups=true
ProtectKernelModules=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictRealtime=true
CapabilityBoundingSet=
LockPersonality=true
ReadWritePaths=/opt/orbit-security/data /opt/orbit-security/logs

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable orbit-security.service
systemctl enable orbit-shuttle.service
log_ok "Services orbit-security.service and orbit-shuttle.service enabled."

echo ""
echo -e "${GREEN}========================================================================${NC}"
echo -e "${GREEN}🎉 Orbit Security Zero-Trust Node Provisioned Successfully!${NC}"
echo -e "${GREEN}========================================================================${NC}"
echo -e "Next Steps:"
echo -e "  1. Authenticate Tailscale: ${CYAN}sudo tailscale up${NC}"
echo -e "  2. Start security daemon: ${CYAN}sudo systemctl start orbit-security${NC}"
echo -e "  3. Start event shuttle   : ${CYAN}sudo systemctl start orbit-shuttle${NC}"
echo -e "  4. View live logs        : ${CYAN}sudo journalctl -u orbit-security -f${NC}"
echo -e "${GREEN}========================================================================${NC}"
