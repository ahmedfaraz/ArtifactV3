#!/usr/bin/env bash
# run_scenario_d.sh — Standalone wrapper for Scenario D.
#
# Resolves infrastructure IPs from Terraform, then runs scenario_d.py.
# The OpenClaw gateway must already be running in another terminal via
# start_baseline.sh or start_hardened.sh.
#
# Usage:
#   # Baseline
#   cd ~/ArtifactV3
#   source .venv/bin/activate
#   bash v4_extension/attacks/run_scenario_d.sh baseline
#
#   # Hardened
#   bash v4_extension/attacks/run_scenario_d.sh hardened
set -euo pipefail

ARCHITECTURE="${1:-baseline}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT_DIR="${REPO_ROOT}/v4_extension/attacks"

if [[ "${ARCHITECTURE}" != "baseline" && "${ARCHITECTURE}" != "hardened" ]]; then
    echo "Usage: $0 [baseline|hardened]"
    exit 1
fi

echo "[run_scenario_d] Architecture: ${ARCHITECTURE}"

# ---------------------------------------------------------------------------
# Resolve attacker IP
# ---------------------------------------------------------------------------
if [[ "${ARCHITECTURE}" == "baseline" ]]; then
    # For baseline, the listener runs on Kali; the ECS task has internet access.
    # The attacker IP for the http_client exfil call must be reachable from the
    # ECS task. Use the attacker EC2 public IP (it has an open SG on port 9999
    # from the baseline Terraform, or adjust accordingly).
    ATTACKER_IP=$(terraform -chdir="${REPO_ROOT}/hardened" output -raw attacker_public_ip 2>/dev/null || true)
    if [ -z "${ATTACKER_IP}" ] || [ "${ATTACKER_IP}" = "None" ]; then
        echo "[WARN] Could not resolve attacker_public_ip from Terraform."
        echo "  Set ATTACKER_IP manually: ATTACKER_IP=1.2.3.4 $0 baseline"
        ATTACKER_IP="${ATTACKER_IP:-}"
    fi
else
    # For hardened, the listener runs on the attacker EC2 (private IP);
    # the ECS task reaches it via VPC routing. The SSM tunnel is already open
    # (started by start_hardened.sh). We use the private IP here, which means
    # this script must be run FROM the attacker EC2, or ATTACKER_IP must be
    # exported manually (the attacker EC2's private IP).
    ATTACKER_IP="${ATTACKER_IP:-}"
    if [ -z "${ATTACKER_IP}" ]; then
        # Try to get the private IP via AWS CLI
        AWS_REGION=$(terraform -chdir="${REPO_ROOT}/hardened" output -json 2>/dev/null \
            | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('aws_region',{}).get('value','eu-west-1'))" \
            2>/dev/null || echo "eu-west-1")
        ATTACKER_IP=$(aws ec2 describe-instances \
            --filters "Name=tag:Name,Values=attacker" "Name=instance-state-name,Values=running" \
            --query "Reservations[0].Instances[0].PrivateIpAddress" \
            --output text \
            --region "${AWS_REGION}" 2>/dev/null || echo "")
    fi
fi

if [ -z "${ATTACKER_IP}" ]; then
    echo "[ERROR] ATTACKER_IP could not be resolved automatically."
    echo "  Export it manually: export ATTACKER_IP=<ip>; then re-run this script."
    exit 1
fi

echo "[run_scenario_d] Attacker IP (listener): ${ATTACKER_IP}"

# ---------------------------------------------------------------------------
# Activate venv and run
# ---------------------------------------------------------------------------
source "${REPO_ROOT}/.venv/bin/activate"

python "${SCRIPT_DIR}/scenario_d.py" \
    --architecture "${ARCHITECTURE}" \
    --attacker-ip "${ATTACKER_IP}" \
    --runs 3 \
    --include-subtle \
    "$@"
