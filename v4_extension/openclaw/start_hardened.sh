#!/usr/bin/env bash
# start_hardened.sh — Launch OpenClaw gateway against the hardened MCP server
#                     via SSM Session Manager port-forwarding.
#
# Architecture: Kali → [SSM tunnel] → Attacker EC2 → [VPC routing] → ECS task (private subnet)
#               OpenClaw on Kali points at localhost:8080 (tunnel endpoint).
#
# Prerequisites:
#   - install.sh has been run
#   - ANTHROPIC_API_KEY is exported
#   - AWS CLI configured with credentials that have ssm:StartSession permission
#   - Hardened Terraform is applied and the ECS task is running
#   - The attacker EC2 has the SSM Agent installed and an SSM-compatible IAM role
#   - Run from ~/ArtifactV3/ root
#
# What it does:
#   1. Reads task_private_ip and attacker instance ID from hardened Terraform
#   2. Opens an SSM port-forwarding session: localhost:8080 → ECS private IP:8080 via attacker EC2
#   3. Writes OpenClaw config pointing at localhost:8080
#   4. Starts the OpenClaw gateway in the foreground (Ctrl-C stops both gateway and tunnel)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TEMPLATE="${SCRIPT_DIR}/openclaw.template.json"
CONFIG_OUT="/tmp/openclaw_hardened.json"
LOCAL_PORT=8080
SSM_TUNNEL_PID_FILE="/tmp/openclaw_ssm_tunnel.pid"

# ---------------------------------------------------------------------------
# Guards
# ---------------------------------------------------------------------------
if [ -z "${ANTHROPIC_API_KEY:-}" ]; then
    echo "[ERROR] ANTHROPIC_API_KEY is not set."
    echo "  Run: export ANTHROPIC_API_KEY=sk-ant-..."
    exit 1
fi

if ! command -v openclaw &>/dev/null; then
    echo "[ERROR] openclaw not found. Run ./install.sh first."
    exit 1
fi

if ! command -v aws &>/dev/null; then
    echo "[ERROR] AWS CLI not found. Install it and configure credentials."
    exit 1
fi

# ---------------------------------------------------------------------------
# Resolve hardened infrastructure values
# ---------------------------------------------------------------------------
echo "[config] Reading outputs from hardened Terraform..."

TASK_PRIVATE_IP=$(terraform -chdir="${REPO_ROOT}/hardened" output -raw task_private_ip 2>/dev/null || true)
if [ -z "${TASK_PRIVATE_IP}" ] || echo "${TASK_PRIVATE_IP}" | grep -q "unavailable"; then
    echo "[ERROR] Could not retrieve task_private_ip from hardened Terraform."
    echo "  Ensure the hardened ECS task is running and Terraform state is current."
    exit 1
fi

# Retrieve the attacker EC2 instance ID via AWS CLI (the attacker EC2 is the SSM target)
AWS_REGION=$(terraform -chdir="${REPO_ROOT}/hardened" output -json 2>/dev/null \
    | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('aws_region',{}).get('value','eu-west-1'))" \
    2>/dev/null || echo "eu-west-1")

ATTACKER_INSTANCE_ID=$(aws ec2 describe-instances \
    --filters "Name=tag:Name,Values=attacker" "Name=instance-state-name,Values=running" \
    --query "Reservations[0].Instances[0].InstanceId" \
    --output text \
    --region "${AWS_REGION}" 2>/dev/null || true)

if [ -z "${ATTACKER_INSTANCE_ID}" ] || [ "${ATTACKER_INSTANCE_ID}" = "None" ]; then
    echo "[ERROR] Could not find running attacker EC2 instance (tag:Name=attacker)."
    echo "  Check it is running: aws ec2 describe-instances --filters Name=tag:Name,Values=attacker"
    exit 1
fi

echo "[config] ECS task private IP:  ${TASK_PRIVATE_IP}"
echo "[config] Attacker instance ID: ${ATTACKER_INSTANCE_ID}"
echo "[config] AWS region:           ${AWS_REGION}"

# ---------------------------------------------------------------------------
# Open SSM port-forwarding tunnel (background)
# ---------------------------------------------------------------------------
echo ""
echo "[tunnel] Opening SSM port-forwarding session..."
echo "  Local  :${LOCAL_PORT} → ${ATTACKER_INSTANCE_ID} → ${TASK_PRIVATE_IP}:8080"

aws ssm start-session \
    --target "${ATTACKER_INSTANCE_ID}" \
    --document-name AWS-StartPortForwardingSessionToRemoteHost \
    --parameters "{\"host\":[\"${TASK_PRIVATE_IP}\"],\"portNumber\":[\"8080\"],\"localPortNumber\":[\"${LOCAL_PORT}\"]}" \
    --region "${AWS_REGION}" &

SSM_PID=$!
echo "${SSM_PID}" > "${SSM_TUNNEL_PID_FILE}"
echo "[tunnel] PID ${SSM_PID} — waiting 5s for tunnel to establish..."
sleep 5

# Verify tunnel is alive
if ! kill -0 "${SSM_PID}" 2>/dev/null; then
    echo "[ERROR] SSM tunnel process exited unexpectedly. Check AWS credentials and SSM permissions."
    exit 1
fi
echo "[tunnel] Tunnel established."

# ---------------------------------------------------------------------------
# Write config pointing at localhost (tunnel endpoint)
# ---------------------------------------------------------------------------
sed "s|<MCP_SERVER_IP>|127.0.0.1|g" "${TEMPLATE}" > "${CONFIG_OUT}"
echo "[config] Config written to ${CONFIG_OUT}"

# ---------------------------------------------------------------------------
# Cleanup handler: kill tunnel when gateway exits
# ---------------------------------------------------------------------------
cleanup() {
    echo ""
    echo "[cleanup] Stopping SSM tunnel (PID ${SSM_PID})..."
    kill "${SSM_PID}" 2>/dev/null || true
    rm -f "${SSM_TUNNEL_PID_FILE}"
    echo "[cleanup] Done."
}
trap cleanup EXIT INT TERM

# ---------------------------------------------------------------------------
# Start gateway
# ---------------------------------------------------------------------------
echo ""
echo "Starting OpenClaw gateway (hardened)..."
echo "  MCP server: http://${TASK_PRIVATE_IP}:8080/sse  [via SSM tunnel on localhost:${LOCAL_PORT}]"
echo "  WebChat UI: http://127.0.0.1:18788"
echo "  Press Ctrl-C to stop gateway and close tunnel."
echo ""

openclaw gateway --config "${CONFIG_OUT}"
