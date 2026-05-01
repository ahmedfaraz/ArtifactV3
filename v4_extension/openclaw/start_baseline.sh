#!/usr/bin/env bash
# start_baseline.sh — Launch OpenClaw gateway pointed at the baseline MCP server.
#
# Prerequisites:
#   - install.sh has been run
#   - ANTHROPIC_API_KEY is exported
#   - Baseline Terraform is applied and the ECS task is running
#   - Run from ~/ArtifactV3/ root
#
# What it does:
#   1. Reads task_public_ip from baseline Terraform output
#   2. Substitutes the IP into openclaw.template.json → /tmp/openclaw_baseline.json
#   3. Starts the OpenClaw gateway in the foreground (Ctrl-C to stop)
#
# WebChat UI:  http://127.0.0.1:18788  (open in browser)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TEMPLATE="${SCRIPT_DIR}/openclaw.template.json"
CONFIG_OUT="/tmp/openclaw_baseline.json"

# ---------------------------------------------------------------------------
# Guard: API key
# ---------------------------------------------------------------------------
if [ -z "${ANTHROPIC_API_KEY:-}" ]; then
    echo "[ERROR] ANTHROPIC_API_KEY is not set."
    echo "  Run: export ANTHROPIC_API_KEY=sk-ant-..."
    exit 1
fi

# ---------------------------------------------------------------------------
# Guard: openclaw installed
# ---------------------------------------------------------------------------
if ! command -v openclaw &>/dev/null; then
    echo "[ERROR] openclaw not found. Run ./install.sh first."
    exit 1
fi

# ---------------------------------------------------------------------------
# Resolve baseline MCP server IP
# ---------------------------------------------------------------------------
echo "[config] Reading task_public_ip from baseline Terraform output..."
MCP_IP=$(terraform -chdir="${REPO_ROOT}/baseline" output -raw task_public_ip 2>/dev/null || true)

if [ -z "${MCP_IP}" ] || [ "${MCP_IP}" = "unavailable" ]; then
    echo "[ERROR] Could not retrieve task_public_ip from baseline Terraform."
    echo "  Check that the ECS task is running:"
    echo "    aws ecs list-tasks --cluster <cluster-name> --region <region>"
    echo "  Or pass the IP manually: MCP_IP=1.2.3.4 ./start_baseline.sh"
    exit 1
fi

echo "[config] MCP server IP: ${MCP_IP}"

# ---------------------------------------------------------------------------
# Write config
# ---------------------------------------------------------------------------
sed "s|<MCP_SERVER_IP>|${MCP_IP}|g" "${TEMPLATE}" > "${CONFIG_OUT}"
echo "[config] Config written to ${CONFIG_OUT}"

# ---------------------------------------------------------------------------
# Start gateway
# ---------------------------------------------------------------------------
echo ""
echo "Starting OpenClaw gateway (baseline)..."
echo "  MCP server: http://${MCP_IP}:8080/sse"
echo "  WebChat UI: http://127.0.0.1:18788"
echo "  Press Ctrl-C to stop."
echo ""

exec openclaw gateway --config "${CONFIG_OUT}"
