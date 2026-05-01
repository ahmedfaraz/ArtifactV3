#!/usr/bin/env bash
# install.sh — Idempotent installer for OpenClaw on Kali Linux (WSL2).
# Safe to re-run: skips steps that are already complete.
# Run as a normal user (sudo will be invoked where needed).
set -euo pipefail

REQUIRED_NODE_MAJOR=22
OPENCLAW_PACKAGE="openclaw@latest"

echo "=== OpenClaw install script ==="

# ---------------------------------------------------------------------------
# 1. Check / install Node.js
# ---------------------------------------------------------------------------
install_node() {
    echo "[node] Adding NodeSource repository for Node.js ${REQUIRED_NODE_MAJOR}.x ..."
    curl -fsSL "https://deb.nodesource.com/setup_${REQUIRED_NODE_MAJOR}.x" | sudo -E bash -
    sudo apt-get install -y nodejs
}

if command -v node &>/dev/null; then
    NODE_MAJOR=$(node --version | sed 's/v//' | cut -d. -f1)
    if [ "$NODE_MAJOR" -ge "$REQUIRED_NODE_MAJOR" ]; then
        echo "[node] OK — $(node --version) (>= ${REQUIRED_NODE_MAJOR}.x required)"
    else
        echo "[node] Found v${NODE_MAJOR}.x but need ${REQUIRED_NODE_MAJOR}.x+. Upgrading..."
        install_node
    fi
else
    echo "[node] Not found. Installing..."
    install_node
fi

# ---------------------------------------------------------------------------
# 2. Check disk space (warn if under 500 MB free)
# ---------------------------------------------------------------------------
FREE_MB=$(df -m ~ | awk 'NR==2 {print $4}')
if [ "$FREE_MB" -lt 500 ]; then
    echo "[WARN] Only ${FREE_MB} MB free in ~. OpenClaw needs ~120 MB. Proceeding anyway."
else
    echo "[disk] ${FREE_MB} MB free — OK"
fi

# ---------------------------------------------------------------------------
# 3. Install openclaw globally via npm
# ---------------------------------------------------------------------------
if command -v openclaw &>/dev/null; then
    INSTALLED=$(openclaw --version 2>/dev/null || echo "unknown")
    echo "[openclaw] Already installed (${INSTALLED}). Updating to latest..."
fi

echo "[openclaw] Running: npm install -g ${OPENCLAW_PACKAGE}"
npm install -g "${OPENCLAW_PACKAGE}"

echo ""
echo "=== Install complete ==="
echo "openclaw version: $(openclaw --version 2>/dev/null || echo 'check manually')"
echo ""
echo "Next steps:"
echo "  1. Set your API key:  export ANTHROPIC_API_KEY=sk-ant-..."
echo "  2. Start the gateway: cd v4_extension/openclaw && ./start_baseline.sh"
echo "  3. Open WebChat:      http://127.0.0.1:18788"
