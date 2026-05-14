#!/usr/bin/env bash
# run_server.sh — start the MCP dashboard FastAPI server.
# Assumes ~/ArtifactV3/.venv exists and FastAPI/uvicorn are installed.

set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${HERE}/../.." && pwd)"

cd "${REPO_ROOT}"

if [[ -d .venv ]]; then
  # shellcheck disable=SC1091
  source .venv/bin/activate
fi

PORT="${PORT:-8501}"
HOST="${HOST:-0.0.0.0}"

echo "[mcp-dashboard] starting on http://${HOST}:${PORT}"
echo "[mcp-dashboard] repo root: ${REPO_ROOT}"

exec python -m uvicorn v4_extension.dashboard.server:app \
  --host "${HOST}" --port "${PORT}" --log-level info
