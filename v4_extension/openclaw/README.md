# OpenClaw — Installation and Demo Guide

OpenClaw is a self-hosted AI gateway daemon used in this artefact as the **MCP client**
(the agent host). It provides the host–client–server layer that Scenarios A–C bypass by
targeting the MCP server directly. Scenario D attacks *through* the agent.

## Architecture

```
User (WebChat browser tab)
        |
        v
OpenClaw Gateway  ←── openclaw.template.json
  (daemon on Kali)      model: anthropic/claude-sonnet-4-6
        |
        | SSE  (http://<MCP_SERVER_IP>:8080/sse)
        v
MCP Server (app.py on ECS Fargate)
  tools: file_reader, http_client, db_query
```

For the hardened architecture, an SSM Session Manager tunnel replaces the direct connection:

```
OpenClaw (Kali:8080 tunnel endpoint)
  → SSM → Attacker EC2 → VPC routing → ECS task (private subnet)
```

## Prerequisites

- Kali Linux (WSL2 on Windows 11 is supported)
- Node.js 22.14+ or 24 (installed by `install.sh`)
- `ANTHROPIC_API_KEY` exported in your shell
- AWS CLI configured (for the hardened run only)
- Terraform applied for the target environment

## Installation

```bash
# From ~/ArtifactV3/
chmod +x v4_extension/openclaw/install.sh
./v4_extension/openclaw/install.sh
```

The script is idempotent — safe to re-run.

## Running against baseline

```bash
# Terminal 1
export ANTHROPIC_API_KEY=sk-ant-...
cd ~/ArtifactV3
chmod +x v4_extension/openclaw/start_baseline.sh
./v4_extension/openclaw/start_baseline.sh
```

When the gateway prints `WebChat UI: http://127.0.0.1:18788`, open that URL in a browser.
Type a message in the chat box to interact with the agent.

## Running against hardened

```bash
# Terminal 1
export ANTHROPIC_API_KEY=sk-ant-...
cd ~/ArtifactV3
chmod +x v4_extension/openclaw/start_hardened.sh
./v4_extension/openclaw/start_hardened.sh
```

This opens an SSM tunnel automatically. The attacker EC2 must be running and have the SSM
Agent installed with an appropriate IAM role (present in the hardened Terraform).

## Smoke test

With the gateway running in Terminal 1:

```bash
# Terminal 2
source ~/ArtifactV3/.venv/bin/activate
pip install websockets   # if not already installed
python v4_extension/openclaw/smoke_test.py
```

Expected output on success:
```
Check 1 — Gateway HTTP reachability
  [OK]  HTTP GET http://127.0.0.1:18788/ → 200
Check 2 — WebSocket connectivity + agent tool invocation
  [OK]  WebSocket connected to ws://127.0.0.1:18788/ws
  [..] Message sent. Waiting up to 60s for response...
Check 3 — Agent response contains expected content
  [OK]  Response contains expected patterns: ['line', '4']
=== Summary ===
  PASS  http
  PASS  websocket
  PASS  tool_invocation
Smoke test PASSED.
```

### If the WebSocket check fails with a protocol error

The OpenClaw WebChat WebSocket message format may differ from what `smoke_test.py` assumes.
To identify the correct format:

1. Open `http://127.0.0.1:18788` in Chrome.
2. Open DevTools → Network → WS tab.
3. Send a message in the chat box and inspect the frames.
4. Update the `payload` dict in `smoke_test.py` to match the observed format.

## API cost

A single demo session (smoke test + Scenario D three-run trial) makes approximately 6–12
API calls. At Sonnet 4.6 pricing (April 2026), this is well under £1 total.

## Stopping the gateway

Press `Ctrl-C` in the terminal running `start_baseline.sh` or `start_hardened.sh`.
The hardened script automatically closes the SSM tunnel on exit.
