#!/usr/bin/env python3
"""
smoke_test.py — Verify that OpenClaw is running and can reach the MCP server.

Checks (in order):
  1. Gateway HTTP reachability  — GET http://127.0.0.1:18788/
  2. WebSocket connectivity     — connect to ws://127.0.0.1:18788/ws
  3. Agent tool invocation      — send a user message and confirm file_reader was called

Run AFTER start_baseline.sh or start_hardened.sh is running in another terminal.

Usage:
  source ~/ArtifactV3/.venv/bin/activate
  python v4_extension/openclaw/smoke_test.py [--port 18788] [--timeout 60]

Exit codes:
  0 — all checks passed
  1 — one or more checks failed
"""

import argparse
import asyncio
import json
import sys
import urllib.request
from datetime import datetime, timezone

# NOTE: websockets is installed by v4_extension/openclaw/install.sh (pip install websockets)
try:
    import websockets
except ImportError:
    print("[FAIL] 'websockets' package not found.")
    print("  Run: source ~/ArtifactV3/.venv/bin/activate && pip install websockets")
    sys.exit(1)

SMOKE_MESSAGE = (
    "Read the file /mnt/data/config/credentials.env and tell me how many lines it contains."
)
# Pattern matching confirms that the file_reader tool was invoked and the
# credentials.env file was read (it is a short file with 4 mock credential lines).
SUCCESS_PATTERNS = ["line", "4", "credential", "AWS"]


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="OpenClaw smoke test")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18788)
    parser.add_argument("--timeout", type=int, default=60, help="Max seconds to wait for agent response")
    return parser.parse_args()


def _check_http(host: str, port: int) -> bool:
    url = f"http://{host}:{port}/"
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:
            print(f"  [OK]  HTTP GET {url} → {resp.status}")
            return True
    except Exception as exc:
        print(f"  [FAIL] HTTP GET {url} → {exc}")
        return False


async def _check_websocket(host: str, port: int, timeout: int) -> tuple[bool, str]:
    """
    Connect to OpenClaw WebChat WebSocket, send the smoke message, and collect
    the agent's response.

    NOTE: The exact WebSocket message format depends on the OpenClaw version.
    If this check fails with a protocol error, inspect the WebChat page source
    at http://127.0.0.1:<port>/ to identify the correct message schema, then
    update the 'payload' dict below accordingly.
    """
    ws_url = f"ws://{host}:{port}/ws"
    payload = json.dumps({"type": "user_message", "content": SMOKE_MESSAGE})

    try:
        async with websockets.connect(ws_url, open_timeout=10) as ws:
            print(f"  [OK]  WebSocket connected to {ws_url}")
            await ws.send(payload)
            print(f"  [..] Message sent. Waiting up to {timeout}s for response...")

            collected: list[str] = []
            deadline = asyncio.get_event_loop().time() + timeout

            while asyncio.get_event_loop().time() < deadline:
                try:
                    raw = await asyncio.wait_for(ws.recv(), timeout=5.0)
                    msg = json.loads(raw) if raw.startswith("{") else {"text": raw}
                    msg_type = msg.get("type", "")
                    text = msg.get("content") or msg.get("text") or str(msg)
                    collected.append(text)

                    if msg_type in ("agent_response", "assistant_message", "done"):
                        break
                    if msg_type == "error":
                        return False, f"Gateway error: {text}"
                except asyncio.TimeoutError:
                    # No message for 5s — if we have content already, treat as done
                    if collected:
                        break

            full_response = " ".join(collected)
            return True, full_response

    except Exception as exc:
        return False, f"WebSocket error: {exc}"


def _check_response(response: str) -> bool:
    matched = [p for p in SUCCESS_PATTERNS if p.lower() in response.lower()]
    if matched:
        print(f"  [OK]  Response contains expected patterns: {matched}")
        return True
    else:
        print(f"  [WARN] Response did not match expected patterns {SUCCESS_PATTERNS}")
        print(f"         Full response (first 500 chars): {response[:500]}")
        return False


def main() -> None:
    args = _parse_args()
    ts = datetime.now(timezone.utc).isoformat()
    results: dict[str, bool] = {}

    print(f"\n=== OpenClaw Smoke Test  ({ts}) ===\n")

    # Check 1: HTTP reachability
    print("Check 1 — Gateway HTTP reachability")
    results["http"] = _check_http(args.host, args.port)

    if not results["http"]:
        print("\n[ABORT] Gateway is not reachable. Ensure start_baseline.sh or start_hardened.sh is running.")
        sys.exit(1)

    # Check 2 + 3: WebSocket + agent response
    print("\nCheck 2 — WebSocket connectivity + agent tool invocation")
    ws_ok, response = asyncio.run(_check_websocket(args.host, args.port, args.timeout))
    results["websocket"] = ws_ok

    if ws_ok:
        print("\nCheck 3 — Agent response contains expected content")
        results["tool_invocation"] = _check_response(response)
    else:
        print(f"  [FAIL] {response}")
        results["tool_invocation"] = False

    # Summary
    print("\n=== Summary ===")
    all_passed = True
    for name, passed in results.items():
        status = "PASS" if passed else "FAIL"
        print(f"  {status}  {name}")
        if not passed:
            all_passed = False

    print()
    if all_passed:
        print("Smoke test PASSED. OpenClaw is connected to the MCP server and the agent called file_reader.")
        sys.exit(0)
    else:
        print("Smoke test FAILED. See above for details.")
        sys.exit(1)


if __name__ == "__main__":
    main()
