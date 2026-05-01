"""
log_replay.py — Convert a scenario result JSON file into a replay-friendly
                list of event rows for the event stream panel.

No real-time CloudWatch tailing — events are reconstructed from the result
file after a run completes. Timestamps are preserved from the run records;
sources and severities are inferred from the event content.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

_REPO_ROOT = Path(__file__).resolve().parents[3]
RESULTS_DIR = _REPO_ROOT / "results"

SOURCE_LABELS = {
    "openclaw": "OpenClaw",
    "attacker": "Attacker",
    "cloudtrail": "CloudTrail",
    "vpcflow": "VPC Flow",
    "mcp": "MCP Server",
    "system": "System",
}

SOURCE_COLOURS = {
    "OpenClaw":   "blue",
    "Attacker":   "red",
    "CloudTrail": "orange",
    "VPC Flow":   "orange",
    "MCP Server": "violet",
    "System":     "gray",
}


@dataclass
class EventRow:
    timestamp: str
    source: str
    colour: str
    message: str
    severity: str  # "info" | "warning" | "danger" | "success"


def _severity(outcome: str) -> str:
    if outcome in ("SUCCESS", "FULL_COMPLY"):
        return "danger"
    if outcome in ("PARTIAL_COMPLY",):
        return "warning"
    if outcome in ("FAILED", "DECLINED"):
        return "success"
    return "info"


def _events_from_scenario(data: dict) -> list[EventRow]:
    events: list[EventRow] = []
    scenario = data.get("scenario", "?")
    arch = data.get("architecture", "?")

    events.append(EventRow(
        timestamp=data.get("timestamp_start", ""),
        source="System",
        colour=SOURCE_COLOURS["System"],
        message=f"Scenario {scenario} started against {arch} architecture",
        severity="info",
    ))

    for run in data.get("runs", []):
        run_n = run.get("run_number", "?")
        run_ts = run.get("run_start_time", data.get("timestamp_start", ""))
        outcome = run.get("outcome", "UNKNOWN")
        sev = _severity(outcome)

        # File reader call (Scenarios A/D inferred; B/C use different tools)
        if scenario in ("A", "D"):
            events.append(EventRow(
                timestamp=run_ts,
                source="MCP Server",
                colour=SOURCE_COLOURS["MCP Server"],
                message=f"Run {run_n}: file_reader tool invoked",
                severity="info",
            ))

        # Scenario D — agent-mediated details
        if scenario == "D":
            tool_calls = run.get("tool_calls_observed", [])
            if "db_query" in tool_calls:
                events.append(EventRow(
                    timestamp=run_ts,
                    source="Attacker",
                    colour=SOURCE_COLOURS["Attacker"],
                    message=f"Run {run_n}: agent issued db_query (injection succeeded)",
                    severity="danger",
                ))
            if "http_client" in tool_calls:
                events.append(EventRow(
                    timestamp=run_ts,
                    source="Attacker",
                    colour=SOURCE_COLOURS["Attacker"],
                    message=f"Run {run_n}: agent issued http_client (exfil attempt)",
                    severity="danger",
                ))
            m1b = run.get("m1b_exfil_received", False)
            events.append(EventRow(
                timestamp=run_ts,
                source="VPC Flow" if arch == "hardened" else "Attacker",
                colour=SOURCE_COLOURS["VPC Flow" if arch == "hardened" else "Attacker"],
                message=f"Run {run_n}: exfil delivery {'BLOCKED by egress controls' if arch == 'hardened' and not m1b else ('RECEIVED' if m1b else 'not received')}",
                severity="success" if (arch == "hardened" and not m1b) else ("danger" if m1b else "warning"),
            ))

        # Credential items (Scenarios A/B/C)
        for item in run.get("m2_items_accessed", []):
            events.append(EventRow(
                timestamp=run_ts,
                source="Attacker",
                colour=SOURCE_COLOURS["Attacker"],
                message=f"Run {run_n}: credential accessed — {item.get('item', '?')} ({item.get('sensitivity_tier', '?')} severity)",
                severity="danger",
            ))

        # CloudTrail / detection events (hardened only)
        m3 = data.get("m3_log_events_generated")
        if arch == "hardened" and m3:
            events.append(EventRow(
                timestamp=run_ts,
                source="CloudTrail",
                colour=SOURCE_COLOURS["CloudTrail"],
                message=f"Run {run_n}: {m3} log events generated (CloudTrail / VPC Flow)",
                severity="warning",
            ))

        events.append(EventRow(
            timestamp=run.get("run_end_time", run_ts),
            source="System",
            colour=SOURCE_COLOURS["System"],
            message=f"Run {run_n} outcome: {outcome}",
            severity=sev,
        ))

    events.append(EventRow(
        timestamp=data.get("timestamp_end", ""),
        source="System",
        colour=SOURCE_COLOURS["System"],
        message=f"Scenario {scenario} complete — M1={data.get('m1_success_rate_pct', 0):.0f}%",
        severity="info",
    ))
    return events


def load_events(scenario: str, arch: str) -> list[EventRow]:
    """Load replay events for the given scenario and architecture."""
    filename_map = {
        "A": "scenario_a_results.json",
        "B": "scenario_b_results.json",
        "C": "scenario_c_results.json",
        "D": "scenario_d_results.json",
    }
    path = RESULTS_DIR / arch / filename_map.get(scenario.upper(), "")
    if not path.exists():
        return []
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        return _events_from_scenario(data)
    except (json.JSONDecodeError, OSError):
        return []
