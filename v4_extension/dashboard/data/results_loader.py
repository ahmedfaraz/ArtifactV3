"""
results_loader.py — Load scenario result JSON files from results/<arch>/.

Reads the same files produced by scenario_a.py through scenario_d.py.
Returns a normalised dict keyed by (scenario_letter, architecture).
Missing files return None so the dashboard can display "—" cleanly.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional

# Repo root is three levels up from this file:
# dashboard/data/results_loader.py → dashboard/ → v4_extension/ → ArtifactV3/
_REPO_ROOT = Path(__file__).resolve().parents[3]
RESULTS_DIR = _REPO_ROOT / "results"

SCENARIOS = ["A", "B", "C", "D"]
ARCHITECTURES = ["baseline", "hardened"]

_FILENAME_MAP = {
    "A": "scenario_a_results.json",
    "B": "scenario_b_results.json",
    "C": "scenario_c_results.json",
    "D": "scenario_d_results.json",
}


def _load_one(scenario: str, arch: str) -> Optional[dict]:
    path = RESULTS_DIR / arch / _FILENAME_MAP[scenario]
    if not path.exists():
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (json.JSONDecodeError, OSError):
        return None


def load_all() -> dict[tuple[str, str], Optional[dict]]:
    """Return all results as {(scenario, arch): data_or_None}."""
    results = {}
    for s in SCENARIOS:
        for a in ARCHITECTURES:
            results[(s, a)] = _load_one(s, a)
    return results


def extract_metrics(results: dict) -> list[dict]:
    """
    Build a flat list of metric rows for the metrics table.
    Each row: {scenario, m1_baseline, m1_hardened, m1a_baseline, m1a_hardened,
                m2_baseline, m2_hardened, m3_hardened}
    Missing values are None (rendered as "—" by metrics_table.py).
    """
    rows = []
    for s in SCENARIOS:
        baseline = results.get((s, "baseline"))
        hardened = results.get((s, "hardened"))

        def _m1(d: Optional[dict]) -> Optional[int]:
            if d is None:
                return None
            return round(d.get("m1_success_rate_pct", 0))

        def _m1a(d: Optional[dict]) -> Optional[int]:
            if d is None:
                return None
            # Scenario D has m1a separately; others use m1_success_rate_pct
            val = d.get("m1a_agent_issued_db_query_pct", d.get("m1_success_rate_pct"))
            return round(val) if val is not None else None

        def _m2(d: Optional[dict]) -> Optional[int]:
            if d is None:
                return None
            runs = d.get("runs", [])
            if not runs:
                return d.get("m2_max_records_exfiltrated")
            # For A/B/C, M2 = number of distinct credential items across all successful runs
            items: set[str] = set()
            for r in runs:
                for item in r.get("m2_items_accessed", []):
                    items.add(item.get("item", ""))
            return len(items) if items else d.get("m2_max_records_exfiltrated", 0)

        def _m3(d: Optional[dict]) -> Optional[int]:
            if d is None:
                return None
            return d.get("m3_log_events_generated")

        rows.append({
            "Scenario": s,
            "M1 Baseline (%)": _m1(baseline),
            "M1 Hardened (%)": _m1(hardened),
            "M1a Agent (%)": _m1a(baseline) if s == "D" else None,
            "M2 Baseline": _m2(baseline),
            "M2 Hardened": _m2(hardened),
            "M3 Hardened": _m3(hardened),
        })
    return rows
