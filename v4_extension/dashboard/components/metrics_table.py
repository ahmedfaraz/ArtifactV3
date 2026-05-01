"""
metrics_table.py — Comparative metrics table across all four scenarios.
Reads from results/baseline/ and results/hardened/ result JSON files.
Missing files render as "—". Percentages are rounded to integers.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

import pandas as pd
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from data.results_loader import load_all, extract_metrics


def _fmt(val: Optional[int], suffix: str = "") -> str:
    if val is None:
        return "—"
    return f"{val}{suffix}"


def render() -> None:
    st.subheader("Metrics Summary")

    results = load_all()
    rows = extract_metrics(results)

    display_rows = []
    for r in rows:
        s = r["Scenario"]
        row = {
            "Scenario": s,
            "M1 Baseline (%)": _fmt(r["M1 Baseline (%)"], "%"),
            "M1 Hardened (%)": _fmt(r["M1 Hardened (%)"], "%"),
        }
        # M1a column only meaningful for Scenario D
        if s == "D":
            row["M1a Agent (%)"] = _fmt(r["M1a Agent (%)"], "%")
        else:
            row["M1a Agent (%)"] = "N/A"

        row["M2 Baseline"] = _fmt(r["M2 Baseline"])
        row["M2 Hardened"] = _fmt(r["M2 Hardened"])
        row["M3 Hardened (events)"] = _fmt(r["M3 Hardened"])
        display_rows.append(row)

    df = pd.DataFrame(display_rows)
    st.dataframe(df, hide_index=True, use_container_width=True)

    st.caption(
        "M1: attack success rate. "
        "M1a (Scenario D only): agent issued malicious db_query. "
        "M2: credential items / customer records exfiltrated. "
        "M3: CloudTrail/VPC Flow log events generated (hardened only). "
        "— = results file not yet available."
    )
