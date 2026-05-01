"""
event_stream.py — Event stream panel.
Replays events from the last completed scenario result file.
No live CloudWatch tailing — data is read from the results JSON after a run.
"""

from __future__ import annotations

import sys
from pathlib import Path

import streamlit as st

# Make the data module importable from this location
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from data.log_replay import EventRow, SOURCE_COLOURS, load_events


_SEVERITY_BADGE = {
    "danger":  ":red",
    "warning": ":orange",
    "success": ":green",
    "info":    ":blue",
}


def _format_row(event: EventRow) -> str:
    ts = event.timestamp[:19].replace("T", " ") if event.timestamp else "—"
    colour = SOURCE_COLOURS.get(event.source, "gray")
    badge = f":{colour}[{event.source}]"
    return f"`{ts}`  {badge}  {event.message}"


def render(selected_scenario: str, selected_arch: str) -> None:
    """Render the event stream for the selected scenario and architecture."""
    st.subheader("Event Stream")

    if selected_arch == "both":
        tab_bl, tab_hd = st.tabs(["Baseline", "Hardened"])
        with tab_bl:
            _render_one(selected_scenario, "baseline")
        with tab_hd:
            _render_one(selected_scenario, "hardened")
    else:
        _render_one(selected_scenario, selected_arch)


def _render_one(scenario: str, arch: str) -> None:
    events = load_events(scenario, arch)

    if not events:
        st.info(
            f"No results found for Scenario {scenario} / {arch}. "
            "Run the scenario first using the control bar above."
        )
        return

    st.caption(f"Replaying {len(events)} events from results/{arch}/scenario_{scenario.lower()}_results.json")
    st.divider()

    for event in events:
        st.markdown(_format_row(event))
