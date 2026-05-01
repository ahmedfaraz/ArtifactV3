"""
control_bar.py — Top section of the dashboard.
Renders the scenario selector, architecture toggle, Run button, and last-run timestamp.
Returns the user's current selections via a dict.
"""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

import streamlit as st

_REPO_ROOT = Path(__file__).resolve().parents[3]


def _run_scenario(scenario: str, arch: str) -> None:
    """Execute the appropriate scenario script and stream its stdout."""
    script_map = {
        "A": _REPO_ROOT / "attacks" / "scenario_a.py",
        "B": _REPO_ROOT / "attacks" / "scenario_b.py",
        "C": _REPO_ROOT / "attacks" / "scenario_c.py",
        "D": _REPO_ROOT / "v4_extension" / "attacks" / "run_scenario_d.sh",
    }
    script = script_map.get(scenario)
    if script is None or not script.exists():
        st.error(f"Script not found for Scenario {scenario}: {script}")
        return

    if scenario == "D":
        cmd = ["bash", str(script), arch]
    else:
        # Scenarios A/B/C require --target-ip; prompt if not already in session state
        target_ip = st.session_state.get("target_ip", "")
        if not target_ip:
            st.error("Set the MCP server IP in the sidebar or session state before running.")
            return
        cmd = [sys.executable, str(script), "--target-ip", target_ip, "--architecture", arch]

    st.session_state["last_run_scenario"] = scenario
    st.session_state["last_run_arch"] = arch
    st.session_state["run_in_progress"] = True
    st.session_state["run_output"] = []

    log_area = st.empty()
    lines: list[str] = []

    with subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        cwd=str(_REPO_ROOT),
    ) as proc:
        for line in proc.stdout:
            lines.append(line.rstrip())
            log_area.code("\n".join(lines[-80:]), language="")
        proc.wait()
        rc = proc.returncode

    st.session_state["run_in_progress"] = False
    st.session_state["run_output"] = lines
    st.session_state["last_run_ts"] = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())

    if rc == 0:
        st.success(f"Scenario {scenario} ({arch}) finished.")
    else:
        st.warning(f"Scenario {scenario} ({arch}) exited with code {rc}.")


def render() -> dict:
    """Render the control bar and return current selections."""
    col1, col2, col3, col4 = st.columns([2, 2, 1, 3])

    with col1:
        scenario = st.radio(
            "Scenario",
            options=["A", "B", "C", "D"],
            horizontal=True,
            key="selected_scenario",
        )

    with col2:
        arch = st.radio(
            "Architecture",
            options=["baseline", "hardened", "both"],
            horizontal=True,
            key="selected_arch",
        )

    with col3:
        run_clicked = st.button("Run", type="primary", use_container_width=True)

    with col4:
        last_ts: Optional[str] = st.session_state.get("last_run_ts")
        if last_ts:
            st.caption(f"Last run: {last_ts}")
        else:
            st.caption("No run yet this session")

    # MCP server IP input (needed for Scenarios A/B/C)
    if scenario != "D":
        with st.expander("MCP server IP (required for A/B/C)", expanded=False):
            target_ip = st.text_input(
                "ECS task IP",
                value=st.session_state.get("target_ip", ""),
                placeholder="e.g. 54.123.45.67",
                key="target_ip_input",
            )
            st.session_state["target_ip"] = target_ip

    if run_clicked:
        if arch == "both":
            for a in ["baseline", "hardened"]:
                st.subheader(f"Running Scenario {scenario} — {a}")
                _run_scenario(scenario, a)
        else:
            _run_scenario(scenario, arch)
        st.rerun()

    return {"scenario": scenario, "arch": arch}
