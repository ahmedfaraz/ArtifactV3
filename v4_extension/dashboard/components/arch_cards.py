"""
arch_cards.py — Side-by-side architecture status cards.
Component list is read from Terraform outputs, not hard-coded.
A coloured border highlights the card matching the current run.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Optional

import streamlit as st

_REPO_ROOT = Path(__file__).resolve().parents[3]
_TF_TIMEOUT = 5  # seconds before giving up on terraform output


def _get_tf_outputs(env: str) -> Optional[dict]:
    """Run `terraform output -json` for the given environment and return parsed dict."""
    tf_dir = str(_REPO_ROOT / env)
    try:
        result = subprocess.run(
            ["terraform", "output", "-json"],
            cwd=tf_dir,
            capture_output=True,
            text=True,
            timeout=_TF_TIMEOUT,
        )
        if result.returncode != 0 or not result.stdout.strip():
            return None
        return json.loads(result.stdout)
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
        return None


def _component_rows(outputs: Optional[dict], include_openclaw: bool) -> list[tuple[str, bool]]:
    """
    Return list of (component_name, is_present) for the architecture card.
    Derived from Terraform output keys rather than hard-coded.
    """
    if outputs is None:
        return [("Terraform state unavailable", False)]

    # Map output keys to readable component names
    key_labels = {
        "vpc_id":          "VPC",
        "subnet_id":       "Subnet (public)",
        "private_subnet_id": "Subnet (private)",
        "security_group_id": "Security Group",
        "ecs_cluster_name": "ECS Cluster",
        "ecs_service_name": "ECS Service",
        "task_public_ip":  "ECS Task (public IP)",
        "task_private_ip": "ECS Task (private IP)",
        "rds_endpoint":    "RDS Instance",
        "efs_id":          "EFS Filesystem",
        "cloudtrail_bucket": "CloudTrail Bucket",
        "sns_topic_arn":   "SNS Alert Topic",
        "attacker_public_ip": "Attacker EC2",
    }

    rows = []
    for key, label in key_labels.items():
        if key in outputs:
            value = outputs[key].get("value", "")
            present = bool(value) and value not in ("unavailable", "unavailable-push-image-and-reapply")
            rows.append((label, present))

    if include_openclaw:
        rows.append(("OpenClaw Agent (WS4)", True))

    return rows if rows else [("No outputs found", False)]


def _status_dot(present: bool) -> str:
    return ":green[●]" if present else ":gray[●]"


def _card(env: str, label: str, is_active: bool, include_openclaw: bool) -> None:
    border_colour = "#1f77b4" if env == "baseline" else "#d62728"
    border_style = f"3px solid {border_colour}" if is_active else "1px solid #444"

    outputs = _get_tf_outputs(env)

    with st.container(border=True):
        # Active border via custom CSS workaround (inject a thin divider with colour)
        if is_active:
            st.markdown(
                f"<div style='height:4px; background:{border_colour}; "
                f"margin:-1rem -1rem 0.5rem -1rem; border-radius:4px 4px 0 0'></div>",
                unsafe_allow_html=True,
            )

        st.subheader(label)
        if outputs is None:
            st.caption("Terraform state unavailable — run `terraform output` manually.")
        else:
            rows = _component_rows(outputs, include_openclaw)
            for name, present in rows:
                st.markdown(f"{_status_dot(present)}  {name}")


def render(selected_scenario: str, selected_arch: str) -> None:
    """Render the two-up architecture cards."""
    include_openclaw = selected_scenario == "D"

    baseline_active = selected_arch in ("baseline", "both")
    hardened_active = selected_arch in ("hardened", "both")

    col_left, col_right = st.columns(2)
    with col_left:
        _card("baseline", "Baseline Architecture", baseline_active, include_openclaw)
    with col_right:
        _card("hardened", "Hardened Architecture", hardened_active, include_openclaw)
