"""
app.py — Streamlit orchestration dashboard for the viva demo.

Sections (top to bottom):
  1. Control bar   — scenario selector, architecture toggle, Run button, last-run timestamp
  2. Architecture cards — side-by-side baseline / hardened component status
  3. Event stream  — post-run event replay from result JSON
  4. Metrics table — M1/M1a/M2/M3 across all four scenarios

Launch:
    source ~/ArtifactV3/.venv/bin/activate
    streamlit run v4_extension/dashboard/app.py --server.port 8501

No external CSS frameworks. Uses st.columns, st.container, st.metric, st.dataframe only.
"""

import sys
from pathlib import Path

# Make components importable
sys.path.insert(0, str(Path(__file__).parent))

import streamlit as st
from components import arch_cards, control_bar, event_stream, metrics_table

st.set_page_config(
    page_title="MCP Security — Scenario Dashboard",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------
st.title("MCP Server Security — Experimental Dashboard")
st.caption(
    "MSc Cybersecurity Dissertation Artefact — "
    "Securing Model Context Protocol Servers in Cloud (ArtifactV3 v4)"
)
st.divider()

# ---------------------------------------------------------------------------
# Section 1 — Control bar
# ---------------------------------------------------------------------------
selections = control_bar.render()
selected_scenario = selections["scenario"]
selected_arch = selections["arch"]

st.divider()

# ---------------------------------------------------------------------------
# Section 2 — Architecture cards
# ---------------------------------------------------------------------------
arch_cards.render(selected_scenario, selected_arch)

st.divider()

# ---------------------------------------------------------------------------
# Section 3 — Event stream
# ---------------------------------------------------------------------------
event_stream.render(selected_scenario, selected_arch)

st.divider()

# ---------------------------------------------------------------------------
# Section 4 — Metrics table
# ---------------------------------------------------------------------------
metrics_table.render()
