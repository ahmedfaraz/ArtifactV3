# Streamlit Orchestration Dashboard

Single-page Streamlit app for the viva demo. Displays four sections:

1. **Control bar** — scenario selector, architecture toggle, Run button
2. **Architecture cards** — component status pulled from Terraform outputs
3. **Event stream** — post-run event replay from result JSON files
4. **Metrics table** — M1/M1a/M2/M3 across all four scenarios

## Launch

```bash
# From ~/ArtifactV3/
source .venv/bin/activate
pip install streamlit pandas     # if not already installed
streamlit run v4_extension/dashboard/app.py --server.port 8501
```

Open `http://localhost:8501` in a browser.

## Prerequisites

- At least one scenario result file in `results/baseline/` or `results/hardened/`
  to see populated metrics. Empty cells show "—" until results are available.
- Terraform must be applied (and `terraform output -json` must work) to see
  component status dots in the architecture cards. If Terraform is unavailable,
  the cards display a notice instead of erroring out.

## Running scenarios from the dashboard

The **Run** button in the control bar executes the scenario script directly:

- **Scenarios A/B/C:** requires the MCP server IP to be entered in the
  "MCP server IP" expander below the selectors.
- **Scenario D:** calls `run_scenario_d.sh` which resolves the IP from Terraform.
  The OpenClaw gateway must already be running (via `start_baseline.sh` or
  `start_hardened.sh`) before clicking Run for Scenario D.

Stdout from the script is streamed live into the dashboard while the scenario runs.

## Layout notes

- No custom CSS or external stylesheets.
- Streamlit's built-in `st.columns`, `st.container`, `st.dataframe` only.
- Scenario D adds an M1a column to the metrics table (agent-side compliance).
- Architecture cards derive the component list from `terraform output -json` so
  they stay in sync with the Terraform state automatically.
