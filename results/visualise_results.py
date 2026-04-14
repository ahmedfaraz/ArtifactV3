#!/usr/bin/env python3
"""
Purpose: Generates three publication-quality charts from scenario result JSON
         files produced by run_all.sh / collect_logs.sh.  Uses design-time
         predicted values as defaults; replace DATA_M1, DATA_M3, and
         CONTROL_EFFECTIVENESS below with empirical values once
         collect_logs.sh has completed and patched the results JSON files.
Component: 4 — Experimental Results
Metrics:   M1 (attack success rate), M3 (detection visibility),
           plus control effectiveness heatmap covering M1/M2/M3
"""

# ---------------------------------------------------------------------------
# REPLACE THESE BLOCKS WITH EMPIRICAL VALUES AFTER collect_logs.sh RUNS
#
# How to update:
#   1. Open results/baseline/scenario_a_results.json  -> read m1_success_rate_pct
#                                                       and m3_log_events_generated
#   2. Repeat for scenario_b and scenario_c (both architectures)
#   3. Replace the corresponding values in DATA_M1 and DATA_M3 below
#   4. Update CONTROL_EFFECTIVENESS cells from Table 4.4 empirical values
#   5. Re-run: python3 results/visualise_results.py
# ---------------------------------------------------------------------------

import argparse
import json
import os

import matplotlib
matplotlib.use("Agg")  # non-interactive backend for headless systems
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

# ---------------------------------------------------------------------------
# Default data — design-time predictions from Table 4.4
# Structure: { "baseline": [A, B, C], "hardened": [A, B, C] }
# ---------------------------------------------------------------------------
DATA_M1 = {
    "baseline": [100.0, 100.0, 100.0],  # All scenarios succeed on baseline
    "hardened": [0.0,   0.0,   0.0],    # All scenarios blocked on hardened
}

DATA_M3 = {
    "baseline": [0.0,   0.0,   0.0],    # No structured logging on baseline
    "hardened": [100.0, 100.0, 100.0],  # Full detection on hardened
}

# Control effectiveness: rows = control families, cols = M1, M2, M3
# Values: 0=None, 1=Low, 2=Moderate, 3=Large
CONTROL_EFFECTIVENESS = {
    "rows": [
        "Network Isolation",
        "Container Hardening",
        "Managed Identities\n+ Secrets Mgmt",
        "Logging &\nMonitoring",
    ],
    "cols": ["M1\n(Attack Rate)", "M2\n(Scope)", "M3\n(Detection)"],
    "data": [
        [3, 2, 2],  # Network Isolation
        [2, 2, 1],  # Container Hardening
        [3, 3, 2],  # Managed Identities + Secrets Management
        [0, 0, 3],  # Logging and Monitoring
    ],
    "labels": {
        0: "None",
        1: "Low",
        2: "Moderate",
        3: "Large",
    },
}

SCENARIOS = ["Scenario A", "Scenario B", "Scenario C"]
COLOUR_BASELINE = "#D32F2F"   # red
COLOUR_HARDENED = "#388E3C"   # green


# ---------------------------------------------------------------------------
# Helper: load empirical data from JSON files (if available)
# If files do not exist (pre-experiment), falls back to the defaults above.
# ---------------------------------------------------------------------------
def _load_empirical(results_dir: str) -> None:
    """
    Attempt to read m1_success_rate_pct and m3_log_events_generated from
    results/<arch>/scenario_<x>_results.json.  Updates DATA_M1 and DATA_M3
    in-place if files are found.  Missing or null values are left as defaults.
    """
    for arch_key, arch_dir in [("baseline", "baseline"), ("hardened", "hardened")]:
        for idx, letter in enumerate(("a", "b", "c")):
            path = os.path.join(results_dir, arch_dir, f"scenario_{letter}_results.json")
            if not os.path.exists(path):
                continue
            try:
                with open(path, encoding="utf-8") as fh:
                    data = json.load(fh)
                m1 = data.get("m1_success_rate_pct")
                m3 = data.get("m3_log_events_generated")
                if m1 is not None:
                    DATA_M1[arch_key][idx] = float(m1)
                if m3 is not None:
                    DATA_M3[arch_key][idx] = float(m3)
            except (json.JSONDecodeError, KeyError, TypeError):
                pass  # use defaults for this entry


# ---------------------------------------------------------------------------
# Chart 1 — M1: Grouped bar chart, Attack Success Rate
# ---------------------------------------------------------------------------
def chart_m1(output_dir: str) -> str:
    fig, ax = plt.subplots(figsize=(8, 5))
    x       = np.arange(len(SCENARIOS))
    width   = 0.35

    bars_b = ax.bar(x - width / 2, DATA_M1["baseline"], width,
                    label="Baseline", color=COLOUR_BASELINE, edgecolor="white", linewidth=0.8)
    bars_h = ax.bar(x + width / 2, DATA_M1["hardened"],  width,
                    label="Hardened", color=COLOUR_HARDENED, edgecolor="white", linewidth=0.8)

    # Value labels on bars
    for bar in list(bars_b) + list(bars_h):
        h = bar.get_height()
        if h > 0:
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                h + 1.5,
                f"{h:.0f}%",
                ha="center", va="bottom", fontsize=9, fontweight="bold",
            )

    ax.set_xlabel("Attack Scenario", fontsize=11)
    ax.set_ylabel("Mean Success Rate (%)", fontsize=11)
    ax.set_title("M1 — Attack Success Rate: Baseline vs. Hardened", fontsize=13, fontweight="bold")
    ax.set_xticks(x)
    ax.set_xticklabels(SCENARIOS, fontsize=10)
    ax.set_ylim(0, 115)
    ax.set_yticks(range(0, 101, 20))
    ax.yaxis.grid(True, linestyle="--", alpha=0.6)
    ax.set_axisbelow(True)
    ax.legend(fontsize=10)

    fig.tight_layout()
    out = os.path.join(output_dir, "chart_m1_attack_success_rate.png")
    fig.savefig(out, dpi=150, bbox_inches="tight")
    plt.close(fig)
    return out


# ---------------------------------------------------------------------------
# Chart 2 — M3: Grouped bar chart, Detection Rate
# ---------------------------------------------------------------------------
def chart_m3(output_dir: str) -> str:
    fig, ax = plt.subplots(figsize=(8, 5))
    x       = np.arange(len(SCENARIOS))
    width   = 0.35

    bars_b = ax.bar(x - width / 2, DATA_M3["baseline"], width,
                    label="Baseline", color=COLOUR_BASELINE, edgecolor="white", linewidth=0.8)
    bars_h = ax.bar(x + width / 2, DATA_M3["hardened"],  width,
                    label="Hardened", color=COLOUR_HARDENED, edgecolor="white", linewidth=0.8)

    for bar in list(bars_b) + list(bars_h):
        h = bar.get_height()
        if h > 0:
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                h + 1.5,
                f"{h:.0f}%",
                ha="center", va="bottom", fontsize=9, fontweight="bold",
            )

    ax.set_xlabel("Attack Scenario", fontsize=11)
    ax.set_ylabel("Detection Rate (%)", fontsize=11)
    ax.set_title("M3 — Detection Visibility: Baseline vs. Hardened", fontsize=13, fontweight="bold")
    ax.set_xticks(x)
    ax.set_xticklabels(SCENARIOS, fontsize=10)
    ax.set_ylim(0, 115)
    ax.set_yticks(range(0, 101, 20))
    ax.yaxis.grid(True, linestyle="--", alpha=0.6)
    ax.set_axisbelow(True)
    ax.legend(fontsize=10)

    fig.tight_layout()
    out = os.path.join(output_dir, "chart_m3_detection_visibility.png")
    fig.savefig(out, dpi=150, bbox_inches="tight")
    plt.close(fig)
    return out


# ---------------------------------------------------------------------------
# Chart 3 — Control Effectiveness Heatmap
# ---------------------------------------------------------------------------
def chart_heatmap(output_dir: str) -> str:
    rows   = CONTROL_EFFECTIVENESS["rows"]
    cols   = CONTROL_EFFECTIVENESS["cols"]
    matrix = np.array(CONTROL_EFFECTIVENESS["data"], dtype=float)
    labels = CONTROL_EFFECTIVENESS["labels"]

    fig, ax = plt.subplots(figsize=(7, 5))

    # white -> green colourmap (0 = white, 3 = deep green)
    cmap = matplotlib.colormaps.get_cmap("Greens").resampled(4)
    im   = ax.imshow(matrix, cmap=cmap, vmin=-0.5, vmax=3.5, aspect="auto")

    # Axis ticks
    ax.set_xticks(range(len(cols)))
    ax.set_yticks(range(len(rows)))
    ax.set_xticklabels(cols,  fontsize=11)
    ax.set_yticklabels(rows,  fontsize=10)
    ax.xaxis.tick_top()
    ax.xaxis.set_label_position("top")

    # Annotate each cell with qualitative label
    for r in range(len(rows)):
        for c in range(len(cols)):
            val   = int(matrix[r, c])
            label = labels[val]
            # Use dark text on light cells, light text on dark cells
            text_colour = "white" if val >= 2 else "black"
            ax.text(
                c, r, label,
                ha="center", va="center",
                fontsize=11, fontweight="bold",
                color=text_colour,
            )

    ax.set_title("Control Effectiveness by Metric", fontsize=13, fontweight="bold", pad=18)

    # Colourbar with qualitative tick labels
    cbar = fig.colorbar(im, ax=ax, ticks=[0, 1, 2, 3], fraction=0.046, pad=0.04)
    cbar.ax.set_yticklabels(["None (0)", "Low (1)", "Moderate (2)", "Large (3)"], fontsize=9)
    cbar.set_label("Effect Size", fontsize=10)

    # Grid lines between cells
    ax.set_xticks(np.arange(-0.5, len(cols), 1), minor=True)
    ax.set_yticks(np.arange(-0.5, len(rows), 1), minor=True)
    ax.grid(which="minor", color="white", linewidth=2)
    ax.tick_params(which="minor", bottom=False, left=False, top=False)

    fig.tight_layout()
    out = os.path.join(output_dir, "chart_control_effectiveness_heatmap.png")
    fig.savefig(out, dpi=150, bbox_inches="tight")
    plt.close(fig)
    return out


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------
def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate M1, M3, and control-effectiveness charts from scenario results"
    )
    parser.add_argument(
        "--results-dir",
        default="./results",
        help="Root directory containing baseline/ and hardened/ result subdirs (default: ./results)",
    )
    parser.add_argument(
        "--output-dir",
        default="./results/charts",
        help="Directory to save PNG charts (default: ./results/charts)",
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()

    # Load empirical data if available
    _load_empirical(args.results_dir)

    # Create output directory
    os.makedirs(args.output_dir, exist_ok=True)

    print(f"Generating charts -> {args.output_dir}/")

    out1 = chart_m1(args.output_dir)
    print(f"  [OK] Chart 1 (M1 Attack Success Rate):      {out1}")

    out2 = chart_m3(args.output_dir)
    print(f"  [OK] Chart 2 (M3 Detection Visibility):     {out2}")

    out3 = chart_heatmap(args.output_dir)
    print(f"  [OK] Chart 3 (Control Effectiveness Heatmap): {out3}")

    print("\nDone. Three charts saved.")
    print(
        "\nNOTE: Charts currently show design-time predictions.\n"
        "After running run_all.sh for both architectures, re-run this script\n"
        "to regenerate with empirical values from the results JSON files."
    )


if __name__ == "__main__":
    main()
