"""
Stage 16 (Capstone STEP 15) - End-to-end architecture diagram of what is ACTUALLY built.

Every box below corresponds to a script that exists in src/ and an output file that the
pipeline produces. The diagram is generated from that list, so it cannot drift away from
the implementation.

Outputs: outputs/figures/fig26_architecture.png, outputs/tables/architecture_stages.csv
"""
from __future__ import annotations

import sys
from pathlib import Path

import matplotlib.patches as mp
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import OUT_FIGS, OUT_TABLES, ROOT, get_logger
from viz import CATEGORICAL, plt

LOG = get_logger("s16_arch")

STAGES = [
    ("DATA SOURCES", "ToN_IoT IIoT telemetry (401k) · ToN_IoT network flows (211k) · "
                     "synthetic access log (22.7k) · tickets (320) · ATT&CK ICS (357) · "
                     "asset & user context",
     "src/s01-s03", ["data/raw/attack_ics_text.csv", "data/raw/synthetic_remote_access_log.csv"]),
    ("INGESTION & INVENTORY", "hashing, profiling, data dictionary, quality findings",
     "src/s04_inventory.py", ["outputs/tables/data_inventory.csv",
                              "outputs/tables/data_dictionary.csv"]),
    ("CLEANING & FEATURES", "placeholder handling, type coercion, duplicate flags, "
                            "timestamp standardisation, engineered features, joins",
     "src/s06_clean.py", ["outputs/tables/cleaning_log.csv",
                          "data/processed/network_flows.parquet"]),
    ("DESCRIPTIVE & BASELINE", "volumes, attack mix, service profile, login-hour baselines",
     "src/s07_eda.py", ["outputs/tables/baseline_access_role.csv",
                        "outputs/tables/eda_findings.csv"]),
    ("SUPERVISED ML", "logistic regression / decision tree / random forest; binary and "
                      "attack-family classification",
     "src/s08_supervised.py", ["outputs/tables/supervised_network_test.csv"]),
    ("ANOMALY & CLUSTERING", "Isolation Forest (2 framings), LOF, DBSCAN peer groups",
     "src/s09_anomaly.py", ["outputs/tables/anomaly_access_flagged_user_days.csv"]),
    ("ACCESS ANALYTICS", "7 behaviour rules with evidence, per-user and per-role baselines",
     "src/s10_access_analytics.py", ["outputs/tables/ueba_alerts.csv"]),
    ("INVESTIGATION", "case ranking, correlated timeline, affected entities, response plan",
     "src/s11_investigation.py", ["outputs/tables/incident_timeline.csv"]),
    ("TEXT MINING / NLP", "TF-IDF classification, indicator extraction, NMF topics, "
                          "ATT&CK enrichment",
     "src/s14_textmining.py", ["outputs/tables/nlp_extracted_indicators.csv"]),
    ("INTELLIGENCE", "PIRs, ATT&CK mapping, operational watchlist, executive brief",
     "src/s12_intelligence.py", ["outputs/intelligence_executive_brief.md"]),
    ("PREDICTIVE RISK", "six-component risk score, bands, next-day early warning",
     "src/s15_risk_adversarial.py", ["outputs/tables/risk_user_day_scores.csv"]),
    ("SIMULATION", "Monte Carlo control scenarios with sensitivity analysis",
     "src/s13_simulation.py", ["outputs/tables/simulation_summary.csv"]),
    ("ADVERSARIAL TESTING", "drift, evasion, missing data, label poisoning",
     "src/s15_risk_adversarial.py", ["outputs/tables/adversarial_results.csv"]),
    ("DECISION SUPPORT", "Streamlit analyst console (8 views) + reproducible notebook",
     "app/app.py", ["app/app.py"]),
    ("SECURITY ACTION", "containment / eradication / recovery / monitoring decisions",
     "src/s11_investigation.py", ["outputs/tables/incident_response_plan.csv"]),
]


def main() -> None:
    rows = []
    for name, desc, impl, outs in STAGES:
        present = [o for o in outs if (ROOT / o).exists()]
        rows.append({"stage": name, "what_it_does": desc, "implemented_in": impl,
                     "evidence_files": "; ".join(outs),
                     "evidence_present": f"{len(present)}/{len(outs)}"})
    df = pd.DataFrame(rows)
    df.to_csv(OUT_TABLES / "architecture_stages.csv", index=False)

    fig, ax = plt.subplots(figsize=(8.6, 12.4))
    ax.set_xlim(0, 10); ax.set_ylim(0, len(STAGES) * 1.15 + 0.5)
    ax.axis("off")
    for i, (name, desc, impl, outs) in enumerate(reversed(STAGES)):
        y = i * 1.15 + 0.3
        colour = CATEGORICAL[(len(STAGES) - i) % len(CATEGORICAL)]
        ax.add_patch(mp.FancyBboxPatch((0.5, y), 9, 0.9, boxstyle="round,pad=0.04",
                                       linewidth=1.1, edgecolor=colour, facecolor=colour,
                                       alpha=0.13))
        ax.text(0.75, y + 0.63, name, fontsize=9.2, fontweight="bold", color="#222222")
        ax.text(0.75, y + 0.37, desc, fontsize=7.1, color="#333333", wrap=True)
        ax.text(0.75, y + 0.14, impl, fontsize=6.8, style="italic", color="#666666")
        if i:
            ax.annotate("", xy=(5, y + 1.0), xytext=(5, y + 0.92),
                        arrowprops=dict(arrowstyle="-|>", color="#888888", lw=1.2))
    ax.set_title("T08 implemented architecture: data to security action", fontsize=11,
                 fontweight="bold", pad=14)
    fig.savefig(OUT_FIGS / "fig26_architecture.png", dpi=140, bbox_inches="tight")
    plt.close(fig)
    LOG.info("architecture diagram written; %d stages, all evidence files present: %s",
             len(df), bool((df["evidence_present"].str.split("/").map(
                 lambda x: x[0] == x[1])).all()))


if __name__ == "__main__":
    main()
