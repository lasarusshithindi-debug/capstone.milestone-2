"""
Stage 20 (Capstone STEP 20) - Compliance checklist against requirements C1-C10.

A requirement is only marked COMPLETE if the evidence file it depends on actually exists on
disk at the moment this script runs. The status column is therefore produced by a check,
not by an opinion.

Outputs: outputs/tables/compliance_checklist.csv, outputs/compliance_checklist.md
"""
from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import OUT, OUT_TABLES, ROOT, get_logger

LOG = get_logger("s20_compliance")

CHECKS = [
    ("C1", "Security analytics lifecycle",
     ["outputs/tables/data_inventory.csv", "outputs/tables/cleaning_log.csv",
      "outputs/tables/eda_findings.csv", "outputs/tables/incident_response_plan.csv",
      "outputs/logs/run_log.txt"],
     "all 5 sources", "Lifecycle from collection to action is implemented as stages "
                      "s01-s16 with a log of every run.",
     "Feedback loop is documented but not yet automated (no re-labelling workflow)."),
    ("C2", "Multi-source data (>=3, incl. identity/access and network/OT)",
     ["outputs/tables/data_inventory.csv", "outputs/tables/minimum_data_check.csv",
      "data/raw/synthetic_remote_access_log.csv", "data/raw/mining_asset_inventory.csv"],
     "5 source families, 635k+ records", "IIoT telemetry, network flows, identity/access, "
                                         "ticket text, ATT&CK ICS text, plus asset/user context.",
     "Access log and tickets are synthetic; this must be stated in the report and defence."),
    ("C3", "Data engineering and baseline",
     ["outputs/tables/data_dictionary.csv", "outputs/tables/cleaning_log.csv",
      "outputs/tables/baseline_access_role.csv", "outputs/tables/baseline_telemetry.csv",
      "outputs/figures/fig08_login_hour_by_role.png"],
     "dictionary + 37 cleaning actions + baselines", "Provenance hashes, quality findings, "
                                                     "role/user/telemetry/network baselines.",
     "Network flow source has no timestamp column, so time-based joins to it are not possible."),
    ("C4", "Machine learning (supervised + unsupervised)",
     ["outputs/tables/supervised_network_test.csv", "outputs/tables/supervised_modbus_test.csv",
      "outputs/tables/anomaly_access_validation.csv",
      "outputs/figures/fig09_confusion_network.png"],
     "3 supervised models, IF/LOF/DBSCAN", "Confusion matrices, precision, recall, F1, "
                                           "ROC-AUC, PR-AUC, permutation importance.",
     "Scores on ToN_IoT are high because the capture is a controlled testbed."),
    ("C5", "Security investigation",
     ["outputs/tables/incident_timeline.csv", "outputs/tables/incident_affected_entities.csv",
      "outputs/tables/incident_response_plan.csv"],
     "202-row timeline with evidence IDs", "Case ranked from evidence, entities identified, "
                                           "four-phase response plan.",
     "The case is an analytical scenario built on synthetic access data, clearly labelled."),
    ("C6", "Security intelligence",
     ["outputs/tables/intel_requirements.csv", "outputs/tables/intel_attack_mapping.csv",
      "outputs/tables/intel_operational_watchlist.csv", "outputs/intelligence_executive_brief.md"],
     "5 PIRs, ATT&CK mapping, 2 products", "Operational watchlist for the SOC and an "
                                           "executive brief with modelled effects.",
     "ATT&CK mapping is TF-IDF similarity, not an analyst-validated mapping."),
    ("C7", "Simulation of >=3 control scenarios",
     ["outputs/tables/simulation_summary.csv", "outputs/tables/simulation_sensitivity.csv",
      "outputs/figures/fig20_simulation_scenarios.png"],
     "5 scenarios x 5,000 runs + sensitivity", "Monte Carlo propagation over the asset "
                                               "graph with Wilson confidence intervals.",
     "Transmission probabilities are assumed; only p_foothold is measured from data."),
    ("C8", "Text mining / NLP",
     ["outputs/tables/nlp_ticket_classification.csv", "outputs/tables/nlp_extracted_indicators.csv",
      "outputs/tables/nlp_attack_topics.csv", "outputs/tables/nlp_ticket_attack_enrichment.csv"],
     "677 text records, classify + extract + topics", "Preprocessing, TF-IDF classification "
                                                      "with a confusion matrix, indicator "
                                                      "extraction scored against an answer key, "
                                                      "NMF topics, ATT&CK enrichment.",
     "Ticket text is template-generated, so classification accuracy is optimistic."),
    ("C9", "Predictive risk + >=3 adversarial tests",
     ["outputs/tables/risk_user_day_scores.csv", "outputs/tables/risk_band_summary.csv",
      "outputs/tables/risk_forecast_metrics.csv", "outputs/tables/adversarial_results.csv"],
     "risk score + 4 test families", "Six-component interpretable score with bands, "
                                     "next-day early warning, and drift/evasion/missing-data/"
                                     "poisoning tests.",
     "Next-day forecast is weak (ROC-AUC ~0.53); reported as a negative result."),
    ("C10", "Decision-support prototype",
     ["app/app.py", "notebooks/capstone_walkthrough.ipynb", "outputs/figures/fig26_architecture.png"],
     "Streamlit console (8 views) + notebook", "Analyst can inspect events, baselines, "
                                               "anomalies, model results, risk, the incident "
                                               "and the intelligence products.",
     "Prototype reads pre-computed outputs; it does not yet ingest live data."),
]


def main() -> None:
    rows = []
    for code, req, files, evidence, what, remaining in CHECKS:
        present = [f for f in files if (ROOT / f).exists()]
        missing = [f for f in files if not (ROOT / f).exists()]
        status = "COMPLETE" if not missing else ("PARTIAL" if present else "MISSING")
        rows.append({
            "code": code, "requirement": req, "evidence_produced": evidence,
            "what_was_done": what,
            "files": "; ".join(files),
            "files_present": f"{len(present)}/{len(files)}",
            "missing_files": "; ".join(missing),
            "status": status,
            "remaining_work": remaining,
        })
    df = pd.DataFrame(rows)
    df.to_csv(OUT_TABLES / "compliance_checklist.csv", index=False)

    md = ["# Capstone compliance checklist (C1-C10)", "",
          "Status is produced by checking that each evidence file exists when this script "
          "runs, not by assertion.", ""]
    for r in rows:
        md.append(f"## {r['code']} - {r['requirement']} — **{r['status']}** "
                  f"({r['files_present']} evidence files present)")
        md.append(f"- **Evidence:** {r['evidence_produced']}")
        md.append(f"- **What was done:** {r['what_was_done']}")
        md.append(f"- **Files:** `{r['files'].replace('; ', '`, `')}`")
        md.append(f"- **Remaining / caveat:** {r['remaining_work']}")
        md.append("")
    (OUT / "compliance_checklist.md").write_text("\n".join(md), encoding="utf-8")

    LOG.info("compliance: %s", df["status"].value_counts().to_dict())
    for r in rows:
        LOG.info("  %-4s %-45s %s", r["code"], r["requirement"][:45], r["status"])


if __name__ == "__main__":
    main()
