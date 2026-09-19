"""
Stage 12 (Capstone STEP 9) - Security intelligence: requirements, enrichment, products.

Plain English: analysis only becomes intelligence when it answers a question someone asked
and reaches the person who can act. This stage writes down the mine's intelligence
requirements, enriches the analytical findings with asset, account and ATT&CK context, and
produces two products: one for the SOC analyst and one for management.

The ATT&CK mapping is DERIVED, not asserted: each detection rule description is compared
with the 357 ATT&CK for ICS descriptions using TF-IDF similarity, and the nearest entries
are reported with their scores. Where the similarity is low, that is stated rather than
dressed up as a confident mapping.

Outputs: outputs/tables/intel_*.csv, outputs/intelligence_executive_brief.md
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import DATA_PROCESSED, DATA_RAW, OUT, OUT_TABLES, env_stamp, get_logger, write_json

LOG = get_logger("s12_intel")

PIRS = [
    ("PIR1", "Which remote accounts show behaviour consistent with credential abuse, and "
             "which assets did they touch?",
     "access log, UEBA rules, anomaly model", "daily"),
    ("PIR2", "Is there evidence of an attacker reaching the OT zone or an industrial "
             "protocol (Modbus, DNP3, MQTT)?",
     "network flows, Modbus telemetry classifier", "daily"),
    ("PIR3", "Which IIoT devices or network sources deviate from their established "
             "behavioural baseline?",
     "telemetry baselines, Isolation Forest", "daily"),
    ("PIR4", "Which control package most reduces the chance of an intrusion reaching "
             "critical OT assets?",
     "Monte Carlo simulation", "quarterly"),
    ("PIR5", "Are maintenance and incident reports describing security-relevant conditions "
             "that the technical telemetry has not surfaced?",
     "ticket corpus, ATT&CK enrichment", "weekly"),
]

RULE_TEXT = {
    "R1": "repeated failed authentication attempts against a single account",
    "R2": "password spraying from one source address against many accounts",
    "R3": "account authenticating from two distant locations within a short period",
    "R4": "privileged engineering action performed outside normal working hours",
    "R5": "account authenticating from a country never seen before for that account",
    "R6": "dormant account reactivated and used for remote access",
    "R7": "privileged remote session established without multi-factor authentication",
}


def attack_mapping(attack: pd.DataFrame) -> pd.DataFrame:
    vec = TfidfVectorizer(ngram_range=(1, 2), min_df=2, stop_words="english", sublinear_tf=True)
    A = vec.fit_transform(attack["text"].str.lower())
    Q = vec.transform(pd.Series(list(RULE_TEXT.values())).str.lower())
    sim = (Q @ A.T).toarray()
    rows = []
    for i, rule in enumerate(RULE_TEXT):
        order = sim[i].argsort()[::-1][:2]
        for rank, j in enumerate(order, 1):
            rows.append({
                "rule": rule, "rule_description": RULE_TEXT[rule], "rank": rank,
                "attack_id": attack["record_id"].iloc[j],
                "attack_name": attack["name"].iloc[j],
                "attack_class": attack["record_class"].iloc[j],
                "similarity": round(float(sim[i, j]), 3),
                "confidence": ("moderate" if sim[i, j] >= 0.15 else
                               "low - reported for context only"),
            })
    return pd.DataFrame(rows)


def main() -> None:
    risk = pd.read_parquet(DATA_PROCESSED / "access_user_day_risk.parquet")
    alerts = pd.read_csv(OUT_TABLES / "ueba_alerts.csv")
    assets = pd.read_csv(DATA_RAW / "mining_asset_inventory.csv")
    users = pd.read_csv(DATA_RAW / "mining_user_directory.csv")
    attack = pd.read_csv(DATA_RAW / "attack_ics_text.csv")
    sim_summary = pd.read_csv(OUT_TABLES / "simulation_summary.csv")
    incident = json.loads((OUT_TABLES / "incident_summary.json").read_text())
    nlp = json.loads((OUT_TABLES / "nlp_summary.json").read_text())
    sup = json.loads((OUT_TABLES / "supervised_summary.json").read_text())
    anom = json.loads((OUT_TABLES / "anomaly_summary.json").read_text())

    pd.DataFrame(PIRS, columns=["pir", "question", "sources", "review_cycle"]).to_csv(
        OUT_TABLES / "intel_requirements.csv", index=False)

    mapping = attack_mapping(attack)
    mapping.to_csv(OUT_TABLES / "intel_attack_mapping.csv", index=False)

    # ---------------- operational product: what the SOC should work today -------------
    top_rule = (alerts.groupby("username", observed=True)
                .agg(alerts=("alert_id", "count"),
                     rules=("rule", lambda s: ",".join(sorted(set(s)))),
                     highest_sev=("severity", lambda s: "high" if "high" in set(s) else
                                  ("medium" if "medium" in set(s) else "low")),
                     last_seen=("timestamp", "max"),
                     evidence=("evidence_event_ids", lambda s: "|".join(s)[:180])).reset_index())
    peak_risk = (risk.groupby("username", observed=True)
                 .agg(max_risk=("risk_score", "max"), worst_day=("risk_score", "idxmax"),
                      band=("risk_band", lambda s: sorted(s, key=lambda b: ["low", "moderate",
                            "high", "critical"].index(b))[-1]),
                      top_driver=("top_driver", lambda s: s.mode().iloc[0])).reset_index())
    ops = (top_rule.merge(peak_risk, on="username", how="outer")
           .merge(users[["username", "user_role", "employment_type", "home_site",
                         "privileged_account", "mfa_enrolled"]], on="username", how="left"))
    ops["alerts"] = ops["alerts"].fillna(0).astype(int)
    ops["priority"] = ops["max_risk"].fillna(0) + 8 * ops["alerts"] + \
                      ops["highest_sev"].map({"high": 25, "medium": 10, "low": 3}).fillna(0)
    rule_first = mapping[mapping["rank"] == 1].set_index("rule")
    ops["attack_context"] = ops["rules"].fillna("").map(
        lambda rr: "; ".join(f"{r}->{rule_first.loc[r, 'attack_id']} "
                             f"{rule_first.loc[r, 'attack_name']}"
                             for r in rr.split(",") if r in rule_first.index))
    ops = ops.sort_values("priority", ascending=False)
    ops.to_csv(OUT_TABLES / "intel_operational_watchlist.csv", index=False)

    # assets that the highest-priority accounts touched
    top_accounts = ops.head(10)["username"].tolist()
    acc = pd.read_parquet(DATA_PROCESSED / "access_events.parquet")
    touched = (acc[acc.username.isin(top_accounts)]
               .groupby("asset_id", observed=True)
               .agg(events=("event_id", "count"),
                    accounts=("username", lambda s: ",".join(sorted(set(s))))).reset_index()
               .merge(assets, on="asset_id", how="left"))
    touched = touched.sort_values(
        ["criticality", "events"],
        key=lambda s: s.map({"critical": 0, "high": 1, "medium": 2, "low": 3}) if s.name == "criticality" else s)
    touched.to_csv(OUT_TABLES / "intel_assets_in_scope.csv", index=False)

    # ---------------- executive product ----------------
    crit_days = int((risk["risk_band"] == "critical").sum())
    high_days = int((risk["risk_band"] == "high").sum())
    s0 = sim_summary[sim_summary.scenario == "S0_baseline"].iloc[0]
    s4 = sim_summary[sim_summary.scenario == "S4_combined"].iloc[0]
    s2 = sim_summary[sim_summary.scenario == "S2_strong_auth"].iloc[0]
    brief = f"""# Executive security brief - Mining remote operations and IIoT

**Prepared by:** SAS821S Capstone group T08 (222093471 Kalume, 215103815 Shithindi)
**Data window:** 1-30 April 2019 (access, ticket and telemetry sources aligned to the same window)
**Status of the data:** ToN_IoT research captures plus a documented synthetic access log. This is a
university exercise; none of the accounts, assets or events describe a real organisation.

## What we found

1. **Remote access is the weakest link in this environment.** {int(risk['priv_no_mfa'].sum())}
   privileged actions took place without multi-factor authentication, and
   {len(ops[ops.alerts > 0])} accounts raised at least one behavioural alert during the month.
   {crit_days} user-days scored in the *critical* risk band and {high_days} in the *high* band
   (out of {len(risk):,} user-days in the month).

2. **The strongest single case** involves account `{incident['case_account']}`
   ({incident['account_role']}, {incident['employment_type']}), with
   {incident['privileged_actions']} privileged actions of which
   {incident['privileged_without_mfa']} had no MFA, touching {incident['affected_assets']}
   assets over {len(incident['alert_window_days'])} days. A containment, eradication,
   recovery and monitoring plan is attached to the technical report.

3. **Detection works, but only where the data is complete.** The network intrusion
   classifier reaches an F1 of {sup['network']['test_metrics'][2]['f1']:.3f} on unseen flows,
   and the Modbus telemetry classifier {sup['modbus']['metrics'][1]['f1']:.3f}. However, when
   half of the collected fields are missing the network detector falls to F1 0.77, so
   telemetry collection reliability is itself a security control.

4. **Unsupervised detection needs a trusted baseline.** Scoring "whatever is rare" gave a
   ROC-AUC of {anom['network']['roc_auc_unsupervised']:.2f} - worse than guessing - because in that
   capture attacks are the majority. Learning a known-good baseline first raised it to
   {anom['network']['roc_auc_clean_baseline']:.2f}.

5. **Text sources add context the telemetry does not have.**
   {nlp['topics_and_enrichment']['matched_tickets']} of 320 maintenance and incident tickets
   matched an ATT&CK for ICS description closely enough to be useful for triage.

## What it would cost us

Under the modelled assumptions, an intrusion that starts with a stolen remote-access
credential reaches the OT zone in **{s0['p_reach_ot']:.0%}** of runs today and a critical OT
asset in **{s0['p_reach_critical']:.0%}**, compromising **{s0['mean_assets_compromised']:.0f} assets** on average.

## What we recommend, in order

| Priority | Action | Modelled effect |
|---|---|---|
| 1 | Enforce MFA on every remote and privileged session | P(reach OT) falls from {s0['p_reach_ot']:.0%} to {s2['p_reach_ot']:.0%} |
| 2 | Restrict IT-OT to OT traffic to an approved flow list | mean assets compromised falls from {s0['mean_assets_compromised']:.0f} to {sim_summary[sim_summary.scenario=='S1_segmentation'].iloc[0]['mean_assets_compromised']:.0f} |
| 3 | Deploy detection and isolation on jump hosts and engineering workstations | modest on its own, valuable in combination |
| 4 | All three together | P(reach OT) {s4['p_reach_ot']:.0%}, critical assets {s4['p_reach_critical']:.0%}, {s4['mean_assets_compromised']:.0f} assets |

## What we are not claiming

* The simulation compares control packages under stated assumptions; it does not forecast
  how often a real intrusion would occur.
* The access log is synthetic, so detection results show that the method finds the
  behaviour we injected, not that it has found a real attacker.
* ToN_IoT is a research testbed, not mining equipment; its captures stand in for mining
  IIoT behaviour and the substitution is documented.
"""
    (OUT / "intelligence_executive_brief.md").write_text(brief, encoding="utf-8")

    write_json({
        "pirs": len(PIRS),
        "watchlist_accounts": int(len(ops)),
        "accounts_with_alerts": int((ops["alerts"] > 0).sum()),
        "critical_risk_user_days": crit_days,
        "high_risk_user_days": high_days,
        "attack_mappings": mapping.to_dict(orient="records"),
        "assets_in_scope": int(len(touched)),
        "env": env_stamp(),
    }, OUT_TABLES / "intel_summary.json")
    LOG.info("watchlist=%d accounts (%d with alerts); assets in scope=%d; brief written",
             len(ops), int((ops["alerts"] > 0).sum()), len(touched))
    LOG.info("ATT&CK mapping confidence: %s",
             mapping[mapping["rank"] == 1]["confidence"].value_counts().to_dict())


if __name__ == "__main__":
    main()
