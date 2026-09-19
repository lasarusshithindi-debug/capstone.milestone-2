"""
SAS821S Capstone T08 - Analyst decision-support console (Streamlit prototype).

Run it with:      streamlit run app/app.py
from the project root, after `python src/run_all.py` has produced the outputs.

The console is organised the way an analyst works: what is happening today, who to look at,
what the models say, what the evidence is, what to tell management, and what changing a
control would do.
"""
from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

ROOT = Path(__file__).resolve().parents[1]
T = ROOT / "outputs" / "tables"
F = ROOT / "outputs" / "figures"
P = ROOT / "data" / "processed"

st.set_page_config(page_title="T08 Mining IIoT Security Console", layout="wide")


@st.cache_data
def csv(name: str, folder: Path = T) -> pd.DataFrame:
    path = folder / name
    return pd.read_csv(path) if path.exists() else pd.DataFrame()


@st.cache_data
def js(name: str) -> dict:
    path = T / name
    return json.loads(path.read_text()) if path.exists() else {}


@st.cache_data
def parquet(name: str) -> pd.DataFrame:
    path = P / name
    return pd.read_parquet(path) if path.exists() else pd.DataFrame()


risk = parquet("access_user_day_risk.parquet")
acc = parquet("access_events.parquet")
alerts = csv("ueba_alerts.csv")
watch = csv("intel_operational_watchlist.csv")
timeline = csv("incident_timeline.csv")
sim = csv("simulation_summary.csv")
adv = csv("adversarial_results.csv")

st.title("Mining Remote Operations & Industrial-IoT Security Console")
st.caption("SAS821S Capstone T08 · 222093471 Kalume · 215103815 Shithindi · "
           "Data: ToN_IoT research captures + documented synthetic access log · "
           "University exercise, not a live security system")

tabs = st.tabs(["Overview", "Accounts & risk", "Anomalies", "Investigation",
                "Intelligence", "Simulation", "Models & robustness", "Data & method"])

# ----------------------------------------------------------------------------- Overview
with tabs[0]:
    inv = csv("data_inventory.csv")
    sup = js("supervised_summary.json")
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Records analysed", f"{int(inv['rows'].sum()):,}" if len(inv) else "-")
    c2.metric("Accounts monitored", f"{risk['username'].nunique():,}" if len(risk) else "-")
    c3.metric("Behaviour alerts", f"{len(alerts):,}")
    c4.metric("Critical-risk user-days",
              int((risk["risk_band"] == "critical").sum()) if len(risk) else 0)
    if sup:
        c5.metric("Network detector F1",
                  f"{sup['network']['test_metrics'][2]['f1']:.3f}")

    if len(alerts):
        a = alerts.copy()
        a["day"] = pd.to_datetime(a["timestamp"]).dt.date
        daily = a.groupby(["day", "severity"]).size().reset_index(name="alerts")
        st.plotly_chart(px.bar(daily, x="day", y="alerts", color="severity",
                               title="Access alerts per day",
                               color_discrete_map={"high": "#D55E00", "medium": "#E69F00",
                                                   "low": "#0072B2"}),
                        use_container_width=True)
    if len(risk):
        band = risk["risk_band"].value_counts().reset_index()
        band.columns = ["band", "user_days"]
        st.plotly_chart(px.bar(band, x="band", y="user_days", title="Risk band distribution",
                               color="band",
                               category_orders={"band": ["critical", "high", "moderate", "low"]}),
                        use_container_width=True)

# ---------------------------------------------------------------------- Accounts & risk
with tabs[1]:
    st.subheader("Priority watchlist")
    if len(watch):
        band_pick = st.multiselect("Risk band", sorted(watch["band"].dropna().unique()),
                                   default=["critical", "high"] if
                                   "critical" in set(watch["band"].dropna()) else None)
        view = watch[watch["band"].isin(band_pick)] if band_pick else watch
        st.dataframe(view[["username", "user_role", "employment_type", "alerts", "rules",
                           "highest_sev", "max_risk", "band", "top_driver", "mfa_enrolled",
                           "attack_context"]].head(50), use_container_width=True, height=330)

    st.subheader("Account drill-down")
    if len(risk):
        who = st.selectbox("Account", sorted(risk["username"].unique()))
        sub = risk[risk.username == who].sort_values("day")
        st.plotly_chart(px.line(sub, x="day", y="risk_score", markers=True,
                                title=f"Daily risk score - {who}"), use_container_width=True)
        comp_cols = [c for c in risk.columns if c.startswith("comp_")]
        worst = sub.nlargest(1, "risk_score")
        if len(worst):
            st.write(f"**Worst day:** {worst.iloc[0]['day']} · score "
                     f"{worst.iloc[0]['risk_score']} · band {worst.iloc[0]['risk_band']} · "
                     f"largest driver: {worst.iloc[0]['top_driver']}")
            drv = worst[comp_cols].T.reset_index()
            drv.columns = ["component", "percentile"]
            st.plotly_chart(px.bar(drv, x="percentile", y="component", orientation="h",
                                   title="What drove the score that day"),
                            use_container_width=True)
        st.write("**Alerts for this account**")
        st.dataframe(alerts[alerts.username == who][["timestamp", "rule", "severity", "detail",
                                                     "evidence_event_ids"]],
                     use_container_width=True, height=200)
        st.write("**Raw events**")
        st.dataframe(acc[acc.username == who][["event_id", "timestamp", "event_type", "result",
                                               "src_ip", "src_country", "target_system",
                                               "privileged_action", "mfa_used"]].head(300),
                     use_container_width=True, height=240)

# ------------------------------------------------------------------------------ Anomaly
with tabs[2]:
    st.subheader("Unsupervised detection")
    an = js("anomaly_summary.json")
    if an:
        c1, c2, c3 = st.columns(3)
        c1.metric("Network IF (fully unsupervised) ROC-AUC",
                  f"{an['network']['roc_auc_unsupervised']:.2f}")
        c2.metric("Network IF trained on clean baseline",
                  f"{an['network']['roc_auc_clean_baseline']:.2f}")
        c3.metric("Access user-day IF ROC-AUC",
                  f"{an['access']['validation'][0]['roc_auc_vs_injected']:.3f}")
        st.info(an["network"]["interpretation"])
    for img in ["fig13_network_anomaly_scores.png", "fig14_anomaly_share_by_type.png",
                "fig15_access_anomaly_scatter.png", "fig16_top_anomalous_user_days.png"]:
        if (F / img).exists():
            st.image(str(F / img), use_container_width=True)
    st.subheader("Flagged user-days and why")
    st.dataframe(csv("anomaly_access_flagged_user_days.csv"), use_container_width=True,
                 height=320)

# ------------------------------------------------------------------------- Investigation
with tabs[3]:
    inc = js("incident_summary.json")
    if inc:
        st.subheader(f"Case: {inc['case_account']} ({inc['account_role']}, "
                     f"{inc['employment_type']})")
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Timeline rows", inc["timeline_rows"])
        c2.metric("Privileged actions", inc["privileged_actions"])
        c3.metric("of those without MFA", inc["privileged_without_mfa"])
        c4.metric("Assets touched", inc["affected_assets"])
        st.warning(inc["status"])
    st.write("**Correlated timeline** (check the `linkage_basis` column before drawing "
             "conclusions across sources)")
    st.dataframe(timeline, use_container_width=True, height=330)
    if (F / "fig19_incident_timeline.png").exists():
        st.image(str(F / "fig19_incident_timeline.png"), use_container_width=True)
    c1, c2 = st.columns(2)
    with c1:
        st.write("**Affected entities**")
        st.dataframe(csv("incident_affected_entities.csv"), use_container_width=True, height=240)
    with c2:
        st.write("**Response plan**")
        st.dataframe(csv("incident_response_plan.csv"), use_container_width=True, height=240)

# -------------------------------------------------------------------------- Intelligence
with tabs[4]:
    st.subheader("Intelligence requirements")
    st.dataframe(csv("intel_requirements.csv"), use_container_width=True)
    st.subheader("Detection rules mapped to MITRE ATT&CK for ICS (TF-IDF nearest match)")
    st.dataframe(csv("intel_attack_mapping.csv"), use_container_width=True)
    st.subheader("Assets in scope for the top accounts")
    st.dataframe(csv("intel_assets_in_scope.csv"), use_container_width=True, height=260)
    brief = ROOT / "outputs" / "intelligence_executive_brief.md"
    if brief.exists():
        st.subheader("Executive brief")
        st.markdown(brief.read_text())

# ----------------------------------------------------------------------------- Simulation
with tabs[5]:
    st.subheader("Control scenarios (Monte Carlo, 5,000 runs each)")
    if len(sim):
        st.dataframe(sim, use_container_width=True)
        st.plotly_chart(px.bar(sim, x="scenario", y=["p_reach_ot", "p_reach_critical"],
                               barmode="group",
                               title="Probability of reaching the OT zone / a critical OT asset"),
                        use_container_width=True)
    sens = csv("simulation_sensitivity.csv")
    if len(sens):
        st.plotly_chart(px.line(sens, x="scale", y="p_reach_ot", color="scenario", markers=True,
                                title="Sensitivity to the assumed transmission probabilities"),
                        use_container_width=True)
    sj = js("simulation_summary.json")
    if sj:
        st.write("**Assumptions and limitations**")
        st.json({"measured_inputs": {"p_foothold": sj["measured_p_foothold"],
                                     "from_events": sj["measured_from_events"]},
                 "assumptions": sj["assumptions"], "limitations": sj["limitations"]})

# --------------------------------------------------------------------- Models & robustness
with tabs[6]:
    st.subheader("Supervised detection")
    st.dataframe(csv("supervised_network_test.csv"), use_container_width=True)
    c1, c2 = st.columns(2)
    for col, img in zip([c1, c2], ["fig09_confusion_network.png", "fig12_confusion_modbus.png"]):
        if (F / img).exists():
            col.image(str(F / img), use_container_width=True)
    if (F / "fig11_confusion_network_multiclass.png").exists():
        st.image(str(F / "fig11_confusion_network_multiclass.png"), use_container_width=True)
    st.subheader("Robustness and adversarial tests")
    if len(adv):
        st.dataframe(adv, use_container_width=True)
        st.plotly_chart(px.line(adv[adv.test != "T0_baseline"], x="setting", y="f1",
                                color="test", markers=True,
                                title="F1 under perturbation"), use_container_width=True)
    st.subheader("Text mining")
    st.dataframe(csv("nlp_ticket_classification.csv"), use_container_width=True)
    st.dataframe(csv("nlp_extracted_indicators.csv").head(50), use_container_width=True,
                 height=260)

# -------------------------------------------------------------------------- Data & method
with tabs[7]:
    st.subheader("Data inventory")
    st.dataframe(csv("data_inventory.csv"), use_container_width=True)
    st.subheader("Minimum-data compliance (specification 5.1)")
    st.dataframe(csv("minimum_data_check.csv"), use_container_width=True)
    st.subheader("Cleaning log")
    st.dataframe(csv("cleaning_log.csv"), use_container_width=True, height=300)
    st.subheader("Data dictionary")
    st.dataframe(csv("data_dictionary.csv"), use_container_width=True, height=300)
    st.subheader("Capstone compliance checklist")
    st.dataframe(csv("compliance_checklist.csv"), use_container_width=True)
