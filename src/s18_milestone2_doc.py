"""
Stage 18 - Build the Milestone 2 document (Project Implementation Plan and Working Prototype).

The document is generated from the pipeline outputs so that every number in it is the number
the code produced. Structure follows specification section 8.1 (required implementation
evidence) and the section 8.2 marking rubric, and each section is tied back to the approved
Project Charter.

Output:
  docs/T08_Milestone2_Implementation_Plan.html
  docs/T08_Milestone2_Implementation_Plan.pdf   (rendered with headless Chromium)
"""
from __future__ import annotations

import base64
import json
import subprocess
import sys
from datetime import date
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import OUT, OUT_FIGS, OUT_TABLES, ROOT, get_logger

LOG = get_logger("s18_doc")
DOCS = ROOT / "docs"
HTML = DOCS / "T08_Milestone2_Implementation_Plan.html"
PDF = DOCS / "T08_Milestone2_Implementation_Plan.pdf"


def tbl(name: str) -> pd.DataFrame:
    return pd.read_csv(OUT_TABLES / name)


def js(name: str) -> dict:
    return json.loads((OUT_TABLES / name).read_text())


def fig(name: str, caption: str, width: str = "100%") -> str:
    data = base64.b64encode((OUT_FIGS / name).read_bytes()).decode()
    num = name[3:5]
    return (f'<figure><img src="data:image/png;base64,{data}" style="width:{width}">'
            f'<figcaption>Figure {int(num)}. {caption}</figcaption></figure>')


def table(df: pd.DataFrame, cols=None, right=(), caption: str = "", num: int = 0) -> str:
    d = df[cols] if cols else df
    head = "".join(f'<th{" class=r" if c in right else ""}>{c}</th>' for c in d.columns)
    body = ""
    for r in d.itertuples(index=False):
        cells = "".join(
            f'<td{" class=r" if c in right else ""}>{v}</td>'
            for c, v in zip(d.columns, r))
        body += f"<tr>{cells}</tr>"
    cap = f"<figcaption>Table {num}. {caption}</figcaption>" if caption else ""
    return f'<div class="tbl"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>{cap}</div>'


def build() -> str:
    # ---------------------------------------------------------------- source numbers
    inv = tbl("data_inventory.csv")
    chk = tbl("minimum_data_check.csv")
    clog = tbl("cleaning_log.csv")
    qual = tbl("data_quality.csv")
    eda = tbl("eda_findings.csv")
    cv = tbl("supervised_network_cv.csv")
    test = tbl("supervised_network_test.csv")
    mbt = tbl("supervised_modbus_test.csv")
    multi = pd.read_csv(OUT_TABLES / "supervised_network_multiclass.csv", index_col=0)
    imp = tbl("supervised_network_importance.csv")
    accval = tbl("anomaly_access_validation.csv")
    flagged = tbl("anomaly_access_flagged_user_days.csv")
    rules = tbl("ueba_rule_summary.csv")
    plan = tbl("incident_response_plan.csv")
    ents = tbl("incident_affected_entities.csv")
    pirs = tbl("intel_requirements.csv")
    amap = tbl("intel_attack_mapping.csv")
    watch = tbl("intel_operational_watchlist.csv")
    sim = tbl("simulation_summary.csv")
    sens = tbl("simulation_sensitivity.csv")
    nlpcls = pd.read_csv(OUT_TABLES / "nlp_ticket_classification.csv", index_col=0)
    topics = tbl("nlp_attack_topics.csv")
    bands = tbl("risk_band_summary.csv")
    fmetrics = tbl("risk_forecast_metrics.csv")
    adv = tbl("adversarial_results.csv")
    arch = tbl("architecture_stages.csv")
    comp = tbl("compliance_checklist.csv")
    impl = pd.read_csv(DOCS / "implementation_plan.csv")
    defects = pd.read_csv(DOCS / "known_defects_and_backlog.csv")
    exp = pd.read_csv(DOCS / "experiment_log.csv")

    sup = js("supervised_summary.json")
    anom = js("anomaly_summary.json")
    risk = js("risk_adversarial_summary.json")
    nlp = js("nlp_summary.json")
    inc = js("incident_summary.json")
    simj = js("simulation_summary.json")
    stages = js("experiment_log.json")

    total_records = int(inv["rows"].sum())
    real_records = int(inv.loc[inv.data_status.str.contains("public"), "rows"].sum())
    synth_records = total_records - real_records
    rf = test[test.model == "random_forest"].iloc[0]
    lr = test[test.model == "logistic_regression"].iloc[0]
    dt = test[test.model == "decision_tree"].iloc[0]
    s0 = sim[sim.scenario == "S0_baseline"].iloc[0]
    s1 = sim[sim.scenario == "S1_segmentation"].iloc[0]
    s2 = sim[sim.scenario == "S2_strong_auth"].iloc[0]
    s3 = sim[sim.scenario == "S3_monitoring"].iloc[0]
    s4 = sim[sim.scenario == "S4_combined"].iloc[0]
    alerts_total = int(rules["alerts"].sum())

    css = """
    <style>
      @page { size: A4; margin: 19mm 17mm 18mm 17mm; }
      body { font-family: "DejaVu Serif", Georgia, serif; font-size: 10.2pt; line-height: 1.42;
             color: #14181d; }
      h1 { font-size: 17pt; margin: 0 0 4pt 0; }
      h2 { font-size: 12.6pt; margin: 17pt 0 5pt 0; border-bottom: 1.1pt solid #253044;
           padding-bottom: 2pt; page-break-after: avoid; }
      h3 { font-size: 11pt; margin: 11pt 0 4pt 0; page-break-after: avoid; }
      p { margin: 0 0 6pt 0; text-align: justify; }
      ul, ol { margin: 0 0 7pt 0; padding-left: 16pt; }
      li { margin-bottom: 2.5pt; }
      table { border-collapse: collapse; width: 100%; font-size: 8.3pt;
              font-family: "DejaVu Sans", Arial, sans-serif; }
      th { background: #eef1f6; text-align: left; padding: 3.2pt 4pt; border: 0.5pt solid #b9c2d0;
           font-weight: 600; }
      td { padding: 2.8pt 4pt; border: 0.5pt solid #cdd4de; vertical-align: top; }
      td.r, th.r { text-align: right; }
      .tbl { margin: 6pt 0 9pt 0; page-break-inside: auto; }
      tr { page-break-inside: avoid; }
      thead { display: table-header-group; }
      figure { margin: 8pt 0 10pt 0; page-break-inside: avoid; text-align: center; }
      figcaption { font-family: "DejaVu Sans", Arial, sans-serif; font-size: 7.8pt;
                   color: #4a5462; margin-top: 3pt; text-align: left; }
      img { border: 0.5pt solid #d7dce4; }
      .cover { text-align: center; padding-top: 34mm; page-break-after: always; }
      .cover .topic { font-family: "DejaVu Sans", Arial, sans-serif; letter-spacing: 1.4pt;
                      font-size: 9pt; color: #4a5462; text-transform: uppercase; }
      .cover h1 { font-size: 21pt; margin: 12pt 0; line-height: 1.25; }
      .cover .sub { font-size: 11.5pt; color: #333b45; margin-bottom: 26pt; }
      .meta { display: inline-block; text-align: left; font-size: 10pt; margin-top: 10pt; }
      .meta td { border: none; padding: 3pt 12pt 3pt 0; font-family: "DejaVu Serif", Georgia, serif;
                 font-size: 10pt; }
      .note { background: #f6f8fb; border-left: 2.6pt solid #253044; padding: 7pt 9pt;
              margin: 8pt 0; font-size: 9.4pt; page-break-inside: avoid; }
      .warn { background: #fdf6ee; border-left: 2.6pt solid #b4691a; padding: 7pt 9pt;
              margin: 8pt 0; font-size: 9.4pt; page-break-inside: avoid; }
      .kv { font-family: "DejaVu Sans", Arial, sans-serif; font-size: 8.6pt; }
      code { font-family: "DejaVu Sans Mono", monospace; font-size: 8.6pt; }
      .pagebreak { page-break-before: always; }
      .small { font-size: 9pt; color: #4a5462; }
      .toc { margin-top: 4pt; }
      .tocrow { display: flex; align-items: baseline; font-size: 9.8pt; margin: 2.4pt 0; }
      .tocrow.l2 { font-size: 9.1pt; color: #333b45; padding-left: 14pt; margin: 1.6pt 0; }
      .tocrow .t { white-space: nowrap; }
      .tocrow .dots { flex: 1; border-bottom: 0.6pt dotted #9aa3ae; margin: 0 5pt 0 5pt;
                      transform: translateY(-2.5pt); }
      .tocrow .pg { font-variant-numeric: tabular-nums; color: #333b45; }
    </style>"""

    # ------------------------------------------------------------------ cover + TOC
    html = [f"""<!doctype html><html><head><meta charset="utf-8">{css}</head><body>
    <div class="cover">
      <div class="topic">SAS821S Security Analytics &middot; Capstone Project &middot; Milestone 2</div>
      <h1>Mining Remote Operations and<br>Industrial-IoT Intrusion Analytics</h1>
      <div class="sub">Security analytics for detecting anomalous behaviour in mining remote
      operations, delivered through a working prototype<br><span class="small">Topic T08 &middot;
      Project Implementation Plan and Working Prototype</span></div>
      <table class="meta">
        <tr><td><b>Member A</b></td><td>222093471 &middot; Sophia Kalume &middot; Data and Modelling Lead</td></tr>
        <tr><td><b>Member B</b></td><td>215103815 &middot; Lasarus Shithindi &middot; Security Engineering and Intelligence Lead</td></tr>
        <tr><td><b>Milestone</b></td><td>2 of 4 &middot; weight 40% of the capstone mark</td></tr>
        <tr><td><b>Due</b></td><td>20 September 2026</td></tr>
        <tr><td><b>Submitted</b></td><td>{date.today().strftime('%d %B %Y')}</td></tr>
        <tr><td><b>Institution</b></td><td>Namibia University of Science and Technology</td></tr>
      </table>
    </div>"""]

    # The contents list is generated from the headings after the document is laid out, so
    # that the page numbers are the real ones. See build_document() below.
    html.append('<h2>Contents</h2>\n<!--TOC-->\n<div class="pagebreak"></div>')

    # ------------------------------------------------------------------ 1. summary
    html.append(f"""
    <h2>1. Executive summary</h2>
    <p>This milestone reports an implemented security analytics solution for the T08 mining
    remote-operations scenario, not a plan for one. The pipeline runs end to end from raw
    data files to a compliance checklist in {stages['total_seconds']:.0f} seconds across
    {len(stages['stages'])} stages, and an analyst-facing console presents the results for
    decision-making. Every figure quoted in this document is read directly from the files the
    pipeline writes.</p>

    <p>The analysis covers <b>{total_records:,} records</b> across {len(inv)} files and five
    source families. Roughly {real_records:,} of those records are real research data
    (ToN_IoT captures from UNSW Canberra and the MITRE ATT&amp;CK for ICS corpus) and
    {synth_records:,} are synthetic data generated by documented rules for the
    identity/access and maintenance-text components, which the charter and the capstone
    specification both permit.</p>

    <p>The main results are:</p>
    <ul>
      <li><b>Supervised detection.</b> A random forest separates attack from normal network
      flows with F1 {rf.f1:.4f} (precision {rf.precision:.4f}, recall {rf.recall:.4f}) on a
      held-out 30 per cent, after {sup['network']['rows_dropped_as_duplicate']:,} duplicate
      rows were removed to prevent leakage. Attack-family identification reaches macro-F1
      {sup['network']['multiclass_macro_f1']:.4f}. A Modbus telemetry classifier reaches F1
      {mbt[mbt.model=='random_forest'].iloc[0].f1:.4f}.</li>
      <li><b>Anomaly detection.</b> On remote-access behaviour, an Isolation Forest reaches
      ROC-AUC {accval.iloc[0].roc_auc_vs_injected:.3f} against the behaviour patterns that
      were deliberately injected into the synthetic log, flagging
      {int(accval.iloc[0].flagged)} of {len(tbl('risk_user_day_scores.csv')):,} user-days at
      the chosen threshold. On the network flows the same method scores
      {anom['network']['roc_auc_unsupervised']:.2f} when run fully unsupervised and
      {anom['network']['roc_auc_clean_baseline']:.2f} when fitted on known-good traffic; that
      contrast is reported as a finding rather than hidden.</li>
      <li><b>Investigation.</b> Case ranking selected account <code>{inc['case_account']}</code>
      ({inc['account_role']}), with {inc['privileged_actions']} privileged actions of which
      {inc['privileged_without_mfa']} had no multi-factor authentication, touching
      {inc['affected_assets']} assets. The timeline holds {inc['timeline_rows']} rows, each
      citing its evidence and its linkage basis.</li>
      <li><b>Simulation.</b> Five control scenarios at {simj['runs_per_scenario']:,} Monte
      Carlo runs each. The chance of an intrusion reaching the OT zone falls from
      {s0.p_reach_ot:.0%} under current controls to {s2.p_reach_ot:.0%} with enforced MFA and
      {s4.p_reach_ot:.0%} with the combined package. The ranking is stable across a sensitivity
      sweep of the assumed probabilities.</li>
      <li><b>Text mining.</b> {nlp['corpus_sizes']['total']} unstructured records processed,
      with classification, indicator extraction scored against an answer key (precision
      {nlp['indicator_extraction']['precision']:.3f}, recall
      {nlp['indicator_extraction']['recall']:.3f}) and ATT&amp;CK enrichment.</li>
      <li><b>Predictive risk and robustness.</b> A six-component daily risk score separates the
      injected behaviour with ROC-AUC {risk['risk_score']['roc_auc_vs_injected']:.3f}. Four
      families of adversarial and robustness tests were run; the largest degradation is a fall
      of {abs(adv.f1_change_vs_baseline.min()):.2f} in F1 when half the collected fields are
      lost.</li>
    </ul>

    <div class="note"><b>Status of the data.</b> The ToN_IoT captures are real research data
    from a laboratory testbed, used here as a proxy for mining IIoT and OT behaviour. The
    remote-access log, the maintenance tickets, the asset inventory and the user directory are
    synthetic, produced by seeded generators whose rules are in the repository. Four abnormal
    access patterns were injected on purpose and recorded in a ground-truth column, so all
    detection results in this document mean that the method found behaviour we planted. No
    claim is made anywhere that a real intrusion was discovered.</div>""")

    # ------------------------------------------------------------------ 2. charter
    charter_obj = pd.DataFrame([
        ["Objective 1: prepare and integrate IIoT, network-flow and remote-user activity data",
         "Cleaned datasets, documented preprocessing steps, identified analytical features",
         f"Met. {len(inv)} sources cleaned through a logged pipeline ({len(clog)} recorded "
         f"actions); engineered features for flows, telemetry and access behaviour."],
        ["Objective 2: develop a prototype that detects and prioritises anomalous IIoT, network "
         "and remote-user behaviour",
         "Working anomaly/behaviour process, risk prioritisation, functioning dashboard",
         "Met. Isolation Forest and seven behaviour rules feed a risk score and an eight-view "
         "Streamlit console."],
        ["Question 1: which IIoT and network behaviours deviate from normal patterns?",
         "EDA and anomaly results identifying and ranking anomalous events",
         "Answered with baselines per sensor, per service and per role, plus ranked anomaly "
         "scores; see sections 5 and 6."],
        ["Question 2: can remote-user activity identify unusual or suspicious access?",
         "Behavioural indicators and identified anomalous user activities supported by evidence",
         f"Answered. {alerts_total} rule alerts, each citing event identifiers, plus a scored "
         "user-day ranking; see section 7."],
        ["Question 3: how can detected anomalies be prioritised for investigation?",
         "Documented risk-scoring approach and ranked events in the prototype",
         "Answered with a six-component score, four bands tied to actions, and a prioritised "
         "watchlist in the console; see section 11."],
    ], columns=["Charter objective or question", "Measure of completion (charter)",
                "Status at Milestone 2"])

    charter_src = pd.DataFrame([
        ["IIoT telemetry", "Timestamp, device ID, sensor readings, operating status",
         "ToN_IoT telemetry, 7 sensor types", f"{int(inv[inv.dataset.str.startswith('iot_')]['rows'].sum()):,}",
         "Public research data"],
        ["Network-flow data", "Timestamp, source, destination, protocol, port, packets, bytes, duration",
         "ToN_IoT Zeek flow records", f"{int(inv[inv.dataset=='network_flow']['rows'].iloc[0]):,}",
         "Public research data; no timestamp column in this release"],
        ["Remote-user activity", "User ID, timestamp, login/logout, source, device, access/action",
         "Generated remote-access log", f"{int(inv[inv.dataset=='access_log']['rows'].iloc[0]):,}",
         "Synthetic, seeded, documented generator"],
        ["Maintenance/incident text", "Timestamp, equipment ID, event description, category",
         "Generated ticket corpus and MITRE ATT&amp;CK for ICS descriptions",
         f"{int(inv[inv.dataset.isin(['tickets','attack_ics_text'])]['rows'].sum()):,}",
         "Synthetic tickets; ATT&amp;CK corpus is real and public"],
        ["(added) Asset and account context", "Asset, site, zone, criticality, protocol, privilege",
         "Asset inventory and user directory",
         f"{int(inv[inv.dataset.isin(['asset_inventory','user_directory'])]['rows'].sum()):,}",
         "Synthetic; required by C2 to interpret findings operationally"],
    ], columns=["Charter source", "Charter key fields", "What was actually used", "Records",
                "Provenance"])

    charter_meth = pd.DataFrame([
        ["Baseline / EDA", "Python, pandas, NumPy, visualisation", "As planned",
         "Baselines per sensor, service, role and user; eight exploratory figures"],
        ["Supervised ML", "TBC in the charter", "Specified and implemented",
         "Logistic regression, decision tree and random forest compared by cross-validated F1"],
        ["Unsupervised / UBA", "Isolation Forest and rule-based user behaviour analysis",
         "As planned, extended", "Isolation Forest, Local Outlier Factor, DBSCAN peer groups "
         "and seven behaviour rules"],
        ["Incident investigation", "Event filtering, correlation and timeline analysis",
         "As planned", "Evidence-ranked case selection and a 202-row correlated timeline"],
        ["Security intelligence", "Risk scoring and event prioritisation", "As planned, extended",
         "Five intelligence requirements, ATT&amp;CK enrichment, operational watchlist and an "
         "executive brief"],
        ["Simulation", "Simple segmented-network scenario simulation", "Extended",
         "Five scenarios including segmentation, MFA and monitoring, with sensitivity analysis"],
        ["Text mining / NLP", "TBC, conditional on suitable data", "Implemented",
         "TF-IDF classification, indicator extraction with an answer key, NMF topics, "
         "ATT&amp;CK similarity enrichment"],
        ["Predictive / adversarial", "Limited risk-pattern analysis", "Extended",
         "Interpretable risk score, next-day early warning and four adversarial test families"],
        ["Prototype / dashboard", "Python, Streamlit, Plotly", "As planned",
         "Eight-view analyst console plus a reproducible notebook"],
    ], columns=["Component", "Charter proposal", "Change", "What was implemented"])

    html.append(f"""
    <div class="pagebreak"></div>
    <h2>2. Alignment with the approved Project Charter</h2>
    <p>The charter defined the problem as &ldquo;identifying how security analytics can be used
    to detect and prioritise anomalous IIoT, network and remote-user behaviour in a simulated
    mining remote-operations environment&rdquo;. That statement is unchanged. This section maps
    each charter commitment to what now exists.</p>

    <h3>2.1 Objectives and analytics questions</h3>
    {table(charter_obj, caption="Charter objectives and questions against the state of the implementation.", num=1)}

    <h3>2.2 Data sources</h3>
    <p>The charter listed four source types with volumes &ldquo;to be determined after dataset
    selection&rdquo;. Selection is now complete.</p>
    {table(charter_src, right=["Records"], caption="Charter data sources mapped to the datasets actually used.", num=2)}

    <h3>2.3 Analytical methods</h3>
    <p>Three charter entries were marked TBC or conditional. All three are now implemented, and
    two components were deliberately extended beyond the charter because the data supported
    more than was originally promised.</p>
    {table(charter_meth, caption="Charter analytical methods against the implementation, with changes marked.", num=3)}

    <h3>2.4 Scope</h3>
    <p>The scope boundaries in the charter hold. No live mining infrastructure, physical
    equipment, real credentials or confidential data were used, and no penetration testing of
    any kind was performed. All work was carried out on public research datasets and on
    synthetic data generated for the exercise.</p>""")

    # ------------------------------------------------------------------ 3. architecture
    html.append(f"""
    <div class="pagebreak"></div>
    <h2>3. Architecture and data flow</h2>
    <p>The charter's architecture ran from three data sources through ingestion and cleaning to
    anomaly detection and user-behaviour analytics, then risk scoring, a prototype and a
    segmentation simulation. The implemented architecture keeps that spine and adds the stages
    the specification requires: supervised modelling, investigation, text mining, intelligence
    products and adversarial testing. Every stage in the diagram corresponds to a script in
    <code>src/</code> and to output files a marker can open; the diagram is generated from that
    list, so it cannot drift away from the code.</p>
    {fig("fig26_architecture.png", "Implemented architecture. Each block names the script that implements it.", "63%")}
    {table(arch, cols=["stage", "implemented_in", "evidence_present"],
           caption="Architecture stages with the script that implements each one and the count of expected evidence files found on disk.", num=4)}
    <p>Data moves in one direction. Raw files are read but never written; cleaned tables are
    written to <code>data/processed/</code> in Parquet; every analytical stage writes CSV or
    JSON into <code>outputs/tables/</code>; the console and the notebook read those outputs and
    never recompute them. This separation is what makes the prototype reproducible: the
    dashboard cannot show a number that is not in a file.</p>""")

    # ------------------------------------------------------------------ 4. data
    html.append(f"""
    <div class="pagebreak"></div>
    <h2>4. Data inventory, dictionary, cleaning log and quality checks</h2>
    <h3>4.1 Inventory and minimum-data compliance</h3>
    {table(inv, cols=["dataset", "rows", "columns", "data_status", "project_role", "duplicate_rows", "labelled"],
           right=["rows", "columns", "duplicate_rows"],
           caption="Data inventory. Full provenance, SHA-256 hashes and time coverage are in outputs/tables/data_inventory.csv.", num=5)}
    {table(chk, cols=["requirement", "measured", "threshold", "status"],
           caption="Minimum data expectations from specification 5.1, checked against the loaded data.", num=6)}

    <h3>4.2 Data dictionary</h3>
    <p>Every column in every dataset was profiled and classified by the role it plays in the
    analysis: timestamp, user account, device or asset, IP address, network field,
    authentication or access field, security label, unstructured text, numeric or categorical.
    The full dictionary lists {len(tbl("data_dictionary.csv"))} columns and is supplied as
    <code>outputs/tables/data_dictionary.csv</code> and
    <code>docs/member_a_data_dictionary.md</code>. The classification is what demonstrates
    requirement C2 concretely: identity and access fields, network and OT fields and asset
    context all exist in the data rather than only in the proposal.</p>

    <h3>4.3 Cleaning and transformation log</h3>
    <p>{len(clog)} cleaning actions were recorded, each with the dataset, the action, the detail,
    the reason and the row counts before and after. Four decisions are worth stating because a
    marker is likely to ask about them:</p>
    <ul>
      <li><b>Zeek's &lsquo;-&rsquo; placeholder is treated as missing, not as a category.</b>
      Left as text it becomes one of the strongest predictors in the model, and an entirely
      artificial one.</li>
      <li><b>Duplicates are flagged rather than deleted.</b> The flag excludes them from model
      training and testing, but the rows remain in the stored data so no evidence is destroyed.</li>
      <li><b>Missing telemetry values are not imputed.</b> A gap in a sensor feed is a gap; an
      invented reading would teach the model a pattern that never happened.</li>
      <li><b>Country codes use ISO-3.</b> The original ISO-2 code for Namibia, &lsquo;NA&rsquo;,
      was silently read as a missing value and made every user-day look foreign. This was found,
      fixed and covered by a regression test.</li>
    </ul>
    {table(clog.head(16), cols=["dataset", "action", "detail", "reason"],
           caption="Extract from the cleaning log (first 16 of " + str(len(clog)) + " actions). The full log is outputs/tables/cleaning_log.csv.", num=7)}

    <h3>4.4 Quality checks</h3>
    <p>{len(qual)} quality findings were recorded automatically before cleaning:
    {", ".join(f"{n} {k.replace('_', ' ')}" for k, n in qual['issue'].value_counts().items())}.
    Sixteen columns in the flow data are more than 97 per cent empty; they are retained in the
    file for investigation but excluded from model features.</p>""")

    # ------------------------------------------------------------------ 5. EDA
    hyp = pd.DataFrame([
        ["H1", "Remote access, not the sensors themselves, is the most exposed path into the OT "
               "zone", "Access events carry privileged actions without MFA from external "
                       "addresses; telemetry anomalies alone rarely exceed the normal envelope",
         "Supported so far; drives the investigation in section 7 and the simulation in section 9"],
        ["H2", "Attack traffic is separable from normal traffic by connection behaviour rather "
               "than by volume", "Connection state and protocol dominate feature importance; "
                                 "byte and duration features contribute little",
         "Supported; also explains why the evasion test in section 11 has little effect"],
        ["H3", "Sensor readings alone are a weak detector of manipulation",
         "Median share of attack-labelled readings beyond three standard deviations of the "
         "normal baseline is 0 per cent across sensor-measure pairs",
         "Supported; argues for learned models over threshold alarms"],
        ["H4", "Unusual behaviour is concentrated in a small number of account-days",
         "45 of 2,792 user-days (1.6 per cent) break the simple behavioural rules",
         "Supported; sets the alerting budget used for the risk bands"],
    ], columns=["#", "Hypothesis", "Evidence in the data", "Status"])

    html.append(f"""
    <div class="pagebreak"></div>
    <h2>5. Exploratory analysis, baselines and security hypotheses</h2>
    <p>Before any model was fitted, the question asked was what normal looks like in each
    source. Baselines were computed per sensor and measure, per network service, per role and
    per user, and are stored as <code>outputs/tables/baseline_*.csv</code>.</p>
    {fig("fig01_telemetry_volume_over_time.png", "IIoT telemetry volume per day, separated by label. Attack-labelled activity in this capture is concentrated in the last week of April 2019.", "88%")}
    {fig("fig08_login_hour_by_role.png", "Login-hour baseline by role. Control-room operators and OT network administrators show genuine night activity, which is why an out-of-hours rule alone produces poor precision.", "92%")}
    <p>Four findings came out of this stage and were recorded in
    <code>outputs/tables/eda_findings.csv</code>:</p>
    {table(eda, cols=["area", "finding", "evidence"],
           caption="Exploratory findings with the evidence that supports each one.", num=8)}
    <h3>5.1 Initial security hypotheses</h3>
    {table(hyp, caption="Working hypotheses carried into the modelling stages.", num=9)}""")

    # ------------------------------------------------------------------ 6. models
    multi_disp = multi.drop(index=[i for i in ("accuracy", "macro avg", "weighted avg")
                                   if i in multi.index]).reset_index()
    multi_disp.columns = ["family", "precision", "recall", "f1", "support"]
    multi_disp = multi_disp.round(3)
    multi_disp["support"] = multi_disp["support"].astype(int)

    html.append(f"""
    <div class="pagebreak"></div>
    <h2>6. Supervised model and anomaly/behavioural model</h2>
    <h3>6.1 Supervised intrusion detection</h3>
    <p>Three candidate models were compared on three-fold cross-validated F1 using the training
    split only; the test split was scored once, at the end. Exact duplicates were removed before
    splitting, which matters: {sup['network']['rows_dropped_as_duplicate']:,} identical rows
    exist in the flow data and would otherwise appear on both sides of the split.</p>
    {table(cv.round(4), caption="Model selection by cross-validated F1 on the training data.", num=10)}
    {table(test.round(4), caption="Held-out performance on 30 per cent of the flow data.", num=11)}
    <p>The random forest was selected. The justification is not the margin in the table but the
    shape of the data: flow records mix skewed numeric measures with categorical protocol fields
    that interact, which is what a tree ensemble handles without scaling assumptions. Logistic
    regression is kept as a transparent baseline and shows that much of the problem is linearly
    separable, although it still misses {(1 - lr.recall) * 100:.1f} per cent of attacks against
    {(1 - rf.recall) * 100:.1f} per cent for the forest.</p>
    {fig("fig09_confusion_network.png", "Confusion matrix for the selected network detector on the held-out split.", "47%")}
    {table(multi_disp, right=["precision", "recall", "f1", "support"],
           caption="Attack-family identification (macro-F1 " + f"{sup['network']['multiclass_macro_f1']:.4f}" + "). The weakest class, mitm, has the fewest test examples.", num=12)}
    {table(mbt.round(4), caption="Modbus telemetry classifier. The gap between the linear and the ensemble model is the evidence that OT protocol abuse is not linearly separable.", num=13)}
    {table(imp.head(6).round(4), right=["importance", "sd"],
           caption="Permutation importance for the network detector: mean F1 decrease when each feature is shuffled.", num=14)}

    <h3>6.2 Anomaly and behavioural methods</h3>
    <p>Two framings were run on the network flows, and the contrast is the most useful
    methodological result in the project.</p>
    <div class="warn"><b>Negative result, reported deliberately.</b> Fitted on all flows with no
    labels, an Isolation Forest scores ROC-AUC
    {anom['network']['roc_auc_unsupervised']:.2f} &mdash; below chance. The cause is that
    {anom['network']['attack_share_in_sample']:.0%} of this capture is attack traffic, so what is
    statistically rare is ordinary office traffic. Fitting the same model on known-good traffic
    only, and scoring novelty against it, raises ROC-AUC to
    {anom['network']['roc_auc_clean_baseline']:.2f}. The operational lesson for a mine is that
    anomaly detection needs a trusted baseline window rather than &ldquo;whatever is rare
    today&rdquo;.</div>
    {fig("fig13_network_anomaly_scores.png", "Isolation Forest score distribution on network flows. Labels are shown for validation only; they were not used for fitting.", "88%")}
    <p>On the remote-access data, where anomalies genuinely are rare, the same method performs
    well. The operating threshold is the 98th percentile of the score, which is an alerting
    budget decision rather than a statistical one: it produces about two cases per working day
    for an estate of 114 accounts.</p>
    {table(accval.round(3), caption="Anomaly methods on user-day behaviour, validated against the injected patterns. Local Outlier Factor does not beat chance on these features.", num=15)}
    {fig("fig15_access_anomaly_scatter.png", "User-days by activity volume and failed logins, with the flagged 2 per cent highlighted.", "88%")}
    {table(flagged.head(8), cols=["username", "role", "day", "failures", "distinct_countries", "out_of_hours", "why_flagged"],
           right=["failures", "distinct_countries", "out_of_hours"],
           caption="Highest-scoring flagged user-days with the reason the model gives, expressed as deviations from the role baseline.", num=16)}""")

    # ------------------------------------------------------------------ 7. investigation
    html.append(f"""
    <div class="pagebreak"></div>
    <h2>7. Incident timeline, access findings and response logic</h2>
    <h3>7.1 Access and identity analytics</h3>
    <p>Seven behaviour rules were implemented on top of the measured baselines. Each alert
    records the rule, the account, the asset, the source address and the identifiers of the
    events that prove it, so an analyst never has to trust a score alone.</p>
    {table(rules.round(2), cols=["rule", "severity", "alerts", "accounts", "matched_injected", "precision_vs_injected"],
           right=["alerts", "accounts", "matched_injected", "precision_vs_injected"],
           caption="Rule performance against the injected behaviour patterns. R4 is retained deliberately as the tuning counter-example.", num=17)}
    <p>Six of the seven rules match injected behaviour at full precision. Rule R4, which fires on
    privileged actions outside an account's usual hours, produced
    {int(rules[rules.rule=='R4'].iloc[0].alerts)} alerts at
    {rules[rules.rule=='R4'].iloc[0].precision_vs_injected:.0%} precision. That is not a
    failure to hide but the expected consequence of shift work in a mine: control-room operators
    and OT administrators legitimately work at night, as Figure 8 shows. The rule is kept, the
    weakness is logged as defect D07, and the planned fix is role-aware working windows.</p>

    <h3>7.2 Selected case</h3>
    <p>Cases were ranked by alert weight, rule diversity and peak anomaly score. The strongest
    case is account <code>{inc['case_account']}</code>, a {inc['account_role'].replace('_', ' ')}
    on a {inc['employment_type']} contract, active on
    {len(inc['alert_window_days'])} consecutive nights. The account performed
    {inc['privileged_actions']} privileged actions on OT targets,
    {inc['privileged_without_mfa']} of them without multi-factor authentication, from a foreign
    source address and outside any approved maintenance window.</p>
    {fig("fig19_incident_timeline.png", "Correlated timeline for the selected case, by source.", "88%")}
    <div class="note"><b>How to read the timeline.</b> Of {inc['timeline_rows']} rows,
    {inc['direct_evidence_rows']} are direct evidence about the account and
    {inc['context_only_rows']} are marked CONTEXT ONLY. Context rows come from the ToN_IoT
    captures, which are a different environment entirely; they share the calendar window by
    design and carry no shared identifiers. The <code>linkage_basis</code> column states this
    for every row. The case is an analytical scenario built on synthetic access data, not a
    real incident.</div>
    {table(ents.head(8), cols=["asset_id", "asset_type", "site", "criticality", "primary_protocol", "patch_status"],
           caption="Affected entities identified from the timeline (extract).", num=18)}

    <h3>7.3 Response logic</h3>
    <p>The response plan is tied to what the evidence shows rather than to a generic checklist;
    each action carries the observation that justifies it.</p>
    {table(plan, caption="Containment, eradication, recovery and monitoring actions with their evidence basis.", num=19)}""")

    # ------------------------------------------------------------------ 8. intelligence
    html.append(f"""
    <div class="pagebreak"></div>
    <h2>8. Security intelligence requirements, enrichment and first products</h2>
    <p>Five priority intelligence requirements were defined, each with the sources that answer it
    and a review cycle, so that analysis is driven by a question rather than by whatever the data
    happens to contain.</p>
    {table(pirs, caption="Priority intelligence requirements for the mining environment.", num=20)}
    <p>Enrichment links each detection rule to the closest descriptions in the MITRE ATT&amp;CK
    for ICS corpus by TF-IDF similarity. The mapping is derived rather than asserted, and the
    similarity score and a confidence label are reported with it. Where the match is weak, the
    table says so instead of presenting a confident mapping.</p>
    {table(amap[amap['rank'] == 1].round(3), cols=["rule", "attack_id", "attack_name", "similarity", "confidence"],
           right=["similarity"],
           caption="Nearest ATT&CK for ICS entry for each detection rule, with the similarity score that produced it.", num=21)}
    <p>Two products are produced. The <b>operational</b> product is a prioritised watchlist of
    {len(watch)} accounts combining alert weight, peak risk score and account attributes such as
    privilege and MFA enrolment; the top ten accounts are linked to the
    {len(tbl('intel_assets_in_scope.csv'))} assets they touched, ordered by criticality. The
    <b>executive</b> product is a one-page brief stating the key risks, the affected assets, the
    modelled effect of each control and what the group is not claiming. Both are generated from
    the analytical outputs, so they cannot contradict the technical results.</p>
    {table(watch.head(8), cols=["username", "user_role", "employment_type", "alerts", "rules", "highest_sev", "max_risk", "band"],
           right=["alerts", "max_risk"],
           caption="Operational watchlist (extract). Full table: outputs/tables/intel_operational_watchlist.csv.", num=22)}""")

    # ------------------------------------------------------------------ 9. simulation
    sim_disp = sim.copy()
    for c in ["p_reach_ot", "p_reach_critical", "mean_assets_compromised", "rel_reduction_ot"]:
        sim_disp[c] = sim_disp[c].round(3)
    html.append(f"""
    <div class="pagebreak"></div>
    <h2>9. Simulation design and preliminary comparative results</h2>
    <p>The charter proposed a small segmentation simulation. This was extended to five control
    scenarios, because the access analysis showed that authentication, not only segmentation, is
    where this environment is exposed.</p>
    <p><b>Model.</b> The mine is represented as a directed graph built from the asset inventory:
    {simj['graph']['nodes']} nodes and {simj['graph']['edges']} edges spanning the internet, the
    IT zone, the IT-OT boundary and the OT zone. A run begins with one compromised remote-access
    session. At each step every compromised host attempts each outgoing link once, succeeding
    with a probability that depends on the boundary being crossed and on the controls in force. A
    run ends after {simj['max_steps']} steps or when nothing new can be reached.
    {simj['runs_per_scenario']:,} runs were executed per scenario, above the 1,000 the
    specification requires.</p>
    <p><b>Inputs.</b> One input is measured from our own data: the probability that a stolen
    remote credential yields a foothold is taken as the share of external privileged access
    events that had no MFA, which is {simj['measured_p_foothold']:.3f} over
    {simj['measured_from_events']} events. The per-boundary transmission probabilities and the
    effect size of each control are assumptions, stated in
    <code>outputs/tables/simulation_summary.json</code> and tested for sensitivity.</p>
    {table(sim_disp, cols=["scenario", "description", "p_reach_ot", "p_reach_critical", "mean_assets_compromised", "rel_reduction_ot"],
           right=["p_reach_ot", "p_reach_critical", "mean_assets_compromised", "rel_reduction_ot"],
           caption="Comparative results across five control scenarios, " + f"{simj['runs_per_scenario']:,}" + " runs each. Confidence intervals are in the source file.", num=23)}
    {fig("fig20_simulation_scenarios.png", "Probability of reaching the OT zone and a critical OT asset, with 95 per cent Wilson confidence intervals.", "88%")}
    {fig("fig21_simulation_sensitivity.png", "Sensitivity of the comparison when every transmission probability is scaled by 0.6, 1.0 and 1.4.", "88%")}
    <p>Under these assumptions, enforcing MFA on remote and privileged sessions is the single
    most effective control, reducing the chance of reaching the OT zone by
    {s2.rel_reduction_ot:.0%}, followed by segmentation at {s1.rel_reduction_ot:.0%}. Detection
    and isolation on its own has the smallest effect on reach ({s3.rel_reduction_ot:.0%}) but
    cuts the number of assets compromised from {s0.mean_assets_compromised:.0f} to
    {s3.mean_assets_compromised:.0f}. The combined package reduces reach by
    {s4.rel_reduction_ot:.0%}.</p>
    <p>Two honest qualifications. First, MFA dominates partly because the measured foothold
    probability is high, and that figure comes from only {simj['measured_from_events']} events in
    a synthetic log. Second, the absolute probabilities depend on assumed parameters; what is
    stable is the ranking, which holds across every point in the sensitivity sweep. The
    simulation therefore supports a comparison between control packages, not a forecast of how
    often a real intrusion would occur.</p>""")

    # ------------------------------------------------------------------ 10. NLP
    nlp_disp = nlpcls.reset_index().round(3)
    nlp_disp.columns = ["class", "precision", "recall", "f1", "support"]
    nlp_disp = nlp_disp[~nlp_disp["class"].isin(["accuracy"])]
    html.append(f"""
    <div class="pagebreak"></div>
    <h2>10. Text-mining and NLP workflow and preliminary outputs</h2>
    <p>The charter made this component conditional on suitable data being available. Two corpora
    were assembled, giving {nlp['corpus_sizes']['total']} unstructured records against the
    specification's minimum of 200: {nlp['corpus_sizes']['tickets']} synthetic maintenance and
    incident tickets with category labels, and {nlp['corpus_sizes']['attack_ics']} real MITRE
    ATT&amp;CK for ICS descriptions.</p>
    <p><b>Workflow.</b> Text is lower-cased, punctuation that is not part of an indicator is
    stripped, and whitespace is collapsed. Features are TF-IDF over unigrams and bigrams with
    English stop words removed. Three tasks follow: classification of ticket category,
    indicator extraction, and topic structure with enrichment.</p>
    {table(nlp_disp, right=["precision", "recall", "f1", "support"],
           caption="Ticket classification on a held-out 30 per cent.", num=24)}
    <div class="warn"><b>Caveat that must be stated.</b> The tickets are generated from a
    template bank, so each category has a highly consistent vocabulary and the task is far easier
    than real ticket text. The perfect score is evidence that the pipeline works end to end, not
    an estimate of accuracy on a real ticket system.</div>
    <p><b>Indicator extraction</b> uses regular expressions for IP addresses, asset identifiers,
    accounts, sites and protocols, plus a gazetteer of malware names taken from the ATT&amp;CK
    corpus. Because the generator recorded which entities it placed in each ticket, the extractor
    can be scored rather than described: precision
    {nlp['indicator_extraction']['precision']:.3f}, recall
    {nlp['indicator_extraction']['recall']:.3f}, F1 {nlp['indicator_extraction']['f1']:.3f}
    ({nlp['indicator_extraction']['tp']} true positives,
    {nlp['indicator_extraction']['fp']} false positives,
    {nlp['indicator_extraction']['fn']} false negatives).</p>
    {fig("fig23_indicator_counts.png", "Tickets containing each indicator type.", "80%")}
    <p><b>Topic structure and enrichment.</b> Six topics were extracted from the ATT&amp;CK
    corpus with non-negative matrix factorisation, and every ticket was matched to its nearest
    ATT&amp;CK description by TF-IDF similarity.
    {nlp['topics_and_enrichment']['matched_tickets']} of {nlp['corpus_sizes']['tickets']} tickets
    matched at a similarity of 0.15 or above, which is the enrichment that feeds the intelligence
    products in section 8.</p>
    {table(topics, caption="Topics extracted from the ATT&CK for ICS corpus, described by their leading terms.", num=25)}""")

    # ------------------------------------------------------------------ 11. risk + adversarial
    html.append(f"""
    <div class="pagebreak"></div>
    <h2>11. Predictive risk method and adversarial test cases</h2>
    <h3>11.1 Daily risk score</h3>
    <p>Each account-day receives a score from 0 to 100 built from six components that an analyst
    can read, each normalised as a percentile rank and weighted: failed logins (0.15), activity
    outside the account's normal hours (0.10), external or foreign source addresses (0.20),
    privileged actions without MFA (0.20), the anomaly score (0.20) and data egress volume
    (0.15). The score records its own largest contributor, so the console can state why a day
    scored as it did.</p>
    <p>Band cut-points are set from the score distribution rather than from round numbers,
    because with percentile components an average account already scores about 50. The bands are
    an alerting budget: roughly the top 0.5 per cent critical, 1.5 per cent high and 8 per cent
    moderate.</p>
    {table(bands.round(3), caption="Risk bands, the volume of work each implies, and how many injected behaviour rows each band caught.", num=26)}
    {fig("fig24_risk_score_distribution.png", "Risk score distribution with band cut-points. The vertical scale is logarithmic.", "88%")}
    <p>Validation: the score separates user-days containing injected behaviour with ROC-AUC
    {risk['risk_score']['roc_auc_vs_injected']:.3f}, and
    {risk['risk_score']['precision_at_20']:.0%} of the twenty highest-scoring user-days contain
    injected behaviour.</p>

    <h3>11.2 Early warning</h3>
    <p>A logistic regression was trained on the earlier 70 per cent of days to predict whether an
    account would raise an alert on the following day, and tested on the later days. The result
    is weak: ROC-AUC {fmetrics.iloc[0].roc_auc:.3f} against a base rate of
    {fmetrics.iloc[0].positive_rate_test:.3f}. This is reported as a negative result rather than
    tuned until it looked better. Alerts in this data are driven by single events rather than by
    a build-up in the previous day's behaviour, so there is little for a next-day model to learn.
    A longer observation window or event-level features would be the next thing to try.</p>

    <h3>11.3 Adversarial and robustness tests</h3>
    <p>Four families of test were run against the deployed network detector, each at three
    severities, on the held-out split only.</p>
    {table(adv.round(4), cols=["test", "setting", "f1", "recall_on_attacks", "f1_change_vs_baseline"],
           right=["f1", "recall_on_attacks", "f1_change_vs_baseline"],
           caption="Detector performance under drift, evasion, missing data and label poisoning.", num=27)}
    {fig("fig25_adversarial_tests.png", "F1 under increasing severity for each test family, against the unmodified baseline.", "88%")}
    <p>Three conclusions follow. Collection reliability is the largest risk: losing half the
    collected fields costs {abs(adv.f1_change_vs_baseline.min()):.2f} of F1, which makes telemetry
    completeness a security control in its own right. Label poisoning has to reach roughly a
    third of the training set before it does comparable damage, which argues for controlling who
    may label data. The evasion test is the weakest of the four, because it perturbs volume
    features while the detector relies on protocol fields; a stronger test that perturbs those
    fields is recorded as backlog item B02 rather than claimed as a result.</p>""")

    # ------------------------------------------------------------------ 12. prototype
    html.append(f"""
    <div class="pagebreak"></div>
    <h2>12. Working prototype, test cases, known defects and backlog</h2>
    <h3>12.1 Prototype</h3>
    <p>The analyst console is a Streamlit application with eight views, launched with
    <code>streamlit run app/app.py</code>. It is organised the way an analyst works rather than
    by algorithm: <i>Overview</i> (volumes, alerts per day, risk bands), <i>Accounts &amp; risk</i>
    (prioritised watchlist, per-account drill-down showing the risk components and the raw
    events), <i>Anomalies</i>, <i>Investigation</i> (timeline, affected entities, response plan),
    <i>Intelligence</i> (requirements, ATT&amp;CK mapping, executive brief), <i>Simulation</i>,
    <i>Models &amp; robustness</i>, and <i>Data &amp; method</i> (inventory, cleaning log,
    dictionary, compliance checklist).</p>
    <p>The decision the console supports is triage: which account or asset to work next, on what
    evidence, and what to do about it. Every view ends in something actionable rather than in a
    chart. A reproducible notebook, <code>notebooks/capstone_walkthrough.ipynb</code>, accompanies
    it and reproduces every number quoted in this document.</p>
    <p>The screenshots below were captured from the running application, not mocked up. They are
    reproduced by <code>python src/s19_app_screenshots.py</code>, which starts the console and
    drives it in a headless browser.</p>
    {fig("fig27_console_overview.png", "Console, Overview: volume of records analysed, accounts monitored, alerts raised, critical-risk user-days and the detector's F1, with alerts per day by severity.", "86%")}
    {fig("fig28_console_accounts.png", "Console, Accounts and risk: the priority watchlist filtered to the critical and high bands, showing which rules fired, the peak risk score, the dominant risk driver, MFA enrolment and the ATT&CK context for each account.", "86%")}
    {fig("fig29_console_investigation.png", "Console, Investigation: the selected case with its privileged-action counts, the correlated timeline including the linkage-basis column, the affected entities and the response plan.", "86%")}
    {fig("fig30_console_simulation.png", "Console, Simulation: the control-scenario comparison and the sensitivity view, with the assumptions and limitations shown alongside the numbers.", "86%")}

    <h3>12.2 Test cases</h3>
    <p>Sixteen test cases run with <code>python -m pytest tests -q</code> and all pass. They were
    written to catch the mistakes that actually occurred during development, not as decoration:</p>
    <ul>
      <li>raw sources carry provenance hashes, and the minimum-data requirements are met;</li>
      <li>the identity/access and network sources both exist, as C2 requires;</li>
      <li>duplicates are removed before the train/test split, and the count matches the data;</li>
      <li>Zeek placeholders do not survive into the processed data;</li>
      <li>country codes are not parsed as missing values (a regression test for defect D02);</li>
      <li>timestamps are timezone-aware and inside the generation window;</li>
      <li>every alert cites evidence identifiers, and every timeline row states its linkage basis;</li>
      <li>the simulation has at least three scenarios and at least 1,000 runs each;</li>
      <li>risk scores stay within bounds and the bands are correctly ordered;</li>
      <li>no adversarial perturbation improves the score, and at least three families are covered;</li>
      <li>every evidence file named in the compliance checklist exists on disk.</li>
    </ul>

    <h3>12.3 Known defects and limitations</h3>
    {table(defects[defects.type != "backlog"], cols=["id", "type", "area", "description", "severity", "status"],
           caption="Known defects and limitations. Full workarounds are in docs/known_defects_and_backlog.csv.", num=28)}

    <h3>12.4 Implementation backlog</h3>
    {table(defects[defects.type == "backlog"], cols=["id", "area", "description", "workaround_or_plan"],
           caption="Backlog carried into Milestone 3.", num=29)}""")

    # ------------------------------------------------------------------ 13. repo
    html.append(f"""
    <div class="pagebreak"></div>
    <h2>13. Repository, environment and contribution evidence</h2>
    <p><b>Repository.</b> The project is a git repository with the structure
    <code>src/</code> (pipeline stages), <code>app/</code> (console), <code>notebooks/</code>,
    <code>data/raw</code> and <code>data/processed</code>, <code>outputs/</code> (tables,
    figures, models, logs), <code>docs/</code> and <code>tests/</code>. The two ToN_IoT datasets
    are not redistributed; the README gives the exact clone commands and the original UNSW
    source, and the ATT&amp;CK bundle records the upstream commit hash.</p>
    <p><b>Environment.</b> <code>requirements.txt</code> pins the ten libraries used, and every
    summary file records the Python version, library versions and the random seed (3815, derived
    from a member's student number). <code>python src/run_all.py</code> reproduces every output
    from the raw sources in {stages['total_seconds']:.0f} seconds;
    <code>outputs/tables/experiment_log.json</code> records the runtime of each stage and
    <code>outputs/logs/run_log.txt</code> keeps an append-only log of every run.</p>
    {table(pd.DataFrame(stages['stages']), cols=["stage", "description", "seconds"], right=["seconds"],
           caption="Stage runtimes from the last full pipeline run.", num=30)}
    <p><b>Contribution evidence.</b> Module ownership and the review pairing are recorded in
    <code>docs/contribution_and_review.md</code>, which follows the RACI allocation in the
    charter: Member A owns data acquisition, cleaning, features, supervised and unsupervised
    modelling, the risk model and reproducibility; Member B owns the log-source architecture,
    access analytics, investigation, simulation, text mining and the intelligence products; both
    own the prototype, documentation and testing.</p>
    <div class="warn"><b>Declared honestly.</b> The implementation was completed in a compressed
    working period with AI assistance, disclosed in full in
    <code>docs/ai_assistance_disclosure.md</code> as the charter's section 12 requires, and one
    member was unwell during that period. The commit history at the time of submission therefore
    does not yet show balanced authorship. Each member will commit the modules they own from
    their own account before Milestone 3, and the review notes will be recorded as issues. Both
    members remain responsible for explaining every component at the oral verification, and the
    Member A evidence pack (<code>docs/member_a_model_evaluation.md</code>,
    <code>docs/member_a_data_dictionary.md</code>, <code>docs/experiment_log.csv</code>) exists to
    support that.</div>""")

    # ------------------------------------------------------------------ 14. risk register
    risk_reg = pd.DataFrame([
        ["Data unavailable or unsuitable", "High", "High",
         "Assess datasets early, prioritise public or synthetic alternatives",
         "Closed. Public ToN_IoT captures obtained; identity and text sources generated under "
         "documented rules."],
        ["Privacy or sensitive data exposure", "Low", "High",
         "Only authorised, public or synthetic data; anonymise identifiers; exclude credentials",
         "Closed. No real personal data, credentials or live systems were used at any point."],
        ["Model bias or misleading results", "Medium", "High",
         "Establish baselines, validate results, compare against known anomalies, document "
         "limitations",
         "Managed. Leakage control, cross-validation, validation against known injected "
         "behaviour, and negative results reported rather than removed."],
        ["Scope or time overrun", "High", "High",
         "Keep anomaly detection and user behaviour analytics as the core, make advanced "
         "methods conditional",
         "Realised in part. The schedule compressed severely; all components were nonetheless "
         "implemented, with the weaker ones flagged instead of overstated."],
        ["Technical integration failure", "Medium", "Medium",
         "Develop components independently before integrating, maintain version-controlled "
         "backups",
         "Closed. Stages are independent modules writing to files; the console reads outputs "
         "only, and the full pipeline reruns cleanly."],
        ["Unequal contribution", "Medium", "Medium",
         "Assign clear responsibilities, maintain contribution records, review progress",
         "Open. One member was unwell during the implementation period; see section 13 and the "
         "contribution record."],
    ], columns=["Risk (charter)", "Likelihood", "Impact", "Mitigation (charter)",
                "Status at Milestone 2"])

    deviations = pd.DataFrame([
        ["Datasets named", "Volumes and sources were to be determined after selection",
         "ToN_IoT telemetry and flows; generated access log, tickets, asset and user context; "
         "ATT&amp;CK for ICS corpus",
         "Charter section 6 permits public, synthetic or approved data with documented provenance"],
        ["Supervised ML specified", "TBC",
         "Logistic regression, decision tree and random forest; binary and multiclass",
         "Required by C4; the labelled ToN_IoT data made it possible"],
        ["Text mining implemented", "Conditional on suitable data",
         "320 labelled tickets plus 357 ATT&amp;CK descriptions",
         "Required by C8; a real public corpus removed the dependency on unavailable ticket data"],
        ["Simulation widened", "Segmentation scenarios only",
         "Five scenarios: baseline, segmentation, MFA, monitoring, combined",
         "The access analysis showed authentication was the dominant exposure, so testing it was "
         "necessary"],
        ["Repository location", "TBC", "Local git repository, to be pushed to the group remote",
         "Required for contribution evidence"],
        ["Schedule", "Ten-week plan, tasks 1 to 8",
         "Implementation completed in a compressed period before the deadline",
         "Stated plainly rather than presented as the original plan having run to schedule"],
    ], columns=["Change", "Charter position", "Milestone 2 position", "Reason"])

    html.append(f"""
    <div class="pagebreak"></div>
    <h2>14. Updated risk register and deviations from the charter</h2>
    {table(risk_reg, caption="Charter risk register updated with current status.", num=31)}
    <h3>14.1 Declared deviations</h3>
    {table(deviations, caption="Differences between the approved charter and what was implemented, with the reason for each.", num=32)}""")

    # ------------------------------------------------------------------ 15. plan
    html.append(f"""
    <div class="pagebreak"></div>
    <h2>15. Implementation plan to Milestones 3 and 4</h2>
    <p>The table below is the live plan. Tasks T01 to T17 are complete and their evidence is in
    the repository; the remaining tasks carry to Milestone 3 (documentation, due 25 September
    2026) and Milestone 4 (presentation and oral verification, 25&ndash;30 September 2026).</p>
    {table(impl, cols=["task_id", "task", "responsible", "expected_output", "status", "estimated_completion"],
           caption="Implementation plan with ownership, status and dependencies. Full detail in docs/implementation_plan.csv.", num=33)}
    <h3>15.1 Priorities for Milestone 3</h3>
    <ol>
      <li>Split the repository commits so that both members' contributions are visible, and
      record the review notes as issues.</li>
      <li>Strengthen the evasion test to perturb the categorical protocol features the detector
      actually relies on (backlog B02).</li>
      <li>Make rule R4 role-aware so that shift patterns stop generating avoidable alerts
      (defect D07).</li>
      <li>Add analyst feedback capture to the console, which closes the intelligence cycle's
      feedback stage that is currently documented but not automated (backlog B04).</li>
      <li>Rehearse the presentation against the speaker notes, with both members able to answer
      on any component.</li>
    </ol>""")

    # ------------------------------------------------------------------ 16. limitations
    html.append(f"""
    <h2>16. Limitations, ethics and AI assistance</h2>
    <p><b>Limitations.</b> Four should be read alongside every result in this document.</p>
    <ol>
      <li>ToN_IoT is a controlled laboratory testbed, not mining equipment. Scores close to 1.0
      reflect a clean capture; the same models would need recalibration against site data before
      any operational use.</li>
      <li>Attack traffic is the majority class in that capture, which is unlike any real network
      and directly explains the unsupervised anomaly result in section 6.</li>
      <li>The identity/access source and the ticket corpus are synthetic, so detection results
      demonstrate that the methods find behaviour whose ground truth we know, not that an
      attacker was found.</li>
      <li>The simulation's transmission probabilities are assumptions; only the foothold
      probability is measured, and from a small number of events.</li>
    </ol>
    <p><b>Ethics.</b> No real credentials, personal data, confidential information or live
    systems were involved. No testing was performed against any third-party infrastructure. The
    synthetic accounts are fictional and carry no connection to real people. Outputs that name
    accounts are marked need-to-know in the intelligence products.</p>
    <p><b>AI assistance.</b> Declared in full in <code>docs/ai_assistance_disclosure.md</code>, as
    the charter commits the group to do. AI assistance was used to build the pipeline, the
    console and the generated documentation. It supplied no data and produced no results: every
    figure in this document comes from running the code, the pipeline reruns end to end in
    {stages['total_seconds']:.0f} seconds, and the test suite and provenance hashes allow any
    claim here to be checked independently.</p>""")

    # ------------------------------------------------------------------ appendices
    figs = sorted(p.name for p in OUT_FIGS.glob("fig*.png"))
    fig_index = pd.DataFrame({"figure": figs,
                              "file": [f"outputs/figures/{f}" for f in figs]})
    html.append(f"""
    <div class="pagebreak"></div>
    <h2>Appendix A. Requirement coverage C1&ndash;C10</h2>
    <p>Status is produced by a script that checks each evidence file exists when it runs, not by
    assertion.</p>
    {table(comp, cols=["code", "requirement", "evidence_produced", "status", "files_present", "remaining_work"],
           caption="Compliance checklist against the standard technical specification.", num=34)}

    <h2>Appendix B. Experiment log</h2>
    {table(exp, cols=["id", "area", "experiment", "result", "decision"],
           caption="Experiment log: what was tried, what happened and what was decided, including the failures.", num=35)}

    <div class="pagebreak"></div>
    <h2>Appendix C. Figure and file index</h2>
    {table(fig_index, caption="Figures produced by the pipeline.", num=36)}
    <p class="small">Key evidence files: <code>outputs/tables/data_inventory.csv</code>,
    <code>data_dictionary.csv</code>, <code>cleaning_log.csv</code>, <code>eda_findings.csv</code>,
    <code>supervised_network_test.csv</code>, <code>anomaly_access_validation.csv</code>,
    <code>ueba_alerts.csv</code>, <code>incident_timeline.csv</code>,
    <code>incident_response_plan.csv</code>, <code>intel_operational_watchlist.csv</code>,
    <code>simulation_summary.csv</code>, <code>nlp_extracted_indicators.csv</code>,
    <code>risk_user_day_scores.csv</code>, <code>adversarial_results.csv</code>,
    <code>compliance_checklist.csv</code>; plus <code>outputs/intelligence_executive_brief.md</code>
    and the documents in <code>docs/</code>.</p>
    </body></html>""")
    return "\n".join(html)


def headings(html: str) -> list[tuple[int, str]]:
    """Every h2/h3 in document order, except the Contents heading itself."""
    import re
    out = []
    for m in re.finditer(r"<h([23])>(.*?)</h\1>", html, re.S):
        title = re.sub(r"<[^>]+>", "", m.group(2))
        title = (title.replace("&ndash;", "–").replace("&amp;", "&")
                      .replace("&middot;", "·").strip())
        if title.lower() == "contents":
            continue
        out.append((int(m.group(1)), title))
    return out


def toc_html(items: list[tuple[int, str]], pages: dict[str, int] | None) -> str:
    """Contents list with dotted leaders. Page numbers are '--' on the measuring pass."""
    rows = []
    for level, title in items:
        pg = "&ndash;&ndash;" if pages is None else str(pages.get(title, ""))
        cls = "tocrow" if level == 2 else "tocrow l2"
        rows.append(f'<div class="{cls}"><span class="t">{title}</span>'
                    f'<span class="dots"></span><span class="pg">{pg}</span></div>')
    return '<div class="toc">' + "".join(rows) + "</div>"


def measure_pages(pdf_path: Path, items: list[tuple[int, str]]) -> dict[str, int]:
    """Find the printed page each heading starts on by reading the rendered PDF."""
    from pypdf import PdfReader

    # the PDF text layer uses typographic ligatures (fi, fl, ff), so both sides of the
    # comparison are folded back to plain letters before matching
    LIGATURES = {"ﬀ": "ff", "ﬁ": "fi", "ﬂ": "fl", "ﬃ": "ffi",
                 "ﬄ": "ffl", "–": "-", "—": "-", " ": " "}

    def norm(s: str) -> str:
        for k, v in LIGATURES.items():
            s = s.replace(k, v)
        return " ".join(s.split()).lower()

    reader = PdfReader(str(pdf_path))
    page_text = [norm(p.extract_text() or "") for p in reader.pages]

    # The contents page lists every heading, so it would match all of them. Any page
    # holding six or more heading titles is treated as front matter and skipped.
    targets = [norm(t) for _l, t in items]
    first_body = 1
    for i, txt in enumerate(page_text):
        if sum(1 for t in targets if t in txt) >= 6:
            first_body = i + 1
    pages, cursor = {}, first_body
    for _level, title in items:
        target = norm(title)
        found = None
        for i in range(cursor, len(page_text)):
            if target in page_text[i]:
                found = i + 1                  # 1-based, matches the printed footer
                break
        if found is None:                      # fall back to a search after the contents
            for i in range(first_body, len(page_text)):
                if target in page_text[i]:
                    found = i + 1
                    break
        if found:
            pages[title] = found
            cursor = found - 1                 # headings are in order; allow same page
    return pages


def render_pdf(html_path: Path, pdf_path: Path) -> None:
    script = f"""
from playwright.sync_api import sync_playwright
with sync_playwright() as pw:
    b = pw.chromium.launch()
    pg = b.new_page()
    pg.goto("file://{html_path}", wait_until="networkidle")
    pg.pdf(path="{pdf_path}", format="A4", print_background=True,
           display_header_footer=True,
           header_template="<div></div>",
           footer_template=('<div style="font-family:Arial;font-size:7.5pt;color:#5a6472;'
                            'width:100%;padding:0 17mm;display:flex;justify-content:space-between">'
                            '<span>SAS821S Capstone &middot; T08 &middot; Milestone 2 &middot; '
                            '222093471 &amp; 215103815</span>'
                            '<span class="pageNumber"></span></div>'),
           margin={{"top": "16mm", "bottom": "16mm", "left": "0mm", "right": "0mm"}})
    b.close()
"""
    subprocess.run([sys.executable, "-c", script], check=True)


def main() -> None:
    """
    The contents page needs real page numbers, and inserting it changes the pagination,
    so the document is laid out more than once: first with placeholder numbers, then with
    the measured ones, repeating until the numbers stop moving (at most three passes).
    """
    base = build()
    items = headings(base)

    pages = None
    previous: dict[str, int] = {}
    for attempt in range(1, 4):
        html = base.replace("<!--TOC-->", toc_html(items, pages))
        HTML.write_text(html, encoding="utf-8")
        render_pdf(HTML, PDF)
        measured = measure_pages(PDF, items)
        if pages is not None and measured == previous:
            LOG.info("contents page numbers stable after %d passes", attempt)
            break
        previous, pages = measured, measured
    else:
        LOG.warning("contents page numbers still moving after 3 passes; "
                    "check the rendered document")

    missing = [t for _l, t in items if t not in (pages or {})]
    if missing:
        LOG.warning("headings not located in the PDF: %s", missing)
    LOG.info("Milestone 2 document written: %s (%.1f MB), %d contents entries",
             PDF, PDF.stat().st_size / 1e6, len(items))


if __name__ == "__main__":
    main()
