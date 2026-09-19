"""
Stage 11 (Capstone STEP 8) - Security investigation: case selection, timeline, response.

IMPORTANT FRAMING (say this in the presentation)
------------------------------------------------
This is an ANALYTICAL SCENARIO, not a real incident. The access events in the timeline are
synthetic records produced by our own generator, and the telemetry/network rows come from
the ToN_IoT research testbed, which is a different environment altogether. Rows from
different sources are therefore linked by *time and account*, and each row states its
linkage basis. No causal link between the ToN_IoT captures and the access log is claimed.

What the stage does
  1. scores every candidate case from the UEBA alerts and the anomaly model
  2. takes the strongest case and pulls every event for the account involved
  3. enriches each event with asset, site, criticality and user-role context
  4. adds same-window context rows from the telemetry and network sources, labelled as
     context rather than proof
  5. writes the affected-entity list and a containment/eradication/recovery/monitoring plan

Outputs: outputs/tables/incident_*.csv, outputs/figures/fig19_incident_timeline.png
"""
from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import DATA_PROCESSED, DATA_RAW, OUT_FIGS, OUT_TABLES, env_stamp, get_logger, write_json
from viz import CATEGORICAL, finish, plt

LOG = get_logger("s11_investigation")

SEV_WEIGHT = {"high": 3.0, "medium": 1.5, "low": 0.5}


def select_case(alerts: pd.DataFrame, ud: pd.DataFrame) -> tuple[str, pd.DataFrame]:
    a = alerts[alerts["username"].str.contains(r"^\w+\d+$", na=False)].copy()
    a["w"] = a["severity"].map(SEV_WEIGHT)
    score = (a.groupby("username", observed=True)
             .agg(alert_weight=("w", "sum"), alerts=("alert_id", "count"),
                  rules=("rule", "nunique"),
                  first_seen=("timestamp", "min"), last_seen=("timestamp", "max"))
             .reset_index())
    peak = (ud.groupby("username", observed=True)["iso_score"].max()
            .rename("max_anomaly_score").reset_index())
    score = score.merge(peak, on="username", how="left")
    score["case_score"] = score["alert_weight"] * (1 + score["rules"]) + \
                          20 * score["max_anomaly_score"].fillna(0)
    score = score.sort_values("case_score", ascending=False)
    score.to_csv(OUT_TABLES / "incident_case_ranking.csv", index=False)
    return score.iloc[0]["username"], score


def main() -> None:
    acc = pd.read_parquet(DATA_PROCESSED / "access_events.parquet")
    ud = pd.read_parquet(DATA_PROCESSED / "access_user_day_scored.parquet")
    tel = pd.read_parquet(DATA_PROCESSED / "telemetry_events.parquet")
    flows = pd.read_parquet(DATA_PROCESSED / "network_flows.parquet")
    alerts = pd.read_csv(OUT_TABLES / "ueba_alerts.csv")
    assets = pd.read_csv(DATA_RAW / "mining_asset_inventory.csv")
    users = pd.read_csv(DATA_RAW / "mining_user_directory.csv")
    tickets = pd.read_csv(DATA_RAW / "synthetic_maintenance_tickets.csv")

    subject, ranking = select_case(alerts, ud)
    LOG.info("case selected: %s (top case score %.1f)", subject,
             ranking.iloc[0]["case_score"])

    user_row = users[users.username == subject].iloc[0]
    ev = acc[acc.username == subject].sort_values("timestamp").copy()
    window_days = sorted(pd.to_datetime(
        alerts.loc[alerts.username == subject, "timestamp"]).dt.date.unique())

    rows = []
    for r in ev.itertuples():
        in_window = r.timestamp.date() in window_days
        rows.append({
            "timestamp": r.timestamp,
            "source": "remote_access_log (synthetic)",
            "event_id": r.event_id,
            "user": r.username,
            "user_role": r.user_role,
            "employment_type": r.employment_type,
            "asset_id": r.asset_id,
            "site": r.site,
            "src": f"{r.src_ip} ({r.src_country})",
            "dst": r.target_system,
            "event_type": r.event_type,
            "result": r.result,
            "privileged": bool(r.privileged_action),
            "mfa": bool(r.mfa_used),
            "bytes_out": int(r.bytes_out),
            "evidence": r.event_id,
            "linkage_basis": "direct - same account",
            "in_alert_window": in_window,
        })
    tl = pd.DataFrame(rows)

    # alert rows, interleaved with the raw events
    for r in alerts[alerts.username == subject].itertuples():
        tl.loc[len(tl)] = {
            "timestamp": pd.to_datetime(r.timestamp), "source": "UEBA rule engine",
            "event_id": r.alert_id, "user": r.username, "user_role": user_row.user_role,
            "employment_type": user_row.employment_type, "asset_id": r.asset_id,
            "site": "", "src": str(r.src_ip), "dst": "", "event_type": f"ALERT {r.rule}",
            "result": r.severity, "privileged": False, "mfa": False, "bytes_out": 0,
            "evidence": r.evidence_event_ids, "linkage_basis": "derived from the events above",
            "in_alert_window": True,
        }

    # context row set 1 - ToN_IoT telemetry on the same calendar days
    tel_ctx = (tel[(tel["is_attack"] == 1) &
                   (pd.to_datetime(tel["day"]).dt.date.isin(window_days))]
               .groupby(["day", "sensor", "type"], observed=True).size()
               .reset_index(name="rows").sort_values("rows", ascending=False).head(8))
    for r in tel_ctx.itertuples():
        tl.loc[len(tl)] = {
            "timestamp": pd.Timestamp(r.day).tz_localize("UTC"),
            "source": "ToN_IoT IIoT telemetry (research testbed)",
            "event_id": f"TEL-{r.sensor}-{r.day}", "user": "", "user_role": "",
            "employment_type": "", "asset_id": f"sensor:{r.sensor}", "site": "", "src": "",
            "dst": "", "event_type": f"telemetry labelled '{r.type}'", "result": f"{r.rows} readings",
            "privileged": False, "mfa": False, "bytes_out": 0,
            "evidence": f"{r.rows} attack-labelled readings on {r.day}",
            "linkage_basis": "CONTEXT ONLY - same calendar day, different source environment",
            "in_alert_window": True,
        }

    # context row set 2 - the most attack-heavy internal addresses in the flow capture
    cross = pd.read_csv(DATA_PROCESSED / "ip_asset_crosswalk.csv")
    top_ips = cross[(cross.is_internal == 1) & (cross.flows_out > 1000)] \
        .nlargest(3, "attack_share_out")
    for r in top_ips.itertuples():
        tl.loc[len(tl)] = {
            "timestamp": pd.Timestamp(window_days[0]).tz_localize("UTC"),
            "source": "ToN_IoT network flows (research testbed)",
            "event_id": f"NET-{r.ip}", "user": "", "user_role": "", "employment_type": "",
            "asset_id": r.mining_archetype_ASSUMED, "site": "", "src": r.ip, "dst": "",
            "event_type": "high attack-labelled outbound flow share",
            "result": f"{r.attack_share_out:.0%} of {int(r.flows_out):,} flows",
            "privileged": False, "mfa": False, "bytes_out": 0,
            "evidence": f"{int(r.flows_out):,} outbound flows profiled in the crosswalk",
            "linkage_basis": "CONTEXT ONLY - behavioural parallel, no shared identifiers",
            "in_alert_window": True,
        }

    # context row set 3 - tickets that name the account or its assets
    tk = tickets[tickets["text"].str.contains(subject, na=False) |
                 tickets["reported_by"].eq(subject)]
    for r in tk.itertuples():
        tl.loc[len(tl)] = {
            "timestamp": pd.to_datetime(r.opened_at).tz_localize("UTC"),
            "source": "maintenance ticket (synthetic)", "event_id": r.ticket_id,
            "user": subject, "user_role": user_row.user_role,
            "employment_type": user_row.employment_type, "asset_id": r.asset_id,
            "site": r.site, "src": "", "dst": "", "event_type": f"ticket:{r.category}",
            "result": r.priority, "privileged": False, "mfa": False, "bytes_out": 0,
            "evidence": r.text[:160], "linkage_basis": "direct - ticket names the account",
            "in_alert_window": pd.to_datetime(r.opened_at).date() in window_days,
        }

    tl = tl.sort_values("timestamp").reset_index(drop=True)
    tl.to_csv(OUT_TABLES / "incident_timeline.csv", index=False)

    # affected entities
    involved_assets = [a for a in tl["asset_id"].dropna().unique() if str(a).startswith("AST-")]
    ent = assets[assets.asset_id.isin(involved_assets)].copy()
    ent["why_involved"] = "accessed during the alert window by " + subject
    ent.to_csv(OUT_TABLES / "incident_affected_entities.csv", index=False)

    # response plan, tied to what the evidence actually shows
    priv_events = int(tl["privileged"].sum())
    no_mfa = int(((~tl["mfa"]) & tl["privileged"]).sum())
    ext = tl[tl["src"].str.contains(r"\((?!NAM)", na=False, regex=True)]["src"].unique().tolist()
    plan = pd.DataFrame([
        ("Containment", "Suspend the remote-access entitlement for "
         f"{subject} and terminate active sessions",
         f"{priv_events} privileged actions in the window, {no_mfa} of them without MFA"),
        ("Containment", "Block the external source addresses at the VPN concentrator",
         f"non-domestic sources observed: {', '.join(ext) if ext else 'none'}"),
        ("Containment", "Place the OT jump host and the engineering workstation used in the "
         "window under enhanced logging", "out-of-hours privileged access to OT targets"),
        ("Eradication", "Reset credentials and re-enrol MFA for the account, and review any "
         "keys or tokens issued to it", "authentication occurred without MFA"),
        ("Eradication", "Verify the configuration of the assets listed in "
         "incident_affected_entities.csv against a known-good export",
         f"{len(ent)} assets touched in the window"),
        ("Recovery", "Restore vendor access only through a time-boxed, approved maintenance "
         "window with supervision", "activity fell outside any approved window"),
        ("Recovery", "Confirm normal telemetry and control behaviour for the affected assets "
         "before closing the case", "telemetry context rows in the same window"),
        ("Monitoring", "Keep rules R2, R3, R6 and R7 at high severity and review R4 tuning",
         "R4 produced the majority of alerts at low precision against known behaviour"),
        ("Monitoring", "Alert on any first-seen country for privileged accounts (rule R5)",
         "R5 matched every injected pattern in the test window"),
    ], columns=["phase", "action", "evidence_basis"])
    plan.to_csv(OUT_TABLES / "incident_response_plan.csv", index=False)

    # timeline figure
    fig, ax = plt.subplots(figsize=(8.6, 3.4))
    srcs = list(tl["source"].unique())
    for i, s in enumerate(srcs):
        sub = tl[tl["source"] == s]
        ax.scatter(sub["timestamp"], [i] * len(sub), s=46, alpha=0.85,
                   color=CATEGORICAL[i % len(CATEGORICAL)], edgecolors="white", linewidths=0.6)
    ax.set_yticks(range(len(srcs)))
    ax.set_yticklabels([s.replace(" (", "\n(") for s in srcs], fontsize=7)
    ax.set_title(f"Correlated timeline for the selected case ({subject})")
    ax.tick_params(axis="x", rotation=30, labelsize=7.5)
    finish(fig, ax, OUT_FIGS / "fig19_incident_timeline.png")

    write_json({
        "case_account": subject,
        "account_role": str(user_row.user_role),
        "employment_type": str(user_row.employment_type),
        "alert_window_days": [str(d) for d in window_days],
        "timeline_rows": int(len(tl)),
        "direct_evidence_rows": int((tl["linkage_basis"].str.startswith("direct")).sum()),
        "context_only_rows": int((tl["linkage_basis"].str.startswith("CONTEXT")).sum()),
        "privileged_actions": priv_events,
        "privileged_without_mfa": no_mfa,
        "affected_assets": int(len(ent)),
        "injected_pattern_behind_case": sorted(
            set(acc.loc[acc.username == subject, "gt_scenario"]) - {""}),
        "status": "ANALYTICAL SCENARIO - synthetic access data, testbed context rows",
        "env": env_stamp(),
    }, OUT_TABLES / "incident_summary.json")
    LOG.info("timeline rows=%d (direct=%d, context=%d), affected assets=%d",
             len(tl), int((tl["linkage_basis"].str.startswith("direct")).sum()),
             int((tl["linkage_basis"].str.startswith("CONTEXT")).sum()), len(ent))


if __name__ == "__main__":
    main()
