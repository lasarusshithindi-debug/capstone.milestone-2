"""
Stage 07 (Capstone STEP 4) - Descriptive and diagnostic analytics, and behavioural baselines.

Plain English: this stage describes what the data normally looks like before any model is
built. It answers "what is normal here?" for the sensors, the network and the remote-access
accounts, and then lists the things that stand out from that normal picture. Nothing here
is called an attack; the labels that exist in ToN_IoT are used as ground truth for
comparison, and the access data is described purely by behaviour.

Outputs: outputs/figures/fig01..fig08*.png, outputs/tables/baseline_*.csv,
         outputs/tables/eda_findings.csv
"""
from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import DATA_PROCESSED, OUT_FIGS, OUT_TABLES, get_logger, write_json
from viz import ATTACK_C, CATEGORICAL, NORMAL_C, SEQ_CMAP, finish, plt

LOG = get_logger("s07_eda")
FINDINGS: list[dict] = []


def note(area: str, finding: str, evidence: str, interpretation: str) -> None:
    FINDINGS.append({"area": area, "finding": finding, "evidence": evidence,
                     "interpretation": interpretation})


def telemetry_eda(tel: pd.DataFrame) -> None:
    # ---- fig01: telemetry volume per day, normal vs attack-labelled -------------------
    daily = (tel.assign(d=pd.to_datetime(tel["day"]))
                .groupby(["d", "is_attack"], observed=True).size().unstack(fill_value=0))
    fig, ax = plt.subplots(figsize=(8.2, 3.1))
    ax.plot(daily.index, daily.get(0, 0), lw=2, color=NORMAL_C, label="normal-labelled")
    ax.plot(daily.index, daily.get(1, 0), lw=2, color=ATTACK_C, label="attack-labelled")
    ax.set_title("IIoT telemetry readings per day (ToN_IoT, 7 sensors)")
    ax.set_ylabel("measurement rows")
    ax.legend()
    finish(fig, ax, OUT_FIGS / "fig01_telemetry_volume_over_time.png")

    # ---- fig02: attack mix per sensor --------------------------------------------------
    mix = (tel[tel.type != "normal"].groupby(["sensor", "type"], observed=True).size()
           .unstack(fill_value=0))
    mix = mix[mix.sum().sort_values(ascending=False).index]
    fig, ax = plt.subplots(figsize=(8.2, 3.6))
    bottom = np.zeros(len(mix))
    for i, col in enumerate(mix.columns):
        ax.bar(mix.index, mix[col], bottom=bottom, label=col,
               color=CATEGORICAL[i % len(CATEGORICAL)], width=0.68, linewidth=0.6,
               edgecolor="white")
        bottom += mix[col].values
    ax.set_title("Attack-labelled telemetry by sensor and attack type")
    ax.set_ylabel("measurement rows")
    ax.tick_params(axis="x", rotation=20)
    ax.legend(ncol=4, fontsize=7.5)
    finish(fig, ax, OUT_FIGS / "fig02_attack_mix_by_sensor.png")

    # ---- baseline table: normal-only statistics per sensor/measure ---------------------
    norm = tel[(tel.is_attack == 0) & tel["value"].notna()]
    base = (norm.groupby(["sensor", "measure"], observed=True)["value"]
            .agg(n="size", mean="mean", sd="std",
                 p01=lambda s: s.quantile(0.01), p50="median",
                 p99=lambda s: s.quantile(0.99), min="min", max="max").reset_index())
    base.to_csv(OUT_TABLES / "baseline_telemetry.csv", index=False)

    # diagnostic: how far do attack-labelled readings sit from the normal baseline?
    key = base.set_index(["sensor", "measure"])[["mean", "sd"]]
    att = tel[(tel.is_attack == 1) & tel["value"].notna()].merge(
        key, left_on=["sensor", "measure"], right_index=True, how="left")
    att["z"] = (att["value"] - att["mean"]) / att["sd"].replace(0, np.nan)
    z_tbl = (att.groupby(["sensor", "measure"], observed=True)["z"]
             .agg(n="size", share_beyond_3sd=lambda s: float((s.abs() > 3).mean()))
             .reset_index().sort_values("share_beyond_3sd", ascending=False))
    z_tbl.to_csv(OUT_TABLES / "diagnostic_attack_vs_baseline.csv", index=False)
    top = z_tbl.iloc[0]
    note("IIoT telemetry",
         "Attack-labelled readings are not uniformly extreme",
         f"highest separation: {top.sensor}/{top.measure} with "
         f"{top.share_beyond_3sd:.1%} of attack rows beyond 3 SD of the normal baseline; "
         f"median across sensor-measures is {z_tbl.share_beyond_3sd.median():.1%}",
         "Simple threshold alarms on sensor values alone would miss most attack-labelled "
         "traffic, which is the argument for the learned models in steps 5 and 6.")

    # ---- fig03: Modbus register behaviour, normal vs attack ---------------------------
    mb = tel[(tel.sensor == "modbus") & tel["value"].notna()]
    fig, ax = plt.subplots(figsize=(8.2, 3.2))
    order = sorted(mb["measure"].unique())
    data = [mb[(mb.measure == m) & (mb.is_attack == a)]["value"].values
            for m in order for a in (0, 1)]
    pos, colors = [], []
    for i in range(len(order)):
        pos += [i * 3 + 1, i * 3 + 1.9]
        colors += [NORMAL_C, ATTACK_C]
    bp = ax.boxplot(data, positions=pos, widths=0.75, patch_artist=True, showfliers=False)
    for patch, c in zip(bp["boxes"], colors):
        patch.set_facecolor(c); patch.set_alpha(0.65); patch.set_edgecolor("white")
    for med in bp["medians"]:
        med.set_color("#222222")
    ax.set_xticks([i * 3 + 1.45 for i in range(len(order))])
    ax.set_xticklabels([o.replace("_Read_", "\n") for o in order], fontsize=7.5)
    ax.set_title("Modbus register values: normal (blue) vs attack-labelled (orange)")
    ax.set_ylabel("register value")
    finish(fig, ax, OUT_FIGS / "fig03_modbus_registers.png")
    LOG.info("telemetry EDA done")


def network_eda(net: pd.DataFrame) -> None:
    # ---- fig04: flows by attack type ---------------------------------------------------
    cnt = net["type"].value_counts()
    fig, ax = plt.subplots(figsize=(8.2, 3.1))
    ax.bar(cnt.index, cnt.values, color=[NORMAL_C if t == "normal" else CATEGORICAL[1]
                                         for t in cnt.index], width=0.68)
    for x, v in zip(range(len(cnt)), cnt.values):
        ax.text(x, v, f"{v:,}", ha="center", va="bottom", fontsize=7.5, color="#444444")
    ax.set_title("Network flows by labelled activity type (ToN_IoT Zeek)")
    ax.set_ylabel("flows")
    ax.tick_params(axis="x", rotation=25)
    finish(fig, ax, OUT_FIGS / "fig04_network_type_counts.png")

    # ---- fig05: service usage, normal vs attack ---------------------------------------
    svc = (net.assign(service=net["service"].fillna("none"))
             .groupby(["service", "label"], observed=True).size().unstack(fill_value=0))
    svc = svc.loc[svc.sum(axis=1).sort_values(ascending=False).index[:8]]
    fig, ax = plt.subplots(figsize=(8.2, 3.1))
    idx = np.arange(len(svc))
    ax.bar(idx - 0.2, svc.get(0, 0), width=0.38, color=NORMAL_C, label="normal")
    ax.bar(idx + 0.2, svc.get(1, 0), width=0.38, color=ATTACK_C, label="attack-labelled")
    ax.set_xticks(idx); ax.set_xticklabels(svc.index)
    ax.set_title("Flows by application service")
    ax.set_ylabel("flows"); ax.legend()
    finish(fig, ax, OUT_FIGS / "fig05_network_service.png")

    # ---- baseline: normal traffic profile per service ---------------------------------
    nb = (net[net.label == 0].groupby(net["service"].fillna("none"), observed=True)
          .agg(flows=("label", "size"),
               median_duration=("duration", "median"),
               median_total_bytes=("total_bytes", "median"),
               p95_total_bytes=("total_bytes", lambda s: s.quantile(0.95)),
               median_pkts=("total_pkts", "median")).reset_index())
    nb.to_csv(OUT_TABLES / "baseline_network.csv", index=False)

    # diagnostic: connection-state mix tells you about scanning and refused connections
    cs = pd.crosstab(net["conn_state"], net["label"], normalize="index")
    cs_counts = net["conn_state"].value_counts()
    cs = cs.join(cs_counts.rename("flows")).sort_values("flows", ascending=False)
    cs.to_csv(OUT_TABLES / "diagnostic_conn_state.csv")
    worst = cs[cs["flows"] > 500].sort_values(1, ascending=False).head(1)
    note("Network flows",
         "Connection state separates attack-labelled traffic strongly",
         f"state '{worst.index[0]}' carries {worst['flows'].iloc[0]:,} flows of which "
         f"{worst[1].iloc[0]:.1%} are attack-labelled",
         "Half-open and rejected connections are the fingerprint of scanning and flooding; "
         "this is why conn_state is kept as a model feature.")

    # ---- fig06: top internal talkers ---------------------------------------------------
    cross = pd.read_csv(DATA_PROCESSED / "ip_asset_crosswalk.csv")
    top = cross[cross.is_internal == 1].nlargest(10, "flows_out")
    fig, ax = plt.subplots(figsize=(8.2, 3.4))
    ax.barh(top["ip"][::-1], top["flows_out"][::-1], color=NORMAL_C, height=0.62)
    for y, (v, a) in enumerate(zip(top["flows_out"][::-1], top["attack_share_out"][::-1])):
        ax.text(v, y, f"  {v:,.0f}  ({a:.0%} attack-labelled)", va="center", fontsize=7.5,
                color="#444444")
    ax.set_title("Most active internal addresses by outbound flows")
    ax.set_xlabel("flows")
    ax.set_xlim(0, top["flows_out"].max() * 1.45)
    finish(fig, ax, OUT_FIGS / "fig06_top_talkers.png")
    LOG.info("network EDA done")


def access_eda(acc: pd.DataFrame, ud: pd.DataFrame) -> None:
    # ---- fig07: access events per day by event type -----------------------------------
    daily = (acc.assign(d=pd.to_datetime(acc["day"]))
                .groupby(["d", "event_type"], observed=True).size().unstack(fill_value=0))
    fig, ax = plt.subplots(figsize=(8.2, 3.1))
    for i, col in enumerate(["LOGIN_SUCCESS", "LOGIN_FAILURE", "RESOURCE_ACCESS", "LOGOUT"]):
        if col in daily:
            ax.plot(daily.index, daily[col], lw=2, label=col.lower(),
                    color=CATEGORICAL[i % len(CATEGORICAL)])
    ax.set_title("Remote-access events per day (synthetic mining access log)")
    ax.set_ylabel("events"); ax.legend(ncol=4, fontsize=7.5)
    finish(fig, ax, OUT_FIGS / "fig07_access_events_over_time.png")

    # ---- fig08: hour-of-day baseline by role (heatmap, single hue) --------------------
    hm = (acc[acc.event_type == "LOGIN_SUCCESS"]
          .pivot_table(index="user_role", columns="hour", values="event_id", aggfunc="count")
          .fillna(0))
    hm = hm.div(hm.sum(axis=1), axis=0)          # share of that role's logins per hour
    fig, ax = plt.subplots(figsize=(8.6, 3.2))
    im = ax.imshow(hm.values, aspect="auto", cmap=SEQ_CMAP)
    ax.set_xticks(range(0, 24, 2)); ax.set_xticklabels(range(0, 24, 2))
    ax.set_yticks(range(len(hm.index))); ax.set_yticklabels(hm.index, fontsize=7.5)
    ax.set_title("Login hour profile by role (share of each role's successful logins)")
    ax.set_xlabel("hour of day (UTC)")
    ax.grid(False)
    fig.colorbar(im, ax=ax, shrink=0.8, label="share of logins")
    finish(fig, ax, OUT_FIGS / "fig08_login_hour_by_role.png")

    # ---- baseline tables ---------------------------------------------------------------
    role_base = (ud.groupby("role", observed=True)
                 .agg(users=("username", "nunique"), user_days=("day", "size"),
                      mean_events=("events", "mean"), sd_events=("events", "std"),
                      mean_failures=("failures", "mean"),
                      p95_failures=("failures", lambda s: s.quantile(0.95)),
                      mean_ooh=("out_of_hours", "mean"),
                      mean_distinct_ips=("distinct_ips", "mean"),
                      mean_bytes_out=("bytes_out", "mean")).reset_index())
    role_base.to_csv(OUT_TABLES / "baseline_access_role.csv", index=False)

    user_base = (ud.groupby("username", observed=True)
                 .agg(days_active=("day", "size"), mean_events=("events", "mean"),
                      sd_events=("events", "std"), mean_failures=("failures", "mean"),
                      max_failures=("failures", "max"),
                      mean_ooh=("out_of_hours", "mean"),
                      max_distinct_countries=("distinct_countries", "max"),
                      mean_bytes_out=("bytes_out", "mean")).reset_index())
    user_base.to_csv(OUT_TABLES / "baseline_access_user.csv", index=False)

    # ---- diagnostic: which user-days stand out on simple, explainable rules -----------
    thr_fail = ud["failures"].quantile(0.99)
    odd = ud[(ud["failures"] >= max(thr_fail, 3)) | (ud["distinct_countries"] > 1) |
             (ud["foreign"] > 0)]
    odd = odd.sort_values(["failures", "foreign"], ascending=False)
    odd.to_csv(OUT_TABLES / "eda_unusual_user_days.csv", index=False)
    note("Remote access",
         "A small number of user-days break the behavioural baseline",
         f"{len(odd)} of {len(ud)} user-days ({len(odd)/len(ud):.1%}) show either >= "
         f"{max(thr_fail,3):.0f} failed logins, more than one source country, or any "
         f"non-domestic source address; the 99th percentile of daily failures is "
         f"{thr_fail:.1f}",
         "These are candidates for investigation, not confirmed incidents. They are used "
         "in step 7 as the rule-based comparison for the machine-learning anomaly scores.")

    fail_rate = acc["is_failure"].mean()
    note("Remote access", "Baseline authentication failure rate",
         f"{fail_rate:.2%} of all access events are failures "
         f"({int(acc['is_failure'].sum()):,} of {len(acc):,})",
         "This is the reference level any alerting threshold has to beat; a rule that fires "
         "on single failures would generate roughly "
         f"{int(acc['is_failure'].sum()):,} alerts a month.")
    LOG.info("access EDA done")


def main() -> None:
    tel = pd.read_parquet(DATA_PROCESSED / "telemetry_events.parquet")
    net = pd.read_parquet(DATA_PROCESSED / "network_flows.parquet")
    acc = pd.read_parquet(DATA_PROCESSED / "access_events.parquet")
    ud = pd.read_parquet(DATA_PROCESSED / "access_user_day.parquet")

    telemetry_eda(tel)
    network_eda(net)
    access_eda(acc, ud)

    pd.DataFrame(FINDINGS).to_csv(OUT_TABLES / "eda_findings.csv", index=False)
    write_json({"figures": sorted(p.name for p in OUT_FIGS.glob("fig*.png")),
                "findings": len(FINDINGS)}, OUT_TABLES / "eda_summary.json")
    for f in FINDINGS:
        LOG.info("[%s] %s | %s", f["area"], f["finding"], f["evidence"])


if __name__ == "__main__":
    main()
