"""
Stage 10 (Capstone STEP 7) - Access and user-behaviour analytics (UEBA).

Plain English: the anomaly model in stage 09 gives a score but not a reason a control-room
supervisor can act on. This stage adds seven explicit behaviour rules, each of which states
what was seen, which account and asset it involves and which events prove it. The rules are
built from the baselines measured in stage 07, not from guesswork, and every alert carries
its evidence event IDs.

Rules
  R1 burst of failed logins for one account inside one hour
  R2 password spraying: one source address failing against several accounts in one hour
  R3 impossible travel: one account authenticating from two countries within 60 minutes
  R4 privileged action outside the account's normal working hours
  R5 first-seen country for an account
  R6 dormant account reactivation (no activity for 14+ days, then a successful login)
  R7 privileged session without MFA from an external address

Outputs: outputs/tables/ueba_alerts.csv, ueba_rule_summary.csv, ueba_user_baseline.csv,
         outputs/figures/fig17*, fig18*
"""
from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import DATA_PROCESSED, OUT_FIGS, OUT_TABLES, env_stamp, get_logger, write_json
from viz import CATEGORICAL, finish, plt

LOG = get_logger("s10_access")

SEV = {"R1": "medium", "R2": "high", "R3": "high", "R4": "medium",
       "R5": "low", "R6": "high", "R7": "high"}


def alerts_from_rules(acc: pd.DataFrame) -> pd.DataFrame:
    out: list[dict] = []
    acc = acc.sort_values("timestamp").copy()

    def add(rule, ts, user, detail, evidence, asset="", src_ip=""):
        out.append({"alert_id": f"{rule}-{len(out)+1:04d}", "rule": rule, "severity": SEV[rule],
                    "timestamp": ts, "username": user, "asset_id": asset, "src_ip": src_ip,
                    "detail": detail, "evidence_event_ids": evidence})

    # R1 - failed-login burst per account, one-hour window
    fails = acc[acc.event_type == "LOGIN_FAILURE"]
    for (user, hr), grp in fails.groupby(["username", fails["timestamp"].dt.floor("h")],
                                         observed=True):
        if len(grp) >= 3:      # baseline: 99th percentile is 2 failures per DAY
            add("R1", hr, user, f"{len(grp)} failed logins within one hour",
                "|".join(grp["event_id"].head(10)), src_ip=grp["src_ip"].mode().iloc[0])

    # R2 - one source address failing against several accounts in one hour
    for (ip, hr), grp in fails.groupby(["src_ip", fails["timestamp"].dt.floor("h")],
                                       observed=True):
        n_users = grp["username"].nunique()
        if n_users >= 5:
            add("R2", hr, f"{n_users} accounts",
                f"source {ip} failed against {n_users} distinct accounts in one hour "
                f"({len(grp)} attempts)", "|".join(grp["event_id"].head(15)), src_ip=ip)

    # R3 - impossible travel
    logins = acc[acc.event_type.isin(["LOGIN_SUCCESS"])].sort_values(["username", "timestamp"])
    logins["prev_country"] = logins.groupby("username", observed=True)["src_country"].shift()
    logins["prev_ts"] = logins.groupby("username", observed=True)["timestamp"].shift()
    logins["prev_id"] = logins.groupby("username", observed=True)["event_id"].shift()
    gap = (logins["timestamp"] - logins["prev_ts"]).dt.total_seconds() / 60
    imp = logins[(logins["src_country"] != logins["prev_country"]) &
                 logins["prev_country"].notna() & (gap <= 60)]
    for r in imp.itertuples():
        add("R3", r.timestamp, r.username,
            f"authenticated from {r.prev_country} then {r.src_country} within "
            f"{(r.timestamp - r.prev_ts).total_seconds()/60:.0f} minutes",
            f"{r.prev_id}|{r.event_id}", src_ip=r.src_ip)

    # R4 - privileged action outside the account's usual hours (own 5th-95th percentile)
    hours = acc[acc.event_type == "LOGIN_SUCCESS"].groupby("username", observed=True)["hour"]
    lo, hi = hours.quantile(0.05), hours.quantile(0.95)
    priv = acc[acc["privileged_action"].astype(str).str.lower().isin(["true", "1"])]
    for r in priv.itertuples():
        l, h = lo.get(r.username, 6), hi.get(r.username, 18)
        if r.hour < l or r.hour > h:
            add("R4", r.timestamp, r.username,
                f"privileged action on {r.target_system} at {r.hour:02d}:00, outside this "
                f"account's usual {int(l):02d}:00-{int(h):02d}:00 pattern",
                r.event_id, asset=r.asset_id, src_ip=r.src_ip)

    # R5 - first time an account is seen from a country
    seen: dict[str, set] = {}
    for r in acc.sort_values("timestamp").itertuples():
        s = seen.setdefault(r.username, set())
        if r.src_country not in s:
            if s:                                    # not the account's first ever event
                add("R5", r.timestamp, r.username,
                    f"first activity from {r.src_country} (previously {sorted(s)})",
                    r.event_id, src_ip=r.src_ip)
            s.add(r.src_country)

    # R6 - dormant account reactivation
    succ = acc[acc.event_type == "LOGIN_SUCCESS"].sort_values(["username", "timestamp"])
    succ["prev"] = succ.groupby("username", observed=True)["timestamp"].shift()
    dormant = succ[(succ["timestamp"] - succ["prev"]).dt.days >= 14]
    for r in dormant.itertuples():
        add("R6", r.timestamp, r.username,
            f"account dormant for {(r.timestamp - r.prev).days} days then authenticated "
            f"from {r.src_country}", r.event_id, src_ip=r.src_ip)

    # R7 - privileged session without MFA from an external address
    nomfa = acc[(acc["privileged_action"].astype(str).str.lower().isin(["true", "1"])) &
                (~acc["mfa_used"].astype(str).str.lower().isin(["true", "1"])) &
                (acc["is_external_src"] == 1)]
    for r in nomfa.itertuples():
        add("R7", r.timestamp, r.username,
            f"privileged action on {r.target_system} from external address {r.src_ip} "
            "with no MFA", r.event_id, asset=r.asset_id, src_ip=r.src_ip)

    return pd.DataFrame(out).sort_values("timestamp").reset_index(drop=True)


def main() -> None:
    acc = pd.read_parquet(DATA_PROCESSED / "access_events.parquet")
    ud = pd.read_parquet(DATA_PROCESSED / "access_user_day_scored.parquet")

    alerts = alerts_from_rules(acc)

    # tie every alert back to the injected ground truth, for validation only
    gt_by_event = (acc[acc["gt_scenario"] != ""]
                   .set_index("event_id")["gt_scenario"].to_dict())

    def injected(evidence: str) -> str:
        hits = {gt_by_event.get(e, "") for e in str(evidence).split("|")}
        return "|".join(sorted(h for h in hits if h))

    alerts["matches_injected_pattern"] = alerts["evidence_event_ids"].map(injected)
    alerts.to_csv(OUT_TABLES / "ueba_alerts.csv", index=False)

    summary = (alerts.groupby(["rule", "severity"], observed=True)
               .agg(alerts=("alert_id", "count"),
                    accounts=("username", "nunique"),
                    matched_injected=("matches_injected_pattern",
                                      lambda s: int((s != "").sum()))).reset_index())
    summary["precision_vs_injected"] = summary["matched_injected"] / summary["alerts"]
    summary.to_csv(OUT_TABLES / "ueba_rule_summary.csv", index=False)

    # per-user baseline table for the dashboard
    base = (ud.groupby(["username", "role", "employment_type"], observed=True)
            .agg(active_days=("day", "size"), mean_events=("events", "mean"),
                 sd_events=("events", "std"), mean_failures=("failures", "mean"),
                 mean_ooh=("out_of_hours", "mean"), max_iso_score=("iso_score", "max"),
                 flagged_days=("iso_flag", "sum")).reset_index()
            .sort_values("max_iso_score", ascending=False))
    base.to_csv(OUT_TABLES / "ueba_user_baseline.csv", index=False)

    # figures
    fig, ax = plt.subplots(figsize=(8.2, 3.2))
    s = summary.sort_values("alerts")
    colors = {"high": CATEGORICAL[5], "medium": CATEGORICAL[1], "low": CATEGORICAL[0]}
    ax.barh(s["rule"], s["alerts"], color=[colors[x] for x in s["severity"]], height=0.6)
    for y, (v, m) in enumerate(zip(s["alerts"], s["matched_injected"])):
        ax.text(v, y, f"  {v} alerts ({m} on injected behaviour)", va="center", fontsize=7.5,
                color="#444444")
    ax.set_xlim(0, s["alerts"].max() * 1.7)
    ax.set_title("UEBA rule alerts (colour = severity)")
    finish(fig, ax, OUT_FIGS / "fig17_ueba_rule_alerts.png")

    daily = (alerts.assign(d=pd.to_datetime(alerts["timestamp"]).dt.date)
             .groupby(["d", "severity"], observed=True).size().unstack(fill_value=0))
    fig, ax = plt.subplots(figsize=(8.2, 3.0))
    bottom = np.zeros(len(daily))
    for sev in [c for c in ["low", "medium", "high"] if c in daily.columns]:
        ax.bar(daily.index, daily[sev], bottom=bottom, label=sev, color=colors[sev],
               width=0.7, edgecolor="white", linewidth=0.5)
        bottom += daily[sev].values
    ax.set_title("Access alerts per day by severity")
    ax.set_ylabel("alerts"); ax.legend()
    ax.tick_params(axis="x", rotation=45, labelsize=7)
    finish(fig, ax, OUT_FIGS / "fig18_alerts_per_day.png")

    write_json({"alerts": int(len(alerts)),
                "by_rule": summary.to_dict(orient="records"),
                "accounts_with_alerts": int(alerts["username"].nunique()),
                "env": env_stamp()}, OUT_TABLES / "ueba_summary.json")
    LOG.info("alerts=%d over %d accounts", len(alerts), alerts["username"].nunique())
    for r in summary.itertuples():
        LOG.info("  %-3s %-6s alerts=%-4d matched_injected=%-3d", r.rule, r.severity,
                 r.alerts, r.matched_injected)


if __name__ == "__main__":
    main()
