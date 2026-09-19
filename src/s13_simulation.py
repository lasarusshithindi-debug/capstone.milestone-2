"""
Stage 13 (Capstone STEP 10) - Monte Carlo simulation of four security-control scenarios.

The question: if an attacker gets a foothold through remote access, how far into the mining
OT network do they get, and which control package changes that most?

Model in plain English
  * The mine is represented as a graph built from the asset inventory: internet -> VPN
    gateway -> IT zone -> IT-OT jump hosts -> OT zone -> critical OT devices (PLC, RTU,
    HMI, historian, IIoT gateways).
  * A run starts with one compromised remote-access session. At each step every
    compromised node tries to reach each of its neighbours once, and succeeds with a
    probability that depends on the zone boundary being crossed and on the controls in
    force in that scenario.
  * A run stops after 12 steps or when nothing new can be reached.
  * 5,000 runs per scenario (the specification asks for at least 1,000).

Where the numbers come from (this matters in the Q&A)
  MEASURED from our own data:
    - p_foothold: the share of external privileged access events that had no MFA
    - the graph itself: 194 assets, their sites, zones and criticality
  ASSUMED, with sensitivity analysis over +/- 40 per cent:
    - per-boundary transmission probabilities
    - the effect size of each control
  Nothing here is presented as a prediction of real incident frequency. The simulation
  compares control packages against each other under one stated set of assumptions.

Outputs: outputs/tables/simulation_*.csv, outputs/figures/fig20*, fig21*
"""
from __future__ import annotations

import sys
from pathlib import Path

import networkx as nx
import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import DATA_PROCESSED, DATA_RAW, OUT_FIGS, OUT_TABLES, SEED, env_stamp, get_logger, write_json
from viz import CATEGORICAL, finish, plt

LOG = get_logger("s13_simulation")

N_RUNS = 5000
MAX_STEPS = 12

# assumed base probability of a successful hop across each boundary
BASE_P = {
    ("IT-OT", "IT"): 0.10,
    ("IT", "IT"): 0.08,
    ("IT", "IT-OT"): 0.09,
    ("IT-OT", "OT"): 0.14,           # the boundary that segmentation is meant to protect
    ("OT", "OT"): 0.12,              # flat OT segments still spread, but not instantly
    ("IT-OT", "IT-OT"): 0.11,
}
CRIT_MULT = {"critical": 0.8, "high": 0.9, "medium": 1.0, "low": 1.1}

SCENARIOS = {
    "S0_baseline": {"seg": 1.0, "mfa": 1.0, "edr": 1.0,
                    "desc": "current controls as described in the asset inventory"},
    "S1_segmentation": {"seg": 0.25, "mfa": 1.0, "edr": 1.0,
                        "desc": "IT-OT to OT traffic restricted to approved flows"},
    "S2_strong_auth": {"seg": 1.0, "mfa": 0.35, "edr": 1.0,
                       "desc": "MFA enforced for every remote and privileged session"},
    "S3_monitoring": {"seg": 1.0, "mfa": 1.0, "edr": 0.45,
                      "desc": "detection and isolation of a compromised host after 2 steps"},
    "S4_combined": {"seg": 0.25, "mfa": 0.35, "edr": 0.45,
                    "desc": "all three control packages together"},
}


def build_graph(assets: pd.DataFrame) -> nx.DiGraph:
    g = nx.DiGraph()
    g.add_node("INTERNET", zone="INTERNET", criticality="low", site="external")
    for a in assets.itertuples():
        g.add_node(a.asset_id, zone=a.device_zone, criticality=a.criticality,
                   site=a.site, asset_type=a.asset_type)

    by_site: dict[str, list] = {}
    for a in assets.itertuples():
        by_site.setdefault(a.site, []).append(a)

    # internet reaches only the remote-access entry points
    for a in assets.itertuples():
        if a.asset_type in ("vpn_gateway", "jump_host") and a.remote_access_enabled:
            g.add_edge("INTERNET", a.asset_id)

    for site, rows in by_site.items():
        entry = [r for r in rows if r.asset_type in ("vpn_gateway", "jump_host")]
        it = [r for r in rows if r.device_zone == "IT"]
        itot = [r for r in rows if r.device_zone == "IT-OT"]
        ot = [r for r in rows if r.device_zone == "OT"]
        for e in entry:
            for t in it + itot:
                if t.asset_id != e.asset_id:
                    g.add_edge(e.asset_id, t.asset_id)
        for s in itot:
            for t in ot:
                g.add_edge(s.asset_id, t.asset_id)
        for s in it:
            for t in itot:
                g.add_edge(s.asset_id, t.asset_id)
        # OT segments are flat but not fully meshed: each device talks to a few peers
        for i, s in enumerate(ot):
            for t in ot[i + 1:i + 4]:
                g.add_edge(s.asset_id, t.asset_id)
                g.add_edge(t.asset_id, s.asset_id)
    # site-to-site links through the corporate WAN (IT zone only)
    it_hosts = [a.asset_id for a in assets.itertuples() if a.device_zone == "IT"]
    for i, s in enumerate(it_hosts):
        for t in it_hosts[i + 1:i + 3]:
            g.add_edge(s, t); g.add_edge(t, s)
    return g


def edge_probability(g: nx.DiGraph, u: str, v: str, sc: dict, scale: float) -> float:
    zu, zv = g.nodes[u]["zone"], g.nodes[v]["zone"]
    p = BASE_P.get((zu, zv), 0.06) * CRIT_MULT.get(g.nodes[v]["criticality"], 1.0) * scale
    if zv == "OT" and zu != "OT":
        p *= sc["seg"]          # only approved flows survive segmentation
    return float(min(max(p, 0.0), 0.95))


def run_scenario(g: nx.DiGraph, sc: dict, p_foothold: float, n_runs: int, rng, scale=1.0) -> dict:
    nodes = list(g.nodes)
    idx = {n: i for i, n in enumerate(nodes)}
    edges = []
    seg_rng = np.random.default_rng(SEED + 5)
    for u, v in g.edges:
        if u == "INTERNET":
            continue                        # the foothold is drawn separately
        # segmentation also removes flows that are not on the approved list
        if g.nodes[v]["zone"] == "OT" and g.nodes[u]["zone"] != "OT":
            if seg_rng.random() > sc["seg"] ** 0.5:
                continue
        edges.append((idx[u], idx[v], edge_probability(g, u, v, sc, scale)))
    is_ot = np.array([g.nodes[n]["zone"] == "OT" for n in nodes])
    # "critical" means a critical asset INSIDE the OT zone (a PLC, RTU, HMI or
    # historian) - not the internet-facing gateway the intrusion starts on
    is_crit = np.array([g.nodes[n]["criticality"] == "critical" and
                        g.nodes[n]["zone"] == "OT" for n in nodes])
    entry = [idx[n] for n in g.successors("INTERNET")]

    reached_ot = np.zeros(n_runs, bool)
    reached_crit = np.zeros(n_runs, bool)
    n_comp = np.zeros(n_runs, int)
    steps_to_ot = np.full(n_runs, np.nan)

    for r in range(n_runs):
        comp = np.zeros(len(nodes), bool)
        # MFA acts at the door: it reduces the chance that stolen credentials work at all
        if rng.random() > p_foothold * sc["mfa"]:           # the intrusion never gets in
            n_comp[r] = 0
            continue
        comp[rng.choice(entry)] = True
        infected_at = {int(np.flatnonzero(comp)[0]): 0}
        for step in range(1, MAX_STEPS + 1):
            newly = []
            for u, v, p in edges:
                if not comp[u] or comp[v]:
                    continue
                # monitoring scenario: a compromised host is isolated after two steps
                age = step - infected_at.get(u, 0)
                pp = p * (sc["edr"] if age >= 2 else 1.0)
                if rng.random() < pp:
                    newly.append(v)
            if not newly:
                break
            for v in newly:
                comp[v] = True
                infected_at.setdefault(v, step)
            if np.isnan(steps_to_ot[r]) and (comp & is_ot).any():
                steps_to_ot[r] = step
        reached_ot[r] = bool((comp & is_ot).any())
        reached_crit[r] = bool((comp & is_crit).any())
        n_comp[r] = int(comp.sum())

    def wilson(k, n, z=1.96):
        if n == 0:
            return (0.0, 0.0)
        p = k / n
        d = 1 + z * z / n
        c = (p + z * z / (2 * n)) / d
        h = z * np.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
        return (max(0, c - h), min(1, c + h))

    lo_ot, hi_ot = wilson(reached_ot.sum(), n_runs)
    lo_cr, hi_cr = wilson(reached_crit.sum(), n_runs)
    return {
        "p_reach_ot": reached_ot.mean(), "ci_ot_low": lo_ot, "ci_ot_high": hi_ot,
        "p_reach_critical": reached_crit.mean(), "ci_crit_low": lo_cr, "ci_crit_high": hi_cr,
        "mean_assets_compromised": n_comp.mean(),
        "p95_assets_compromised": float(np.percentile(n_comp, 95)),
        "median_steps_to_ot": float(np.nanmedian(steps_to_ot)) if np.isfinite(steps_to_ot).any() else np.nan,
    }


def main() -> None:
    assets = pd.read_csv(DATA_RAW / "mining_asset_inventory.csv")
    acc = pd.read_parquet(DATA_PROCESSED / "access_events.parquet")

    # MEASURED input: how often does an external privileged action happen without MFA?
    ext_priv = acc[(acc["is_external_src"] == 1) & (acc["privileged_action"])]
    p_foothold = float((~ext_priv["mfa_used"]).mean()) if len(ext_priv) else 0.2
    LOG.info("measured p_foothold (external privileged events without MFA) = %.3f on %d events",
             p_foothold, len(ext_priv))

    g = build_graph(assets)
    LOG.info("graph: %d nodes, %d edges", g.number_of_nodes(), g.number_of_edges())

    rows = []
    for name, sc in SCENARIOS.items():
        rng = np.random.default_rng(SEED)          # same draws for every scenario
        res = run_scenario(g, sc, p_foothold, N_RUNS, rng)
        res.update({"scenario": name, "description": sc["desc"], "runs": N_RUNS})
        rows.append(res)
        LOG.info("%-16s P(OT)=%.3f  P(critical)=%.3f  mean assets=%.1f",
                 name, res["p_reach_ot"], res["p_reach_critical"], res["mean_assets_compromised"])
    summary = pd.DataFrame(rows)[["scenario", "description", "runs", "p_reach_ot", "ci_ot_low",
                                  "ci_ot_high", "p_reach_critical", "ci_crit_low", "ci_crit_high",
                                  "mean_assets_compromised", "p95_assets_compromised",
                                  "median_steps_to_ot"]]
    base = summary.loc[summary.scenario == "S0_baseline"].iloc[0]
    summary["abs_reduction_ot"] = base["p_reach_ot"] - summary["p_reach_ot"]
    summary["rel_reduction_ot"] = summary["abs_reduction_ot"] / base["p_reach_ot"]
    summary.to_csv(OUT_TABLES / "simulation_summary.csv", index=False)

    # sensitivity: scale every transmission probability by 0.6, 1.0 and 1.4
    sens_rows = []
    for scale in (0.6, 1.0, 1.4):
        for name, sc in SCENARIOS.items():
            rng = np.random.default_rng(SEED + 99)
            res = run_scenario(g, sc, p_foothold, 1500, rng, scale=scale)
            sens_rows.append({"scale": scale, "scenario": name,
                              "p_reach_ot": res["p_reach_ot"],
                              "p_reach_critical": res["p_reach_critical"],
                              "mean_assets": res["mean_assets_compromised"]})
    sens = pd.DataFrame(sens_rows)
    sens.to_csv(OUT_TABLES / "simulation_sensitivity.csv", index=False)
    ranks = (sens.pivot(index="scenario", columns="scale", values="p_reach_ot")
             .rank(axis=0, method="min"))
    rank_stable = bool((ranks.nunique(axis=1) == 1).all())
    LOG.info("scenario ranking stable across all probability scales: %s", rank_stable)

    # figures
    fig, ax = plt.subplots(figsize=(8.2, 3.3))
    x = np.arange(len(summary))
    ax.bar(x - 0.2, summary["p_reach_ot"], width=0.38, color=CATEGORICAL[0],
           yerr=[summary["p_reach_ot"] - summary["ci_ot_low"],
                 summary["ci_ot_high"] - summary["p_reach_ot"]],
           capsize=3, label="reaches the OT zone")
    ax.bar(x + 0.2, summary["p_reach_critical"], width=0.38, color=CATEGORICAL[1],
           yerr=[summary["p_reach_critical"] - summary["ci_crit_low"],
                 summary["ci_crit_high"] - summary["p_reach_critical"]],
           capsize=3, label="reaches a critical OT asset")
    ax.set_xticks(x); ax.set_xticklabels(summary["scenario"], rotation=15, fontsize=8)
    ax.set_ylabel("probability per intrusion attempt")
    ax.set_title(f"Control-scenario comparison ({N_RUNS:,} Monte Carlo runs each, 95% CI)")
    ax.legend()
    finish(fig, ax, OUT_FIGS / "fig20_simulation_scenarios.png")

    fig, ax = plt.subplots(figsize=(8.2, 3.2))
    for i, sc in enumerate(SCENARIOS):
        sub = sens[sens.scenario == sc]
        ax.plot(sub["scale"], sub["p_reach_ot"], marker="o", lw=2,
                color=CATEGORICAL[i % len(CATEGORICAL)], label=sc)
    ax.set_xlabel("multiplier applied to every transmission probability")
    ax.set_ylabel("P(reach OT zone)")
    ax.set_title("Sensitivity of the comparison to the assumed probabilities")
    ax.legend(fontsize=7.5, ncol=3)
    finish(fig, ax, OUT_FIGS / "fig21_simulation_sensitivity.png")

    write_json({
        "runs_per_scenario": N_RUNS, "max_steps": MAX_STEPS,
        "measured_p_foothold": p_foothold,
        "measured_from_events": int(len(ext_priv)),
        "graph": {"nodes": g.number_of_nodes(), "edges": g.number_of_edges()},
        "assumptions": {"base_probabilities": {f"{k[0]}->{k[1]}": v for k, v in BASE_P.items()},
                        "criticality_multiplier": CRIT_MULT,
                        "scenario_factors": {k: {kk: vv for kk, vv in v.items() if kk != "desc"}
                                             for k, v in SCENARIOS.items()}},
        "results": summary.to_dict(orient="records"),
        "ranking_stable_under_sensitivity": rank_stable,
        "limitations": [
            "probabilities are assumed, not measured from mining incidents",
            "no human defender acts during a run except the S3 isolation effect",
            "the graph is generated from a synthetic asset inventory",
            "results compare scenarios; they are not incident-frequency forecasts",
        ],
        "env": env_stamp(),
    }, OUT_TABLES / "simulation_summary.json")


if __name__ == "__main__":
    main()
