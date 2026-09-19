"""
Stage 02 - Generate the SYNTHETIC identity/access source and the asset/user context.

Why this exists
---------------
Capstone requirement C2 asks for at least three distinct security data sources, one of
which must represent IDENTITY/ACCESS activity. The ToN_IoT datasets contain IIoT
telemetry and network flows but no remote-access or login records, and the project
charter (section 3) forbids using real credentials or live mining systems. The charter
(section 6) and the capstone specification (5.1) both allow synthetically generated data
provided the generation method is documented. This script is that documentation: every
rule used to create the data is written here in the open.

IMPORTANT - how to describe this in the report and the oral defence
-------------------------------------------------------------------
Nothing in this file is a real security event. It is a simulated remote-operations
access log for a fictional mining operator, produced by fixed rules and a fixed random
seed. The four abnormal behaviour patterns are INSERTED DELIBERATELY and recorded in the
`gt_scenario` column, so they can be used as ground truth when testing detection methods.
Any detection result must therefore be reported as "detected the behaviour we injected",
never as "detected a real intrusion".

What is produced
----------------
  data/raw/mining_asset_inventory.csv        - device/asset context (C2 context requirement)
  data/raw/mining_user_directory.csv         - user/account context
  data/raw/synthetic_remote_access_log.csv   - the identity/access event source
  outputs/tables/provenance_synthetic_access.json

Time window: 2019-04-01 to 2019-04-30, chosen to overlap the ToN_IoT telemetry window
(2019-03-31 to 2019-04-29). The four injected behaviour patterns are placed between
24 and 29 April because that is when ToN_IoT itself contains attack-labelled telemetry,
so the investigation stage can compare the two sources on the same calendar days. The
overlap is a deliberate design choice for the exercise, NOT evidence that the two sources
describe the same environment.
"""
from __future__ import annotations

import sys
from datetime import datetime, timedelta
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import DATA_RAW, OUT_TABLES, SEED, env_stamp, get_logger, sha256, write_json

LOG = get_logger("s02_synth_access")
rng = np.random.default_rng(SEED)

START = datetime(2019, 4, 1)
END = datetime(2019, 4, 30, 23, 59, 59)
N_DAYS = 30

SITES = {
    "PIT-A":      {"zone": "OT", "country": "NAM", "desc": "Open-pit mining area A"},
    "PIT-B":      {"zone": "OT", "country": "NAM", "desc": "Open-pit mining area B"},
    "PLANT-01":   {"zone": "OT", "country": "NAM", "desc": "Processing plant"},
    "TAILINGS-01":{"zone": "OT", "country": "NAM", "desc": "Tailings storage facility"},
    "WORKSHOP-01":{"zone": "IT-OT", "country": "NAM", "desc": "Heavy-equipment workshop"},
    "CAMP-01":    {"zone": "IT", "country": "NAM", "desc": "Remote accommodation camp"},
    "HQ-WHK":     {"zone": "IT", "country": "NAM", "desc": "Corporate head office, Windhoek"},
    "PORT-WVB":   {"zone": "IT", "country": "NAM", "desc": "Port logistics office, Walvis Bay"},
}

ROLES = {
    # role: (count, privileged_share, out_of_hours_share, typical zones)
    "control_room_operator": (26, 0.10, 0.45, ["OT"]),
    "maintenance_engineer":  (24, 0.25, 0.25, ["OT", "IT-OT"]),
    "ot_network_admin":      (8,  0.90, 0.30, ["OT", "IT-OT", "IT"]),
    "it_service_desk":       (10, 0.40, 0.15, ["IT"]),
    "vendor_technician":     (9,  0.60, 0.20, ["OT", "IT-OT"]),
    "contractor_surveyor":   (12, 0.05, 0.10, ["OT", "IT"]),
    "mine_planner":          (14, 0.05, 0.08, ["IT"]),
    "supervisor":            (11, 0.20, 0.35, ["IT", "OT"]),
}

AUTH_METHODS = ["vpn_gateway", "rdp_broker", "ssh_bastion", "ot_jump_host", "web_portal"]
TARGETS = ["scada_hmi", "historian", "plc_engineering_ws", "fleet_mgmt", "erp", "file_share",
           "cctv_nvr", "telemetry_broker", "maintenance_portal"]

DEVICE_TYPES = {
    "plc":              ("OT", "critical", "modbus"),
    "rtu":              ("OT", "critical", "dnp3"),
    "hmi":              ("OT", "critical", "http"),
    "historian":        ("OT", "high", "sql"),
    "iiot_gateway":     ("OT", "high", "mqtt"),
    "sensor_weather":   ("OT", "medium", "mqtt"),
    "sensor_modbus":    ("OT", "critical", "modbus"),
    "sensor_thermostat":("OT", "medium", "mqtt"),
    "sensor_motion":    ("OT", "low", "mqtt"),
    "gps_tracker":      ("OT", "medium", "mqtt"),
    "garage_door_ctrl": ("IT-OT", "low", "http"),
    "fridge_unit":      ("IT-OT", "low", "mqtt"),
    "haul_truck_edge":  ("OT", "high", "mqtt"),
    "vpn_gateway":      ("IT-OT", "critical", "ipsec"),
    "jump_host":        ("IT-OT", "critical", "rdp"),
    "laptop":           ("IT", "medium", "n/a"),
    "workstation":      ("IT", "medium", "n/a"),
}


def build_assets() -> pd.DataFrame:
    """Asset inventory: what equipment exists, where it sits and how critical it is."""
    rows, n = [], 0
    for site, meta in SITES.items():
        for dtype, (zone, crit, proto) in DEVICE_TYPES.items():
            # OT devices are not installed at IT-only sites, and vice versa
            if meta["zone"] == "IT" and zone == "OT":
                continue
            if meta["zone"] == "OT" and dtype in ("erp", "workstation") :
                continue
            count = int(rng.integers(1, 4))
            for _ in range(count):
                n += 1
                rows.append({
                    "asset_id": f"AST-{n:04d}",
                    "asset_type": dtype,
                    "site": site,
                    "site_zone": meta["zone"],
                    "device_zone": zone,
                    "criticality": crit,
                    "primary_protocol": proto,
                    "ip_address": f"192.168.{list(SITES).index(site)+10}.{rng.integers(2, 250)}",
                    "owner_team": "OT Engineering" if zone == "OT" else "IT Operations",
                    "patch_status": rng.choice(["current", "behind_1_cycle", "behind_2_cycles", "unsupported"],
                                               p=[0.45, 0.30, 0.18, 0.07]),
                    "remote_access_enabled": bool(rng.random() < 0.55),
                })
    return pd.DataFrame(rows)


def build_users() -> pd.DataFrame:
    """User directory: who has accounts, their role, employment type and normal site."""
    rows, n = [], 0
    for role, (count, priv_share, _ooh, zones) in ROLES.items():
        for _ in range(count):
            n += 1
            site = rng.choice([s for s, m in SITES.items() if m["zone"] in zones])
            rows.append({
                "username": f"{role.split('_')[0][:4]}{n:03d}",
                "user_role": role,
                "employment_type": ("vendor" if role.startswith("vendor")
                                    else "contractor" if role.startswith("contractor")
                                    else "employee"),
                "home_site": site,
                "privileged_account": bool(rng.random() < priv_share),
                "account_created": (START - timedelta(days=int(rng.integers(90, 1800)))).date().isoformat(),
                "mfa_enrolled": bool(rng.random() < 0.82),
            })
    return pd.DataFrame(rows)


def _timestamp_for(day: datetime, out_of_hours: bool) -> datetime:
    """Day shift 06:00-18:00, night/out-of-hours otherwise."""
    if out_of_hours:
        hour = int(rng.choice(list(range(0, 6)) + list(range(18, 24))))
    else:
        hour = int(rng.integers(6, 18))
    return day + timedelta(hours=hour, minutes=int(rng.integers(0, 60)), seconds=int(rng.integers(0, 60)))


def build_access_log(users: pd.DataFrame, assets: pd.DataFrame) -> pd.DataFrame:
    """
    Normal behaviour model
    ----------------------
    * each user has 1-3 usual source IPs, a usual auth method and usual target systems
    * weekday activity is roughly twice weekend activity
    * each session = 1 LOGIN_SUCCESS (or LOGIN_FAILURE) plus optional ACCESS/LOGOUT events
    * baseline authentication failure rate ~6 per cent, mostly single failures
    """
    events, eid = [], 0
    user_profile = {}
    for u in users.itertuples():
        base_ip = f"10.{rng.integers(20, 60)}.{rng.integers(1, 250)}"
        user_profile[u.username] = {
            "ips": [f"{base_ip}.{rng.integers(2, 250)}" for _ in range(int(rng.integers(1, 4)))],
            "auth": rng.choice(AUTH_METHODS, p=[0.35, 0.2, 0.15, 0.2, 0.1]),
            "targets": list(rng.choice(TARGETS, size=int(rng.integers(2, 5)), replace=False)),
            "ooh": ROLES[u.user_role][2],
            "assets": list(assets.loc[assets.site == u.home_site, "asset_id"]
                           .sample(min(6, (assets.site == u.home_site).sum()), random_state=int(rng.integers(1e6)))),
            "priv": u.privileged_account,
            "mfa": u.mfa_enrolled,
            "role": u.user_role,
            "site": u.home_site,
            "emp": u.employment_type,
        }

    def add(ts, user, etype, result, **kw):
        nonlocal eid
        eid += 1
        p = user_profile[user]
        events.append({
            "event_id": f"ACC{eid:06d}",
            "timestamp": ts,
            "username": user,
            "user_role": p["role"],
            "employment_type": p["emp"],
            "site": kw.get("site", p["site"]),
            "asset_id": kw.get("asset_id", rng.choice(p["assets"]) if p["assets"] else ""),
            "src_ip": kw.get("src_ip", rng.choice(p["ips"])),
            "src_country": kw.get("src_country", "NAM"),
            "auth_method": kw.get("auth_method", p["auth"]),
            "mfa_used": kw.get("mfa_used", p["mfa"]),
            "event_type": etype,
            "result": result,
            "target_system": kw.get("target_system", rng.choice(p["targets"])),
            "privileged_action": kw.get("privileged_action", False),
            "session_duration_s": kw.get("session_duration_s", 0),
            "bytes_out": kw.get("bytes_out", 0),
            "gt_scenario": kw.get("gt_scenario", ""),
        })

    # ---------------- normal activity ----------------
    for d in range(N_DAYS):
        day = START + timedelta(days=d)
        weekend = day.weekday() >= 5
        for user, p in user_profile.items():
            lam = (0.8 if weekend else 2.0) * (1.4 if p["role"] in
                   ("control_room_operator", "ot_network_admin") else 1.0)
            for _ in range(int(rng.poisson(lam))):
                ooh = rng.random() < p["ooh"]
                ts = _timestamp_for(day, ooh)
                if rng.random() < 0.06:                       # isolated failed login
                    add(ts, user, "LOGIN_FAILURE", "failure")
                    if rng.random() < 0.55:                   # user retries and succeeds
                        add(ts + timedelta(seconds=int(rng.integers(20, 180))), user,
                            "LOGIN_SUCCESS", "success")
                    continue
                dur = int(abs(rng.normal(2400, 1500))) + 120
                add(ts, user, "LOGIN_SUCCESS", "success", session_duration_s=dur)
                for _ in range(int(rng.poisson(1.6))):
                    add(ts + timedelta(seconds=int(rng.integers(30, max(180, dur)))), user,
                        "RESOURCE_ACCESS", "success",
                        privileged_action=bool(p["priv"] and rng.random() < 0.35),
                        bytes_out=int(abs(rng.normal(2.5e6, 2e6))))
                add(ts + timedelta(seconds=dur), user, "LOGOUT", "success",
                    session_duration_s=dur)

    # ---------------- injected behaviour patterns (ground truth) ----------------
    # GT1: password spraying from a single external address against many accounts
    spray_ip, spray_day = "196.44.128.77", START + timedelta(days=23)
    victims = list(rng.choice(list(user_profile), size=38, replace=False))
    t = spray_day + timedelta(hours=2, minutes=14)
    for v in victims:
        for _ in range(int(rng.integers(1, 4))):
            add(t, v, "LOGIN_FAILURE", "failure", src_ip=spray_ip, src_country="ZZZ",
                mfa_used=False, gt_scenario="GT1_password_spray")
            t += timedelta(seconds=int(rng.integers(5, 40)))
    # two accounts fall to the spray
    for v in victims[:2]:
        add(t, v, "LOGIN_SUCCESS", "success", src_ip=spray_ip, src_country="ZZZ",
            mfa_used=False, session_duration_s=1800, gt_scenario="GT1_password_spray")
        add(t + timedelta(minutes=3), v, "RESOURCE_ACCESS", "success", target_system="file_share",
            privileged_action=False, bytes_out=42_000_000, gt_scenario="GT1_password_spray")
        t += timedelta(minutes=12)

    # GT2: vendor maintenance account used out of hours on OT systems for four nights
    vendor = [u for u, p in user_profile.items() if p["role"] == "vendor_technician"][0]
    for d in (24, 25, 26, 27):
        night = START + timedelta(days=d, hours=int(rng.integers(0, 4)))
        add(night, vendor, "LOGIN_SUCCESS", "success", auth_method="ot_jump_host",
            src_ip="41.182.90.6", src_country="ZAF", mfa_used=False, session_duration_s=5400,
            gt_scenario="GT2_vendor_out_of_hours")
        for _ in range(4):
            add(night + timedelta(minutes=int(rng.integers(3, 80))), vendor, "RESOURCE_ACCESS",
                "success", target_system=rng.choice(["plc_engineering_ws", "scada_hmi", "historian"]),
                privileged_action=True, bytes_out=int(abs(rng.normal(9e6, 3e6))),
                auth_method="ot_jump_host", src_ip="41.182.90.6", src_country="ZAF",
                mfa_used=False,   # inherited from the session login above
                gt_scenario="GT2_vendor_out_of_hours")

    # GT3: dormant contractor account reactivated and used from a new country
    dormant = [u for u, p in user_profile.items() if p["role"] == "contractor_surveyor"][3]
    day23 = START + timedelta(days=28, hours=3, minutes=40)
    add(day23, dormant, "LOGIN_SUCCESS", "success", src_ip="102.89.33.14", src_country="NGA",
        mfa_used=False, session_duration_s=2700, gt_scenario="GT3_dormant_account")
    for k in range(6):
        add(day23 + timedelta(minutes=6 * k + 4), dormant, "RESOURCE_ACCESS", "success",
            target_system=rng.choice(["file_share", "fleet_mgmt", "maintenance_portal"]),
            privileged_action=bool(k % 3 == 0), bytes_out=int(abs(rng.normal(3.5e7, 8e6))),
            src_ip="102.89.33.14", src_country="NGA", mfa_used=False,
            gt_scenario="GT3_dormant_account")

    # GT4: impossible travel - same admin account from two countries 25 minutes apart
    admin = [u for u, p in user_profile.items() if p["role"] == "ot_network_admin"][0]
    base = START + timedelta(days=26, hours=9, minutes=5)
    add(base, admin, "LOGIN_SUCCESS", "success", src_ip="10.44.12.9", src_country="NAM",
        session_duration_s=1500, gt_scenario="GT4_impossible_travel")
    add(base + timedelta(minutes=25), admin, "LOGIN_SUCCESS", "success", src_ip="185.220.101.44",
        src_country="RUS", mfa_used=False, session_duration_s=900,
        gt_scenario="GT4_impossible_travel")
    add(base + timedelta(minutes=31), admin, "PRIVILEGE_CHANGE", "success",
        target_system="plc_engineering_ws", privileged_action=True, src_ip="185.220.101.44",
        src_country="RUS", gt_scenario="GT4_impossible_travel")

    df = pd.DataFrame(events).sort_values("timestamp").reset_index(drop=True)

    # The GT3 account is described as dormant, so its routine traffic is removed for the
    # 18 days before the reactivation. Without this the "dormant" label would not match
    # the data, and the rule that looks for reactivation could never fire.
    quiet_from = START + timedelta(days=8)
    quiet_to = START + timedelta(days=28, hours=3)
    drop = ((df["username"] == dormant) & (df["timestamp"] >= quiet_from) &
            (df["timestamp"] < quiet_to) & (df["gt_scenario"] == ""))
    df = df[~drop].reset_index(drop=True)

    df["event_id"] = [f"ACC{i+1:06d}" for i in range(len(df))]   # renumber in time order
    return df


def main() -> None:
    assets = build_assets()
    users = build_users()
    access = build_access_log(users, assets)

    paths = {
        "assets": DATA_RAW / "mining_asset_inventory.csv",
        "users": DATA_RAW / "mining_user_directory.csv",
        "access": DATA_RAW / "synthetic_remote_access_log.csv",
    }
    assets.to_csv(paths["assets"], index=False)
    users.to_csv(paths["users"], index=False)
    access.to_csv(paths["access"], index=False)

    prov = {
        "generator": "src/s02_generate_context_and_access.py",
        "seed": SEED,
        "window": [START.isoformat(), END.isoformat()],
        "data_status": "SYNTHETIC - generated by rule, contains no real person, credential or system",
        "files": {k: {"path": str(v), "rows": int(len(df)), "sha256": sha256(v)}
                  for (k, v), df in zip(paths.items(), [assets, users, access])},
        "ground_truth_scenarios": access[access.gt_scenario != ""]["gt_scenario"]
                                  .value_counts().to_dict(),
        "event_type_counts": access["event_type"].value_counts().to_dict(),
        "env": env_stamp(),
    }
    write_json(prov, OUT_TABLES / "provenance_synthetic_access.json")
    LOG.info("assets=%d users=%d access_events=%d", len(assets), len(users), len(access))
    LOG.info("ground truth rows: %s", prov["ground_truth_scenarios"])


if __name__ == "__main__":
    main()
