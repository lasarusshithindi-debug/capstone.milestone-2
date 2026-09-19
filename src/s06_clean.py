"""
Stage 06 (Capstone STEP 3) - Data engineering pipeline: validate, clean, standardise, join.

Plain English: the raw files are never modified. This script reads them, fixes the
problems found in stage 04 (stray spaces, '-' placeholders, text stored as numbers,
duplicate rows, mixed time formats), adds the features later stages need, writes the
analysis-ready tables to data/processed/, and records every change in a cleaning log so
that a marker or a teammate can see exactly what was done and why.

Outputs (parquet, analysis-ready)
  data/processed/telemetry_events.parquet   unified IIoT telemetry, all 7 sensors
  data/processed/network_flows.parquet      Zeek flows with cleaned types and features
  data/processed/access_events.parquet      remote-access events with behaviour features
  data/processed/access_user_day.parquet    per-user per-day behaviour aggregates
  data/processed/ip_asset_crosswalk.csv     data-derived mapping of flow IPs to asset roles
  outputs/tables/cleaning_log.csv           every action taken, with reason and row counts
"""
from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import (DATA_PROCESSED, DATA_RAW, OUT_TABLES, SRC_IOT_DIR, SRC_NETWORK,
                    env_stamp, get_logger, write_json)

LOG = get_logger("s06_clean")
CLEAN_LOG: list[dict] = []

SENSOR_FILES = {
    "fridge": "Train_Test_IoT_Fridge.csv",
    "garage_door": "Train_Test_IoT_Garage_Door.csv",
    "gps_tracker": "Train_Test_IoT_GPS_Tracker.csv",
    "modbus": "Train_Test_IoT_Modbus.csv",
    "motion_light": "Train_Test_IoT_Motion_Light.csv",
    "thermostat": "Train_Test_IoT_Thermostat.csv",
    "weather": "Train_Test_IoT_Weather.csv",
}

# Sensor -> the numeric measurement columns that carry the signal
SENSOR_VALUE_COLS = {
    "fridge": ["fridge_temperature"],
    "garage_door": ["sphone_signal"],
    "gps_tracker": ["latitude", "longitude"],
    "modbus": ["FC1_Read_Input_Register", "FC2_Read_Discrete_Value",
               "FC3_Read_Holding_Register", "FC4_Read_Coil"],
    "motion_light": ["motion_status"],
    "thermostat": ["current_temperature", "thermostat_status"],
    "weather": ["temperature", "pressure", "humidity"],
}
SENSOR_CAT_COLS = {
    "fridge": ["temp_condition"],
    "garage_door": ["door_state"],
    "gps_tracker": [],
    "modbus": [],
    "motion_light": ["light_status"],
    "thermostat": [],
    "weather": [],
}


def log_action(dataset: str, action: str, detail: str, reason: str,
               before: int | str = "", after: int | str = "") -> None:
    CLEAN_LOG.append({"dataset": dataset, "action": action, "detail": detail,
                      "reason": reason, "rows_before": before, "rows_after": after})


def tidy_strings(df: pd.DataFrame) -> pd.DataFrame:
    """Remove BOM characters and stray spaces that stop joins and grouping working."""
    df.columns = [str(c).replace("﻿", "").strip() for c in df.columns]
    for c in df.columns:
        if df[c].dtype == object:
            df[c] = df[c].astype(str).str.replace("﻿", "", regex=False).str.strip()
    return df


# --------------------------------------------------------------------------------------
# 1. IIoT telemetry
# --------------------------------------------------------------------------------------
def clean_telemetry() -> pd.DataFrame:
    frames = []
    for sensor, fname in SENSOR_FILES.items():
        path = SRC_IOT_DIR / fname
        raw = pd.read_csv(path, encoding="utf-8-sig", low_memory=False)
        n0 = len(raw)
        df = tidy_strings(raw.copy())
        log_action(f"iot_{sensor}", "strip_whitespace_bom", "all object columns",
                   "raw files contain a BOM and padded values such as ' off '", n0, n0)

        # timestamps: ts is a unix second counter; date/time are the same instant as text
        df["timestamp"] = pd.to_datetime(df["ts"], unit="s", errors="coerce", utc=True)
        bad_ts = int(df["timestamp"].isna().sum())
        if bad_ts:
            df = df[df["timestamp"].notna()]
            log_action(f"iot_{sensor}", "drop_unparseable_timestamp", f"{bad_ts} rows",
                       "a timestamp is required for every downstream time analysis", n0, len(df))
        df = df.drop(columns=[c for c in ("date", "time") if c in df.columns])
        log_action(f"iot_{sensor}", "drop_redundant_columns", "date, time",
                   "both duplicate the information already held in ts", len(df), len(df))

        # numeric coercion of the measurement columns
        for c in SENSOR_VALUE_COLS[sensor]:
            before_na = int(df[c].isna().sum()) if c in df else 0
            df[c] = pd.to_numeric(df[c], errors="coerce")
            after_na = int(df[c].isna().sum())
            if after_na > before_na:
                log_action(f"iot_{sensor}", "coerce_numeric", f"{c}: {after_na - before_na} values to NaN",
                           "non-numeric text found in a measurement column", len(df), len(df))

        # categorical standardisation
        for c in SENSOR_CAT_COLS[sensor]:
            df[c] = df[c].str.lower().str.strip()
            log_action(f"iot_{sensor}", "standardise_category", c,
                       "case and spacing varied between records", len(df), len(df))

        # labels
        df["label"] = pd.to_numeric(df["label"], errors="coerce").astype("Int64")
        df["type"] = df["type"].str.lower().str.strip()

        # exact duplicates: identical timestamp AND identical values - kept out of modelling
        n_dup = int(df.duplicated().sum())
        df["is_exact_duplicate"] = df.duplicated(keep="first")
        log_action(f"iot_{sensor}", "flag_exact_duplicates", f"{n_dup} rows flagged",
                   "identical ts and values; kept but flagged so models can exclude them "
                   "without deleting evidence", len(df), len(df))

        # missing-value handling for measurements: leave gaps visible, do not invent values
        for c in SENSOR_VALUE_COLS[sensor]:
            miss = int(df[c].isna().sum())
            if miss:
                log_action(f"iot_{sensor}", "retain_missing", f"{c}: {miss} NaN",
                           "gaps are treated as missing telemetry, not imputed, so that the "
                           "model cannot learn from invented readings", len(df), len(df))

        # unified long format: one value column per reading keeps every sensor comparable
        long = df.melt(
            id_vars=["timestamp", "label", "type", "is_exact_duplicate"],
            value_vars=SENSOR_VALUE_COLS[sensor],
            var_name="measure", value_name="value",
        )
        long["sensor"] = sensor
        # keep the sensor-specific categorical state as a separate column where it exists
        if SENSOR_CAT_COLS[sensor]:
            state = df[SENSOR_CAT_COLS[sensor][0]]
            long = long.merge(
                pd.DataFrame({"idx": np.tile(df.index, len(SENSOR_VALUE_COLS[sensor])),
                              "device_state": np.tile(state.values, len(SENSOR_VALUE_COLS[sensor]))}),
                left_index=True, right_index=True, how="left").drop(columns=["idx"])
        else:
            long["device_state"] = pd.NA
        frames.append(long)

        # per-sensor wide file for supervised modelling
        wide_out = DATA_PROCESSED / f"telemetry_{sensor}.parquet"
        df.to_parquet(wide_out, index=False)
        LOG.info("telemetry %-13s rows=%-7d dup_flagged=%-6d -> %s", sensor, len(df), n_dup, wide_out.name)

    events = pd.concat(frames, ignore_index=True)
    events["hour"] = events["timestamp"].dt.hour
    events["day"] = events["timestamp"].dt.date
    events["dow"] = events["timestamp"].dt.dayofweek
    events["is_night"] = ((events["hour"] < 6) | (events["hour"] >= 18)).astype(int)
    events["is_attack"] = (events["label"] == 1).astype(int)
    events.to_parquet(DATA_PROCESSED / "telemetry_events.parquet", index=False)
    log_action("telemetry_events", "unify_sensors", f"{len(events)} measurement rows",
               "single long table lets every sensor be compared on one timeline", "", len(events))
    return events


# --------------------------------------------------------------------------------------
# 2. Network flows
# --------------------------------------------------------------------------------------
NUMERIC_FLOW = ["src_port", "dst_port", "duration", "src_bytes", "dst_bytes", "missed_bytes",
                "src_pkts", "src_ip_bytes", "dst_pkts", "dst_ip_bytes", "dns_qclass",
                "dns_qtype", "dns_rcode", "http_trans_depth", "http_request_body_len",
                "http_response_body_len", "http_status_code"]


def clean_network() -> pd.DataFrame:
    raw = pd.read_csv(SRC_NETWORK, low_memory=False)
    n0 = len(raw)
    df = tidy_strings(raw.copy())
    log_action("network_flow", "strip_whitespace_bom", "all object columns",
               "consistent keys for grouping and joining", n0, n0)

    # Zeek writes '-' where a field does not apply; that is missing, not a value
    placeholder = ["-", "(empty)", ""]
    n_placeholder = int(df.isin(placeholder).sum().sum())
    df = df.replace(placeholder, np.nan)
    log_action("network_flow", "placeholder_to_missing", f"{n_placeholder} cells",
               "Zeek uses '-' for not-applicable fields; treating it as a category would "
               "create fake patterns", n0, len(df))

    for c in NUMERIC_FLOW:
        if c in df.columns:
            df[c] = pd.to_numeric(df[c], errors="coerce")
    log_action("network_flow", "coerce_numeric", ", ".join(NUMERIC_FLOW[:6]) + " ...",
               "numeric fields arrive as text because of the '-' placeholder", len(df), len(df))

    for c in ["proto", "service", "conn_state", "type"]:
        if c in df.columns:
            df[c] = df[c].astype(str).str.lower().str.strip().replace("nan", np.nan)

    df["label"] = pd.to_numeric(df["label"], errors="coerce").astype("Int64")

    # columns that are almost entirely missing carry no usable signal
    sparse = [c for c in df.columns if df[c].isna().mean() > 0.97]
    log_action("network_flow", "flag_sparse_columns", ", ".join(sparse),
               f"{len(sparse)} columns are >97% missing; excluded from modelling features "
               "but retained in the file for investigation", len(df), len(df))

    n_dup = int(df.duplicated().sum())
    df["is_exact_duplicate"] = df.duplicated(keep="first")
    log_action("network_flow", "flag_exact_duplicates", f"{n_dup} rows",
               "identical flows are plausible in a testbed; flagged rather than deleted", len(df), len(df))

    # engineered features
    df["total_bytes"] = df["src_bytes"].fillna(0) + df["dst_bytes"].fillna(0)
    df["total_pkts"] = df["src_pkts"].fillna(0) + df["dst_pkts"].fillna(0)
    df["bytes_ratio"] = (df["src_bytes"].fillna(0) + 1) / (df["dst_bytes"].fillna(0) + 1)
    df["log_duration"] = np.log1p(df["duration"].clip(lower=0).fillna(0))
    df["log_total_bytes"] = np.log1p(df["total_bytes"])
    df["bytes_per_pkt"] = df["total_bytes"] / df["total_pkts"].replace(0, np.nan)
    df["is_internal_dst"] = df["dst_ip"].astype(str).str.startswith("192.168.").astype(int)
    df["is_wellknown_dst_port"] = (df["dst_port"] < 1024).astype("Int64")
    log_action("network_flow", "feature_engineering",
               "total_bytes, total_pkts, bytes_ratio, log_duration, log_total_bytes, "
               "bytes_per_pkt, is_internal_dst, is_wellknown_dst_port",
               "size and direction features are the standard way to separate scanning, "
               "flooding and data-transfer behaviour", len(df), len(df))

    df.to_parquet(DATA_PROCESSED / "network_flows.parquet", index=False)
    LOG.info("network flows rows=%d dup_flagged=%d sparse_cols=%d", len(df), n_dup, len(sparse))
    return df


# --------------------------------------------------------------------------------------
# 3. Remote-access events
# --------------------------------------------------------------------------------------
def clean_access() -> tuple[pd.DataFrame, pd.DataFrame]:
    df = pd.read_csv(DATA_RAW / "synthetic_remote_access_log.csv", keep_default_na=False,
                     na_values=[""])
    df = tidy_strings(df)
    n0 = len(df)
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    bad = int(df["timestamp"].isna().sum())
    if bad:
        df = df[df["timestamp"].notna()]
    log_action("access_log", "parse_timestamps", f"{bad} unparseable rows removed",
               "time is the backbone of behaviour analytics", n0, len(df))

    df["hour"] = df["timestamp"].dt.hour
    df["day"] = df["timestamp"].dt.date
    df["dow"] = df["timestamp"].dt.dayofweek
    df["is_weekend"] = (df["dow"] >= 5).astype(int)
    df["is_out_of_hours"] = ((df["hour"] < 6) | (df["hour"] >= 18)).astype(int)
    df["is_failure"] = (df["result"] == "failure").astype(int)
    df["is_external_src"] = (~df["src_ip"].astype(str).str.startswith("10.")).astype(int)
    df["is_foreign_country"] = (df["src_country"].fillna("NAM") != "NAM").astype(int)
    df["gt_scenario"] = df["gt_scenario"].fillna("")
    log_action("access_log", "feature_engineering",
               "hour, dow, is_weekend, is_out_of_hours, is_failure, is_external_src, is_foreign_country",
               "these are the behavioural dimensions used for the user baseline in step 7",
               len(df), len(df))

    df.to_parquet(DATA_PROCESSED / "access_events.parquet", index=False)

    # per-user per-day behaviour profile - the unit of analysis for UEBA
    g = df.groupby(["username", "day"], observed=True)
    user_day = g.agg(
        events=("event_id", "count"),
        logins=("event_type", lambda s: int((s == "LOGIN_SUCCESS").sum())),
        failures=("event_type", lambda s: int((s == "LOGIN_FAILURE").sum())),
        resource_access=("event_type", lambda s: int((s == "RESOURCE_ACCESS").sum())),
        priv_actions=("privileged_action", "sum"),
        distinct_ips=("src_ip", "nunique"),
        distinct_countries=("src_country", "nunique"),
        distinct_targets=("target_system", "nunique"),
        out_of_hours=("is_out_of_hours", "sum"),
        weekend=("is_weekend", "max"),
        foreign=("is_foreign_country", "sum"),
        external=("is_external_src", "sum"),
        bytes_out=("bytes_out", "sum"),
        mfa_absent=("mfa_used", lambda s: int((~s.astype(bool)).sum())),
        gt=("gt_scenario", lambda s: "|".join(sorted({x for x in s if x}))),
    ).reset_index()
    user_day["failure_ratio"] = user_day["failures"] / user_day["events"].clip(lower=1)
    user_day["role"] = user_day["username"].map(
        df.drop_duplicates("username").set_index("username")["user_role"])
    user_day["employment_type"] = user_day["username"].map(
        df.drop_duplicates("username").set_index("username")["employment_type"])
    user_day.to_parquet(DATA_PROCESSED / "access_user_day.parquet", index=False)
    log_action("access_user_day", "aggregate", f"{len(user_day)} user-day rows",
               "behaviour analytics compares a user against their own daily history", len(df), len(user_day))
    LOG.info("access events=%d user-days=%d", len(df), len(user_day))
    return df, user_day


# --------------------------------------------------------------------------------------
# 4. IP -> asset crosswalk, derived from the data itself
# --------------------------------------------------------------------------------------
def build_crosswalk(flows: pd.DataFrame) -> pd.DataFrame:
    """
    The ToN_IoT capture uses 192.168.1.x addresses with no asset names. Rather than
    inventing an asset map, each address is profiled from its own observed behaviour
    (flow counts, attack share, services, ports) and given a provisional role. The mapping
    to a mining asset archetype is an explicit ASSUMPTION and is labelled as such.
    """
    src = flows.groupby("src_ip").agg(
        flows_out=("label", "size"),
        attack_share_out=("label", "mean"),
        distinct_dst=("dst_ip", "nunique"),
        distinct_dports=("dst_port", "nunique"),
        top_service=("service", lambda s: s.dropna().mode().iloc[0] if s.dropna().any() else "unknown"),
    )
    dst = flows.groupby("dst_ip").agg(
        flows_in=("label", "size"),
        attack_share_in=("label", "mean"),
        distinct_src=("src_ip", "nunique"),
    )
    x = src.join(dst, how="outer").fillna(0).reset_index(names="ip")
    x["is_internal"] = x["ip"].astype(str).str.startswith("192.168.").astype(int)

    def role(r):
        if not r.is_internal:
            return "external_endpoint"
        if r.distinct_dports > 200 or (r.distinct_dst > 5 and r.attack_share_out > 0.9):
            return "high_fanout_source (scanner-like)"
        if r.flows_in > 5000 and r.distinct_src > 3:
            return "service_host (many inbound clients)"
        if r.flows_out > 1000:
            return "talkative_endpoint"
        return "low_volume_endpoint"

    x["observed_role"] = x.apply(role, axis=1)
    archetype = {
        "high_fanout_source (scanner-like)": "compromised engineering laptop / attacker foothold",
        "service_host (many inbound clients)": "site telemetry broker or historian",
        "talkative_endpoint": "IIoT gateway or field sensor cluster",
        "low_volume_endpoint": "occasional field device",
        "external_endpoint": "internet endpoint outside the mine network",
    }
    x["mining_archetype_ASSUMED"] = x["observed_role"].map(archetype)
    x = x.sort_values("flows_out", ascending=False)
    x.to_csv(DATA_PROCESSED / "ip_asset_crosswalk.csv", index=False)
    log_action("network_flow", "derive_ip_profile", f"{len(x)} addresses profiled",
               "ToN_IoT provides no asset names; roles are inferred from observed behaviour and "
               "the mining archetype column is explicitly an assumption", len(flows), len(x))
    return x


def main() -> None:
    tel = clean_telemetry()
    flows = clean_network()
    acc, user_day = clean_access()
    cross = build_crosswalk(flows)

    log = pd.DataFrame(CLEAN_LOG)
    log.to_csv(OUT_TABLES / "cleaning_log.csv", index=False)
    write_json({
        "telemetry_measurement_rows": int(len(tel)),
        "network_flow_rows": int(len(flows)),
        "access_events": int(len(acc)),
        "user_days": int(len(user_day)),
        "ip_profiles": int(len(cross)),
        "cleaning_actions": int(len(log)),
        "env": env_stamp(),
    }, OUT_TABLES / "cleaning_summary.json")
    LOG.info("cleaning log entries: %d -> outputs/tables/cleaning_log.csv", len(log))


if __name__ == "__main__":
    main()
