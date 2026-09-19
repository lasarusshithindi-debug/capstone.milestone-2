"""
Stage 01 - Extract unstructured security text from the MITRE ATT&CK for ICS knowledge base.

Why: capstone requirement C8 needs at least 200 unstructured security-text records.
The ATT&CK for ICS bundle is real, public, citable text written by security analysts and
is directly relevant to a mining OT/IIoT environment (techniques, mitigations, malware,
groups, campaigns, assets).

What this script does, in plain English:
  1. reads the STIX bundle that was cloned from github.com/mitre-attack/attack-stix-data
  2. keeps every object that has a human-written description
  3. writes one flat CSV (one row = one text record) plus a provenance JSON
It does not alter the original bundle.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import DATA_RAW, OUT_TABLES, env_stamp, git_commit, sha256, write_json, get_logger

LOG = get_logger("s01_attack_text")

# the bundle is kept as a single file so the 1.5 GB source repository does not have to be
# retained; the clone command is documented in the README
BUNDLE_CANDIDATES = [DATA_RAW / "attack_bundle" / "ics-attack.json",
                     DATA_RAW / "attack" / "ics-attack" / "ics-attack.json"]
BUNDLE = next((b for b in BUNDLE_CANDIDATES if b.exists()), BUNDLE_CANDIDATES[0])
OUT_CSV = DATA_RAW / "attack_ics_text.csv"

KEEP_TYPES = {
    "attack-pattern": "technique",
    "course-of-action": "mitigation",
    "malware": "malware",
    "tool": "tool",
    "intrusion-set": "threat_group",
    "campaign": "campaign",
    "x-mitre-asset": "asset",
    "x-mitre-data-source": "data_source",
    "x-mitre-data-component": "data_component",
    "x-mitre-detection-strategy": "detection_strategy",
    "x-mitre-analytic": "analytic",
    "x-mitre-tactic": "tactic",
}


def external_id(obj: dict) -> str:
    for ref in obj.get("external_references", []):
        if ref.get("source_name", "").startswith("mitre"):
            return ref.get("external_id", "")
    return ""


def main() -> None:
    if not BUNDLE.exists():
        raise SystemExit(f"ATT&CK bundle not found at {BUNDLE}")

    bundle = json.loads(BUNDLE.read_text(encoding="utf-8"))
    rows = []
    for obj in bundle["objects"]:
        otype = obj.get("type")
        if otype not in KEEP_TYPES:
            continue
        desc = (obj.get("description") or "").strip()
        if len(desc) < 40:            # skip stubs - they are not usable text records
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        rows.append(
            {
                "record_id": external_id(obj) or obj["id"][:18],
                "stix_id": obj["id"],
                "record_class": KEEP_TYPES[otype],
                "name": obj.get("name", ""),
                "text": desc,
                "platforms": "|".join(obj.get("x_mitre_platforms", []) or []),
                "created": obj.get("created", ""),
                "modified": obj.get("modified", ""),
                "n_chars": len(desc),
                "n_words": len(desc.split()),
                "source": "MITRE ATT&CK for ICS (STIX bundle)",
            }
        )

    df = pd.DataFrame(rows).drop_duplicates(subset=["stix_id"]).reset_index(drop=True)
    df.to_csv(OUT_CSV, index=False)

    prov = {
        "output": str(OUT_CSV.relative_to(DATA_RAW.parent.parent)),
        "records": int(len(df)),
        "by_class": df["record_class"].value_counts().to_dict(),
        "total_words": int(df["n_words"].sum()),
        "bundle_path": str(BUNDLE),
        "bundle_sha256": sha256(BUNDLE),
        "repo": "https://github.com/mitre-attack/attack-stix-data",
        "repo_commit": (DATA_RAW / "attack_bundle" / "SOURCE_COMMIT.txt").read_text().strip()
                       if (DATA_RAW / "attack_bundle" / "SOURCE_COMMIT.txt").exists()
                       else git_commit(DATA_RAW / "attack"),
        "licence": "MITRE ATT&CK - Terms of Use (free to use with attribution)",
        "env": env_stamp(),
    }
    write_json(prov, OUT_TABLES / "provenance_attack_ics_text.json")
    LOG.info("wrote %s rows to %s", len(df), OUT_CSV)
    LOG.info("class counts: %s", prov["by_class"])


if __name__ == "__main__":
    main()
