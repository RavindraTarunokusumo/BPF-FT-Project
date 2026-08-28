#!/usr/bin/env python3
"""
Detailed failure breakdown across all categories and levels.
"""

from __future__ import annotations

import json
from pathlib import Path
from collections import Counter

PROJECT_ROOT = Path(__file__).resolve().parent.parent
VAL_DIR = PROJECT_ROOT / "data" / "validation"

failures_by_cat_lvl = Counter()
pass_by_cat_lvl = Counter()
failure_examples = {}

for val_file in VAL_DIR.rglob("*.json"):
    if not val_file.is_file():
        continue
    try:
        data = json.loads(val_file.read_text(encoding="utf-8"))
    except Exception:
        continue
    
    cand_id = data.get("candidate_id", "")
    # Only check new corpus (pfs, nrf, pit, ptr)
    if not (cand_id.startswith("pfs_") or cand_id.startswith("nrf_") or cand_id.startswith("pit_") or cand_id.startswith("ptr_")):
        continue
        
    cat = data.get("application_category", "")
    lvl = data.get("difficulty", "")
    is_pass = data.get("passed", False)
    
    # We care about whether the gold or r01 candidate passed
    if is_pass:
        pass_by_cat_lvl[(cat, lvl, "pass")] += 1
    else:
        failures_by_cat_lvl[(cat, lvl, "fail")] += 1
        key = (cat, lvl)
        if key not in failure_examples and ("r01" in cand_id or "c00" in cand_id):
            failure_examples[key] = (cand_id, data.get("diagnostic", "")[:200])

print("=" * 70)
print("VALIDATION STATUS BY CATEGORY & LEVEL:")
print("=" * 70)
for cat in ["packet_filtering_security", "network_routing_forwarding", "packet_inspection_telemetry", "protocol_transformation"]:
    for lvl in ["level_1", "level_2", "level_3"]:
        p = pass_by_cat_lvl[(cat, lvl, "pass")]
        f = failures_by_cat_lvl[(cat, lvl, "fail")]
        print(f"{cat:30s} | {lvl:8s} -> Passed: {p:3d} | Failed: {f:3d}")
        if (cat, lvl) in failure_examples:
            cid, diag = failure_examples[(cat, lvl)]
            print(f"   [Example fail in {lvl}]: {cid} -> {diag}")
print("=" * 70)
