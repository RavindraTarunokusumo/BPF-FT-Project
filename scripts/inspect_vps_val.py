#!/usr/bin/env python3
"""
Inspects VPS validation records and diagnostics.
"""

from __future__ import annotations

import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
VAL_DIR = PROJECT_ROOT / "data" / "validation"

total_records = 0
passed = 0
failed = 0
failed_r01 = []
failed_c00_no_r01 = []

for val_file in VAL_DIR.rglob("*.json"):
    if not val_file.is_file():
        continue
    total_records += 1
    try:
        data = json.loads(val_file.read_text(encoding="utf-8"))
    except Exception:
        continue
    cand_id = data.get("candidate_id", "")
    is_pass = data.get("passed", False)
    if is_pass:
        passed += 1
    else:
        failed += 1
        if "r01" in cand_id:
            failed_r01.append((cand_id, data.get("diagnostic", "")[:120]))
        else:
            task_id = data.get("task_id", "")
            cat = data.get("application_category", "")
            lvl = data.get("difficulty", "")
            t_dir = PROJECT_ROOT / "data" / "inbox" / cat / lvl / task_id
            if not (t_dir / "c00-r01.c").exists():
                failed_c00_no_r01.append((cand_id, data.get("diagnostic", "")[:120]))

print(f"Total validation records: {total_records}")
print(f"Total passed candidates: {passed}")
print(f"Total failed candidates: {failed}")
print(f"Failed r01 repair candidates: {len(failed_r01)}")
for cid, diag in failed_r01[:10]:
    print(f"  [r01 fail] {cid}: {diag}")

print(f"Failed clean c00 candidates without r01: {len(failed_c00_no_r01)}")
for cid, diag in failed_c00_no_r01[:10]:
    print(f"  [c00 clean fail] {cid}: {diag}")
