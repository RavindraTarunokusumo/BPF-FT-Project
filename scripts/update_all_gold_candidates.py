#!/usr/bin/env python3
"""
Automatically scans data/validation/ and sets gold_candidate_id in every task.json
across all batches based on passing candidate records.
"""

from __future__ import annotations

import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
INBOX_DIR = PROJECT_ROOT / "data" / "inbox"
VAL_DIR = PROJECT_ROOT / "data" / "validation"


def main() -> None:
    total_tasks = 0
    updated_tasks = 0

    for batch_dir in sorted(INBOX_DIR.iterdir()):
        if not batch_dir.is_dir() or not batch_dir.name.startswith("batch-"):
            continue

        batch_id = batch_dir.name
        val_batch_dir = VAL_DIR / batch_id

        for task_dir in sorted(batch_dir.iterdir()):
            if not task_dir.is_dir():
                continue

            task_id = task_dir.name
            task_json_file = task_dir / "task.json"
            if not task_json_file.exists():
                continue

            total_tasks += 1
            task_data = json.loads(task_json_file.read_text(encoding="utf-8"))

            # Find latest passing candidate
            # Candidates can be c00, c00_r01, c00_r02, etc.
            gold_cand_id = None
            for cand_file in sorted(task_dir.glob("c*.c"), reverse=True):
                cand_stem = cand_file.stem.replace("-", "_")
                cand_id = f"{task_id}_{cand_stem}"
                val_file = val_batch_dir / f"{cand_id}.json"
                if val_file.exists():
                    try:
                        val_data = json.loads(val_file.read_text(encoding="utf-8"))
                        if val_data.get("passed"):
                            gold_cand_id = cand_id
                            break
                    except Exception:
                        pass

            if gold_cand_id:
                task_data["gold_candidate_id"] = gold_cand_id
                task_json_file.write_text(json.dumps(task_data, indent=2), encoding="utf-8")
                updated_tasks += 1
                print(f"[+] {batch_id}/{task_id} -> gold: {gold_cand_id}")
            else:
                print(f"[-] WARNING: No passing candidate for {batch_id}/{task_id}")

    print(f"\nUpdated {updated_tasks}/{total_tasks} tasks with gold candidate IDs.")


if __name__ == "__main__":
    main()
