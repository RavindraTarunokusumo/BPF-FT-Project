#!/usr/bin/env python3
"""
BPF-Guardian Metadata Normalizer
Ensures all existing tasks in data/inbox satisfy the complete JSON schema:
1. Adds harness_type (if missing) derived from template_family or application_category.
2. Updates source_sha256 in all *.meta.json files to match the exact source file hash.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
INBOX_DIR = PROJECT_ROOT / "data" / "inbox"


def get_default_harness(task_data: dict) -> str:
    fam = task_data.get("template_family", "")
    cat = task_data.get("application_category", "")
    if "rewrite" in fam or "transform" in cat:
        return "xdp_l2_rewrite"
    if "map" in fam or "counter" in fam or "telemetry" in cat:
        return "xdp_hash_map_telemetry"
    if "routing" in cat:
        return "xdp_routing_forwarding"
    return "xdp_stateless_filter"


def main() -> None:
    print("=== Normalizing Inbox Metadata & Schemas ===")
    updated_tasks = 0
    updated_metas = 0

    for cat_dir in INBOX_DIR.iterdir():
        if not cat_dir.is_dir():
            continue
        for lvl_dir in cat_dir.iterdir():
            if not lvl_dir.is_dir():
                continue
            for task_dir in lvl_dir.iterdir():
                if not task_dir.is_dir():
                    continue

                # 1. Normalize task.json
                task_file = task_dir / "task.json"
                if task_file.exists():
                    try:
                        task_data = json.loads(task_file.read_text(encoding="utf-8"))
                        changed = False
                        if "harness_type" not in task_data:
                            task_data["harness_type"] = get_default_harness(task_data)
                            changed = True
                        if "semantic_signature" not in task_data:
                            task_data["semantic_signature"] = f"{task_data.get('application_category', 'sec')}+{task_data.get('task_id', 'task')}"
                            changed = True
                        if changed:
                            task_file.write_text(json.dumps(task_data, indent=2), encoding="utf-8")
                            updated_tasks += 1
                    except Exception as e:
                        print(f"[-] Error reading {task_file}: {e}")

                # 2. Normalize *.meta.json
                for meta_file in task_dir.glob("*.meta.json"):
                    try:
                        meta_data = json.loads(meta_file.read_text(encoding="utf-8"))
                        src_name = meta_data.get("source_path", meta_file.name.replace(".meta.json", ".c"))
                        src_file = task_dir / src_name
                        if src_file.exists():
                            actual_sha = hashlib.sha256(src_file.read_bytes()).hexdigest()
                            if meta_data.get("source_sha256") != actual_sha:
                                meta_data["source_sha256"] = actual_sha
                                meta_file.write_text(json.dumps(meta_data, indent=2), encoding="utf-8")
                                updated_metas += 1
                    except Exception as e:
                        print(f"[-] Error reading {meta_file}: {e}")

    print(f"[+] Updated {updated_tasks} task.json files")
    print(f"[+] Updated {updated_metas} *.meta.json SHA256 hashes")


if __name__ == "__main__":
    main()
