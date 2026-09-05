"""
Master Generator for BPF-Guardian RLVR Phase 2 Task Pool.
Generates 264 tasks across 4 categories and 3 difficulty levels:
- Canary:       12 tasks (1 per category x difficulty cell)
- Train:       144 tasks (12 per category x difficulty cell)
- Dev:          48 tasks (4 per category x difficulty cell)
- Confirmation: 60 tasks (5 per category x difficulty cell)
Total:         264 tasks

Features:
- Task-family disjointness between Train, Dev, Confirmation, Canary, and Protected sets
- Complete, verifier-safe C reference implementations in solution.c
- Realistic packet fixtures covering positive, negative, boundary, and truncated cases
- BPF_MAP_TYPE_LPM_TRIE with correct 4-byte prefixlen key struct
- BPF_MAP_TYPE_HASH, LRU_HASH, ARRAY, and bpf_xdp_adjust_head header manipulation
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any, Dict, List

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts.rl_task_gen.tasks_pfs import build_pfs_l1_tasks, build_pfs_l2_tasks, build_pfs_l3_tasks
from scripts.rl_task_gen.tasks_nrf import build_nrf_l1_tasks, build_nrf_l2_tasks, build_nrf_l3_tasks
from scripts.rl_task_gen.tasks_pit import build_pit_l1_tasks, build_pit_l2_tasks, build_pit_l3_tasks
from scripts.rl_task_gen.tasks_ptr import build_ptr_l1_tasks, build_ptr_l2_tasks, build_ptr_l3_tasks


def sha256_str(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def write_task_files(
    output_base: Path,
    task: Dict[str, Any],
) -> Dict[str, Any]:
    """Writes task.json, tests.json, and solution.c to output directory."""
    split = task["split"]
    cat = task["application_category"]
    diff = task["difficulty"]
    tid = task["task_id"]

    task_dir = output_base / split / cat / diff / tid
    task_dir.mkdir(parents=True, exist_ok=True)

    solution_c = task.pop("solution_c")
    tests = task.get("tests", [])
    task["expected_fixture_count"] = len(tests)

    # Compute task_sha256
    core_manifest = {
        "task_id": tid,
        "application_category": cat,
        "difficulty": diff,
        "task_family": task.get("task_family", ""),
        "instruction": task.get("instruction", ""),
        "requirements": task.get("requirements", []),
        "expected_fixture_count": len(tests),
    }
    task["task_sha256"] = sha256_str(json.dumps(core_manifest, sort_keys=True))

    # Write files
    (task_dir / "task.json").write_text(json.dumps(task, indent=2), encoding="utf-8")
    (task_dir / "tests.json").write_text(json.dumps({"task_id": tid, "tests": tests}, indent=2), encoding="utf-8")
    (task_dir / "solution.c").write_text(solution_c, encoding="utf-8")

    # Return index summary entry
    return {
        "task_id": tid,
        "application_category": cat,
        "difficulty": diff,
        "task_family": task.get("task_family", ""),
        "template_family": task.get("template_family", ""),
        "semantic_signature": task.get("semantic_signature", ""),
        "expected_fixture_count": len(tests),
        "task_sha256": task["task_sha256"],
        "relative_path": f"{cat}/{diff}/{tid}",
    }


def main():
    output_base = PROJECT_ROOT / "data" / "rl" / "v2"
    if output_base.exists():
        shutil.rmtree(output_base)
    output_base.mkdir(parents=True, exist_ok=True)

    print("Generating BPF RLVR Phase 2 task pool...")

    all_tasks: List[Dict[str, Any]] = []
    # PFS (66)
    all_tasks.extend(build_pfs_l1_tasks())
    all_tasks.extend(build_pfs_l2_tasks())
    all_tasks.extend(build_pfs_l3_tasks())

    # NRF (66)
    all_tasks.extend(build_nrf_l1_tasks())
    all_tasks.extend(build_nrf_l2_tasks())
    all_tasks.extend(build_nrf_l3_tasks())

    # PIT (66)
    all_tasks.extend(build_pit_l1_tasks())
    all_tasks.extend(build_pit_l2_tasks())
    all_tasks.extend(build_pit_l3_tasks())

    # PTR (66)
    all_tasks.extend(build_ptr_l1_tasks())
    all_tasks.extend(build_ptr_l2_tasks())
    all_tasks.extend(build_ptr_l3_tasks())

    print(f"Total tasks generated in memory: {len(all_tasks)}")

    # Split trackers
    split_indices: Dict[str, List[Dict[str, Any]]] = {
        "canary": [],
        "train": [],
        "dev": [],
        "confirmation": [],
    }

    for task in all_tasks:
        split = task["split"]
        index_entry = write_task_files(output_base, task)
        split_indices[split].append(index_entry)

    # Write per-split index.jsonl and manifest.json
    total_written = 0
    split_manifests = {}
    for split, entries in split_indices.items():
        split_dir = output_base / split
        index_path = split_dir / "index.jsonl"
        with open(index_path, "w", encoding="utf-8") as f:
            for e in entries:
                f.write(json.dumps(e) + "\n")

        manifest = {
            "split": split,
            "task_count": len(entries),
            "categories": sorted(list({e["application_category"] for e in entries})),
            "difficulties": sorted(list({e["difficulty"] for e in entries})),
            "tasks": entries,
        }
        manifest_path = split_dir / "manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

        split_manifests[split] = {
            "task_count": len(entries),
            "manifest_sha256": sha256_str(manifest_path.read_text(encoding="utf-8")),
            "index_sha256": sha256_str(index_path.read_text(encoding="utf-8")),
        }
        total_written += len(entries)
        print(f"Split '{split}': {len(entries)} tasks written to {split_dir}")

    # Write aggregate task pool manifest
    pool_manifest = {
        "version": "rl_v2",
        "total_tasks": total_written,
        "splits": split_manifests,
    }
    pool_manifest_path = output_base / "task_pool_manifest.json"
    pool_manifest_path.write_text(json.dumps(pool_manifest, indent=2), encoding="utf-8")
    print(f"Aggregate manifest written to {pool_manifest_path}")
    print("RL v2 dataset generation complete!")


if __name__ == "__main__":
    main()
