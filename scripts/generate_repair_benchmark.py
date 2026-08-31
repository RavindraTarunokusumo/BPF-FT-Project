#!/usr/bin/env python3
"""
Master benchmark generator script for the 120-Task Private Repair Benchmark Dataset.

Generates:
- 120 repair task directories under data/benchmark/repair/<category>/<difficulty>/<task_id>/
- 5 canonical files per task:
    1. task.json
    2. faulty.c
    3. diagnostic.txt
    4. tests.json
    5. solution.c
- data/benchmark/repair/index.jsonl (complete index with SHA-256 hashes and metadata)
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List

# Ensure scripts directory is in path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from repair_bench.common import RepairTaskSpec, compute_sha256_str
from repair_bench.tasks_filtering import get_filtering_tasks
from repair_bench.tasks_telemetry import get_telemetry_tasks
from repair_bench.tasks_transform import get_transform_tasks
from repair_bench.tasks_routing import get_routing_tasks


def compute_file_sha256(file_path: Path) -> str:
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def main():
    root_dir = Path(__file__).resolve().parent.parent
    bench_dir = root_dir / "data" / "benchmark" / "repair"
    bench_dir.mkdir(parents=True, exist_ok=True)

    print(f"[*] Gathering repair benchmark tasks...")
    all_tasks: List[RepairTaskSpec] = []
    all_tasks.extend(get_filtering_tasks())
    all_tasks.extend(get_telemetry_tasks())
    all_tasks.extend(get_transform_tasks())
    all_tasks.extend(get_routing_tasks())

    total_tasks = len(all_tasks)
    print(f"[*] Total task specifications loaded: {total_tasks}")

    # Integrity verification
    assert total_tasks == 120, f"Expected exactly 120 tasks, got {total_tasks}"

    cat_counts: Dict[str, int] = {}
    diff_counts: Dict[str, int] = {}
    diag_counts: Dict[str, int] = {}
    task_ids = set()

    for t in all_tasks:
        if t.task_id in task_ids:
            raise ValueError(f"Duplicate task_id detected: {t.task_id}")
        task_ids.add(t.task_id)

        cat_counts[t.application_category] = cat_counts.get(t.application_category, 0) + 1
        diff_counts[t.difficulty] = diff_counts.get(t.difficulty, 0) + 1
        diag_counts[t.diagnostic_category] = diag_counts.get(t.diagnostic_category, 0) + 1

    print("\n--- Benchmark Task Distribution Verification ---")
    print(f"Categories ({len(cat_counts)}): {cat_counts}")
    print(f"Difficulties ({len(diff_counts)}): {diff_counts}")
    print(f"Diagnostic Categories ({len(diag_counts)}): {diag_counts}")

    assert diag_counts.get("compilation_error", 0) == 50, f"Expected 50 compilation errors, got {diag_counts.get('compilation_error')}"
    assert diag_counts.get("verifier_rejection", 0) == 45, f"Expected 45 verifier rejections, got {diag_counts.get('verifier_rejection')}"
    assert diag_counts.get("behavioral_logic_bug", 0) == 25, f"Expected 25 behavioral bugs, got {diag_counts.get('behavioral_logic_bug')}"

    for cat in ["packet_filtering_security", "packet_inspection_telemetry", "protocol_transformation", "network_routing_forwarding"]:
        assert cat_counts.get(cat, 0) == 30, f"Expected 30 tasks for {cat}, got {cat_counts.get(cat)}"

    index_entries: List[Dict[str, Any]] = []

    print(f"\n[*] Generating dataset files under {bench_dir}...")
    for idx, t in enumerate(all_tasks, start=1):
        task_dir = bench_dir / t.application_category / t.difficulty / t.task_id
        task_dir.mkdir(parents=True, exist_ok=True)

        # 1. task.json
        task_json_data = {
            "schema_version": 1,
            "task_id": t.task_id,
            "application_category": t.application_category,
            "difficulty": t.difficulty,
            "task_family": t.task_family,
            "template_family": t.template_family,
            "semantic_signature": t.semantic_signature,
            "learning_mode": "repair",
            "program_contract": {
                "program_type": "xdp",
                "section": "xdp",
                "max_source_bytes": 262144,
            },
            "instruction": t.instruction,
            "requirements": t.requirements,
            "diagnostic_category": t.diagnostic_category,
            "failure_reason": t.failure_reason,
            "tests": t.test_cases,
        }
        task_json_path = task_dir / "task.json"
        with open(task_json_path, "w", encoding="utf-8", newline="\n") as f:
            json.dump(task_json_data, f, indent=2)

        # 2. faulty.c
        faulty_c_path = task_dir / "faulty.c"
        with open(faulty_c_path, "w", encoding="utf-8", newline="\n") as f:
            f.write(t.faulty_c)

        # 3. diagnostic.txt
        diag_path = task_dir / "diagnostic.txt"
        with open(diag_path, "w", encoding="utf-8", newline="\n") as f:
            f.write(t.diagnostic_txt)

        # 4. tests.json
        tests_json_data = {
            "schema_version": 1,
            "task_id": t.task_id,
            "test_count": len(t.test_cases),
            "validator": {
                "type": t.validator_type,
            },
            "tests": t.test_cases,
        }
        tests_json_path = task_dir / "tests.json"
        with open(tests_json_path, "w", encoding="utf-8", newline="\n") as f:
            json.dump(tests_json_data, f, indent=2)

        # 5. solution.c
        sol_c_path = task_dir / "solution.c"
        with open(sol_c_path, "w", encoding="utf-8", newline="\n") as f:
            f.write(t.solution_c)

        # Compute hashes
        task_json_sha256 = compute_file_sha256(task_json_path)
        faulty_c_sha256 = compute_file_sha256(faulty_c_path)
        diagnostic_sha256 = compute_file_sha256(diag_path)
        tests_json_sha256 = compute_file_sha256(tests_json_path)
        solution_c_sha256 = compute_file_sha256(sol_c_path)

        rel_path = f"{t.application_category}/{t.difficulty}/{t.task_id}"

        index_entry = {
            "task_id": t.task_id,
            "relative_path": rel_path,
            "application_category": t.application_category,
            "difficulty": t.difficulty,
            "diagnostic_category": t.diagnostic_category,
            "task_family": t.task_family,
            "template_family": t.template_family,
            "semantic_signature": t.semantic_signature,
            "test_count": len(t.test_cases),
            "validator_type": t.validator_type,
            "sha256": {
                "task.json": task_json_sha256,
                "faulty.c": faulty_c_sha256,
                "diagnostic.txt": diagnostic_sha256,
                "tests.json": tests_json_sha256,
                "solution.c": solution_c_sha256,
            },
        }
        index_entries.append(index_entry)

    # Write index.jsonl
    index_path = bench_dir / "index.jsonl"
    print(f"[*] Writing {index_path}...")
    with open(index_path, "w", encoding="utf-8", newline="\n") as f:
        for entry in index_entries:
            f.write(json.dumps(entry) + "\n")

    print(f"\n[+] Successfully generated 120 repair benchmark tasks and index.jsonl ({len(index_entries)} tasks indexed).")


if __name__ == "__main__":
    main()
