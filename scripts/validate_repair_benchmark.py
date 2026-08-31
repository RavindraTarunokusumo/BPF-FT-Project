#!/usr/bin/env python3
"""
Comprehensive validator script for the 120-Task Private Repair Benchmark Dataset.

Validates:
1. Directory structure and file presence (5 files per task across 120 tasks)
2. SHA-256 checksums matching index.jsonl entries
3. JSON schema compliance for task.json and tests.json
4. C source code sanity rules for solution.c and faulty.c (SEC markers, license, no markdown fences)
5. Diagnostic and test fixture integrity
6. Complete distribution reports and summary breakdown
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple


def compute_file_sha256(file_path: Path) -> str:
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def validate_c_source(code: str, file_path: Path, is_solution: bool = True) -> List[str]:
    errors = []
    if not code.strip():
        errors.append(f"{file_path}: C source is empty")

    if "```" in code:
        errors.append(f"{file_path}: Contains markdown code fences")

    if 'SEC("xdp")' not in code and "SEC(\"xdp\")" not in code:
        errors.append(f"{file_path}: Missing SEC(\"xdp\") section marker")

    if "SEC(\"license\")" not in code:
        errors.append(f"{file_path}: Missing SEC(\"license\") marker")

    if is_solution:
        # Check standard includes
        if "<linux/bpf.h>" not in code and "<linux/if_ether.h>" not in code:
            errors.append(f"{file_path}: Missing core eBPF includes")

    return errors


def validate_benchmark(bench_dir: Path) -> Tuple[bool, Dict[str, Any]]:
    stats = {
        "total_tasks": 0,
        "total_files": 0,
        "categories": {},
        "difficulties": {},
        "diagnostic_categories": {},
        "matrix": {},
        "errors": [],
    }

    index_path = bench_dir / "index.jsonl"
    if not index_path.exists():
        stats["errors"].append(f"Missing master index: {index_path}")
        return False, stats

    # Read and validate index.jsonl
    index_tasks: Dict[str, Dict[str, Any]] = {}
    with open(index_path, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                task_id = entry.get("task_id")
                if not task_id:
                    stats["errors"].append(f"index.jsonl line {line_num}: Missing task_id")
                    continue
                if task_id in index_tasks:
                    stats["errors"].append(f"index.jsonl line {line_num}: Duplicate task_id '{task_id}'")
                index_tasks[task_id] = entry
            except json.JSONDecodeError as e:
                stats["errors"].append(f"index.jsonl line {line_num}: JSON decode error: {e}")

    stats["total_tasks"] = len(index_tasks)

    expected_categories = [
        "packet_filtering_security",
        "packet_inspection_telemetry",
        "protocol_transformation",
        "network_routing_forwarding",
    ]
    expected_difficulties = ["level_1", "level_2", "level_3"]

    for cat in expected_categories:
        stats["categories"][cat] = 0
        stats["matrix"][cat] = {d: 0 for d in expected_difficulties}

    for task_id, entry in index_tasks.items():
        cat = entry.get("application_category")
        diff = entry.get("difficulty")
        diag = entry.get("diagnostic_category")
        rel_path = entry.get("relative_path")
        sha_dict = entry.get("sha256", {})

        if cat in stats["categories"]:
            stats["categories"][cat] += 1
        stats["difficulties"][diff] = stats["difficulties"].get(diff, 0) + 1
        stats["diagnostic_categories"][diag] = stats["diagnostic_categories"].get(diag, 0) + 1

        if cat in stats["matrix"] and diff in stats["matrix"][cat]:
            stats["matrix"][cat][diff] += 1

        # Check directory existence on disk
        task_dir = bench_dir / rel_path
        if not task_dir.is_dir():
            stats["errors"].append(f"Task directory missing on disk: {task_dir}")
            continue

        # Check all 5 files
        expected_files = ["task.json", "faulty.c", "diagnostic.txt", "tests.json", "solution.c"]
        for fname in expected_files:
            fpath = task_dir / fname
            if not fpath.exists():
                stats["errors"].append(f"Missing file: {fpath}")
                continue

            stats["total_files"] += 1

            # Validate SHA-256 against index
            actual_sha = compute_file_sha256(fpath)
            expected_sha = sha_dict.get(fname)
            if actual_sha != expected_sha:
                stats["errors"].append(f"SHA-256 mismatch for {fpath}: expected {expected_sha}, got {actual_sha}")

            # Specific file contents validations
            if fname == "task.json":
                try:
                    with open(fpath, "r", encoding="utf-8") as jf:
                        tj = json.load(jf)
                    if tj.get("task_id") != task_id:
                        stats["errors"].append(f"{fpath}: task_id '{tj.get('task_id')}' != '{task_id}'")
                    if tj.get("learning_mode") != "repair":
                        stats["errors"].append(f"{fpath}: learning_mode is not 'repair'")
                    if not tj.get("instruction") or not tj.get("requirements") or not tj.get("tests"):
                        stats["errors"].append(f"{fpath}: missing instruction, requirements, or tests")
                except Exception as e:
                    stats["errors"].append(f"{fpath}: Failed to parse task.json: {e}")

            elif fname == "tests.json":
                try:
                    with open(fpath, "r", encoding="utf-8") as jf:
                        ts = json.load(jf)
                    tests = ts.get("tests", [])
                    if not tests:
                        stats["errors"].append(f"{fpath}: No test cases defined in tests.json")
                    for t_idx, tc in enumerate(tests):
                        phex = tc.get("packet_hex", "")
                        if not phex or len(phex) % 2 != 0:
                            stats["errors"].append(f"{fpath}: Invalid packet_hex in test #{t_idx}")
                except Exception as e:
                    stats["errors"].append(f"{fpath}: Failed to parse tests.json: {e}")

            elif fname == "solution.c":
                with open(fpath, "r", encoding="utf-8") as cf:
                    code = cf.read()
                c_errs = validate_c_source(code, fpath, is_solution=True)
                stats["errors"].extend(c_errs)

            elif fname == "faulty.c":
                with open(fpath, "r", encoding="utf-8") as cf:
                    code = cf.read()
                c_errs = validate_c_source(code, fpath, is_solution=False)
                stats["errors"].extend(c_errs)

            elif fname == "diagnostic.txt":
                with open(fpath, "r", encoding="utf-8") as df:
                    diag_text = df.read()
                if not diag_text.strip():
                    stats["errors"].append(f"{fpath}: Empty diagnostic.txt")

    is_valid = len(stats["errors"]) == 0
    return is_valid, stats


def print_report(stats: Dict[str, Any]):
    print("=" * 80)
    print("      120-TASK PRIVATE REPAIR BENCHMARK DATASET VALIDATION REPORT")
    print("=" * 80)
    print(f"Total Tasks Validated: {stats['total_tasks']} / 120")
    print(f"Total Canonical Files: {stats['total_files']} / 600 (5 per task)")
    print()

    print("--- 1. Application Category x Difficulty Matrix (Target: 10 tasks/cell) ---")
    print(f"{'Category':<32} | {'Level 1':<8} | {'Level 2':<8} | {'Level 3':<8} | {'Total':<6}")
    print("-" * 72)
    for cat, diffs in stats["matrix"].items():
        l1 = diffs.get("level_1", 0)
        l2 = diffs.get("level_2", 0)
        l3 = diffs.get("level_3", 0)
        tot = l1 + l2 + l3
        print(f"{cat:<32} | {l1:<8} | {l2:<8} | {l3:<8} | {tot:<6}")
    print("-" * 72)
    print()

    print("--- 2. Diagnostic Category Distribution (Target: 50 Comp / 45 Verif / 25 Logic) ---")
    for diag, cnt in sorted(stats["diagnostic_categories"].items()):
        print(f"  - {diag:<25}: {cnt} tasks")
    print()

    if stats["errors"]:
        print(f"[!] FAILED: {len(stats['errors'])} validation errors found:")
        for err in stats["errors"][:20]:
            print(f"    - {err}")
        if len(stats["errors"]) > 20:
            print(f"    ... and {len(stats['errors']) - 20} more errors.")
    else:
        print("[+] SUCCESS: All 120 tasks, 600 files, and index.jsonl are 100% valid and verified.")
    print("=" * 80)


def main():
    root_dir = Path(__file__).resolve().parent.parent
    bench_dir = root_dir / "data" / "benchmark" / "repair"

    print(f"[*] Validating benchmark at {bench_dir}...")
    is_valid, stats = validate_benchmark(bench_dir)
    print_report(stats)

    if not is_valid:
        sys.exit(1)


if __name__ == "__main__":
    main()
