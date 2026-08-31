"""
Comprehensive Validation Script for the 120-Task Private Synthesis Benchmark Dataset.
Validates:
  1. Matrix distribution: 4 categories x 3 difficulty levels x 10 tasks = 120 tasks.
  2. Test case count requirements: Level 1 >= 5, Level 2 >= 7, Level 3 >= 9.
  3. JSON Schema and integrity: task.json, tests.json, binary fixtures.
  4. SHA-256 hash consistency with data/benchmark/synthesis/index.jsonl.
  5. Verifier safety patterns and GPL license declarations in solution.c.
  6. Disjointness check: 0% overlap with calibration set and SFT frozen set.
"""

from __future__ import annotations

import collections
import hashlib
import json
import os
import sys
from typing import Any, Dict, List, Set


def sha256_file(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()


def validate_benchmark():
    benchmark_dir = os.path.abspath("data/benchmark/synthesis")
    index_path = os.path.join(benchmark_dir, "index.jsonl")

    print(f"=== Validating Private Synthesis Benchmark Dataset at {benchmark_dir} ===")

    assert os.path.exists(benchmark_dir), f"Benchmark dir missing: {benchmark_dir}"
    assert os.path.exists(index_path), f"Index file missing: {index_path}"

    # Load index entries
    index_entries: List[Dict[str, Any]] = []
    with open(index_path, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                index_entries.append(entry)
            except Exception as e:
                raise ValueError(f"Corrupted JSON in {index_path} line {line_num}: {e}")

    print(f"Total entries in index.jsonl: {len(index_entries)}")
    assert len(index_entries) == 120, f"Expected exactly 120 index entries, got {len(index_entries)}"

    # 1. Check Matrix
    categories = [
        "packet_filtering_security",
        "packet_inspection_telemetry",
        "protocol_transformation",
        "network_routing_forwarding"
    ]
    difficulties = ["level_1", "level_2", "level_3"]

    matrix_counts: Dict[str, Dict[str, int]] = {c: {d: 0 for d in difficulties} for c in categories}
    all_benchmark_ids: Set[str] = set()

    for entry in index_entries:
        task_id = entry["task_id"]
        cat = entry["application_category"]
        diff = entry["difficulty"]

        assert task_id not in all_benchmark_ids, f"Duplicate task_id found: {task_id}"
        all_benchmark_ids.add(task_id)

        assert cat in matrix_counts, f"Unknown category: {cat}"
        assert diff in matrix_counts[cat], f"Unknown difficulty: {diff}"
        matrix_counts[cat][diff] += 1

    print("\n--- Benchmark Matrix Distribution ---")
    for cat in categories:
        for diff in difficulties:
            count = matrix_counts[cat][diff]
            print(f"  {cat:<30} | {diff:<10} : {count} tasks")
            assert count == 10, f"Cell ({cat}, {diff}) has {count} tasks (expected 10)"

    # 2. Check each task directory, files, checksums, and tests
    total_test_cases = 0
    min_tests_by_diff = {"level_1": 5, "level_2": 7, "level_3": 9}

    for entry in index_entries:
        task_id = entry["task_id"]
        cat = entry["application_category"]
        diff = entry["difficulty"]
        rel_path = entry["relative_path"]

        task_dir = os.path.join(benchmark_dir, rel_path)
        assert os.path.isdir(task_dir), f"Task directory missing: {task_dir}"

        task_json_path = os.path.join(task_dir, "task.json")
        tests_json_path = os.path.join(task_dir, "tests.json")
        solution_c_path = os.path.join(task_dir, "solution.c")
        fixtures_dir = os.path.join(task_dir, "fixtures")

        assert os.path.isfile(task_json_path), f"Missing task.json in {task_dir}"
        assert os.path.isfile(tests_json_path), f"Missing tests.json in {task_dir}"
        assert os.path.isfile(solution_c_path), f"Missing solution.c in {task_dir}"
        assert os.path.isdir(fixtures_dir), f"Missing fixtures/ in {task_dir}"

        # Validate task.json
        with open(task_json_path, "r", encoding="utf-8") as f:
            task_json = json.load(f)
        assert task_json["task_id"] == task_id
        assert task_json["application_category"] == cat
        assert task_json["difficulty"] == diff
        assert "instruction" in task_json and len(task_json["instruction"]) > 20
        assert "requirements" in task_json and len(task_json["requirements"]) >= 4

        # Validate tests.json
        with open(tests_json_path, "r", encoding="utf-8") as f:
            tests_json = json.load(f)
        assert tests_json["task_id"] == task_id
        test_cases = tests_json["test_cases"]
        test_count = len(test_cases)
        total_test_cases += test_count

        min_req = min_tests_by_diff[diff]
        assert test_count >= min_req, f"Task {task_id} ({diff}) has {test_count} tests (required >= {min_req})"

        # Validate each test case and fixture file
        for tc in test_cases:
            assert "name" in tc
            assert "packet_hex" in tc
            assert "expected_action" in tc
            fix_rel = tc["fixture_file"]
            fix_abs = os.path.join(task_dir, fix_rel)
            assert os.path.isfile(fix_abs), f"Fixture file missing: {fix_abs}"
            with open(fix_abs, "rb") as f:
                fix_data = f.read()
            assert fix_data == bytes.fromhex(tc["packet_hex"]), f"Fixture binary mismatch in {fix_abs}"

        # Validate solution.c
        with open(solution_c_path, "r", encoding="utf-8") as f:
            sol_c = f.read()
        assert "SEC(" in sol_c, f"Missing SEC macro in {solution_c_path}"
        assert "GPL" in sol_c or "Dual BSD/GPL" in sol_c, f"Missing GPL license in {solution_c_path}"
        assert "data_end" in sol_c and "data" in sol_c, f"Missing verifier pointer bounds in {solution_c_path}"

        # Validate Checksums
        assert sha256_file(task_json_path) == entry["checksums"]["task_json"]
        assert sha256_file(tests_json_path) == entry["checksums"]["tests_json"]
        assert sha256_file(solution_c_path) == entry["checksums"]["solution_c"]

    print(f"\nTotal test cases across 120 benchmark tasks: {total_test_cases}")

    # 3. Disjointness Check against Calibration and SFT Frozen sets
    print("\n--- Disjointness Validation ---")

    # Calibration set check
    calib_index_path = os.path.abspath("data/calibration/index.jsonl")
    if os.path.exists(calib_index_path):
        calib_ids: Set[str] = set()
        with open(calib_index_path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    calib_ids.add(json.loads(line)["task_id"])
        calib_overlap = all_benchmark_ids.intersection(calib_ids)
        print(f"Calibration set tasks: {len(calib_ids)}")
        print(f"Calibration set overlap: {len(calib_overlap)} tasks")
        assert len(calib_overlap) == 0, f"Leakage detected! Overlap with calibration: {calib_overlap}"
    else:
        print("Note: data/calibration/index.jsonl not found, skipping calibration overlap check.")

    # SFT frozen set check
    sft_train_path = os.path.abspath("data/sft/frozen/v1/train.jsonl")
    sft_val_path = os.path.abspath("data/sft/frozen/v1/validation.jsonl")
    sft_ids: Set[str] = set()
    for sft_p in [sft_train_path, sft_val_path]:
        if os.path.exists(sft_p):
            with open(sft_p, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        sft_ids.add(json.loads(line)["task_id"])
    print(f"SFT frozen set tasks: {len(sft_ids)}")
    sft_overlap = all_benchmark_ids.intersection(sft_ids)
    print(f"SFT frozen set overlap: {len(sft_overlap)} tasks")
    assert len(sft_overlap) == 0, f"Leakage detected! Overlap with SFT frozen set: {sft_overlap}"

    print("\n========================================================")
    print("ALL VALIDATION CHECKS PASSED: 120 Private Synthesis Tasks Validated!")
    print("========================================================")


if __name__ == "__main__":
    validate_benchmark()
