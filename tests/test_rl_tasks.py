"""
Unit tests for the 132-Task BPF RLVR Phase 1 Task Pool.
Validates:
1. Matrix coverage (4 categories x 3 difficulties):
   - Canary: 1 task per cell (12 total)
   - Train: 8 tasks per cell (96 total)
   - Dev: 2 tasks per cell (24 total)
2. Zero overlap between Canary, Train, and Dev splits.
3. Zero overlap against all 276 protected benchmark tasks (calibration, synthesis-120, repair-120).
4. Integrity of task.json, tests.json, and solution.c files.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Dict, List, Set

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

CATEGORIES = [
    "packet_filtering_security",
    "packet_inspection_telemetry",
    "protocol_transformation",
    "network_routing_forwarding",
]
DIFFICULTIES = ["level_1", "level_2", "level_3"]


def test_rl_task_pool_counts_and_distribution():
    base_dir = PROJECT_ROOT / "data" / "rl" / "v1"

    for split_name, expected_total, expected_per_cell in [
        ("canary", 12, 1),
        ("train", 96, 8),
        ("dev", 24, 2),
    ]:
        split_dir = base_dir / split_name
        index_file = split_dir / "index.jsonl"
        assert index_file.is_file(), f"Missing index file: {index_file}"

        entries = [json.loads(line) for line in index_file.read_text(encoding="utf-8").splitlines() if line.strip()]
        assert len(entries) == expected_total, f"Split '{split_name}': expected {expected_total}, got {len(entries)}"

        counts = {c: {d: 0 for d in DIFFICULTIES} for c in CATEGORIES}
        for e in entries:
            c = e["application_category"]
            d = e["difficulty"]
            counts[c][d] += 1

        for c in CATEGORIES:
            for d in DIFFICULTIES:
                assert counts[c][d] == expected_per_cell, f"Split '{split_name}' ({c}, {d}): expected {expected_per_cell}, got {counts[c][d]}"


def test_rl_task_pool_zero_overlap_and_benchmark_isolation():
    base_dir = PROJECT_ROOT / "data" / "rl" / "v1"

    canary_ids = {json.loads(l)["task_id"] for l in (base_dir / "canary" / "index.jsonl").read_text().splitlines() if l.strip()}
    train_ids = {json.loads(l)["task_id"] for l in (base_dir / "train" / "index.jsonl").read_text().splitlines() if l.strip()}
    dev_ids = {json.loads(l)["task_id"] for l in (base_dir / "dev" / "index.jsonl").read_text().splitlines() if l.strip()}

    # Check mutual disjointness
    assert not (canary_ids & train_ids), f"Canary and Train overlap: {canary_ids & train_ids}"
    assert not (canary_ids & dev_ids), f"Canary and Dev overlap: {canary_ids & dev_ids}"
    assert not (train_ids & dev_ids), f"Train and Dev overlap: {train_ids & dev_ids}"

    # Check protected benchmark isolation (276 protected tasks)
    protected_ids: Set[str] = set()
    for prot_path in [
        PROJECT_ROOT / "data" / "calibration" / "index.jsonl",
        PROJECT_ROOT / "data" / "benchmark" / "synthesis" / "index.jsonl",
        PROJECT_ROOT / "data" / "benchmark" / "repair" / "index.jsonl",
    ]:
        if prot_path.is_file():
            for line in prot_path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    protected_ids.add(json.loads(line)["task_id"])

    assert len(protected_ids) == 276, f"Expected 276 protected tasks, found {len(protected_ids)}"

    all_rl_ids = canary_ids | train_ids | dev_ids
    assert len(all_rl_ids) == 132, f"Expected 132 unique RL tasks, found {len(all_rl_ids)}"

    leakage = all_rl_ids & protected_ids
    assert not leakage, f"CRITICAL: Protected benchmark task leakage into RL pool: {leakage}"


def test_rl_task_files_exist():
    base_dir = PROJECT_ROOT / "data" / "rl" / "v1"
    for split in ["canary", "train", "dev"]:
        split_dir = base_dir / split
        index_file = split_dir / "index.jsonl"
        for line in index_file.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            entry = json.loads(line)
            task_dir = split_dir / entry["relative_path"]
            assert (task_dir / "task.json").is_file(), f"Missing task.json in {task_dir}"
            assert (task_dir / "tests.json").is_file(), f"Missing tests.json in {task_dir}"
            assert (task_dir / "solution.c").is_file(), f"Missing solution.c in {task_dir}"
            tests_data = json.loads((task_dir / "tests.json").read_text(encoding="utf-8"))
            for tc in tests_data["test_cases"]:
                fix_file = task_dir / tc["fixture_file"]
                assert fix_file.is_file(), f"Missing fixture file: {fix_file}"
