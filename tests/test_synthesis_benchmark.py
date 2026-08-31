#!/usr/bin/env python3
"""
Unit tests for the 120-Task Private Synthesis Benchmark Dataset.
Validates:
1. Matrix coverage (4 categories x 3 difficulties x 10 tasks = 120 tasks).
2. Test count constraints (L1 >= 5, L2 >= 7, L3 >= 9).
3. Checksum integrity with data/benchmark/synthesis/index.jsonl.
4. Total disjointness against calibration and SFT frozen splits.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Set

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts.validate_synthesis_benchmark import sha256_file, validate_benchmark


def test_synthesis_benchmark_validation():
    """Runs the master validation script directly and asserts success."""
    validate_benchmark()


def test_synthesis_benchmark_matrix_and_test_counts():
    """Validates benchmark directory structure, matrix distribution, and test counts."""
    base_dir = PROJECT_ROOT / "data" / "benchmark" / "synthesis"
    index_file = base_dir / "index.jsonl"

    assert index_file.exists(), f"Missing index file: {index_file}"

    entries: List[Dict] = []
    with open(index_file, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                entries.append(json.loads(line))

    assert len(entries) == 120, f"Expected 120 tasks, got {len(entries)}"

    categories = [
        "packet_filtering_security",
        "packet_inspection_telemetry",
        "protocol_transformation",
        "network_routing_forwarding",
    ]
    difficulties = ["level_1", "level_2", "level_3"]
    min_tests = {"level_1": 5, "level_2": 7, "level_3": 9}

    counts = {c: {d: 0 for d in difficulties} for c in categories}
    seen_ids: Set[str] = set()

    for entry in entries:
        tid = entry["task_id"]
        cat = entry["application_category"]
        diff = entry["difficulty"]
        rel = entry["relative_path"]

        assert tid not in seen_ids
        seen_ids.add(tid)
        counts[cat][diff] += 1

        task_dir = base_dir / rel
        assert (task_dir / "task.json").exists()
        assert (task_dir / "tests.json").exists()
        assert (task_dir / "solution.c").exists()
        assert (task_dir / "fixtures").is_dir()

        with open(task_dir / "tests.json", "r", encoding="utf-8") as f:
            tdata = json.load(f)
        assert len(tdata["test_cases"]) >= min_tests[diff]

    for c in categories:
        for d in difficulties:
            assert counts[c][d] == 10
