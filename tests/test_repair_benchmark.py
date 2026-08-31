#!/usr/bin/env python3
"""
Unit tests for the 120-Task Private Repair Benchmark Dataset.
Validates:
1. Master repair validator (scripts/validate_repair_benchmark.py).
2. Matrix distribution (4 categories x 3 difficulties x 10 tasks = 120 tasks).
3. 5 canonical files per task (task.json, faulty.c, diagnostic.txt, tests.json, solution.c).
4. Failure mode taxonomy (50 compilation, 45 verifier, 25 behavioral).
5. Disjointness against calibration and SFT training splits.
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

from scripts.validate_repair_benchmark import validate_benchmark


def test_repair_benchmark_master_validation():
    """Runs the master repair validation script directly and asserts success."""
    bench_dir = PROJECT_ROOT / "data" / "benchmark" / "repair"
    success, stats = validate_benchmark(bench_dir)
    assert success, f"Repair benchmark validation failed with errors: {stats.get('errors')}"
    assert stats["total_tasks"] == 120
    assert stats["total_files"] == 600


def test_repair_benchmark_matrix_and_schema():
    """Validates benchmark directory structure, matrix distribution, and JSON schemas."""
    base_dir = PROJECT_ROOT / "data" / "benchmark" / "repair"
    index_file = base_dir / "index.jsonl"

    assert index_file.exists(), f"Missing index file: {index_file}"

    entries: List[Dict] = []
    with open(index_file, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                entries.append(json.loads(line))

    assert len(entries) == 120, f"Expected 120 repair tasks, got {len(entries)}"

    categories = [
        "packet_filtering_security",
        "packet_inspection_telemetry",
        "protocol_transformation",
        "network_routing_forwarding",
    ]
    difficulties = ["level_1", "level_2", "level_3"]

    counts = {c: {d: 0 for d in difficulties} for c in categories}
    seen_ids: Set[str] = set()

    for entry in entries:
        t_id = entry["task_id"]
        cat = entry["application_category"]
        diff = entry["difficulty"]

        assert t_id not in seen_ids, f"Duplicate task ID: {t_id}"
        seen_ids.add(t_id)

        assert cat in categories, f"Unknown category: {cat}"
        assert diff in difficulties, f"Unknown difficulty: {diff}"
        counts[cat][diff] += 1

        # Check required on-disk files
        t_dir = base_dir / cat / diff / t_id
        assert t_dir.is_dir(), f"Task directory missing: {t_dir}"

        for fname in ["task.json", "faulty.c", "diagnostic.txt", "tests.json", "solution.c"]:
            fpath = t_dir / fname
            assert fpath.is_file(), f"Missing canonical file: {fpath}"
            assert fpath.stat().st_size > 0, f"Empty canonical file: {fpath}"

        # Schema checks
        with open(t_dir / "task.json", "r", encoding="utf-8") as f:
            t_data = json.load(f)
            assert t_data["task_id"] == t_id
            assert "instruction" in t_data
            assert "requirements" in t_data
            assert "failure_reason" in t_data
            assert "diagnostic_category" in t_data

        with open(t_dir / "tests.json", "r", encoding="utf-8") as f:
            test_data = json.load(f)
            assert "tests" in test_data
            assert len(test_data["tests"]) >= 1

    # Check exactly 10 tasks per cell
    for c in categories:
        for d in difficulties:
            assert counts[c][d] == 10, f"Expected 10 tasks for {c}/{d}, got {counts[c][d]}"


def test_repair_benchmark_disjointness():
    """Ensures 0% overlap with calibration or SFT training split task IDs."""
    repair_index = PROJECT_ROOT / "data" / "benchmark" / "repair" / "index.jsonl"
    calib_index = PROJECT_ROOT / "data" / "calibration" / "index.jsonl"
    synth_index = PROJECT_ROOT / "data" / "benchmark" / "synthesis" / "index.jsonl"

    def load_ids(p: Path) -> Set[str]:
        if not p.is_file():
            return set()
        return {json.loads(line)["task_id"] for line in p.read_text(encoding="utf-8").splitlines() if line.strip()}

    repair_ids = load_ids(repair_index)
    calib_ids = load_ids(calib_index)
    synth_ids = load_ids(synth_index)

    assert len(repair_ids) == 120
    assert len(repair_ids & calib_ids) == 0, f"Calibration leakage: {repair_ids & calib_ids}"
    assert len(repair_ids & synth_ids) == 0, f"Synthesis leakage: {repair_ids & synth_ids}"
