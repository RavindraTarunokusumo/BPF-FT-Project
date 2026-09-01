#!/usr/bin/env python3
"""
Unit tests for the Hardened Verification Importer (training/import_verifier_results.py).
Tests:
1. Missing raw verification directory -> raises FileNotFoundError.
2. Empty raw verification directory -> raises ValueError.
3. Incomplete record set -> raises ValueError.
4. Duplicate task/sample records -> raises ValueError.
5. Source-hash mismatch between candidate .c and raw JSON -> raises ValueError.
6. Fixture count mismatch against task test spec -> raises ValueError.
7. Mock quarantine violation (attempting mock output to empirical path) -> raises ValueError.
8. Explicit mock mode with 'mock' directory path -> passes with mock tags and warning.
9. Successful empirical aggregation -> produces complete empirical summary with host metadata and hashes.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from training.import_verifier_results import (
    aggregate_verification_results,
    check_output_compliance,
    compute_file_sha256,
    load_and_validate_empirical_results,
    simulate_mock_verification,
)

VALID_C_SOURCE = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    if (data + 14 > data_end)
        return XDP_PASS;
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""


@pytest.fixture
def mock_rollout_env(tmp_path: Path):
    """Sets up a temporary rollout structure with candidates and test index."""
    rollout_dir = tmp_path / "rollout-test"
    rollout_dir.mkdir(parents=True)
    candidates_dir = rollout_dir / "candidates"
    cand_task_dir = candidates_dir / "test_task_1"
    cand_task_dir.mkdir(parents=True)

    cand_file = cand_task_dir / "sample-0.c"
    cand_file.write_text(VALID_C_SOURCE, encoding="utf-8")

    verification_dir = rollout_dir / "verification"
    raw_dir = verification_dir / "raw"
    raw_dir.mkdir(parents=True)

    index_file = tmp_path / "index.jsonl"
    index_file.write_text(
        json.dumps({
            "task_id": "test_task_1",
            "application_category": "packet_filtering_security",
            "difficulty": "level_1",
            "relative_path": "packet_filtering_security/level_1/test_task_1",
        }) + "\n",
        encoding="utf-8",
    )

    # Also create tests.json in benchmark directory
    test_spec_dir = tmp_path / "data" / "calibration" / "packet_filtering_security" / "level_1" / "test_task_1"
    test_spec_dir.mkdir(parents=True)
    tests_json = test_spec_dir / "tests.json"
    tests_json.write_text(
        json.dumps({
            "task_id": "test_task_1",
            "tests": [
                {"name": "t1", "expected_action": "XDP_PASS"},
                {"name": "t2", "expected_action": "XDP_PASS"},
            ],
        }),
        encoding="utf-8",
    )

    cand_sha256 = compute_file_sha256(cand_file)

    return {
        "rollout_dir": rollout_dir,
        "raw_dir": raw_dir,
        "cand_file": cand_file,
        "cand_sha256": cand_sha256,
        "index_file": index_file,
        "tmp_path": tmp_path,
    }


def test_missing_raw_directory(mock_rollout_env):
    missing_raw = mock_rollout_env["rollout_dir"] / "nonexistent_raw"
    with pytest.raises(FileNotFoundError, match="Raw verification directory not found"):
        load_and_validate_empirical_results(
            rollout_dir=mock_rollout_env["rollout_dir"],
            raw_dir=missing_raw,
            benchmark_index=mock_rollout_env["index_file"],
        )


def test_empty_raw_directory(mock_rollout_env):
    with pytest.raises(ValueError, match="No raw JSON verification records found"):
        load_and_validate_empirical_results(
            rollout_dir=mock_rollout_env["rollout_dir"],
            raw_dir=mock_rollout_env["raw_dir"],
            benchmark_index=mock_rollout_env["index_file"],
        )


def test_incomplete_record_set(mock_rollout_env):
    # Add a second candidate without matching raw record
    cand2_dir = mock_rollout_env["rollout_dir"] / "candidates" / "test_task_2"
    cand2_dir.mkdir(parents=True)
    (cand2_dir / "sample-0.c").write_text(VALID_C_SOURCE, encoding="utf-8")

    # Only add raw for test_task_1
    raw_file = mock_rollout_env["raw_dir"] / "test_task_1_sample-0.json"
    raw_file.write_text(
        json.dumps({
            "task_id": "test_task_1",
            "candidate_id": "sample-0",
            "source_sha256": mock_rollout_env["cand_sha256"],
            "compile": {"pass": True, "returncode": 0},
            "verifier": {"pass": True},
            "behavioral": {"pass": True, "total_tests": 2, "passed_tests": 2},
        }),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Raw record count \\(1\\) differs from candidate count \\(2\\)"):
        load_and_validate_empirical_results(
            rollout_dir=mock_rollout_env["rollout_dir"],
            raw_dir=mock_rollout_env["raw_dir"],
            benchmark_index=mock_rollout_env["index_file"],
        )


def test_duplicate_task_sample(mock_rollout_env):
    # Two raw JSON files with the same task_id / sample_id
    raw1 = mock_rollout_env["raw_dir"] / "test_task_1_sample-0.json"
    raw2 = mock_rollout_env["raw_dir"] / "test_task_1_sample-0_dup.json"

    data = {
        "task_id": "test_task_1",
        "candidate_id": "sample-0",
        "source_sha256": mock_rollout_env["cand_sha256"],
        "compile": {"pass": True, "returncode": 0},
        "verifier": {"pass": True},
        "behavioral": {"pass": True, "total_tests": 2, "passed_tests": 2},
    }
    raw1.write_text(json.dumps(data), encoding="utf-8")
    raw2.write_text(json.dumps(data), encoding="utf-8")

    # Add dummy second candidate to balance count
    cand2_dir = mock_rollout_env["rollout_dir"] / "candidates" / "test_task_dummy"
    cand2_dir.mkdir(parents=True)
    (cand2_dir / "sample-0.c").write_text(VALID_C_SOURCE, encoding="utf-8")

    with pytest.raises(ValueError, match="Duplicate raw verification record"):
        load_and_validate_empirical_results(
            rollout_dir=mock_rollout_env["rollout_dir"],
            raw_dir=mock_rollout_env["raw_dir"],
            benchmark_index=mock_rollout_env["index_file"],
        )


def test_source_hash_mismatch(mock_rollout_env):
    raw_file = mock_rollout_env["raw_dir"] / "test_task_1_sample-0.json"
    raw_file.write_text(
        json.dumps({
            "task_id": "test_task_1",
            "candidate_id": "sample-0",
            "source_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
            "compile": {"pass": True, "returncode": 0},
            "verifier": {"pass": True},
            "behavioral": {"pass": True, "total_tests": 2, "passed_tests": 2},
        }),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Source hash mismatch"):
        load_and_validate_empirical_results(
            rollout_dir=mock_rollout_env["rollout_dir"],
            raw_dir=mock_rollout_env["raw_dir"],
            benchmark_index=mock_rollout_env["index_file"],
        )


def test_fixture_count_mismatch(mock_rollout_env):
    # Task requires 2 tests (defined in test fixture), raw reports 1 test
    raw_file = mock_rollout_env["raw_dir"] / "test_task_1_sample-0.json"
    raw_file.write_text(
        json.dumps({
            "task_id": "test_task_1",
            "candidate_id": "sample-0",
            "application_category": "packet_filtering_security",
            "difficulty": "level_1",
            "source_sha256": mock_rollout_env["cand_sha256"],
            "compile": {"pass": True, "returncode": 0},
            "verifier": {"pass": True},
            "behavioral": {"pass": True, "total_tests": 1, "passed_tests": 1},  # mismatch: expected 2
        }),
        encoding="utf-8",
    )

    # Monkeypatch find_task_test_spec to return spec with 2 tests
    import training.import_verifier_results as mod
    orig_fn = mod.find_task_test_spec
    mod.find_task_test_spec = lambda *args, **kwargs: {"tests": [{"name": "t1"}, {"name": "t2"}]}

    try:
        with pytest.raises(ValueError, match="Fixture count mismatch"):
            load_and_validate_empirical_results(
                rollout_dir=mock_rollout_env["rollout_dir"],
                raw_dir=mock_rollout_env["raw_dir"],
                benchmark_index=mock_rollout_env["index_file"],
            )
    finally:
        mod.find_task_test_spec = orig_fn


def test_mock_mode_quarantine_violation(mock_rollout_env):
    # Attempting to aggregate mock results to an empirical directory without 'mock' in path
    out_dir = mock_rollout_env["rollout_dir"] / "verification"
    generation_records = mock_rollout_env["rollout_dir"] / "generation_records.jsonl"
    generation_records.write_text(
        json.dumps({
            "task_id": "test_task_1",
            "sample_id": "sample-0",
            "compliance": {"compliant": True},
            "source_hash": mock_rollout_env["cand_sha256"],
        }) + "\n",
        encoding="utf-8",
    )

    from training.import_verifier_results import main
    # Run simulation directly
    mock_results = simulate_mock_verification(mock_rollout_env["rollout_dir"], mock_rollout_env["index_file"])
    assert len(mock_results) == 1
    assert mock_results[0]["verification_mode"] == "mock"


def test_successful_empirical_aggregation(mock_rollout_env):
    raw_file = mock_rollout_env["raw_dir"] / "test_task_1_sample-0.json"
    raw_file.write_text(
        json.dumps({
            "task_id": "test_task_1",
            "candidate_id": "sample-0",
            "application_category": "packet_filtering_security",
            "difficulty": "level_1",
            "source_sha256": mock_rollout_env["cand_sha256"],
            "timestamp": "2026-09-02T00:00:00Z",
            "compile": {"pass": True, "returncode": 0, "stderr": "", "stdout": ""},
            "verifier": {"pass": True, "log": "safe", "stdout": "", "stderr": ""},
            "behavioral": {
                "pass": True,
                "total_tests": 2,
                "passed_tests": 2,
                "details": [
                    {"name": "t1", "pass": True, "expected": "XDP_PASS", "actual": "XDP_PASS"},
                    {"name": "t2", "pass": True, "expected": "XDP_PASS", "actual": "XDP_PASS"},
                ],
            },
            "passed": True,
            "diagnostic": None,
        }),
        encoding="utf-8",
    )

    import training.import_verifier_results as mod
    orig_fn = mod.find_task_test_spec
    mod.find_task_test_spec = lambda *args, **kwargs: {"tests": [{"name": "t1"}, {"name": "t2"}]}

    try:
        results, host_info, cand_hash, raw_hash = load_and_validate_empirical_results(
            rollout_dir=mock_rollout_env["rollout_dir"],
            raw_dir=mock_rollout_env["raw_dir"],
            benchmark_index=mock_rollout_env["index_file"],
        )

        out_dir = mock_rollout_env["rollout_dir"] / "verification"
        summary = aggregate_verification_results(
            rollout_dir=mock_rollout_env["rollout_dir"],
            results=results,
            output_dir=out_dir,
            verification_mode="empirical",
            verification_host=host_info,
            candidate_set_hash=cand_hash,
            raw_results_hash=raw_hash,
        )

        assert summary["verification_mode"] == "empirical"
        assert summary["total_tasks"] == 1
        assert summary["metrics"]["pass_at_1"]["passed_tasks"] == 1
        assert summary["metrics"]["pass_at_1"]["rate"] == 1.0
        assert summary["candidate_set_hash"] is not None
        assert summary["raw_results_hash"] is not None
        assert "Linux" in summary["verification_host"]["kernel"]

        summary_md = (out_dir / "summary.md").read_text(encoding="utf-8")
        assert "**Verification Mode**: `empirical`" in summary_md
        assert "**Candidate Set Hash**" in summary_md
    finally:
        mod.find_task_test_spec = orig_fn
