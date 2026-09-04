"""
Unit tests for BPF-Guardian RLVR Phase 1 Reward Function and Output Compliance.
Validates:
1. Multi-stage reward gates (compliance, compile, verifier, behavioral, complete-suite bonus).
2. Infrastructure errors never award training reward.
3. Fixture count mismatch treated as fail-closed error.
4. Fixture weighting prevents trivial pass-all/drop-all exploitation.
5. Deterministic reward reconstruction.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from training.rl.reward import (
    MAX_REWARD,
    WEIGHT_BONUS,
    WEIGHT_COMPILE,
    WEIGHT_COMPLIANCE,
    WEIGHT_FIXTURES,
    WEIGHT_VERIFIER,
    RewardBreakdown,
    compute_rlvr_reward,
)
from training.rl.kernel_executor import check_output_compliance, extract_c_source


def test_output_compliance_valid():
    code = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    comp = check_output_compliance(code)
    assert comp["compliant"] is True
    assert comp["has_fences"] is False
    assert comp["has_include"] is True
    assert comp["has_sec"] is True
    assert comp["has_license"] is True
    assert comp["has_xdp"] is True
    assert comp["has_fault_markers"] is False


def test_output_compliance_fences_and_faults():
    code_with_fence = """```c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
SEC("xdp") int xdp_prog(void *ctx) { return XDP_PASS; }
char _license[] SEC("license") = "GPL";
```"""
    comp = check_output_compliance(code_with_fence)
    assert comp["compliant"] is False
    assert comp["has_fences"] is True

    code_with_fault = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
// FAULT: packet check omitted
SEC("xdp") int xdp_prog(void *ctx) { return XDP_PASS; }
char _license[] SEC("license") = "GPL";"""
    comp2 = check_output_compliance(code_with_fault)
    assert comp2["compliant"] is False
    assert comp2["has_fault_markers"] is True


def test_reward_non_compliant_only():
    result = {
        "infrastructure_error": False,
        "output_compliance": {"compliant": False},
        "compile": {"pass": False},
        "verifier": {"pass": False},
        "behavioral": {"total_tests": 5, "passed_tests": 0, "details": []},
    }
    r = compute_rlvr_reward(result, expected_fixture_count=5)
    assert r.total_reward == 0.0
    assert r.stage_reached == "non_compliant"
    assert r.is_functionally_correct is False


def test_reward_compliance_and_compile():
    result = {
        "infrastructure_error": False,
        "output_compliance": {"compliant": True},
        "compile": {"pass": True},
        "verifier": {"pass": False},
        "behavioral": {"total_tests": 5, "passed_tests": 0, "details": []},
    }
    r = compute_rlvr_reward(result, expected_fixture_count=5)
    expected = round(WEIGHT_COMPLIANCE + WEIGHT_COMPILE, 4)
    assert round(r.total_reward, 4) == expected
    assert r.stage_reached == "compile"
    assert r.is_functionally_correct is False


def test_reward_verifier_pass_no_behavioral():
    result = {
        "infrastructure_error": False,
        "output_compliance": {"compliant": True},
        "compile": {"pass": True},
        "verifier": {"pass": True},
        "behavioral": {
            "total_tests": 4,
            "passed_tests": 0,
            "details": [{"name": f"t{i}", "pass": False, "weight": 1.0} for i in range(4)],
        },
    }
    r = compute_rlvr_reward(result, expected_fixture_count=4)
    expected = round(WEIGHT_COMPLIANCE + WEIGHT_COMPILE + WEIGHT_VERIFIER, 4)
    assert round(r.total_reward, 4) == expected
    assert r.stage_reached == "behavioral"
    assert r.is_functionally_correct is False


def test_reward_partial_behavioral():
    # 2 of 4 tests pass with equal weights
    result = {
        "infrastructure_error": False,
        "output_compliance": {"compliant": True},
        "compile": {"pass": True},
        "verifier": {"pass": True},
        "behavioral": {
            "total_tests": 4,
            "passed_tests": 2,
            "details": [
                {"name": "t0", "pass": True, "weight": 1.0},
                {"name": "t1", "pass": True, "weight": 1.0},
                {"name": "t2", "pass": False, "weight": 1.0},
                {"name": "t3", "pass": False, "weight": 1.0},
            ],
        },
    }
    r = compute_rlvr_reward(result, expected_fixture_count=4)
    expected_fixture_reward = WEIGHT_FIXTURES * 0.5
    expected_total = round(
        WEIGHT_COMPLIANCE + WEIGHT_COMPILE + WEIGHT_VERIFIER + expected_fixture_reward, 4
    )
    assert round(r.total_reward, 4) == expected_total
    assert round(r.fixture_reward, 4) == round(expected_fixture_reward, 4)
    assert r.complete_bonus == 0.0
    assert r.is_functionally_correct is False


def test_reward_complete_suite_pass():
    result = {
        "infrastructure_error": False,
        "output_compliance": {"compliant": True},
        "compile": {"pass": True},
        "verifier": {"pass": True},
        "behavioral": {
            "total_tests": 4,
            "passed_tests": 4,
            "details": [
                {"name": f"t{i}", "pass": True, "weight": 1.0} for i in range(4)
            ],
        },
    }
    r = compute_rlvr_reward(result, expected_fixture_count=4)
    assert round(r.total_reward, 4) == 1.00
    assert r.compliance_reward == WEIGHT_COMPLIANCE
    assert r.compile_reward == WEIGHT_COMPILE
    assert r.verifier_reward == WEIGHT_VERIFIER
    assert r.fixture_reward == WEIGHT_FIXTURES
    assert r.complete_bonus == WEIGHT_BONUS
    assert r.is_functionally_correct is True
    assert r.stage_reached == "full_pass"


def test_reward_infrastructure_error_fail_closed():
    result = {
        "infrastructure_error": True,
        "output_compliance": {"compliant": True},
        "compile": {"pass": True},
        "verifier": {"pass": True},
        "behavioral": {"total_tests": 4, "passed_tests": 4, "details": []},
    }
    r = compute_rlvr_reward(result, expected_fixture_count=4)
    assert r.total_reward == 0.0
    assert r.is_infrastructure_error is True
    assert r.stage_reached == "infrastructure_error"


def test_reward_fixture_count_mismatch_fail_closed():
    # Model executed 3 tests but expected 4 -> infrastructure/harness failure
    result = {
        "infrastructure_error": False,
        "output_compliance": {"compliant": True},
        "compile": {"pass": True},
        "verifier": {"pass": True},
        "behavioral": {
            "total_tests": 3,
            "passed_tests": 3,
            "details": [{"name": f"t{i}", "pass": True, "weight": 1.0} for i in range(3)],
        },
    }
    r = compute_rlvr_reward(result, expected_fixture_count=4)
    assert r.total_reward == 0.0
    assert r.is_infrastructure_error is True
    assert r.stage_reached == "fixture_count_mismatch"


def test_reward_deterministic_recomputation():
    result = {
        "infrastructure_error": False,
        "output_compliance": {"compliant": True},
        "compile": {"pass": True},
        "verifier": {"pass": True},
        "behavioral": {
            "total_tests": 5,
            "passed_tests": 3,
            "details": [
                {"name": "t0", "pass": True, "weight": 2.0},
                {"name": "t1", "pass": True, "weight": 1.0},
                {"name": "t2", "pass": True, "weight": 1.0},
                {"name": "t3", "pass": False, "weight": 3.0},
                {"name": "t4", "pass": False, "weight": 3.0},
            ],
        },
    }
    r1 = compute_rlvr_reward(result, expected_fixture_count=5)
    r2 = compute_rlvr_reward(result, expected_fixture_count=5)
    assert r1.to_dict() == r2.to_dict()
    # Total weight: 2 + 1 + 1 + 3 + 3 = 10; earned: 4; fraction: 0.4
    assert round(r1.fixture_reward, 4) == round(0.70 * 0.4, 4)
