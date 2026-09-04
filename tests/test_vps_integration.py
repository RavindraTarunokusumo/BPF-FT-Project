"""
Live Hostinger Linux VPS Integration Tests for KernelExecutor.
Validates live kernel execution:
1. Valid XDP candidate compiles, passes verifier, and passes packet tests.
2. Compilation error detection.
3. Linux kernel verifier rejection detection.
4. Behavioral packet test failure discrimination.
5. Pinned program cleanup verification in /sys/fs/bpf/.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from training.rl.kernel_executor import KernelExecutor


@pytest.fixture
def executor(tmp_path):
    records_dir = tmp_path / "test_records"
    return KernelExecutor(records_dir=records_dir)


@pytest.mark.skipif(not shutil.which("clang") or not shutil.which("bpftool"), reason="Live BPF toolchain required")
def test_live_vps_valid_program(executor):
    task = {
        "task_id": "test_pass_all",
        "expected_fixture_count": 2,
        "tests": [
            {
                "name": "pkt1",
                "description": "Standard Ethernet IPv4 packet",
                "packet_hex": "525400123456525400654321080045000028123400004006649ac0a8010ac0a80114",
                "expected_action": "XDP_PASS",
                "weight": 1.0,
            },
            {
                "name": "pkt2",
                "description": "Second test packet",
                "packet_hex": "525400123456525400654321080045000028123400004006649ac0a8010ac0a80114",
                "expected_action": "XDP_PASS",
                "weight": 1.0,
            },
        ],
    }
    source = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    res = asyncio.run(executor.evaluate_candidate(task, source, rollout_id="test_live_valid"))
    assert res.infrastructure_error is False
    assert res.compile["pass"] is True
    assert res.verifier["pass"] is True
    assert res.behavioral["pass"] is True
    assert res.behavioral["passed_tests"] == 2
    assert res.passed is True
    assert res.cleanup_passed is True


@pytest.mark.skipif(not shutil.which("clang") or not shutil.which("bpftool"), reason="Live BPF toolchain required")
def test_live_vps_compilation_failure(executor):
    task = {"task_id": "test_syntax_err", "tests": []}
    source = """#include <linux/bpf.h>
SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    this is invalid C syntax !!!
}
"""
    res = asyncio.run(executor.evaluate_candidate(task, source, rollout_id="test_live_syntax_err"))
    assert res.compile["attempted"] is True
    assert res.compile["pass"] is False
    assert res.verifier["attempted"] is False
    assert res.passed is False


@pytest.mark.skipif(not shutil.which("clang") or not shutil.which("bpftool"), reason="Live BPF toolchain required")
def test_live_vps_verifier_rejection(executor):
    task = {"task_id": "test_verifier_reject", "tests": []}
    # Out of bounds packet dereference without bounds checking -> verifier rejects
    source = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    // Direct unchecked dereference at offset 100
    int val = *(int *)(data + 100);
    return val > 0 ? XDP_PASS : XDP_DROP;
}

char _license[] SEC("license") = "GPL";
"""
    res = asyncio.run(executor.evaluate_candidate(task, source, rollout_id="test_live_ver_reject"))
    assert res.compile["pass"] is True
    assert res.verifier["attempted"] is True
    assert res.verifier["pass"] is False
    assert res.behavioral["attempted"] is False
    assert res.passed is False
    assert res.cleanup_passed is True


@pytest.mark.skipif(not shutil.which("clang") or not shutil.which("bpftool"), reason="Live BPF toolchain required")
def test_live_vps_behavioral_failure(executor):
    task = {
        "task_id": "test_behavioral_fail",
        "expected_fixture_count": 1,
        "tests": [
            {
                "name": "pkt1",
                "packet_hex": "525400123456525400654321080045000028123400004006649ac0a8010ac0a80114",
                "expected_action": "XDP_DROP",  # Expect DROP but code returns PASS
                "weight": 1.0,
            }
        ],
    }
    source = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    res = asyncio.run(executor.evaluate_candidate(task, source, rollout_id="test_live_behavioral_fail"))
    assert res.compile["pass"] is True
    assert res.verifier["pass"] is True
    assert res.behavioral["pass"] is False
    assert res.behavioral["passed_tests"] == 0
    assert res.passed is False
    assert res.cleanup_passed is True
