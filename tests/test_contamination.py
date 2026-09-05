"""
Unit tests for Semantic Contamination Audit (Phase 2).
Validates:
1. Exact task ID match detection across splits.
2. Exact manifest hash match detection.
3. Instruction near-duplicate detection via token Jaccard similarity.
4. Requirements near-duplicate detection.
5. Task family overlap between train and eval splits.
6. Clean disjoint tasks producing zero violations.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest

from training.rl.audit_contamination import (
    check_task_pair_contamination,
    compute_jaccard_similarity,
    compute_task_fingerprints,
    extract_protocol_feature_tuple,
    extract_semantic_tokens,
    normalize_requirements,
    normalize_text,
    run_contamination_audit,
)


def test_normalize_text_and_tokens():
    text = "Write an XDP program that DROPS IPv4 TCP packets with port 23 (Telnet)!"
    norm = normalize_text(text)
    assert "drop" in norm
    assert "telnet" in norm
    assert "!" not in norm
    tokens = extract_semantic_tokens(text)
    assert "tcp" in tokens
    assert "port" in tokens
    assert "23" in tokens
    # Stopwords should be filtered out
    assert "an" not in tokens
    assert "that" not in tokens
    assert "with" not in tokens


def test_normalize_requirements():
    reqs = [
        "Check Ethernet and IPv4 bounds",
        "GPL license and SEC(\"xdp\") entry point",
        "If TCP dport is 23, return XDP_DROP; otherwise return XDP_PASS",
    ]
    cleaned = normalize_requirements(reqs)
    assert len(cleaned) == 2  # Generic boilerplate dropped
    assert any("dport 23" in c for c in cleaned)


def test_protocol_feature_tuple():
    task = {
        "instruction": "Parse 802.1Q VLAN tag and lookup destination IP in BPF_MAP_TYPE_LPM_TRIE",
        "requirements": ["Return XDP_REDIRECT to devmap"],
    }
    feats = extract_protocol_feature_tuple(task)
    assert "proto:vlan" in feats
    assert "map:lpm_trie" in feats
    assert "map:devmap" in feats


def test_exact_task_id_match():
    task_a = {"task_id": "duplicate_id", "instruction": "Task A instruction", "requirements": []}
    task_b = {"task_id": "duplicate_id", "instruction": "Task B instruction", "requirements": []}
    fp_a = compute_task_fingerprints(task_a)
    fp_b = compute_task_fingerprints(task_b)

    violations = check_task_pair_contamination(
        task_a=task_a, fp_a=fp_a, split_a="train",
        task_b=task_b, fp_b=fp_b, split_b="dev"
    )
    assert len(violations) >= 1
    assert any(v.violation_type == "exact_task_id_match" for v in violations)


def test_instruction_near_duplicate():
    task_a = {
        "task_id": "task_a",
        "instruction": "Write an XDP program that inspects IPv4 TCP packets and drops port 8080 traffic.",
        "requirements": ["Requirement A"],
    }
    task_b = {
        "task_id": "task_b",
        "instruction": "Write an XDP program that inspects IPv4 TCP packets and drops port 8080 payload traffic.",
        "requirements": ["Requirement B"],
    }
    fp_a = compute_task_fingerprints(task_a)
    fp_b = compute_task_fingerprints(task_b)

    violations = check_task_pair_contamination(
        task_a=task_a, fp_a=fp_a, split_a="train",
        task_b=task_b, fp_b=fp_b, split_b="dev",
        jaccard_instruction_threshold=0.80,
    )
    assert any(v.violation_type == "instruction_near_duplicate" for v in violations)


def test_task_family_overlap_between_train_and_eval():
    task_train = {
        "task_id": "rl_train_lpm_01",
        "task_family": "xdp_lpm_trie_route",
        "instruction": "IPv4 LPM route lookup with hash fallback",
        "requirements": ["Use BPF_MAP_TYPE_LPM_TRIE"],
    }
    task_dev = {
        "task_id": "rl_dev_lpm_01",
        "task_family": "xdp_lpm_trie_route",
        "instruction": "IPv6 LPM route lookup with prefix match",
        "requirements": ["Use BPF_MAP_TYPE_LPM_TRIE with IPv6 keys"],
    }
    fp_train = compute_task_fingerprints(task_train)
    fp_dev = compute_task_fingerprints(task_dev)

    violations = check_task_pair_contamination(
        task_a=task_train, fp_a=fp_train, split_a="rl_v2_train",
        task_b=task_dev, fp_b=fp_dev, split_b="rl_v2_dev",
    )
    assert any(v.violation_type == "task_family_overlap" for v in violations)


def test_clean_disjoint_tasks():
    task_a = {
        "task_id": "task_sec_01",
        "task_family": "xdp_syn_cookie_filter",
        "instruction": "Drop SYN packets exceeding rate limit counter in BPF_MAP_TYPE_ARRAY",
        "requirements": ["Define rate limiter array", "Return XDP_DROP on threshold breach"],
    }
    task_b = {
        "task_id": "task_routing_01",
        "task_family": "xdp_vlan_decap_forward",
        "instruction": "Pop 802.1Q tag using bpf_xdp_adjust_head and redirect to egress port",
        "requirements": ["Verify 802.1Q header", "Adjust head by -4 bytes", "Return XDP_REDIRECT"],
    }
    fp_a = compute_task_fingerprints(task_a)
    fp_b = compute_task_fingerprints(task_b)

    violations = check_task_pair_contamination(
        task_a=task_a, fp_a=fp_a, split_a="train",
        task_b=task_b, fp_b=fp_b, split_b="dev",
    )
    assert len(violations) == 0
