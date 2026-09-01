#!/usr/bin/env python3
"""
BPF-Guardian SFT v2 Comprehensive Test Suite
===========================================
Covers:
1. SFT v2 dataset schema and mandatory provenance metadata validation.
2. Assistant C completion constraints (pure C, no fences, no prose, no <think>, no FAULT markers, BPF markers).
3. Diagnostic repair contract and fault provenance validation.
4. Token length validation with Qwen3-8B / qwen3_disable_thinking.
5. Duplication checks (zero duplicate example_ids or message hashes).
6. Semantic family concentration checks (<= 5.0% ceiling).
7. 3-way split generation, task disjointness, and task grouping.
8. Family-heldout purity and complete isolation from training.
9. Benchmark leakage detection and isolation auditing.
10. Live verification of generated v2 delta and frozen splits.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from training.validate_sft_v2 import (
    ValidationError,
    validate_assistant_c_completion,
    validate_repair_contract,
    validate_sft_v2_dataset,
    run_benchmark_leakage_audit,
    validate_3way_splits_and_manifest,
    normalize_prompt_text,
    normalize_c_code,
    compute_jaccard_similarity,
    compute_file_sha256,
    compute_string_sha256,
)
from training.prepare_sft_v2_splits import (
    select_v1_replay,
    generate_sft_v2_splits,
    compute_split_fingerprint,
)

VALID_V2_C_PROGRAM = """#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int xdp_v2_filter(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""


# ---------------------------------------------------------------------------
# 1. Assistant C Completion Validation Tests
# ---------------------------------------------------------------------------

def test_v2_completion_valid_c():
    validate_assistant_c_completion(
        VALID_V2_C_PROGRAM, Path("test.jsonl"), 1, "v2_syn_001", "task_001"
    )


def test_v2_completion_markdown_fences_rejected():
    fenced = f"```c\n{VALID_V2_C_PROGRAM}\n```"
    with pytest.raises(ValidationError, match="Markdown fences"):
        validate_assistant_c_completion(fenced, Path("test.jsonl"), 1, "v2_syn_001", "task_001")


def test_v2_completion_think_tags_rejected():
    think_code = f"<think>\nNeed to check IP header bounds.\n</think>\n{VALID_V2_C_PROGRAM}"
    with pytest.raises(ValidationError, match="<think> tags"):
        validate_assistant_c_completion(think_code, Path("test.jsonl"), 1, "v2_syn_001", "task_001")


def test_v2_completion_prose_preamble_rejected():
    prose = f"Here is the verified C code for XDP packet filtering:\n{VALID_V2_C_PROGRAM}"
    with pytest.raises(ValidationError, match="starts with explanatory prose"):
        validate_assistant_c_completion(prose, Path("test.jsonl"), 1, "v2_syn_001", "task_001")


def test_v2_completion_missing_include_rejected():
    no_inc = VALID_V2_C_PROGRAM.replace("#include", "// include")
    with pytest.raises(ValidationError, match="missing '#include'"):
        validate_assistant_c_completion(no_inc, Path("test.jsonl"), 1, "v2_syn_001", "task_001")


def test_v2_completion_missing_sec_rejected():
    no_sec = VALID_V2_C_PROGRAM.replace("SEC(", "// sec(")
    with pytest.raises(ValidationError, match="missing 'SEC"):
        validate_assistant_c_completion(no_sec, Path("test.jsonl"), 1, "v2_syn_001", "task_001")


def test_v2_completion_missing_license_rejected():
    no_lic = VALID_V2_C_PROGRAM.replace("char _license[] SEC(\"license\") = \"GPL\";", "// no license")
    with pytest.raises(ValidationError, match="missing license"):
        validate_assistant_c_completion(no_lic, Path("test.jsonl"), 1, "v2_syn_001", "task_001")


def test_v2_completion_fault_tag_rejected():
    with_fault = VALID_V2_C_PROGRAM.replace("return XDP_PASS;", "// FAULT: missing bounds check\n        return XDP_PASS;")
    with pytest.raises(ValidationError, match="forbidden fault/placeholder marker"):
        validate_assistant_c_completion(with_fault, Path("test.jsonl"), 1, "v2_syn_001", "task_001")


def test_v2_completion_todo_tag_rejected():
    with_todo = VALID_V2_C_PROGRAM.replace("return XDP_PASS;", "/* TODO: verify checksum */\n        return XDP_PASS;")
    with pytest.raises(ValidationError, match="forbidden fault/placeholder marker"):
        validate_assistant_c_completion(with_todo, Path("test.jsonl"), 1, "v2_syn_001", "task_001")


# ---------------------------------------------------------------------------
# 2. Repair Contract & Fault Provenance Tests
# ---------------------------------------------------------------------------

def test_v2_repair_contract_valid():
    messages = [
        {"role": "system", "content": "You are a repair expert."},
        {
            "role": "user",
            "content": (
                "Task ID: task_01\n\n"
                "Previous Implementation:\n```c\n#include <linux/bpf.h>\n```\n\n"
                "Diagnostic Output:\n```text\ncandidate.c:12: error: expected ';'\n```"
            ),
        },
        {"role": "assistant", "content": VALID_V2_C_PROGRAM},
    ]
    validate_repair_contract(messages, Path("test.jsonl"), 1, "v2_rep_001", "task_01")


def test_v2_repair_contract_missing_diagnostic():
    messages = [
        {"role": "system", "content": "You are a repair expert."},
        {
            "role": "user",
            "content": "Previous Implementation:\n```c\n#include <linux/bpf.h>\n```\nFix this program.",
        },
        {"role": "assistant", "content": VALID_V2_C_PROGRAM},
    ]
    with pytest.raises(ValidationError, match="missing diagnostic output"):
        validate_repair_contract(messages, Path("test.jsonl"), 1, "v2_rep_001", "task_01")


# ---------------------------------------------------------------------------
# 3. Dataset Schema & Mandatory Provenance Metadata Tests
# ---------------------------------------------------------------------------

def test_v2_dataset_provenance_validation(tmp_path):
    record = {
        "example_id": "v2_syn_task_001",
        "task_id": "task_001",
        "category": "packet_filtering_security",
        "difficulty": "level_1",
        "template_family": "pfs_tunnel_vxlan_filter",
        "semantic_family": "pfs_tunnel_vxlan_filter",
        "example_type": "synthesis",
        "dataset_version": "v2",
        "source_kind": "new_v2",
        "generator_id": "bpf_sft_v2_generator",
        "generation_attempt": 1,
        "gold_source_sha256": "a" * 64,
        "task_spec_sha256": "b" * 64,
        "fixture_manifest_sha256": "c" * 64,
        "messages": [
            {"role": "system", "content": "Expert XDP systems programmer."},
            {"role": "user", "content": "Write XDP filter program for task_001"},
            {"role": "assistant", "content": VALID_V2_C_PROGRAM},
        ],
    }

    test_file = tmp_path / "valid_v2.jsonl"
    test_file.write_text(json.dumps(record) + "\n", encoding="utf-8")

    stats = validate_sft_v2_dataset(test_file, check_token_lengths=False, is_v2_delta=False)
    assert stats["total_examples"] == 1
    assert stats["unique_tasks"] == 1
    assert stats["semantic_families_count"] == 1


def test_v2_dataset_missing_provenance_field(tmp_path):
    record = {
        "example_id": "v2_syn_task_001",
        "task_id": "task_001",
        "category": "packet_filtering_security",
        "difficulty": "level_1",
        "template_family": "pfs_tunnel_vxlan_filter",
        "semantic_family": "pfs_tunnel_vxlan_filter",
        "example_type": "synthesis",
        "dataset_version": "v2",
        "source_kind": "new_v2",
        # Missing generator_id and hashes
        "messages": [
            {"role": "system", "content": "Expert XDP systems programmer."},
            {"role": "user", "content": "Write XDP filter program for task_001"},
            {"role": "assistant", "content": VALID_V2_C_PROGRAM},
        ],
    }

    test_file = tmp_path / "missing_prov.jsonl"
    test_file.write_text(json.dumps(record) + "\n", encoding="utf-8")

    with pytest.raises(ValidationError, match="Missing or empty 'generator_id'"):
        validate_sft_v2_dataset(test_file, check_token_lengths=False)


def test_v2_dataset_duplicate_example_id(tmp_path):
    record = {
        "example_id": "dup_001",
        "task_id": "task_001",
        "category": "packet_filtering_security",
        "difficulty": "level_1",
        "template_family": "pfs_tunnel_vxlan_filter",
        "semantic_family": "pfs_tunnel_vxlan_filter",
        "example_type": "synthesis",
        "dataset_version": "v2",
        "source_kind": "new_v2",
        "generator_id": "bpf_sft_v2_generator",
        "generation_attempt": 1,
        "gold_source_sha256": "a" * 64,
        "task_spec_sha256": "b" * 64,
        "fixture_manifest_sha256": "c" * 64,
        "messages": [
            {"role": "system", "content": "Sys"},
            {"role": "user", "content": "User 1"},
            {"role": "assistant", "content": VALID_V2_C_PROGRAM},
        ],
    }

    test_file = tmp_path / "dup.jsonl"
    test_file.write_text(json.dumps(record) + "\n" + json.dumps(record) + "\n", encoding="utf-8")

    with pytest.raises(ValidationError, match="Duplicate example_id"):
        validate_sft_v2_dataset(test_file, check_token_lengths=False)


# ---------------------------------------------------------------------------
# 4. Semantic Family Concentration & Split Integrity Tests
# ---------------------------------------------------------------------------

def test_v2_semantic_family_concentration_rejection(tmp_path):
    # Create 100 rows where 10 rows belong to the same family (10% > 5.0% ceiling)
    rows = []
    for i in range(100):
        fam = "dominant_family" if i < 10 else f"fam_{i}"
        rows.append({
            "example_id": f"ex_{i:03d}",
            "task_id": f"t_{i:03d}",
            "category": "packet_filtering_security",
            "difficulty": "level_1",
            "template_family": fam,
            "semantic_family": fam,
            "example_type": "synthesis",
            "dataset_version": "v2",
            "source_kind": "new_v2",
            "generator_id": "bpf_sft_v2_generator",
            "generation_attempt": 1,
            "gold_source_sha256": "a" * 64,
            "task_spec_sha256": "b" * 64,
            "fixture_manifest_sha256": "c" * 64,
            "messages": [
                {"role": "system", "content": "Sys"},
                {"role": "user", "content": f"User {i}"},
                {"role": "assistant", "content": VALID_V2_C_PROGRAM},
            ],
        })

    test_file = tmp_path / "high_conc.jsonl"
    test_file.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")

    with pytest.raises(ValidationError, match="exceeds 5.0% threshold"):
        validate_sft_v2_dataset(test_file, check_token_lengths=False, is_v2_delta=True)


def test_v2_3way_split_disjointness(tmp_path):
    train_file = tmp_path / "train.jsonl"
    val_in_file = tmp_path / "validation_in_domain.jsonl"
    val_ho_file = tmp_path / "validation_family_heldout.jsonl"
    manifest_file = tmp_path / "freeze_manifest.json"

    r_train = {
        "example_id": "train_01",
        "task_id": "t_train_01",
        "category": "packet_filtering_security",
        "difficulty": "level_1",
        "template_family": "pfs_standard_fam",
        "semantic_family": "pfs_standard_fam",
        "example_type": "synthesis",
        "dataset_version": "v2",
        "source_kind": "new_v2",
        "generator_id": "gen",
        "generation_attempt": 1,
        "gold_source_sha256": "a" * 64,
        "task_spec_sha256": "b" * 64,
        "fixture_manifest_sha256": "c" * 64,
        "messages": [{"role": "system", "content": "s"}, {"role": "user", "content": "u"}, {"role": "assistant", "content": VALID_V2_C_PROGRAM}],
    }
    r_val_in = {
        "example_id": "val_in_01",
        "task_id": "t_val_in_01",
        "category": "packet_filtering_security",
        "difficulty": "level_1",
        "template_family": "pfs_standard_fam",
        "semantic_family": "pfs_standard_fam",
        "example_type": "synthesis",
        "dataset_version": "v2",
        "source_kind": "new_v2",
        "generator_id": "gen",
        "generation_attempt": 1,
        "gold_source_sha256": "a" * 64,
        "task_spec_sha256": "b" * 64,
        "fixture_manifest_sha256": "c" * 64,
        "messages": [{"role": "system", "content": "s"}, {"role": "user", "content": "u"}, {"role": "assistant", "content": VALID_V2_C_PROGRAM}],
    }
    r_val_ho = {
        "example_id": "val_ho_01",
        "task_id": "t_val_ho_01",
        "category": "packet_filtering_security",
        "difficulty": "level_1",
        "template_family": "pfs_srv6_security_policy",
        "semantic_family": "pfs_srv6_security_policy",
        "example_type": "synthesis",
        "dataset_version": "v2",
        "source_kind": "new_v2",
        "generator_id": "gen",
        "generation_attempt": 1,
        "gold_source_sha256": "a" * 64,
        "task_spec_sha256": "b" * 64,
        "fixture_manifest_sha256": "c" * 64,
        "messages": [{"role": "system", "content": "s"}, {"role": "user", "content": "u"}, {"role": "assistant", "content": VALID_V2_C_PROGRAM}],
    }

    train_file.write_text(json.dumps(r_train) + "\n", encoding="utf-8")
    val_in_file.write_text(json.dumps(r_val_in) + "\n", encoding="utf-8")
    val_ho_file.write_text(json.dumps(r_val_ho) + "\n", encoding="utf-8")

    manifest = {
        "outputs": {
            "train_sha256": compute_file_sha256(train_file),
            "validation_in_domain_sha256": compute_file_sha256(val_in_file),
            "validation_family_heldout_sha256": compute_file_sha256(val_ho_file),
        }
    }
    manifest_file.write_text(json.dumps(manifest), encoding="utf-8")

    res = validate_3way_splits_and_manifest(
        frozen_dir=tmp_path,
        manifest_path=manifest_file,
        heldout_families=["pfs_srv6_security_policy"],
    )
    assert res["status"] == "PASS"
    assert res["task_grouping_compliant"] is True
    assert res["heldout_families_isolated"] is True


def test_v2_heldout_family_contamination_rejection(tmp_path):
    train_file = tmp_path / "train.jsonl"
    val_in_file = tmp_path / "validation_in_domain.jsonl"
    val_ho_file = tmp_path / "validation_family_heldout.jsonl"
    manifest_file = tmp_path / "freeze_manifest.json"

    # Leak heldout family into train
    r_leaked_train = {
        "example_id": "train_leak",
        "task_id": "t_leak_train",
        "category": "packet_filtering_security",
        "difficulty": "level_1",
        "template_family": "pfs_srv6_security_policy",
        "semantic_family": "pfs_srv6_security_policy",
        "example_type": "synthesis",
        "dataset_version": "v2",
        "source_kind": "new_v2",
        "generator_id": "gen",
        "generation_attempt": 1,
        "gold_source_sha256": "a" * 64,
        "task_spec_sha256": "b" * 64,
        "fixture_manifest_sha256": "c" * 64,
        "messages": [{"role": "system", "content": "s"}, {"role": "user", "content": "u"}, {"role": "assistant", "content": VALID_V2_C_PROGRAM}],
    }
    r_val_in = {
        "example_id": "val_in_ex",
        "task_id": "t_val_in_unique",
        "category": "packet_filtering_security",
        "difficulty": "level_1",
        "template_family": "pfs_standard_fam",
        "semantic_family": "pfs_standard_fam",
        "example_type": "synthesis",
        "dataset_version": "v2",
        "source_kind": "new_v2",
        "generator_id": "gen",
        "generation_attempt": 1,
        "gold_source_sha256": "a" * 64,
        "task_spec_sha256": "b" * 64,
        "fixture_manifest_sha256": "c" * 64,
        "messages": [{"role": "system", "content": "s"}, {"role": "user", "content": "u"}, {"role": "assistant", "content": VALID_V2_C_PROGRAM}],
    }
    r_val_ho = {
        "example_id": "val_ho_ex",
        "task_id": "t_val_ho_unique",
        "category": "packet_filtering_security",
        "difficulty": "level_1",
        "template_family": "pfs_srv6_security_policy",
        "semantic_family": "pfs_srv6_security_policy",
        "example_type": "synthesis",
        "dataset_version": "v2",
        "source_kind": "new_v2",
        "generator_id": "gen",
        "generation_attempt": 1,
        "gold_source_sha256": "a" * 64,
        "task_spec_sha256": "b" * 64,
        "fixture_manifest_sha256": "c" * 64,
        "messages": [{"role": "system", "content": "s"}, {"role": "user", "content": "u"}, {"role": "assistant", "content": VALID_V2_C_PROGRAM}],
    }

    train_file.write_text(json.dumps(r_leaked_train) + "\n", encoding="utf-8")
    val_in_file.write_text(json.dumps(r_val_in) + "\n", encoding="utf-8")
    val_ho_file.write_text(json.dumps(r_val_ho) + "\n", encoding="utf-8")

    manifest = {
        "outputs": {
            "train_sha256": compute_file_sha256(train_file),
            "validation_in_domain_sha256": compute_file_sha256(val_in_file),
            "validation_family_heldout_sha256": compute_file_sha256(val_ho_file),
        }
    }
    manifest_file.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ValueError, match="CRITICAL CONTAMINATION"):
        validate_3way_splits_and_manifest(
            frozen_dir=tmp_path,
            manifest_path=manifest_file,
            heldout_families=["pfs_srv6_security_policy"],
        )


# ---------------------------------------------------------------------------
# 5. Benchmark Leakage Detection Tests
# ---------------------------------------------------------------------------

def test_v2_benchmark_leakage_detection():
    mock_benchmark = [
        {
            "task_id": "pfs_l1_tcp23_drop",
            "type": "calibration",
            "prompt": "Write an XDP program that drops Telnet traffic on TCP port 23.",
            "prompt_sha256": compute_string_sha256("Write an XDP program that drops Telnet traffic on TCP port 23."),
            "code": VALID_V2_C_PROGRAM,
            "code_sha256": compute_string_sha256(VALID_V2_C_PROGRAM),
            "path": "data/calibration/pfs_l1_tcp23_drop/task.json",
        }
    ]

    # Row that copies the benchmark task ID
    leaked_row = {
        "example_id": "leaked_ex",
        "task_id": "pfs_l1_tcp23_drop",
        "messages": [
            {"role": "system", "content": "Sys"},
            {"role": "user", "content": "Write an XDP program that drops Telnet traffic on TCP port 23."},
            {"role": "assistant", "content": VALID_V2_C_PROGRAM},
        ],
    }

    audit = run_benchmark_leakage_audit([leaked_row], mock_benchmark)
    assert audit["is_isolated"] is False
    assert audit["exact_id_leaks_count"] == 1
    assert audit["exact_prompt_leaks_count"] == 1
    assert audit["exact_code_leaks_count"] == 1
    assert audit["certification_status"] == "FAILED_LEAKAGE_DETECTED"


# ---------------------------------------------------------------------------
# 6. Live Verification of Frozen SFT v2 Dataset
# ---------------------------------------------------------------------------

def test_live_v2_delta_and_frozen_splits():
    v2_delta_path = PROJECT_ROOT / "data" / "sft" / "v2" / "v2_delta.jsonl"
    frozen_dir = PROJECT_ROOT / "data" / "sft" / "frozen" / "v2"

    assert v2_delta_path.is_file(), f"v2_delta.jsonl not found at {v2_delta_path}"
    assert (frozen_dir / "train.jsonl").is_file()
    assert (frozen_dir / "validation_in_domain.jsonl").is_file()
    assert (frozen_dir / "validation_family_heldout.jsonl").is_file()
    assert (frozen_dir / "freeze_manifest.json").is_file()

    # 1. Validate v2 delta
    v2_stats = validate_sft_v2_dataset(v2_delta_path, check_token_lengths=False, is_v2_delta=True)
    assert v2_stats["total_examples"] == 1200
    assert v2_stats["unique_tasks"] == 720
    assert v2_stats["example_types"]["synthesis"] == 720
    assert v2_stats["example_types"]["repair"] == 480
    assert v2_stats["semantic_families_count"] == 36

    # 2. Validate 3-way splits & manifest
    split_stats = validate_3way_splits_and_manifest(frozen_dir=frozen_dir)
    assert split_stats["total_rows"] == 1600
    assert split_stats["train_rows"] == 1297
    assert split_stats["val_in_domain_rows"] == 159
    assert split_stats["val_family_heldout_rows"] == 144
    assert split_stats["hashes_verified"] is True
    assert split_stats["heldout_families_isolated"] is True
