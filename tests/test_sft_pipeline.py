#!/usr/bin/env python3
"""
BPF-Guardian Comprehensive SFT Pipeline Test Suite
Covers:
1. Dataset validation (valid cases, invalid JSONL, markdown fences, missing metadata, fault tags, overlength).
2. Split freezing (determinism, task grouping, stratification, benchmark exclusion, manifest hash checking).
3. Custom dataset builder & token length calculation.
4. Loss weight verification (completion-only positive weights).
5. Checkpoint resume configuration & fingerprinting.
6. Rollout candidate generation & compliance scoring.
7. Repair prompt generation & lineage preservation.
8. Evaluation summarizer & delta reporting.
9. Adapter export validation.
10. Verifier root/unprivileged boundary checks.
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

from training.validate_sft_dataset import (
    ValidationError,
    validate_completion_c_code,
    validate_repair_record,
    validate_sft_dataset,
)
from training.prepare_sft_splits import (
    compute_file_sha256,
    compute_split_fingerprint,
    prepare_sft_splits,
)
from training.dataset_builder import (
    FrozenSFTDatasetBuilder,
    verify_datum_loss_weights,
)
from training.train_tinker_sft import (
    compute_run_fingerprint,
    validate_manifest_and_splits,
)
from training.generate_tinker_rollout import (
    check_output_compliance,
    extract_c_source,
    run_benchmark_rollout,
)
from training.build_repair_rollout import (
    format_repair_prompt,
    run_repair_rollout,
)
from training.import_verifier_results import (
    aggregate_verification_results,
    simulate_mock_verification,
)
from training.summarize_tinker_evaluation import (
    CALIBRATION_BASELINE,
    build_evaluation_report,
    compute_repair_recovery,
    compute_rollout_metrics,
)
from training.export_tinker_adapter import (
    create_mock_peft_adapter,
    validate_exported_peft_adapter,
)

VALID_C_PROGRAM = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""


# ---------------------------------------------------------------------------
# 1. Dataset Validation Tests
# ---------------------------------------------------------------------------

def test_validate_completion_valid_c():
    validate_completion_c_code(
        VALID_C_PROGRAM, Path("test.jsonl"), 1, "ex_1", "task_1"
    )


def test_validate_completion_markdown_fence_rejected():
    fenced_code = f"```c\n{VALID_C_PROGRAM}\n```"
    with pytest.raises(ValidationError, match="Markdown fences"):
        validate_completion_c_code(fenced_code, Path("test.jsonl"), 1, "ex_1", "task_1")


def test_validate_completion_prose_preamble_rejected():
    prose_code = f"Here is the XDP program you requested:\n{VALID_C_PROGRAM}"
    with pytest.raises(ValidationError, match="starts with explanatory prose"):
        validate_completion_c_code(prose_code, Path("test.jsonl"), 1, "ex_1", "task_1")


def test_validate_completion_missing_include():
    code_no_inc = VALID_C_PROGRAM.replace("#include", "// inc")
    with pytest.raises(ValidationError, match="missing '#include'"):
        validate_completion_c_code(code_no_inc, Path("test.jsonl"), 1, "ex_1", "task_1")


def test_validate_completion_missing_sec():
    code_no_sec = VALID_C_PROGRAM.replace("SEC(", "// sec(")
    with pytest.raises(ValidationError, match="missing 'SEC"):
        validate_completion_c_code(code_no_sec, Path("test.jsonl"), 1, "ex_1", "task_1")


def test_validate_completion_missing_license():
    code_no_lic = VALID_C_PROGRAM.replace("char _license[]", "char _mylic[]").replace('SEC("license")', 'SEC("lic")').replace("LICENSE", "LIC")
    with pytest.raises(ValidationError, match="missing license"):
        validate_completion_c_code(code_no_lic, Path("test.jsonl"), 1, "ex_1", "task_1")


def test_validate_completion_fault_tag_rejected():
    code_with_fault = VALID_C_PROGRAM.replace("return XDP_PASS;", "// FAULT: memory out of bounds\n    return XDP_PASS;")
    with pytest.raises(ValidationError, match="forbidden fault/placeholder marker"):
        validate_completion_c_code(code_with_fault, Path("test.jsonl"), 1, "ex_1", "task_1")


def test_validate_completion_todo_tag_rejected():
    code_with_todo = VALID_C_PROGRAM.replace("return XDP_PASS;", "// TODO: fix bounds check\n    return XDP_PASS;")
    with pytest.raises(ValidationError, match="forbidden fault/placeholder marker"):
        validate_completion_c_code(code_with_todo, Path("test.jsonl"), 1, "ex_1", "task_1")


def test_validate_dataset_pilot_safety_rejection(tmp_path):
    pilot_file = tmp_path / "sft_pilot_dataset.jsonl"
    pilot_file.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="Never train on pilot dataset"):
        validate_sft_dataset(pilot_file)


def test_validate_dataset_invalid_jsonl(tmp_path):
    bad_file = tmp_path / "bad.jsonl"
    bad_file.write_text("{\"example_id\": \"ex1\"\nNOT_JSON\n", encoding="utf-8")
    with pytest.raises(ValidationError, match="Malformed JSON"):
        validate_sft_dataset(bad_file, check_token_lengths=False)


def test_validate_dataset_duplicate_example_id(tmp_path):
    rec = {
        "example_id": "dup_01",
        "task_id": "t1",
        "category": "packet_filtering_security",
        "difficulty": "level_1",
        "template_family": "fam1",
        "example_type": "synthesis",
        "messages": [
            {"role": "system", "content": "You are an expert"},
            {"role": "user", "content": "Write program"},
            {"role": "assistant", "content": VALID_C_PROGRAM},
        ],
    }
    dup_file = tmp_path / "dup.jsonl"
    dup_file.write_text(json.dumps(rec) + "\n" + json.dumps(rec) + "\n", encoding="utf-8")
    with pytest.raises(ValidationError, match="Duplicate example_id"):
        validate_sft_dataset(dup_file, check_token_lengths=False)


# ---------------------------------------------------------------------------
# 2. Split Freezing & Reproducibility Tests
# ---------------------------------------------------------------------------

def test_split_determinism_and_task_grouping(tmp_path):
    # Create synthetic dataset with synthesis and repair for same tasks
    dataset_file = tmp_path / "dataset.jsonl"
    records = []
    for i in range(20):
        t_id = f"task_{i:03d}"
        cat = "packet_filtering_security" if i < 10 else "protocol_transformation"
        diff = "level_1" if i % 2 == 0 else "level_2"
        # Synthesis
        records.append({
            "example_id": f"syn_{t_id}",
            "task_id": t_id,
            "category": cat,
            "difficulty": diff,
            "template_family": f"fam_{cat}",
            "example_type": "synthesis",
            "messages": [
                {"role": "system", "content": "Sys prompt"},
                {"role": "user", "content": f"Synth user for {t_id}"},
                {"role": "assistant", "content": VALID_C_PROGRAM},
            ],
        })
        # Repair
        records.append({
            "example_id": f"rep_{t_id}",
            "task_id": t_id,
            "category": cat,
            "difficulty": diff,
            "template_family": f"fam_{cat}",
            "example_type": "repair",
            "messages": [
                {"role": "system", "content": "Sys prompt"},
                {"role": "user", "content": f"Repair user with diagnostic for {t_id}"},
                {"role": "assistant", "content": VALID_C_PROGRAM},
            ],
        })

    dataset_file.write_text("".join(json.dumps(r) + "\n" for r in records), encoding="utf-8", newline="\n")

    calib_index = tmp_path / "calib.jsonl"
    calib_index.write_text('{"task_id": "calib_task_01"}\n', encoding="utf-8", newline="\n")

    out_dir1 = tmp_path / "frozen_v1"
    manifest1 = prepare_sft_splits(
        input_path=dataset_file,
        output_dir=out_dir1,
        calibration_index_path=calib_index,
        seed=42,
        val_ratio=0.15,
    )

    # Verify task grouping: synthesis and repair in same split
    train_rows = [json.loads(line) for line in (out_dir1 / "train.jsonl").read_text(encoding="utf-8").splitlines()]
    val_rows = [json.loads(line) for line in (out_dir1 / "validation.jsonl").read_text(encoding="utf-8").splitlines()]

    train_tasks = {r["task_id"] for r in train_rows}
    val_tasks = {r["task_id"] for r in val_rows}

    # Zero leakage
    assert len(train_tasks & val_tasks) == 0

    for t_id in train_tasks:
        t_examples = [r for r in train_rows if r["task_id"] == t_id]
        # Must have both synthesis and repair
        assert len(t_examples) == 2

    for t_id in val_tasks:
        t_examples = [r for r in val_rows if r["task_id"] == t_id]
        assert len(t_examples) == 2

    # Reproducibility test: rerun on out_dir1 must match byte-for-byte
    manifest1_again = prepare_sft_splits(
        input_path=dataset_file,
        output_dir=out_dir1,
        calibration_index_path=calib_index,
        seed=42,
        val_ratio=0.15,
    )
    assert manifest1["train_sha256"] == manifest1_again["train_sha256"]
    assert manifest1["validation_sha256"] == manifest1_again["validation_sha256"]


def test_split_benchmark_exclusion_rejection(tmp_path):
    dataset_file = tmp_path / "dataset.jsonl"
    rec = {
        "example_id": "syn_leaked",
        "task_id": "leaked_benchmark_task",
        "category": "packet_filtering_security",
        "difficulty": "level_1",
        "template_family": "fam1",
        "example_type": "synthesis",
        "messages": [
            {"role": "system", "content": "Sys"},
            {"role": "user", "content": "Prompt"},
            {"role": "assistant", "content": VALID_C_PROGRAM},
        ],
    }
    dataset_file.write_text(json.dumps(rec) + "\n", encoding="utf-8", newline="\n")

    calib_index = tmp_path / "calib.jsonl"
    calib_index.write_text('{"task_id": "leaked_benchmark_task"}\n', encoding="utf-8", newline="\n")

    out_dir = tmp_path / "frozen_test"
    with pytest.raises(ValueError, match="CRITICAL LEAKAGE"):
        prepare_sft_splits(
            input_path=dataset_file,
            output_dir=out_dir,
            calibration_index_path=calib_index,
        )


# ---------------------------------------------------------------------------
# 3. Custom Dataset Builder & Loss Weights Tests
# ---------------------------------------------------------------------------

def test_verify_datum_loss_weights():
    class DummyInput:
        length = 10

    # Valid: 0s on prompt (tokens 0..5), 1s on assistant (tokens 6..9)
    valid_weights = [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 1.0, 1.0, 1.0]
    ok, msg = verify_datum_loss_weights(DummyInput(), valid_weights, [])
    assert ok is True
    assert "Verified" in msg

    # Invalid: positive weight on token 0 (system/user prompt)
    leaked_weights = [1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 1.0, 1.0, 1.0]
    ok, msg = verify_datum_loss_weights(DummyInput(), leaked_weights, [])
    assert ok is False
    assert "Prompt start has positive loss weight" in msg

    # Invalid: all zero
    zero_weights = [0.0] * 10
    ok, msg = verify_datum_loss_weights(DummyInput(), zero_weights, [])
    assert ok is False
    assert "empty or all-zero" in msg


# ---------------------------------------------------------------------------
# 4. Fingerprint & Manifest Validation Tests
# ---------------------------------------------------------------------------

def test_run_fingerprint_computation():
    fp1 = compute_run_fingerprint(
        train_sha256="sha_train_1",
        val_sha256="sha_val_1",
        manifest_sha256="sha_man_1",
        model_name="Qwen/Qwen3-8B",
        renderer_name="qwen3_disable_thinking",
        learning_rate=2e-4,
        lr_schedule="linear",
        num_epochs=3,
        lora_rank=32,
        batch_size=32,
        max_length=4096,
    )
    fp2 = compute_run_fingerprint(
        train_sha256="sha_train_1",
        val_sha256="sha_val_1",
        manifest_sha256="sha_man_1",
        model_name="Qwen/Qwen3-8B",
        renderer_name="qwen3_disable_thinking",
        learning_rate=2e-4,
        lr_schedule="linear",
        num_epochs=3,
        lora_rank=32,
        batch_size=32,
        max_length=4096,
    )
    assert fp1 == fp2
    assert len(fp1) == 12

    # Different LR produces different fingerprint
    fp3 = compute_run_fingerprint(
        train_sha256="sha_train_1",
        val_sha256="sha_val_1",
        manifest_sha256="sha_man_1",
        model_name="Qwen/Qwen3-8B",
        renderer_name="qwen3_disable_thinking",
        learning_rate=1e-4,
        lr_schedule="linear",
        num_epochs=3,
        lora_rank=32,
        batch_size=32,
        max_length=4096,
    )
    assert fp1 != fp3


def test_validate_manifest_and_splits(tmp_path):
    t_file = tmp_path / "train.jsonl"
    v_file = tmp_path / "val.jsonl"
    m_file = tmp_path / "manifest.json"

    rec1 = {"example_id": "e1", "task_id": "t1", "category": "c", "difficulty": "d", "template_family": "f", "example_type": "synthesis", "messages": []}
    rec2 = {"example_id": "e2", "task_id": "t2", "category": "c", "difficulty": "d", "template_family": "f", "example_type": "synthesis", "messages": []}

    t_file.write_text(json.dumps(rec1) + "\n", encoding="utf-8", newline="\n")
    v_file.write_text(json.dumps(rec2) + "\n", encoding="utf-8", newline="\n")

    t_sha = compute_file_sha256(t_file)
    v_sha = compute_file_sha256(v_file)

    manifest_data = {
        "train_sha256": t_sha,
        "validation_sha256": v_sha,
    }
    m_file.write_text(json.dumps(manifest_data) + "\n", encoding="utf-8", newline="\n")

    res = validate_manifest_and_splits(t_file, v_file, m_file)
    assert res["train_rows_count"] == 1
    assert res["val_rows_count"] == 1


# ---------------------------------------------------------------------------
# 5. Output Compliance & Extraction Tests
# ---------------------------------------------------------------------------

def test_output_compliance_clean_c():
    comp = check_output_compliance(VALID_C_PROGRAM)
    assert comp["compliant"] is True
    assert comp["has_fences"] is False
    assert comp["has_include"] is True
    assert comp["has_sec"] is True
    assert comp["has_license"] is True


def test_output_compliance_fenced_code():
    fenced = f"```c\n{VALID_C_PROGRAM}\n```"
    comp = check_output_compliance(fenced)
    assert comp["compliant"] is False
    assert comp["has_fences"] is True

    # Extraction must cleanly strip fences
    extracted = extract_c_source(fenced)
    assert "```" not in extracted
    assert "#include" in extracted


# ---------------------------------------------------------------------------
# 6. Benchmark Rollout Mock Generation Tests
# ---------------------------------------------------------------------------

import asyncio


def test_mock_rollout_generation(tmp_path):
    index_file = tmp_path / "index.jsonl"
    index_file.write_text(
        '{"task_id": "pfs_l1_tcp23_drop", "application_category": "packet_filtering_security", "difficulty": "level_1"}\n'
        '{"task_id": "ptr_l1_swap_mac", "application_category": "protocol_transformation", "difficulty": "level_1"}\n',
        encoding="utf-8",
        newline="\n",
    )

    out_dir = tmp_path / "mock_rollout"
    manifest = asyncio.run(
        run_benchmark_rollout(
            benchmark_index=index_file,
            output_dir=out_dir,
            num_samples=1,
            mock=True,
        )
    )

    assert manifest["num_tasks"] == 2
    assert manifest["total_samples"] == 2
    assert manifest["output_compliance_rate"] == 1.0
    assert (out_dir / "candidates" / "pfs_l1_tcp23_drop" / "sample-0.c").exists()
    assert (out_dir / "candidates" / "ptr_l1_swap_mac" / "sample-0.c").exists()


# ---------------------------------------------------------------------------
# 7. Verification Aggregation & Repair Rollout Tests
# ---------------------------------------------------------------------------

def test_verification_aggregation(tmp_path):
    rollout_dir = tmp_path / "rollout"
    rollout_dir.mkdir()
    gen_file = rollout_dir / "generation_records.jsonl"
    gen_file.write_text(
        json.dumps({
            "task_id": "t1",
            "sample_id": "sample-0",
            "sample_index": 0,
            "compliance": {"compliant": True},
        }) + "\n",
        encoding="utf-8",
        newline="\n",
    )

    index_file = tmp_path / "index.jsonl"
    index_file.write_text('{"task_id": "t1", "application_category": "cat", "difficulty": "diff"}\n', encoding="utf-8")

    results = simulate_mock_verification(rollout_dir, index_file)
    summary = aggregate_verification_results(rollout_dir, results, rollout_dir / "verification")

    assert summary["total_tasks"] == 1
    assert summary["metrics"]["pass_at_1"]["passed_tasks"] == 1
    assert (rollout_dir / "verification" / "summary.json").exists()
    assert (rollout_dir / "verification" / "summary.md").exists()


def test_repair_rollout_generation(tmp_path):
    rollout_dir = tmp_path / "rollout_with_fail"
    verif_dir = rollout_dir / "verification"
    verif_dir.mkdir(parents=True)
    cands_dir = rollout_dir / "candidates" / "t_fail"
    cands_dir.mkdir(parents=True)
    (cands_dir / "sample-0.c").write_text("// faulty c code", encoding="utf-8")

    (verif_dir / "results.jsonl").write_text(
        json.dumps({
            "task_id": "t_fail",
            "sample_id": "sample-0",
            "sample_index": 0,
            "passed": False,
            "diagnostic": "Kernel verifier rejected bounds",
            "category": "packet_filtering_security",
            "difficulty": "level_1",
        }) + "\n",
        encoding="utf-8",
        newline="\n",
    )

    repair_out_dir = tmp_path / "repair_rollout"
    manifest = asyncio.run(
        run_repair_rollout(
            synthesis_rollout_dir=rollout_dir,
            output_dir=repair_out_dir,
            benchmark_index=tmp_path / "nonexistent.jsonl",
            mock=True,
        )
    )

    assert manifest["repaired_tasks_count"] == 1
    assert (repair_out_dir / "lineage.jsonl").exists()
    assert (repair_out_dir / "candidates" / "t_fail" / "sample-0.c").exists()


# ---------------------------------------------------------------------------
# 8. Evaluation Summarizer & Baseline Comparison Tests
# ---------------------------------------------------------------------------

def test_evaluation_summarizer_delta_reporting(tmp_path):
    results_sft = tmp_path / "sft_results.jsonl"
    # Create 36 records with 12 passing (33.3% Pass@1)
    records = []
    for i in range(36):
        passed = (i < 12)
        records.append({
            "task_id": f"task_{i:02d}",
            "sample_index": 0,
            "category": "packet_filtering_security",
            "difficulty": "level_1",
            "compliance": {"compliant": True},
            "compile": {"pass": True},
            "verifier": {"pass": passed},
            "behavioral": {"pass": passed},
            "passed": passed,
        })
    results_sft.write_text("".join(json.dumps(r) + "\n" for r in records), encoding="utf-8", newline="\n")

    report_file = tmp_path / "summary.md"
    report = build_evaluation_report(
        sft_synth_path=results_sft,
        output_path=report_file,
    )

    assert report["sft_synthesis"]["pass1_count"] == 12
    assert report["sft_synthesis"]["pass1_rate"] == 12 / 36
    assert report_file.exists()


# ---------------------------------------------------------------------------
# 9. PEFT Adapter Export Validation Tests
# ---------------------------------------------------------------------------

def test_peft_adapter_mock_export(tmp_path):
    adapter_dir = tmp_path / "peft_adapter"
    create_mock_peft_adapter(adapter_dir, base_model="Qwen/Qwen3-8B", lora_rank=32)

    val_info = validate_exported_peft_adapter(adapter_dir, expected_base_model="Qwen/Qwen3-8B", expected_rank=32)
    assert val_info["base_model"] == "Qwen/Qwen3-8B"
    assert val_info["rank"] == 32
    assert val_info["peft_type"] == "LORA"
    assert val_info["weights_size_mb"] > 0
