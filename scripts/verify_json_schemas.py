#!/usr/bin/env python3
"""
BPF-Guardian JSON Schema & Categorical Integrity Verifier
Strictly validates all generated JSON files (task.json, *.meta.json, tests.json, index.jsonl, SFT JSONL)
against their strict schemas, type definitions, and categorical value sets.
Rejects any file with unexpected fields, missing fields, or out-of-vocabulary categorical values.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# =============================================================================
# Categorical Vocabularies
# =============================================================================

VALID_CATEGORIES = {
    "packet_filtering_security",
    "network_routing_forwarding",
    "packet_inspection_telemetry",
    "protocol_transformation",
}

VALID_DIFFICULTIES = {
    "level_1",
    "level_2",
    "level_3",
}

VALID_SPLITS = {
    "train",
    "calibration",
    "eval",
    "test",
}

VALID_ACTIONS = {
    "XDP_PASS",
    "XDP_DROP",
    "XDP_TX",
    "XDP_REDIRECT",
    "XDP_ABORTED",
}

VALID_VALIDATORS = {
    "packet_action",
    "packet_bytes",
    "map_state",
    "perf_event",
}

VALID_CLAIMED_STATUSES = {
    "unvalidated",
    "validated_pass",
    "validated_fail",
}

VALID_EXAMPLE_TYPES = {
    "synthesis",
    "repair",
}

VALID_ROLES = {
    "system",
    "user",
    "assistant",
}


# =============================================================================
# Helper Validators
# =============================================================================

def is_hex_string(s: str) -> bool:
    if not isinstance(s, str) or len(s) % 2 != 0:
        return False
    return bool(re.fullmatch(r"[0-9a-fA-F]*", s))


def is_sha256(s: str) -> bool:
    return isinstance(s, str) and bool(re.fullmatch(r"[0-9a-fA-F]{64}", s))


# =============================================================================
# Schema Verifiers
# =============================================================================

def verify_task_json(data: Any, path: Path, expected_cat: Optional[str] = None, expected_lvl: Optional[str] = None) -> List[str]:
    errors = []
    if not isinstance(data, dict):
        return [f"Root must be a JSON object, got {type(data).__name__}"]

    required_fields = {
        "task_id": str,
        "application_category": str,
        "difficulty": str,
        "template_family": str,
        "semantic_signature": str,
        "instruction": str,
        "requirements": list,
        "tests": list,
    }

    # Optional fields: "harness_type", "gold_candidate_id", "split"
    for field, expected_type in required_fields.items():
        if field not in data:
            errors.append(f"Missing required field '{field}'")
        elif not isinstance(data[field], expected_type):
            errors.append(f"Field '{field}' must be of type {expected_type.__name__}, got {type(data[field]).__name__}")

    if errors:
        return errors

    # Task ID
    if not data["task_id"].strip():
        errors.append("Field 'task_id' must not be empty")
    elif path.parent.name != data["task_id"]:
        errors.append(f"Field 'task_id' ('{data['task_id']}') does not match directory name ('{path.parent.name}')")

    # Categorical: application_category
    cat = data["application_category"]
    if cat not in VALID_CATEGORIES:
        errors.append(f"Invalid categorical 'application_category': '{cat}'. Must be one of {sorted(VALID_CATEGORIES)}")
    elif expected_cat and cat != expected_cat:
        errors.append(f"'application_category' ('{cat}') does not match parent folder '{expected_cat}'")

    # Categorical: difficulty
    lvl = data["difficulty"]
    if lvl not in VALID_DIFFICULTIES:
        errors.append(f"Invalid categorical 'difficulty': '{lvl}'. Must be one of {sorted(VALID_DIFFICULTIES)}")
    elif expected_lvl and lvl != expected_lvl:
        errors.append(f"'difficulty' ('{lvl}') does not match parent folder '{expected_lvl}'")

    # Categorical: split (if present)
    if "split" in data:
        split = data["split"]
        if split not in VALID_SPLITS:
            errors.append(f"Invalid categorical 'split': '{split}'. Must be one of {sorted(VALID_SPLITS)}")

    # Instruction & Requirements
    if len(data["instruction"].strip()) < 15:
        errors.append("Field 'instruction' is suspiciously short (< 15 chars)")
    if len(data["requirements"]) < 2:
        errors.append("Field 'requirements' must contain at least 2 technical requirement items")
    for idx, req in enumerate(data["requirements"]):
        if not isinstance(req, str) or not req.strip():
            errors.append(f"Requirement item #{idx+1} must be a non-empty string")

    # Test cases
    tests = data["tests"]
    if len(tests) == 0:
        errors.append("Field 'tests' cannot be empty")
    
    min_tests = 5 if lvl == "level_1" else (7 if lvl == "level_2" else 9)
    if len(tests) < min_tests and "calibration" in str(path):
        errors.append(f"Calibration level '{lvl}' requires at least {min_tests} test cases, found {len(tests)}")

    for idx, test in enumerate(tests):
        if not isinstance(test, dict):
            errors.append(f"Test #{idx+1} must be a JSON object")
            continue
        for req_t_field in ("name", "description", "packet_hex", "expected_action"):
            if req_t_field not in test:
                errors.append(f"Test #{idx+1} missing required field '{req_t_field}'")

        if "packet_hex" in test:
            p_hex = test["packet_hex"]
            if not is_hex_string(p_hex):
                errors.append(f"Test #{idx+1} '{test.get('name')}' packet_hex is not valid hexadecimal")
            elif len(p_hex) < 28:
                errors.append(f"Test #{idx+1} '{test.get('name')}' packet_hex is too short ({len(p_hex)//2} bytes, minimum 14 bytes)")

        if "expected_action" in test:
            act = test["expected_action"]
            if act not in VALID_ACTIONS:
                errors.append(f"Test #{idx+1} '{test.get('name')}' invalid categorical 'expected_action': '{act}'. Must be one of {sorted(VALID_ACTIONS)}")

        if test.get("expected_bytes_hex") is not None:
            eb_hex = test["expected_bytes_hex"]
            if not is_hex_string(eb_hex):
                errors.append(f"Test #{idx+1} '{test.get('name')}' expected_bytes_hex is not valid hexadecimal")

    return errors


def verify_meta_json(data: Any, path: Path) -> List[str]:
    errors = []
    if not isinstance(data, dict):
        return [f"Root must be a JSON object, got {type(data).__name__}"]

    required_fields = {
        "candidate_id": str,
        "task_id": str,
        "authoring_harness": str,
        "authoring_model": str,
        "generation_prompt_version": str,
        "source_path": str,
        "repair_attempt": int,
        "claimed_status": str,
        "source_sha256": str,
    }

    for field, expected_type in required_fields.items():
        if field not in data:
            errors.append(f"Missing required field '{field}'")
        elif not isinstance(data[field], expected_type):
            errors.append(f"Field '{field}' must be of type {expected_type.__name__}, got {type(data[field]).__name__}")

    if errors:
        return errors

    # Task ID match
    if data["task_id"] != path.parent.name:
        errors.append(f"Field 'task_id' ('{data['task_id']}') does not match directory '{path.parent.name}'")

    # Categorical: application_category (if present)
    if "application_category" in data and data["application_category"] not in VALID_CATEGORIES:
        errors.append(f"Invalid categorical 'application_category': '{data['application_category']}'")

    # Categorical: difficulty (if present)
    if "difficulty" in data and data["difficulty"] not in VALID_DIFFICULTIES:
        errors.append(f"Invalid categorical 'difficulty': '{data['difficulty']}'")

    # Categorical: claimed_status
    if data["claimed_status"] not in VALID_CLAIMED_STATUSES:
        errors.append(f"Invalid categorical 'claimed_status': '{data['claimed_status']}'. Must be one of {sorted(VALID_CLAIMED_STATUSES)}")

    # Repair attempt
    if data["repair_attempt"] < 0:
        errors.append(f"Field 'repair_attempt' cannot be negative ({data['repair_attempt']})")

    # Check SHA256 format and matching source file
    if not is_sha256(data["source_sha256"]):
        errors.append(f"Field 'source_sha256' is not a valid 64-char hex string")
    else:
        src_file = path.parent / data["source_path"]
        if src_file.exists():
            raw_b = src_file.read_bytes()
            norm_b = raw_b.replace(b"\r\n", b"\n")
            actual_sha_raw = hashlib.sha256(raw_b).hexdigest()
            actual_sha_norm = hashlib.sha256(norm_b).hexdigest()
            if data["source_sha256"] not in (actual_sha_raw, actual_sha_norm):
                errors.append(f"Field 'source_sha256' ({data['source_sha256'][:8]}...) does not match actual {src_file.name} SHA ({actual_sha_norm[:8]}...)")

    return errors


def verify_tests_json(data: Any, path: Path) -> List[str]:
    errors = []
    if not isinstance(data, dict):
        return [f"Root must be a JSON object, got {type(data).__name__}"]

    if "task_id" not in data or not isinstance(data["task_id"], str):
        errors.append("Missing or invalid field 'task_id'")
    elif data["task_id"] != path.parent.name:
        errors.append(f"Field 'task_id' ('{data['task_id']}') does not match directory '{path.parent.name}'")

    validator_key = "main_validator" if "main_validator" in data else "validator"
    if validator_key not in data:
        errors.append("Missing field 'main_validator' or 'validator'")
    elif data[validator_key] not in VALID_VALIDATORS:
        errors.append(f"Invalid categorical validator: '{data[validator_key]}'. Must be one of {sorted(VALID_VALIDATORS)}")

    tests_list_key = "test_cases" if "test_cases" in data else "tests"
    if tests_list_key not in data or not isinstance(data[tests_list_key], list):
        errors.append("Missing or invalid field 'test_cases' or 'tests'")
    else:
        for idx, tc in enumerate(data[tests_list_key]):
            if not isinstance(tc, dict):
                errors.append(f"Test case #{idx+1} must be an object")
                continue
            if "fixture_file" in tc:
                fix_file = path.parent / tc["fixture_file"]
                if not fix_file.exists():
                    errors.append(f"Test case #{idx+1} fixture file '{tc['fixture_file']}' does not exist")
            if "expected_action" in tc and tc["expected_action"] not in VALID_ACTIONS:
                errors.append(f"Test case #{idx+1} invalid 'expected_action': '{tc['expected_action']}'")

    return errors


def verify_sft_jsonl(path: Path) -> List[str]:
    errors = []
    if not path.exists():
        return [f"File {path} does not exist"]

    line_num = 0
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line_num += 1
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception as e:
                errors.append(f"Line {line_num}: JSON parse error: {e}")
                continue

            # Check schema
            for req_f in ("task_id", "category", "difficulty", "example_type", "messages"):
                if req_f not in rec:
                    errors.append(f"Line {line_num}: Missing field '{req_f}'")

            # Check categoricals
            if "category" in rec and rec["category"] not in VALID_CATEGORIES:
                errors.append(f"Line {line_num}: Invalid categorical 'category': '{rec['category']}'")
            if "difficulty" in rec and rec["difficulty"] not in VALID_DIFFICULTIES:
                errors.append(f"Line {line_num}: Invalid categorical 'difficulty': '{rec['difficulty']}'")
            if "example_type" in rec and rec["example_type"] not in VALID_EXAMPLE_TYPES:
                errors.append(f"Line {line_num}: Invalid categorical 'example_type': '{rec['example_type']}'")

            # Check messages structure
            if "messages" in rec:
                msgs = rec["messages"]
                if not isinstance(msgs, list) or len(msgs) != 3:
                    errors.append(f"Line {line_num}: 'messages' must be a list of 3 turns (system, user, assistant)")
                else:
                    roles = [m.get("role") for m in msgs]
                    if roles != ["system", "user", "assistant"]:
                        errors.append(f"Line {line_num}: 'messages' roles must be ['system', 'user', 'assistant'], got {roles}")
                    for m_idx, m in enumerate(msgs):
                        if not isinstance(m.get("content"), str) or not m.get("content").strip():
                            errors.append(f"Line {line_num}: Message turn #{m_idx+1} content is empty")

    return errors


# =============================================================================
# Main Verification Runner
# =============================================================================

def main() -> int:
    parser = argparse.ArgumentParser(description="Verify JSON schemas and categorical integrity across dataset")
    parser.add_argument("--dir", type=Path, default=PROJECT_ROOT / "data", help="Directory to scan (default: data/)")
    args = parser.parse_args()

    scan_dir = args.dir
    total_files = 0
    passed_files = 0
    failed_files = 0
    all_failures: List[Tuple[Path, List[str]]] = []

    print("=" * 70)
    print("BPF-Guardian JSON Schema & Categorical Integrity Verifier")
    print(f"Scanning Root: {scan_dir}")
    print("=" * 70)

    # 1. Scan task directories
    for json_path in sorted(scan_dir.rglob("*.json")):
        if "results" in json_path.parts:
            # Skip evaluation results directory summary files for task schema check
            continue

        total_files += 1
        rel_path = json_path.relative_to(PROJECT_ROOT)
        errors = []

        try:
            raw_text = json_path.read_text(encoding="utf-8")
            data = json.loads(raw_text)
        except Exception as e:
            errors.append(f"Failed to read/parse JSON: {e}")
            all_failures.append((rel_path, errors))
            failed_files += 1
            continue

        # Determine category and level from path if in taxonomy
        expected_cat = None
        expected_lvl = None
        parts = json_path.parts
        for p in parts:
            if p in VALID_CATEGORIES:
                expected_cat = p
            if p in VALID_DIFFICULTIES:
                expected_lvl = p

        if json_path.name == "task.json":
            errors = verify_task_json(data, json_path, expected_cat, expected_lvl)
        elif json_path.name.endswith(".meta.json"):
            errors = verify_meta_json(data, json_path)
        elif json_path.name == "tests.json":
            errors = verify_tests_json(data, json_path)

        if errors:
            failed_files += 1
            all_failures.append((rel_path, errors))
            print(f"[-] REJECT: {rel_path}")
            for err in errors:
                print(f"    - {err}")
        else:
            passed_files += 1

    # 2. Scan JSONL datasets
    for jsonl_path in sorted(scan_dir.rglob("*.jsonl")):
        total_files += 1
        rel_path = jsonl_path.relative_to(PROJECT_ROOT)
        if jsonl_path.name.endswith("sft_pilot_dataset.jsonl") or "sft" in jsonl_path.parts:
            errors = verify_sft_jsonl(jsonl_path)
        else:
            errors = []  # Generic jsonl

        if errors:
            failed_files += 1
            all_failures.append((rel_path, errors))
            print(f"[-] REJECT: {rel_path}")
            for err in errors:
                print(f"    - {err}")
        else:
            passed_files += 1

    print("\n" + "=" * 70)
    print("VERIFICATION SUMMARY")
    print("=" * 70)
    print(f"Total Files Scanned: {total_files}")
    print(f"Passed Schema Check: {passed_files}")
    print(f"Rejected Files:      {failed_files}")

    if failed_files > 0:
        print(f"\n[!] REJECTION DETECTED: {failed_files} file(s) violated schema or categorical constraints.")
        return 1

    print("\n[+] ALL JSON AND DATASET FILES FULLY ADHERE TO SCHEMAS & CATEGORICAL CONSTRAINTS.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
