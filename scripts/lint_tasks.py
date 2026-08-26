#!/usr/bin/env python3
"""
Lint and validate task.json specifications across all batches in data/inbox/

Enforces:
1. All required fields are present and non-empty:
   - task_id (str)
   - template_family (str)
   - semantic_signature (str)
   - difficulty (str: "basic" | "beginner" | "intermediate" | "advanced" | "medium")
   - split (str: "train" | "val" | "test")
   - instruction (str, len >= 10)
   - requirements (list of str, len >= 1)
   - tests (list of dict, len >= 3)
2. Each test case in tests:
   - name (str)
   - description (str)
   - packet_hex (str, valid hex, length >= 28 hex chars / 14 bytes)
   - expected_action (str: "XDP_PASS" | "XDP_DROP" | "XDP_TX" | "XDP_REDIRECT" | "XDP_ABORTED")
3. Test suite diversity:
   - Must contain at least one "XDP_PASS" and at least one "XDP_DROP" (for filtering tasks).
"""

from __future__ import annotations

import argparse
import binascii
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
INBOX_DIR = PROJECT_ROOT / "data" / "inbox"

REQUIRED_TOP_FIELDS = [
    ("task_id", str),
    ("template_family", str),
    ("semantic_signature", str),
    ("difficulty", str),
    ("split", str),
    ("instruction", str),
    ("requirements", list),
    ("tests", list),
]

VALID_ACTIONS = {"XDP_PASS", "XDP_DROP", "XDP_TX", "XDP_REDIRECT", "XDP_ABORTED"}


def lint_task_json(task_path: Path) -> list[str]:
    errors = []

    try:
        data = json.loads(task_path.read_text(encoding="utf-8"))
    except Exception as e:
        return [f"Failed to parse JSON: {e}"]

    # 1. Top-level required fields
    for field_name, expected_type in REQUIRED_TOP_FIELDS:
        if field_name not in data:
            errors.append(f"Missing required field: '{field_name}'")
        elif not isinstance(data[field_name], expected_type):
            errors.append(f"Field '{field_name}' expected type {expected_type.__name__}, got {type(data[field_name]).__name__}")
        elif isinstance(data[field_name], (str, list)) and len(data[field_name]) == 0:
            errors.append(f"Field '{field_name}' is empty")

    if errors:
        return errors

    # Check task_id matches directory name
    expected_task_id = task_path.parent.name
    if data.get("task_id") != expected_task_id:
        errors.append(f"task_id '{data.get('task_id')}' does not match directory name '{expected_task_id}'")

    # Check instruction length
    instruction = data.get("instruction", "")
    if len(instruction.strip()) < 10:
        errors.append(f"Instruction too short ({len(instruction.strip())} chars)")

    # Check requirements
    requirements = data.get("requirements", [])
    if not isinstance(requirements, list) or len(requirements) == 0:
        errors.append("Requirements list must not be empty")

    # Check tests
    tests = data.get("tests", [])
    if not isinstance(tests, list) or len(tests) < 3:
        errors.append(f"Tests suite has only {len(tests) if isinstance(tests, list) else 0} test cases (minimum required is 3)")
        return errors

    actions_seen = set()
    for idx, test in enumerate(tests):
        prefix = f"Test #{idx+1}"
        if not isinstance(test, dict):
            errors.append(f"{prefix} is not a dictionary object")
            continue

        if not test.get("name"):
            errors.append(f"{prefix} missing 'name'")
        if "description" not in test:
            errors.append(f"{prefix} missing 'description'")

        packet_hex = test.get("packet_hex")
        if not packet_hex or not isinstance(packet_hex, str):
            errors.append(f"{prefix} missing or invalid 'packet_hex'")
        else:
            try:
                pkt_bytes = binascii.unhexlify(packet_hex.strip())
                if len(pkt_bytes) < 14:
                    errors.append(f"{prefix} packet_hex is too short ({len(pkt_bytes)} bytes, minimum is 14 bytes)")
            except binascii.Error:
                errors.append(f"{prefix} packet_hex contains invalid hexadecimal characters")

        expected_action = test.get("expected_action")
        if expected_action not in VALID_ACTIONS:
            errors.append(f"{prefix} invalid expected_action '{expected_action}' (must be one of {VALID_ACTIONS})")
        else:
            actions_seen.add(expected_action)

    # For standard filter tasks, expect both pass and drop tests
    if len(actions_seen) < 2 and "xdp_filter" in data.get("template_family", ""):
        errors.append(f"Test suite lacks action diversity (only saw: {actions_seen})")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Lint all task.json files in data/inbox/")
    parser.add_argument("--batch-id", help="Optional specific batch to lint (e.g. batch-002)")
    args = parser.parse_args()

    total_tasks = 0
    passed_tasks = 0
    failed_tasks = 0

    print("=" * 60)
    print("XDP Task Specification Linter (task.json)")
    print("=" * 60)

    batch_dirs = [INBOX_DIR / args.batch_id] if args.batch_id else sorted(INBOX_DIR.iterdir())

    for batch_dir in batch_dirs:
        if not batch_dir.is_dir() or not batch_dir.name.startswith("batch-"):
            continue

        print(f"\n[*] Scanning batch: {batch_dir.name}")
        for task_dir in sorted(batch_dir.iterdir()):
            if not task_dir.is_dir():
                continue

            task_json_path = task_dir / "task.json"
            total_tasks += 1

            if not task_json_path.exists():
                print(f"  [-] FAIL: {task_dir.name} -> task.json NOT FOUND")
                failed_tasks += 1
                continue

            errors = lint_task_json(task_json_path)
            if errors:
                print(f"  [-] FAIL: {task_dir.name}")
                for err in errors:
                    print(f"      - {err}")
                failed_tasks += 1
            else:
                print(f"  [+] PASS: {task_dir.name}")
                passed_tasks += 1

    print("\n" + "=" * 60)
    print(f"Linter Summary: Total: {total_tasks} | Passed: {passed_tasks} | Failed: {failed_tasks}")
    print("=" * 60)

    return 0 if failed_tasks == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
