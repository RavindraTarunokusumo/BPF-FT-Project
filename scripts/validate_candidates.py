#!/usr/bin/env python3
"""
Candidate Validation Runner
Validates all candidates across category and level directories in data/inbox/
Records validation diagnostics under data/validation/<category>/<level>/<candidate-id>.json.
Skips candidates whose validation record already exists with the same source hash.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from verifier.engine import BPFValidator, compute_sha256


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate BPF candidates in inbox")
    parser.add_argument(
        "--category",
        type=str,
        default=None,
        help="Optional application category to validate",
    )
    parser.add_argument(
        "--level",
        type=str,
        default=None,
        help="Optional difficulty level to validate",
    )
    parser.add_argument(
        "--inbox-root",
        type=Path,
        default=PROJECT_ROOT / "data" / "inbox",
        help="Root inbox directory for harness",
    )
    parser.add_argument(
        "--validation-root",
        type=Path,
        default=PROJECT_ROOT / "data" / "validation",
        help="Root directory for validation records",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force re-validation even if source hash matches existing record",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    inbox_root = args.inbox_root
    val_root = args.validation_root

    validator = BPFValidator()

    total_candidates = 0
    passed_candidates = 0
    failed_candidates = 0
    skipped_candidates = 0

    print("=" * 60)
    print("BPF-Guardian Candidate Validation Runner")
    print("=" * 60)

    # Discover categories
    cat_dirs = sorted([d for d in inbox_root.iterdir() if d.is_dir()])
    if args.category:
        cat_dirs = [d for d in cat_dirs if d.name == args.category]

    for cat_dir in cat_dirs:
        cat_name = cat_dir.name
        lvl_dirs = sorted([d for d in cat_dir.iterdir() if d.is_dir()])
        if args.level:
            lvl_dirs = [d for d in lvl_dirs if d.name == args.level]

        for lvl_dir in lvl_dirs:
            lvl_name = lvl_dir.name
            val_dir = val_root / cat_name / lvl_name
            val_dir.mkdir(parents=True, exist_ok=True)

            task_dirs = sorted([d for d in lvl_dir.iterdir() if d.is_dir()])
            print(f"\n[*] Validating: {cat_name} / {lvl_name} ({len(task_dirs)} tasks)")

            for task_dir in task_dirs:
                task_id = task_dir.name
                task_json_path = task_dir / "task.json"
                if not task_json_path.exists():
                    print(f"[-] Warning: No task.json in {task_dir}, skipping")
                    continue

                try:
                    task_spec = json.loads(task_json_path.read_text(encoding="utf-8"))
                except Exception as e:
                    print(f"[-] Error parsing task.json in {task_dir}: {e}", file=sys.stderr)
                    continue

                c_files = sorted(task_dir.glob("c*.c"))
                for c_file in c_files:
                    total_candidates += 1
                    cand_stem = c_file.stem.replace("-", "_")
                    cand_id = f"{task_id}_{cand_stem}"

                    meta_path = task_dir / f"{c_file.stem}.meta.json"
                    if meta_path.exists():
                        try:
                            meta_data = json.loads(meta_path.read_text(encoding="utf-8"))
                            cand_id = meta_data.get("candidate_id", cand_id)
                        except Exception:
                            pass

                    val_file = val_dir / f"{cand_id}.json"
                    curr_hash = compute_sha256(c_file)

                    if not args.force and val_file.exists():
                        try:
                            existing_val = json.loads(val_file.read_text(encoding="utf-8"))
                            if existing_val.get("source_sha256") == curr_hash:
                                skipped_candidates += 1
                                status_str = "PASS" if existing_val.get("passed") else "FAIL"
                                print(f"  [*] Task: {task_id} | Candidate: {cand_id} -> Cached ({status_str})")
                                if existing_val.get("passed"):
                                    passed_candidates += 1
                                else:
                                    failed_candidates += 1
                                continue
                        except Exception:
                            pass

                    print(f"  [*] Task: {task_id} | Candidate: {cand_id} ({c_file.name}) -> Running validation...")
                    val_result = validator.validate_candidate(
                        task_id=task_id,
                        candidate_id=cand_id,
                        source_path=c_file,
                        task_spec=task_spec,
                        category=cat_name,
                        level=lvl_name,
                    )

                    val_file.write_text(json.dumps(val_result, indent=2), encoding="utf-8")

                    if val_result["passed"]:
                        passed_candidates += 1
                        print(f"      [+] PASSED all gates (compile: OK, verifier: OK, behavioral: {val_result['behavioral']['passed_tests']}/{val_result['behavioral']['total_tests']})")
                    else:
                        failed_candidates += 1
                        print(f"      [-] FAILED: {val_result.get('diagnostic', 'Unknown error')[:120]}...")

    print(f"\n==================================================")
    print(f"Validation Summary:")
    print(f"  Total candidates:   {total_candidates}")
    print(f"  Passed candidates:  {passed_candidates}")
    print(f"  Failed candidates:  {failed_candidates}")
    print(f"  Skipped (cached):   {skipped_candidates}")
    print(f"==================================================")


if __name__ == "__main__":
    main()
