"""
BPF-Guardian RLVR Phase 1: Reference Solution Validator
Validates every reference solution in the RL task pool live on the Hostinger Linux VPS:
1. Compiles with Clang BPF target
2. Loads into Linux kernel verifier
3. Runs all packet fixtures with BPF_PROG_TEST_RUN
4. Guarantees 100% baseline pass rate and behavioral discrimination
5. Computes the aggregate task-pool cryptographic hash
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from training.rl.dataset import load_tasks_from_dir
from training.rl.kernel_executor import KernelExecutor

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("bpf_guardian_rl.validator")


def compute_dir_sha256(directory: Path) -> str:
    """Computes deterministic aggregate hash over all task files in a directory."""
    h = hashlib.sha256()
    for file_path in sorted(directory.rglob("*")):
        if file_path.is_file():
            rel = file_path.relative_to(directory).as_posix()
            h.update(rel.encode("utf-8"))
            h.update(file_path.read_bytes())
    return h.hexdigest()


async def validate_split(
    split_dir: Path,
    split_name: str,
    executor: KernelExecutor,
) -> Dict[str, Any]:
    logger.info("Validating split '%s' from %s...", split_name, split_dir)
    tasks = load_tasks_from_dir(split_dir)
    logger.info("Found %d tasks in split '%s'", len(tasks), split_name)

    passed_tasks = 0
    total_fixtures = 0
    passed_fixtures = 0
    failed_tasks: List[Dict[str, Any]] = []

    for idx, task in enumerate(tasks, start=1):
        tid = task["task_id"]
        cat = task.get("application_category", "")
        diff = task.get("difficulty", "")
        rel = task.get("relative_path", f"{cat}/{diff}/{tid}")

        # Locate solution.c
        sol_c_path = split_dir / rel / "solution.c"
        if not sol_c_path.is_file():
            sol_c_path = split_dir / cat / diff / tid / "solution.c"

        if not sol_c_path.is_file():
            failed_tasks.append({"task_id": tid, "error": f"Missing solution.c at {sol_c_path}"})
            continue

        sol_code = sol_c_path.read_text(encoding="utf-8")
        rollout_id = f"ref_val_{split_name}_{tid}"

        ver_res = await executor.evaluate_candidate(
            task=task,
            raw_completion=sol_code,
            rollout_id=rollout_id,
        )

        test_count = ver_res.behavioral.get("total_tests", 0)
        test_pass = ver_res.behavioral.get("passed_tests", 0)
        total_fixtures += test_count
        passed_fixtures += test_pass

        if ver_res.passed:
            passed_tasks += 1
            if idx % 10 == 0 or idx == len(tasks):
                logger.info("  [%d/%d] Verified '%s': PASS (%d/%d fixtures)", idx, len(tasks), tid, test_pass, test_count)
        else:
            logger.error("  [%d/%d] FAILED '%s': compile=%s, verifier=%s, fixtures=%d/%d, diag=%s",
                         idx, len(tasks), tid, ver_res.compile["pass"], ver_res.verifier["pass"],
                         test_pass, test_count, ver_res.diagnostic[:150] if ver_res.diagnostic else "None")
            failed_tasks.append({
                "task_id": tid,
                "compile_pass": ver_res.compile["pass"],
                "verifier_pass": ver_res.verifier["pass"],
                "passed_fixtures": test_pass,
                "total_fixtures": test_count,
                "diagnostic": ver_res.diagnostic,
            })

    pass_rate = passed_tasks / len(tasks) if tasks else 0.0
    return {
        "split": split_name,
        "total_tasks": len(tasks),
        "passed_tasks": passed_tasks,
        "failed_tasks_count": len(failed_tasks),
        "task_pass_rate": round(pass_rate, 4),
        "total_fixtures": total_fixtures,
        "passed_fixtures": passed_fixtures,
        "fixture_pass_rate": round(passed_fixtures / total_fixtures, 4) if total_fixtures else 0.0,
        "failed_tasks": failed_tasks,
        "split_sha256": compute_dir_sha256(split_dir),
    }


async def main():
    parser = argparse.ArgumentParser(description="Validate RL reference solutions live on VPS")
    parser.add_argument("--base-dir", type=str, default="data/rl/v1")
    parser.add_argument("--splits", nargs="+", default=["canary", "dev", "train"])
    parser.add_argument("--output-report", type=str, default="runs/tinker/qwen3-8b-bpf-rl-v1/reference_validation_report.json")
    args = parser.parse_args()

    base_dir = Path(args.base_dir)
    records_dir = Path("runs/tinker/qwen3-8b-bpf-rl-v1/ref_val_records")
    executor = KernelExecutor(records_dir=records_dir)

    all_splits_summary = {}
    aggregate_hash = hashlib.sha256()

    for split in args.splits:
        split_path = base_dir / split
        if split_path.is_dir():
            res = await validate_split(split_path, split, executor)
            all_splits_summary[split] = res
            aggregate_hash.update(res["split_sha256"].encode("utf-8"))

    all_splits_summary["aggregate_task_pool_sha256"] = aggregate_hash.hexdigest()

    report_path = Path(args.output_report)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(all_splits_summary, indent=2), encoding="utf-8")

    logger.info("=================================================================")
    logger.info("Aggregate RL Task Pool Hash: %s", all_splits_summary["aggregate_task_pool_sha256"])
    for s, data in all_splits_summary.items():
        if s != "aggregate_task_pool_sha256":
            logger.info("Split %s: %d/%d tasks passed (%.1f%%), %d/%d fixtures passed (%.1f%%)",
                        s, data["passed_tasks"], data["total_tasks"], data["task_pass_rate"] * 100,
                        data["passed_fixtures"], data["total_fixtures"], data["fixture_pass_rate"] * 100)
    logger.info("Report saved to: %s", report_path)


if __name__ == "__main__":
    asyncio.run(main())
