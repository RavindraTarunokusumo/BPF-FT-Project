"""
BPF-Guardian RLVR Phase N3: Two-Turn Empirical Evaluation Driver
Evaluates checkpoints at T=0.0 across:
1. N3 Dev Set (48 tasks)
2. N3 Confirmation Set (60 tasks)
3. Protected Private Synthesis Benchmark (120 tasks)

Tracks:
- Initial Pass@1 (Turn 1 synthesis)
- Final Solve@2 (Pass@1 + Turn 2 repair recoveries)
- Net recovery gain (Solve@2 - Pass@1)
- Stage-specific recovery rates:
  * Compiler failure recovery rate
  * Kernel verifier failure recovery rate
  * Behavioral failure recovery rate (testing the historical 0/15 barrier)
- Exact paired McNemar statistical significance tests
"""

from __future__ import annotations

import argparse
import asyncio
import datetime
import json
import logging
import math
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Safely load environment variables
env_file = PROJECT_ROOT / ".env"
if env_file.is_file():
    for line in env_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            k = k.strip()
            v = v.strip().strip("\"'")
            if k not in os.environ:
                os.environ[k] = v

import tinker

from training.model_profiles import ModelProfile, get_model_profile
from training.rl.bpf_env import REPAIR_SYSTEM_PROMPT, build_task_prompt
from training.rl.config import (
    DEFAULT_CONFIRMATION_DIR_N3,
    DEFAULT_DEV_DIR_N3,
    NEMOTRON_SFT_V1_SAMPLER_CHECKPOINT,
)
from training.rl.dataset import load_tasks_from_dir
from training.rl.kernel_executor import KernelExecutor, check_output_compliance, extract_c_source
from training.rl.reward import compute_rlvr_reward

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("bpf_guardian_rl.eval_n3")


def compute_exact_mcnemar(b: int, c: int) -> Tuple[float, float]:
    """Computes two-sided McNemar test statistic and exact binomial p-value.
    b: Baseline passed, Candidate failed (regressions)
    c: Baseline failed, Candidate passed (recoveries)
    """
    total = b + c
    if total == 0:
        return 0.0, 1.0

    stat = (abs(b - c) - 1.0) ** 2 / total
    k = min(b, c)
    p_val = 2.0 * sum(math.comb(total, i) * (0.5**total) for i in range(k + 1))
    p_val = min(1.0, max(0.0, p_val))
    return stat, p_val


async def evaluate_two_turn_dataset(
    tasks: List[Dict[str, Any]],
    sampler_checkpoint: str,
    output_dir: Path,
    eval_name: str,
    temperature: float = 0.0,
    max_tokens: int = 2048,
    profile_name: str = "nemotron-3.5-lightning",
) -> Dict[str, Any]:
    """Evaluates a model checkpoint in two turns at T=0.0."""
    logger.info("Evaluating %d tasks on '%s' (two-turn, T=%.1f)...", len(tasks), eval_name, temperature)
    records_dir = output_dir / eval_name / "records"
    records_dir.mkdir(parents=True, exist_ok=True)

    profile = get_model_profile(profile_name)
    tokenizer = profile.get_tokenizer()
    renderer = profile.get_renderer(tokenizer=tokenizer)
    executor = KernelExecutor(records_dir=records_dir)

    service = tinker.ServiceClient()
    if sampler_checkpoint.startswith("tinker://"):
        sampler = service.create_sampling_client(sampler_checkpoint)
    else:
        sampler = await service.create_sampling_client_async(base_model=sampler_checkpoint)

    results: List[Dict[str, Any]] = []
    t0 = time.time()

    turn1_passes = 0
    turn2_recoveries = 0
    turn1_compile_fails = 0
    turn1_verifier_fails = 0
    turn1_behavioral_fails = 0

    rec_from_compile = 0
    rec_from_verifier = 0
    rec_from_behavioral = 0

    for idx, task in enumerate(tasks, start=1):
        task_id = task["task_id"]
        cat = task.get("application_category", "")
        diff = task.get("difficulty", "")
        rollout_id_t1 = f"eval_{eval_name}_{task_id}_t1"

        # Turn 1: Build synthesis prompt
        t1_messages = build_task_prompt(task)
        t1_input = renderer.build_generation_prompt(t1_messages)
        stop_seqs = renderer.get_stop_sequences()

        sample_params = tinker.SamplingParams(
            max_tokens=max_tokens,
            temperature=temperature,
            stop=stop_seqs,
        )

        resp1 = await sampler.sample_async(prompt=t1_input, num_samples=1, sampling_params=sample_params)
        raw_text_t1 = renderer.tokenizer.decode(resp1.sequences[0].tokens)

        # Evaluate Turn 1 on Hostinger Linux VPS
        ver_res_t1 = await executor.evaluate_candidate(
            task=task,
            raw_completion=raw_text_t1,
            rollout_id=rollout_id_t1,
        )

        reward_t1 = compute_rlvr_reward(
            ver_res_t1.to_dict(),
            expected_fixture_count=task.get("expected_fixture_count"),
        )

        t1_passed = reward_t1.is_functionally_correct
        entry = {
            "task_id": task_id,
            "category": cat,
            "difficulty": diff,
            "turn1_compile_pass": ver_res_t1.compile["pass"],
            "turn1_verifier_pass": ver_res_t1.verifier["pass"],
            "turn1_behavioral_pass": ver_res_t1.behavioral["pass"],
            "turn1_passed": t1_passed,
            "turn1_stage": reward_t1.stage_reached,
            "pass_at_1": 1.0 if t1_passed else 0.0,
            "solve_at_2": 1.0 if t1_passed else 0.0,
            "recovered": False,
            "turn2_attempted": False,
            "turn2_compile_pass": None,
            "turn2_verifier_pass": None,
            "turn2_behavioral_pass": None,
            "turn2_passed": None,
            "turn2_stage": None,
            "recovery_type": None,
        }

        if t1_passed:
            turn1_passes += 1
            results.append(entry)
            if idx % 10 == 0 or idx == len(tasks):
                logger.info("  [%d/%d] Task %s: PASS@1", idx, len(tasks), task_id)
            continue

        # Classify Turn 1 failure stage
        entry["turn2_attempted"] = True
        t1_stage = reward_t1.stage_reached
        if t1_stage in ("compliance", "non_compliant"):
            turn1_compile_fails += 1
        elif t1_stage == "compile":
            turn1_verifier_fails += 1
        elif t1_stage in ("verifier", "behavioral"):
            turn1_behavioral_fails += 1

        # Turn 1 failed -> Turn 2 repair
        diagnostic = ver_res_t1.diagnostic or "Verification failed"
        if len(diagnostic) > 4000:
            diagnostic = "...[truncated]...\n" + diagnostic[-4000:]
        extracted_c1 = extract_c_source(raw_text_t1)
        reqs = task.get("requirements", [])
        reqs_formatted = "\n".join(f"- {r}" for r in reqs) if reqs else "- Return complete verifier-safe C code"

        repair_prompt = f"""Task ID: {task_id}
Category: {cat}
Difficulty: {diff}

Original Instruction:
{task.get("instruction", "")}

Technical Requirements:
{reqs_formatted}

Previous Implementation:
```c
{extracted_c1.strip()}
```

Diagnostic Output:
```text
{diagnostic.strip()}
```

Please provide the corrected, complete, and self-contained C source code for this XDP program."""

        t2_messages = [
            {"role": "system", "content": REPAIR_SYSTEM_PROMPT},
            {"role": "user", "content": repair_prompt},
        ]
        t2_input = renderer.build_generation_prompt(t2_messages)

        resp2 = await sampler.sample_async(prompt=t2_input, num_samples=1, sampling_params=sample_params)
        raw_text_t2 = renderer.tokenizer.decode(resp2.sequences[0].tokens)
        rollout_id_t2 = f"eval_{eval_name}_{task_id}_t2"

        # Evaluate Turn 2 repair independently on Linux VPS
        ver_res_t2 = await executor.evaluate_candidate(
            task=task,
            raw_completion=raw_text_t2,
            rollout_id=rollout_id_t2,
        )

        reward_t2 = compute_rlvr_reward(
            ver_res_t2.to_dict(),
            expected_fixture_count=task.get("expected_fixture_count"),
        )

        t2_passed = reward_t2.is_functionally_correct
        entry["turn2_compile_pass"] = ver_res_t2.compile["pass"]
        entry["turn2_verifier_pass"] = ver_res_t2.verifier["pass"]
        entry["turn2_behavioral_pass"] = ver_res_t2.behavioral["pass"]
        entry["turn2_passed"] = t2_passed
        entry["turn2_stage"] = reward_t2.stage_reached

        if t2_passed:
            turn2_recoveries += 1
            entry["solve_at_2"] = 1.0
            entry["recovered"] = True

            if t1_stage in ("compliance", "non_compliant"):
                rec_from_compile += 1
                entry["recovery_type"] = "from_compile"
            elif t1_stage == "compile":
                rec_from_verifier += 1
                entry["recovery_type"] = "from_verifier"
            else:
                rec_from_behavioral += 1
                entry["recovery_type"] = "from_behavioral"

            logger.info("  [%d/%d] Task %s: RECOVERED on Turn 2 (%s -> PASS)", idx, len(tasks), task_id, t1_stage)
        else:
            logger.info("  [%d/%d] Task %s: FAIL (T1: %s, T2: %s)", idx, len(tasks), task_id, t1_stage, reward_t2.stage_reached)

        results.append(entry)

    duration = round(time.time() - t0, 2)
    n = len(tasks)
    pass_at_1_rate = turn1_passes / n if n else 0.0
    solve_at_2_count = turn1_passes + turn2_recoveries
    solve_at_2_rate = solve_at_2_count / n if n else 0.0

    # McNemar between Turn 1 and Turn 2: recoveries = turn2_recoveries, regressions = 0
    mcnemar_stat, mcnemar_p = compute_exact_mcnemar(b=0, c=turn2_recoveries)

    summary = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "eval_name": eval_name,
        "sampler_checkpoint": sampler_checkpoint,
        "total_tasks": n,
        "pass_at_1": {
            "count": turn1_passes,
            "rate": round(pass_at_1_rate, 4),
        },
        "solve_at_2": {
            "count": solve_at_2_count,
            "rate": round(solve_at_2_rate, 4),
        },
        "recoveries": {
            "total_recovered": turn2_recoveries,
            "net_gain_percentage": round((solve_at_2_rate - pass_at_1_rate) * 100, 2),
            "mcnemar_stat": round(mcnemar_stat, 4),
            "mcnemar_p": round(mcnemar_p, 4),
        },
        "failure_stage_breakdown": {
            "turn1_compile_failures": {
                "count": turn1_compile_fails,
                "recovered": rec_from_compile,
                "recovery_rate": round(rec_from_compile / turn1_compile_fails, 4) if turn1_compile_fails else 0.0,
            },
            "turn1_verifier_failures": {
                "count": turn1_verifier_fails,
                "recovered": rec_from_verifier,
                "recovery_rate": round(rec_from_verifier / turn1_verifier_fails, 4) if turn1_verifier_fails else 0.0,
            },
            "turn1_behavioral_failures": {
                "count": turn1_behavioral_fails,
                "recovered": rec_from_behavioral,
                "recovery_rate": round(rec_from_behavioral / turn1_behavioral_fails, 4) if turn1_behavioral_fails else 0.0,
            },
        },
        "duration_seconds": duration,
        "results": results,
    }

    summary_file = output_dir / eval_name / "two_turn_summary.json"
    summary_file.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    logger.info(
        "Evaluation '%s' finished: Pass@1=%d/%d (%.1f%%), Solve@2=%d/%d (%.1f%%), Net Gain=+%d (+%.1f%%), Behavioral Rec=%d/%d (%.1f%%) in %.1fs",
        eval_name, turn1_passes, n, pass_at_1_rate * 100,
        solve_at_2_count, n, solve_at_2_rate * 100,
        turn2_recoveries, (solve_at_2_rate - pass_at_1_rate) * 100,
        rec_from_behavioral, turn1_behavioral_fails,
        (rec_from_behavioral / turn1_behavioral_fails * 100) if turn1_behavioral_fails else 0.0,
        duration,
    )
    return summary


async def main():
    parser = argparse.ArgumentParser(description="Phase N3 Two-Turn Evaluation Driver")
    parser.add_argument("--sampler-checkpoint", type=str, default=NEMOTRON_SFT_V1_SAMPLER_CHECKPOINT)
    parser.add_argument("--suites", nargs="+", default=["dev", "confirmation", "synthesis"])
    parser.add_argument("--dev-dir", type=str, default=str(DEFAULT_DEV_DIR_N3))
    parser.add_argument("--confirmation-dir", type=str, default=str(DEFAULT_CONFIRMATION_DIR_N3))
    parser.add_argument("--synthesis-dir", type=str, default=str(PROJECT_ROOT / "data" / "benchmark" / "synthesis"))
    parser.add_argument("--output-dir", type=str, default=str(PROJECT_ROOT / "runs" / "evaluation" / "nemotron-rl-n3"))
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--profile", type=str, default="nemotron-3.5-lightning")
    args = parser.parse_args()

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    master_summary_file = out_dir / "master_summary.json"
    if master_summary_file.exists():
        try:
            master_summary = json.loads(master_summary_file.read_text(encoding="utf-8"))
        except Exception:
            master_summary = {}
    else:
        master_summary = {}

    master_summary["timestamp"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    master_summary["sampler_checkpoint"] = args.sampler_checkpoint
    if "suites" not in master_summary:
        master_summary["suites"] = {}

    for suite in args.suites:
        if suite == "dev":
            tasks = load_tasks_from_dir(Path(args.dev_dir))
            eval_name = "n3-dev-48"
        elif suite == "confirmation":
            tasks = load_tasks_from_dir(Path(args.confirmation_dir))
            eval_name = "n3-confirmation-60"
        elif suite == "synthesis":
            tasks = load_tasks_from_dir(Path(args.synthesis_dir))
            eval_name = "protected-synthesis-120"
        else:
            logger.warning("Unknown suite '%s', skipping", suite)
            continue

        res = await evaluate_two_turn_dataset(
            tasks=tasks,
            sampler_checkpoint=args.sampler_checkpoint,
            output_dir=out_dir,
            eval_name=eval_name,
            temperature=args.temperature,
            profile_name=args.profile,
        )
        master_summary["suites"][eval_name] = res

    master_summary_file = out_dir / "master_summary.json"
    master_summary_file.write_text(json.dumps(master_summary, indent=2), encoding="utf-8")
    print("\nMaster Evaluation Summary written to:", master_summary_file)


if __name__ == "__main__":
    asyncio.run(main())
