"""
BPF-Guardian RLVR Phase 1: Evaluation Driver and Paired Analysis
Evaluates trained RL checkpoints against:
1. RL Development set (24 tasks, T=0.0) for checkpoint selection.
2. Frozen Calibration Benchmark (36 tasks).
3. Frozen Private Synthesis Benchmark (120 tasks).
4. Frozen Private Repair Benchmark (120 tasks).
Computes exact McNemar tests, paired transition matrices (F->F, F->P, P->F, P->P), and audits advancement gates.
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
from typing import Any, Dict, List, Optional, Tuple

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
from tinker_cookbook import renderers
from tinker_cookbook.renderers import get_renderer

from training.rl.bpf_env import build_task_prompt
from training.rl.config import DEFAULT_RENDERER_NAME, SFT_V2_SAMPLER_CHECKPOINT
from training.rl.dataset import load_tasks_from_dir
from training.rl.kernel_executor import KernelExecutor, check_output_compliance
from training.rl.reward import compute_rlvr_reward

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("bpf_guardian_rl.eval")


def compute_exact_mcnemar(b: int, c: int) -> Tuple[float, float]:
    """Computes two-sided McNemar test statistic and p-value.
    b: Baseline passed, Candidate failed (regressions)
    c: Baseline failed, Candidate passed (recoveries)
    """
    total = b + c
    if total == 0:
        return 0.0, 1.0

    # McNemar chi-squared with Edwards continuity correction
    stat = (abs(b - c) - 1.0) ** 2 / total

    # Exact binomial p-value for two-sided test
    # Under H0: b ~ Binomial(total, 0.5)
    k = min(b, c)
    p_val = 2.0 * sum(math.comb(total, i) * (0.5**total) for i in range(k + 1))
    p_val = min(1.0, max(0.0, p_val))
    return stat, p_val


async def evaluate_dataset(
    tasks: List[Dict[str, Any]],
    sampler_checkpoint: str,
    output_dir: Path,
    eval_name: str,
    temperature: float = 0.0,
    max_tokens: int = 2048,
) -> Dict[str, Any]:
    """Evaluates a model checkpoint on a set of tasks at T=0.0."""
    logger.info("Evaluating %d tasks on '%s' (T=%.1f)...", len(tasks), eval_name, temperature)
    records_dir = output_dir / eval_name / "records"
    records_dir.mkdir(parents=True, exist_ok=True)

    from tinker_cookbook.tokenizer_utils import get_tokenizer

    service = tinker.ServiceClient()
    sampler = service.create_sampling_client(sampler_checkpoint)
    tokenizer = get_tokenizer("Qwen/Qwen3-8B")
    renderer = get_renderer(DEFAULT_RENDERER_NAME, tokenizer=tokenizer)
    executor = KernelExecutor(records_dir=records_dir)

    results: List[Dict[str, Any]] = []
    t0 = time.time()

    for idx, task in enumerate(tasks, start=1):
        task_id = task["task_id"]
        cat = task.get("application_category", "")
        diff = task.get("difficulty", "")
        rollout_id = f"eval_{eval_name}_{task_id}"

        messages = build_task_prompt(task)
        model_input = renderer.build_generation_prompt(messages)
        stop_seqs = renderer.get_stop_sequences()

        sample_params = tinker.SamplingParams(
            max_tokens=max_tokens,
            temperature=temperature,
            stop=stop_seqs,
        )

        resp = await sampler.sample_async(prompt=model_input, num_samples=1, sampling_params=sample_params)
        raw_text = renderer.tokenizer.decode(resp.sequences[0].tokens)

        ver_res = await executor.evaluate_candidate(
            task=task,
            raw_completion=raw_text,
            rollout_id=rollout_id,
        )

        reward_breakdown = compute_rlvr_reward(
            ver_res.to_dict(),
            expected_fixture_count=task.get("expected_fixture_count"),
        )

        entry = {
            "task_id": task_id,
            "category": cat,
            "difficulty": diff,
            "rollout_id": rollout_id,
            "compliance_pass": ver_res.output_compliance["compliant"],
            "compile_pass": ver_res.compile["pass"],
            "verifier_pass": ver_res.verifier["pass"],
            "behavioral_pass": ver_res.behavioral["pass"],
            "functional_pass": reward_breakdown.is_functionally_correct,
            "passed": reward_breakdown.is_functionally_correct,
            "total_reward": reward_breakdown.total_reward,
            "timing": ver_res.timing,
        }
        results.append(entry)

    total = len(results)
    func_pass = sum(1 for r in results if r["functional_pass"])
    comp_pass = sum(1 for r in results if r["compile_pass"])
    ver_pass = sum(1 for r in results if r["verifier_pass"])
    compl_pass = sum(1 for r in results if r["compliance_pass"])
    avg_reward = sum(r["total_reward"] for r in results) / total if total else 0.0

    summary = {
        "eval_name": eval_name,
        "sampler_checkpoint": sampler_checkpoint,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "total_tasks": total,
        "pass_count": func_pass,
        "pass_rate": round(func_pass / total, 4) if total else 0.0,
        "compile_rate": round(comp_pass / total, 4) if total else 0.0,
        "verifier_rate": round(ver_pass / total, 4) if total else 0.0,
        "compliance_rate": round(compl_pass / total, 4) if total else 0.0,
        "average_reward": round(avg_reward, 4),
        "duration_seconds": round(time.time() - t0, 2),
        "results": results,
    }

    summary_file = output_dir / eval_name / "summary.json"
    summary_file.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    results_jsonl = output_dir / eval_name / "results.jsonl"
    results_jsonl.write_text("\n".join(json.dumps(r) for r in results) + "\n", encoding="utf-8")
    return summary


def compare_with_baseline(
    baseline_results: List[Dict[str, Any]],
    candidate_results: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Computes paired transitions and McNemar statistics between baseline and candidate."""
    base_by_id = {r["task_id"]: r for r in baseline_results}
    cand_by_id = {r["task_id"]: r for r in candidate_results}

    common_ids = sorted(set(base_by_id.keys()) & set(cand_by_id.keys()))

    f_to_f = 0
    f_to_p = 0  # Recoveries (c)
    p_to_f = 0  # Regressions (b)
    p_to_p = 0

    transitions: List[Dict[str, Any]] = []

    for tid in common_ids:
        b_pass = bool(base_by_id[tid].get("functional_pass", base_by_id[tid].get("passed", False)))
        c_pass = bool(cand_by_id[tid].get("functional_pass", cand_by_id[tid].get("passed", False)))

        if not b_pass and not c_pass:
            trans = "fail->fail"
            f_to_f += 1
        elif not b_pass and c_pass:
            trans = "fail->pass"
            f_to_p += 1
        elif b_pass and not c_pass:
            trans = "pass->fail"
            p_to_f += 1
        else:
            trans = "pass->pass"
            p_to_p += 1

        transitions.append({
            "task_id": tid,
            "category": base_by_id[tid].get("category", ""),
            "difficulty": base_by_id[tid].get("difficulty", ""),
            "transition": trans,
            "baseline_pass": b_pass,
            "candidate_pass": c_pass,
        })

    stat, p_val = compute_exact_mcnemar(b=p_to_f, c=f_to_p)

    return {
        "total_compared": len(common_ids),
        "fail_to_fail": f_to_f,
        "fail_to_pass": f_to_p,
        "pass_to_fail": p_to_f,
        "pass_to_pass": p_to_p,
        "net_gain": f_to_p - p_to_f,
        "mcnemar_stat": round(stat, 4),
        "mcnemar_p_value": round(p_val, 6),
        "transitions": transitions,
    }


def audit_advancement_gates(
    dev_summary: Dict[str, Any],
    dev_baseline_pass_rate: float,
    protected_synthesis_pass: int,
    protected_repair_pass: int,
) -> Dict[str, Any]:
    """Audits the candidate checkpoint against all normative advancement gates."""
    dev_pass_rate = dev_summary["pass_rate"]
    dev_improvement = (dev_pass_rate - dev_baseline_pass_rate) * 100
    dev_compliance = dev_summary["compliance_rate"] * 100

    gate_dev_gain = dev_improvement >= 5.0
    gate_compliance = dev_compliance >= 99.0
    gate_synth_regression = protected_synthesis_pass >= (31 - 3)  # At least 28/120
    gate_repair_regression = protected_repair_pass >= (85 - 5)    # At least 80/120

    all_passed = (
        gate_dev_gain
        and gate_compliance
        and gate_synth_regression
        and gate_repair_regression
    )

    return {
        "promoted": all_passed,
        "gates": {
            "dev_functional_pass_rate_gain_ge_5pct": {
                "passed": gate_dev_gain,
                "value": round(dev_improvement, 2),
                "threshold": "+5.0%",
            },
            "dev_compliance_ge_99pct": {
                "passed": gate_compliance,
                "value": round(dev_compliance, 2),
                "threshold": ">=99.0%",
            },
            "protected_synthesis_regression_le_3_tasks": {
                "passed": gate_synth_regression,
                "value": f"{protected_synthesis_pass}/120",
                "threshold": ">=28/120 (baseline 31/120)",
            },
            "protected_repair_regression_le_5_tasks": {
                "passed": gate_repair_regression,
                "value": f"{protected_repair_pass}/120",
                "threshold": ">=80/120 (baseline 85/120)",
            },
        },
    }


def main():
    parser = argparse.ArgumentParser(description="BPF-Guardian RLVR Evaluation Driver")
    parser.add_argument("--data-dir", type=str, required=True, help="Directory containing evaluation tasks")
    parser.add_argument("--sampler-checkpoint", type=str, default=SFT_V2_SAMPLER_CHECKPOINT, help="Tinker sampler checkpoint path")
    parser.add_argument("--eval-name", type=str, required=True, help="Name of evaluation split (e.g. dev_baseline)")
    parser.add_argument("--output-dir", type=str, default="runs/tinker/qwen3-8b-bpf-rl-v1", help="Output directory")
    parser.add_argument("--temperature", type=float, default=0.0, help="Sampling temperature")
    parser.add_argument("--max-tokens", type=int, default=2048, help="Max tokens per generation")
    parser.add_argument("--compare-with", type=str, default=None, help="Path to baseline summary.json for paired McNemar analysis")
    args = parser.parse_args()

    data_path = Path(args.data_dir)
    tasks = load_tasks_from_dir(data_path)
    logger.info("Loaded %d tasks from %s", len(tasks), data_path)

    output_dir = Path(args.output_dir)
    summary = asyncio.run(
        evaluate_dataset(
            tasks=tasks,
            sampler_checkpoint=args.sampler_checkpoint,
            output_dir=output_dir,
            eval_name=args.eval_name,
            temperature=args.temperature,
            max_tokens=args.max_tokens,
        )
    )

    print("\n" + "=" * 60)
    print(f"EVALUATION SUMMARY: {args.eval_name}")
    print("=" * 60)
    print(f"Total Tasks:     {summary['total_tasks']}")
    print(f"Functional Pass: {summary['pass_count']}/{summary['total_tasks']} ({summary['pass_rate'] * 100:.1f}%)")
    print(f"Compile Pass:    {summary['compile_rate'] * 100:.1f}%")
    print(f"Verifier Pass:   {summary['verifier_rate'] * 100:.1f}%")
    print(f"Compliance:      {summary['compliance_rate'] * 100:.1f}%")
    print(f"Average Reward:  {summary['average_reward']:.4f}")
    print(f"Duration:        {summary['duration_seconds']:.1f}s")
    print("=" * 60)

    if args.compare_with:
        base_path = Path(args.compare_with)
        if base_path.is_file():
            if base_path.suffix == ".jsonl":
                base_results = [json.loads(l) for l in base_path.read_text(encoding="utf-8").splitlines() if l.strip()]
            else:
                base_data = json.loads(base_path.read_text(encoding="utf-8"))
                base_results = base_data.get("results", base_data)
            comparison = compare_with_baseline(
                baseline_results=base_results,
                candidate_results=summary["results"],
            )
            comparison_file = output_dir / args.eval_name / "comparison.json"
            comparison_file.write_text(json.dumps(comparison, indent=2), encoding="utf-8")
            print(f"Paired Comparison vs {args.compare_with}:")
            print(f"  F->F: {comparison['fail_to_fail']}, F->P: {comparison['fail_to_pass']}, P->F: {comparison['pass_to_fail']}, P->P: {comparison['pass_to_pass']}")
            print(f"  Net Gain: {comparison['net_gain']:+d}")
            print(f"  McNemar Stat: {comparison['mcnemar_stat']}, p-value: {comparison['mcnemar_p_value']:.6f}")


if __name__ == "__main__":
    main()

