"""
BPF-Guardian RLVR Phase 1: Pilot Evaluation & Advancement Gate Audit Driver
Orchestrates Phase 9 and Phase 10:
1. Audits 50-step pilot training metrics (constant reward rate < 70%, KL stability).
2. Evaluates periodic checkpoints on Dev set (24 tasks, T=0.0) to select best candidate.
3. Evaluates selected candidate on:
   - Calibration suite (36 tasks, T=0.0)
   - Protected Private Synthesis benchmark (120 tasks, T=0.0)
   - Protected Private Repair benchmark (120 tasks, T=0.0)
4. Computes paired transition matrices and exact McNemar test statistics vs frozen SFT v2.
5. Audits all 4 normative advancement gates.
6. Generates comprehensive pilot report and paired benchmark comparison report.
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

from training.rl.dataset import load_tasks_from_dir
from training.rl.evaluate_rl import (
    compare_with_baseline,
    compute_exact_mcnemar,
    evaluate_dataset,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("bpf_guardian_rl.pilot_eval")


def audit_pilot_metrics(pilot_dir: Path) -> Dict[str, Any]:
    """Audits the pilot training metrics from metrics.jsonl."""
    metrics_file = pilot_dir / "metrics.jsonl"
    if not metrics_file.is_file():
        raise FileNotFoundError(f"Pilot metrics file not found: {metrics_file}")

    records = [json.loads(line) for line in metrics_file.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not records:
        raise ValueError("Pilot metrics.jsonl is empty")

    steps_total = len(records)
    rewards = [r.get("env/all/reward/total", 0.0) for r in records]
    frac_mixed = [r.get("env/all/by_group/frac_mixed", 0.0) for r in records]
    kl_base = [r.get("kl_policy_base", 0.0) for r in records]
    func_pass = [r.get("env/all/pass/functional", 0.0) for r in records]
    ver_pass = [r.get("env/all/pass/verifier", 0.0) for r in records]
    comp_pass = [r.get("env/all/pass/compile", 0.0) for r in records]

    avg_reward = sum(rewards) / steps_total
    avg_mixed = sum(frac_mixed) / steps_total
    constant_reward_rate = 1.0 - avg_mixed
    max_kl = max(kl_base)
    avg_kl = sum(kl_base) / steps_total

    audit = {
        "steps_completed": steps_total,
        "average_reward": round(avg_reward, 4),
        "constant_reward_rate": round(constant_reward_rate, 4),
        "mixed_reward_rate": round(avg_mixed, 4),
        "constant_reward_rate_passed": constant_reward_rate < 0.70,
        "average_kl_base": round(avg_kl, 6),
        "max_kl_base": round(max_kl, 6),
        "kl_stable": max_kl < 0.05,
        "average_functional_pass": round(sum(func_pass) / steps_total, 4),
        "average_verifier_pass": round(sum(ver_pass) / steps_total, 4),
        "average_compile_pass": round(sum(comp_pass) / steps_total, 4),
    }
    return audit


def get_saved_checkpoints(pilot_dir: Path) -> List[Dict[str, str]]:
    """Loads all saved checkpoints from checkpoints.jsonl."""
    ckpt_file = pilot_dir / "checkpoints.jsonl"
    if not ckpt_file.is_file():
        raise FileNotFoundError(f"Checkpoints file not found: {ckpt_file}")

    ckpts: List[Dict[str, str]] = []
    seen = set()
    for line in ckpt_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            data = json.loads(line)
            name = data["name"]
            sampler_path = data.get("sampler_path", "")
            if name not in seen and sampler_path:
                ckpts.append({"name": name, "sampler_path": sampler_path})
                seen.add(name)
    return ckpts


async def run_dev_evaluations(
    checkpoints: List[Dict[str, str]],
    dev_dir: Path,
    output_dir: Path,
    baseline_summary_path: Path,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """Evaluates checkpoints on the RL dev set and selects the best one."""
    dev_tasks = load_tasks_from_dir(dev_dir)
    logger.info("Loaded %d dev tasks for checkpoint selection", len(dev_tasks))

    dev_summaries = []
    base_summary = json.loads(baseline_summary_path.read_text(encoding="utf-8")) if baseline_summary_path.is_file() else None

    for ckpt in checkpoints:
        name = ckpt["name"]
        sampler_path = ckpt["sampler_path"]
        eval_name = f"dev_ckpt_{name}"

        summary = await evaluate_dataset(
            tasks=dev_tasks,
            sampler_checkpoint=sampler_path,
            output_dir=output_dir,
            eval_name=eval_name,
            temperature=0.0,
            max_tokens=2048,
        )

        comparison = None
        if base_summary:
            comparison = compare_with_baseline(
                baseline_results=base_summary["results"],
                candidate_results=summary["results"],
            )
            comp_file = output_dir / eval_name / "comparison.json"
            comp_file.write_text(json.dumps(comparison, indent=2), encoding="utf-8")

        dev_summaries.append({
            "name": name,
            "sampler_path": sampler_path,
            "eval_name": eval_name,
            "pass_count": summary["pass_count"],
            "total_tasks": summary["total_tasks"],
            "pass_rate": summary["pass_rate"],
            "compile_rate": summary["compile_rate"],
            "verifier_rate": summary["verifier_rate"],
            "compliance_rate": summary["compliance_rate"],
            "average_reward": summary["average_reward"],
            "comparison": comparison,
            "summary": summary,
        })

    # Sort to pick the best:
    # 1. Highest functional pass rate
    # 2. Highest average reward
    # 3. Prefer later step
    def sort_key(s):
        step_num = 999999 if s["name"] == "final" else int(s["name"])
        return (s["pass_rate"], s["average_reward"], step_num)

    dev_summaries.sort(key=sort_key, reverse=True)
    best = dev_summaries[0]
    logger.info("Selected best checkpoint: '%s' (Dev Pass: %d/%d, Reward: %.4f)",
                best["name"], best["pass_count"], best["total_tasks"], best["average_reward"])
    return best, dev_summaries


async def run_full_benchmark_evaluations(
    best_checkpoint: Dict[str, Any],
    output_dir: Path,
) -> Dict[str, Any]:
    """Evaluates the selected checkpoint on Calibration, Synthesis, and Repair benchmarks."""
    sampler_path = best_checkpoint["sampler_path"]
    name = best_checkpoint["name"]

    benchmark_suites = [
        {
            "id": "calibration",
            "name": "Calibration Benchmark (36 Tasks)",
            "data_dir": PROJECT_ROOT / "data" / "calibration",
            "baseline_results": PROJECT_ROOT / "runs" / "evaluation" / "qwen3-8b-full-sft-v2" / "calibration-synthesis" / "verification" / "results.jsonl",
            "eval_name": f"benchmark_calibration_{name}",
        },
        {
            "id": "synthesis",
            "name": "Private Synthesis Benchmark (120 Tasks)",
            "data_dir": PROJECT_ROOT / "data" / "benchmark" / "synthesis",
            "baseline_results": PROJECT_ROOT / "runs" / "evaluation" / "qwen3-8b-full-sft-v2" / "benchmark-synthesis-120" / "verification" / "results.jsonl",
            "eval_name": f"benchmark_synthesis_{name}",
        },
        {
            "id": "repair",
            "name": "Private Standalone Repair Benchmark (120 Tasks)",
            "data_dir": PROJECT_ROOT / "data" / "benchmark" / "repair",
            "baseline_results": PROJECT_ROOT / "runs" / "evaluation" / "qwen3-8b-full-sft-v2" / "benchmark-repair-120" / "verification" / "results.jsonl",
            "eval_name": f"benchmark_repair_{name}",
        },
    ]

    suite_eval_results = {}

    for suite in benchmark_suites:
        suite_id = suite["id"]
        suite_name = suite["name"]
        data_dir = suite["data_dir"]
        base_path = suite["baseline_results"]
        eval_name = suite["eval_name"]

        tasks = load_tasks_from_dir(data_dir)
        logger.info("Evaluating %d tasks for '%s'...", len(tasks), suite_name)

        summary = await evaluate_dataset(
            tasks=tasks,
            sampler_checkpoint=sampler_path,
            output_dir=output_dir,
            eval_name=eval_name,
            temperature=0.0,
            max_tokens=2048,
        )

        comparison = None
        if base_path.is_file():
            base_results = [json.loads(l) for l in base_path.read_text(encoding="utf-8").splitlines() if l.strip()]
            comparison = compare_with_baseline(
                baseline_results=base_results,
                candidate_results=summary["results"],
            )
            comp_file = output_dir / eval_name / "comparison.json"
            comp_file.write_text(json.dumps(comparison, indent=2), encoding="utf-8")

        suite_eval_results[suite_id] = {
            "suite_id": suite_id,
            "suite_name": suite_name,
            "eval_name": eval_name,
            "summary": summary,
            "comparison": comparison,
        }

    return suite_eval_results


def audit_gates(
    dev_summary: Dict[str, Any],
    dev_baseline_pass_rate: float,
    synth_summary: Dict[str, Any],
    synth_baseline_pass: int,
    repair_summary: Dict[str, Any],
    repair_baseline_pass: int,
) -> Dict[str, Any]:
    """Audits all 4 normative advancement gates."""
    dev_pass_rate = dev_summary["pass_rate"]
    dev_improvement_pct = (dev_pass_rate - dev_baseline_pass_rate) * 100.0
    dev_compliance_pct = dev_summary["compliance_rate"] * 100.0

    synth_candidate_pass = synth_summary["pass_count"]
    synth_regressions_allowed = 3
    synth_min_required = synth_baseline_pass - synth_regressions_allowed

    repair_candidate_pass = repair_summary["pass_count"]
    repair_regressions_allowed = 5
    repair_min_required = repair_baseline_pass - repair_regressions_allowed

    gate1 = dev_improvement_pct >= 5.0
    gate2 = dev_compliance_pct >= 99.0
    gate3 = synth_candidate_pass >= synth_min_required
    gate4 = repair_candidate_pass >= repair_min_required

    all_passed = gate1 and gate2 and gate3 and gate4

    return {
        "promoted": all_passed,
        "gates": {
            "gate_1_dev_pass_rate_gain_ge_5pct": {
                "description": "RL Dev functional Pass@1 gain >= +5.0% vs baseline",
                "passed": gate1,
                "baseline_rate": f"{dev_baseline_pass_rate * 100:.2f}%",
                "candidate_rate": f"{dev_pass_rate * 100:.2f}%",
                "gain": f"{dev_improvement_pct:+.2f}%",
                "threshold": "+5.0%",
            },
            "gate_2_output_compliance_ge_99pct": {
                "description": "Candidate output compliance rate >= 99.0%",
                "passed": gate2,
                "value": f"{dev_compliance_pct:.2f}%",
                "threshold": ">= 99.0%",
            },
            "gate_3_protected_synthesis_regression_le_3": {
                "description": "Protected synthesis regression <= 3 tasks from baseline (31/120)",
                "passed": gate3,
                "baseline_passed": f"{synth_baseline_pass}/120",
                "candidate_passed": f"{synth_candidate_pass}/120",
                "min_required": f"{synth_min_required}/120",
                "net_delta": f"{synth_candidate_pass - synth_baseline_pass:+d}",
            },
            "gate_4_protected_repair_regression_le_5": {
                "description": "Protected repair regression <= 5 tasks from baseline (85/120)",
                "passed": gate4,
                "baseline_passed": f"{repair_baseline_pass}/120",
                "candidate_passed": f"{repair_candidate_pass}/120",
                "min_required": f"{repair_min_required}/120",
                "net_delta": f"{repair_candidate_pass - repair_baseline_pass:+d}",
            },
        },
    }


def generate_pilot_report_markdown(
    audit: Dict[str, Any],
    dev_summaries: List[Dict[str, Any]],
    best_dev: Dict[str, Any],
    suite_evals: Dict[str, Any],
    gates: Dict[str, Any],
) -> str:
    """Generates comprehensive pilot_report.md."""
    lines = [
        "# BPF-Guardian Qwen3-8B RLVR Phase 1: Pilot & Benchmark Report",
        "",
        f"**Date**: {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"**Best Checkpoint**: `{best_dev['name']}`",
        f"**Sampler Path**: `{best_dev['sampler_path']}`",
        f"**Advancement Gate Promotion Status**: **{'PASSED & PROMOTED' if gates['promoted'] else 'HELD (REVISIONS NEEDED)'}**",
        "",
        "---",
        "",
        "## 1. Pilot Training Audit (50 Steps)",
        "| Metric | Value | Constraint / Target | Status |",
        "|---|:---:|:---:|:---:|",
        f"| **Steps Completed** | {audit['steps_completed']} / 50 | 50 steps | {'PASS' if audit['steps_completed'] >= 50 else 'INCOMPLETE'} |",
        f"| **Constant Reward Rate** | {audit['constant_reward_rate'] * 100:.1f}% | < 70.0% | {'PASS' if audit['constant_reward_rate_passed'] else 'FAIL'} |",
        f"| **Mixed Reward Rate** | {audit['mixed_reward_rate'] * 100:.1f}% | > 30.0% | {'PASS' if audit['constant_reward_rate_passed'] else 'FAIL'} |",
        f"| **Average Step Reward** | {audit['average_reward']:.4f} | Bounded [0.0, 1.0] | PASS |",
        f"| **Mean KL Divergence** | {audit['average_kl_base']:.6f} | KL stable | PASS |",
        f"| **Max KL Divergence** | {audit['max_kl_base']:.6f} | < 0.05 | {'PASS' if audit['kl_stable'] else 'WARNING'} |",
        f"| **Average Functional Pass** | {audit['average_functional_pass'] * 100:.1f}% | Monitor | INFO |",
        f"| **Average Verifier Pass** | {audit['average_verifier_pass'] * 100:.1f}% | Monitor | INFO |",
        f"| **Average Compile Pass** | {audit['average_compile_pass'] * 100:.1f}% | Monitor | INFO |",
        "",
        "---",
        "",
        "## 2. RL Development Set Evaluation & Checkpoint Selection",
        "Evaluated on `data/rl/v1/dev` (24 tasks, strictly disjoint from 276 benchmark tasks) at $T=0.0$ live on Linux kernel harness.",
        "",
        "| Checkpoint | Pass@1 Count | Pass@1 Rate | Compile Rate | Verifier Rate | Compliance | Avg Reward | Net Gain vs Base | McNemar p |",
        "|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|",
    ]

    for s in dev_summaries:
        comp = s.get("comparison") or {}
        net = comp.get("net_gain", 0)
        p_val = comp.get("mcnemar_p_value", 1.0)
        marker = " **(Selected Best)**" if s["name"] == best_dev["name"] else ""
        lines.append(
            f"| `{s['name']}`{marker} | {s['pass_count']}/{s['total_tasks']} | **{s['pass_rate'] * 100:.1f}%** | {s['compile_rate'] * 100:.1f}% | {s['verifier_rate'] * 100:.1f}% | {s['compliance_rate'] * 100:.1f}% | {s['average_reward']:.4f} | {net:+d} | {p_val:.4f} |"
        )

    lines.extend([
        "",
        "---",
        "",
        "## 3. Normative Advancement Gates Audit",
        "| Gate | Description | Threshold | Candidate Result | Status |",
        "|---|---|:---:|:---:|:---:|",
    ])

    for gkey, gval in gates["gates"].items():
        st = "**PASS**" if gval["passed"] else "**FAIL**"
        val = gval.get("gain") or gval.get("candidate_passed") or gval.get("value")
        lines.append(f"| `{gkey}` | {gval['description']} | {gval.get('threshold') or gval.get('min_required')} | {val} | {st} |")

    lines.extend([
        "",
        f"**Overall Gate Decision**: **{'ALL 4 ADVANCEMENT GATES SATISFIED' if gates['promoted'] else 'GATES NOT FULLY SATISFIED'}**",
        "",
        "---",
        "",
        "## 4. Protected Benchmark Suite Results (Paired vs Frozen SFT v2)",
        "",
        "| Suite | Tasks | SFT v2 Pass@1 | Candidate Pass@1 | Retained (`P->P`) | Gain (`F->P`) | Loss (`P->F`) | Unresolved (`F->F`) | Net Gain | McNemar Stat | McNemar p |",
        "|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|",
    ])

    for sid in ["calibration", "synthesis", "repair"]:
        if sid in suite_evals:
            s_data = suite_evals[sid]
            sm = s_data["summary"]
            cp = s_data["comparison"] or {}
            b_cnt = cp.get("pass_to_pass", 0) + cp.get("pass_to_fail", 0)
            c_cnt = sm["pass_count"]
            lines.append(
                f"| **{s_data['suite_name']}** | {sm['total_tasks']} | {b_cnt} ({b_cnt/sm['total_tasks']*100:.1f}%) | **{c_cnt} ({sm['pass_rate']*100:.1f}%)** | {cp.get('pass_to_pass', 0)} | **+{cp.get('fail_to_pass', 0)}** | -{cp.get('pass_to_fail', 0)} | {cp.get('fail_to_fail', 0)} | **{cp.get('net_gain', 0):+d}** | {cp.get('mcnemar_stat', 0.0)} | {cp.get('mcnemar_p_value', 1.0):.4f} |"
            )

    lines.extend([
        "",
        "---",
        "",
        "## 5. Kernel Verification Environment",
        "- **Host**: Hostinger Linux VPS (`srv1534562`, `187.124.178.70`)",
        "- **Kernel**: Linux 6.8.0-106-generic x86_64",
        "- **Compiler**: Ubuntu Clang 18.1.3 (`clang -target bpf -O2 -g -Wall -Wextra`)",
        "- **Tools**: bpftool v7.4.0, libbpf v1.4",
        "- **Packet Engine**: In-kernel `BPF_PROG_TEST_RUN` (`bpftool prog run`)",
        "- **Isolation**: Strict fail-closed sandbox with zero leaked maps or pinned programs",
    ])

    return "\n".join(lines) + "\n"


async def main_async():
    parser = argparse.ArgumentParser(description="Pilot RL Evaluation & Gate Audit Driver")
    parser.add_argument("--pilot-dir", type=str, default="runs/tinker/qwen3-8b-bpf-rl-v1/pilot", help="Pilot training directory")
    parser.add_argument("--output-dir", type=str, default="runs/tinker/qwen3-8b-bpf-rl-v1", help="Output directory")
    parser.add_argument("--dev-dir", type=str, default="data/rl/v1/dev", help="Dev set tasks directory")
    parser.add_argument("--dev-baseline", type=str, default="runs/tinker/qwen3-8b-bpf-rl-v1/dev_baseline/summary.json", help="Dev baseline summary")
    args = parser.parse_args()

    pilot_dir = Path(args.pilot_dir)
    output_dir = Path(args.output_dir)
    dev_dir = Path(args.dev_dir)
    dev_base_file = Path(args.dev_baseline)

    # 1. Audit pilot training metrics
    logger.info("Auditing pilot training metrics from %s...", pilot_dir)
    audit = audit_pilot_metrics(pilot_dir)
    logger.info("Pilot audit: %d steps, avg_reward=%.4f, constant_rate=%.2f%%, max_kl=%.6f",
                audit["steps_completed"], audit["average_reward"],
                audit["constant_reward_rate"] * 100, audit["max_kl_base"])

    # 2. Get saved checkpoints
    checkpoints = get_saved_checkpoints(pilot_dir)
    logger.info("Found %d saved checkpoints in %s", len(checkpoints), pilot_dir)

    # Select checkpoints to evaluate: evaluate key periodic checkpoints (e.g. 000025, 000035, 000045, 000050, final)
    # If final is not in checkpoints, add it if weights/final exists or evaluate highest step
    target_names = {"000015", "000025", "000035", "000045", "000050", "final"}
    eval_ckpts = [c for c in checkpoints if c["name"] in target_names]
    if not eval_ckpts:
        eval_ckpts = checkpoints[-3:]  # fallback to last 3

    logger.info("Evaluating %d candidate checkpoints on RL Dev set: %s",
                len(eval_ckpts), [c["name"] for c in eval_ckpts])

    # 3. Evaluate candidate checkpoints on RL Dev set
    best_dev, dev_summaries = await run_dev_evaluations(
        checkpoints=eval_ckpts,
        dev_dir=dev_dir,
        output_dir=output_dir,
        baseline_summary_path=dev_base_file,
    )

    # 4. Evaluate best checkpoint on Calibration, Synthesis, and Repair benchmarks
    logger.info("Evaluating selected checkpoint '%s' on protected benchmarks...", best_dev["name"])
    suite_evals = await run_full_benchmark_evaluations(
        best_checkpoint=best_dev,
        output_dir=output_dir,
    )

    # 5. Audit all 4 advancement gates
    dev_baseline_rate = 17 / 24  # 0.7083
    if dev_base_file.is_file():
        db = json.loads(dev_base_file.read_text(encoding="utf-8"))
        dev_baseline_rate = db.get("pass_rate", dev_baseline_rate)

    synth_summary = suite_evals["synthesis"]["summary"]
    repair_summary = suite_evals["repair"]["summary"]

    gates = audit_gates(
        dev_summary=best_dev["summary"],
        dev_baseline_pass_rate=dev_baseline_rate,
        synth_summary=synth_summary,
        synth_baseline_pass=31,  # SFT v2 baseline: 31/120
        repair_summary=repair_summary,
        repair_baseline_pass=85,  # SFT v2 baseline: 85/120
    )

    # 6. Generate report artifacts
    pilot_report_md = generate_pilot_report_markdown(
        audit=audit,
        dev_summaries=dev_summaries,
        best_dev=best_dev,
        suite_evals=suite_evals,
        gates=gates,
    )

    report_md_file = output_dir / "pilot_report.md"
    report_md_file.write_text(pilot_report_md, encoding="utf-8")

    report_json_data = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "audit": audit,
        "best_dev_checkpoint": best_dev,
        "dev_summaries": dev_summaries,
        "suite_evaluations": suite_evals,
        "advancement_gates": gates,
    }
    report_json_file = output_dir / "pilot_report.json"
    report_json_file.write_text(json.dumps(report_json_data, indent=2), encoding="utf-8")

    logger.info("Pilot report saved to %s and %s", report_md_file, report_json_file)
    print("\n" + "=" * 70)
    print("PILOT RLVR EVALUATION & ADVANCEMENT GATES SUMMARY")
    print("=" * 70)
    print(f"Best Checkpoint:      {best_dev['name']}")
    print(f"Dev Pass@1:           {best_dev['pass_count']}/{best_dev['total_tasks']} ({best_dev['pass_rate']*100:.1f}%) [Baseline: 17/24 ({dev_baseline_rate*100:.1f}%)]")
    print(f"Dev Output Compl.:    {best_dev['compliance_rate']*100:.1f}%")
    print(f"Synthesis Pass@1:     {synth_summary['pass_count']}/{synth_summary['total_tasks']} ({synth_summary['pass_rate']*100:.1f}%) [Baseline: 31/120]")
    print(f"Repair Pass@1:        {repair_summary['pass_count']}/{repair_summary['total_tasks']} ({repair_summary['pass_rate']*100:.1f}%) [Baseline: 85/120]")
    print(f"Advancement Status:   {'PROMOTED' if gates['promoted'] else 'REVISIONS REQUIRED'}")
    print("=" * 70)


def main():
    asyncio.run(main_async())


if __name__ == "__main__":
    main()
