#!/usr/bin/env python3
"""
BPF-Guardian Evaluation Summary and Baseline Comparison Aggregator
Compares Base Model vs Fine-Tuned (SFT) Model performance on the benchmark suite:
1. Loads verification results for base and SFT synthesis rollouts.
2. Optionally loads Repair@1 verification results.
3. Compares against the pre-SFT calibration baseline (3/36 Pass@1 = 8.3%, 3/33 Repair@1 = 9.1%, 6/36 Total = 16.7%).
4. Calculates absolute improvements in Pass@1, compilation, verifier-load, and behavioral pass rates.
5. Emits comprehensive Markdown and JSON evaluation reports.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Calibration Baseline constants
CALIBRATION_BASELINE = {
    "total_tasks": 36,
    "pass1_passed": 3,
    "pass1_rate": 3 / 36,  # 8.3%
    "repair1_passed": 3,
    "repair1_total_eligible": 33,
    "repair1_rate": 3 / 33,  # 9.1%
    "total_passed_with_repair": 6,
    "total_pass_rate": 6 / 36,  # 16.7%
}


def load_results_file(results_path: Path, allow_mock: bool = False) -> List[Dict[str, Any]]:
    if not results_path.is_file():
        raise FileNotFoundError(f"Verification results file not found: {results_path}")
    records = [json.loads(line) for line in results_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not allow_mock:
        for r in records:
            if r.get("verification_mode") == "mock":
                raise ValueError(
                    f"Quarantine violation: Cannot generate empirical evaluation report using mock verification results in {results_path}"
                )
    return records


def compute_rollout_metrics(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    sample0 = [r for r in records if r.get("sample_index", 0) == 0]
    total_tasks = len(sample0)
    if total_tasks == 0:
        total_tasks = len(records)
        sample0 = records

    total_cands = len(records)
    compliant = sum(1 for r in records if r.get("compliance", {}).get("compliant", True))
    compile_pass = sum(1 for r in records if r.get("compile", {}).get("pass", False))
    verifier_pass = sum(1 for r in records if r.get("verifier", {}).get("pass", False))
    behavioral_pass = sum(1 for r in records if r.get("behavioral", {}).get("pass", False))
    fully_passed = sum(1 for r in sample0 if r.get("passed", False))

    cat_stats: Dict[str, Dict[str, int]] = defaultdict(lambda: {"total": 0, "passed": 0})
    diff_stats: Dict[str, Dict[str, int]] = defaultdict(lambda: {"total": 0, "passed": 0})

    for r in sample0:
        cat = r.get("category") or r.get("application_category", "unknown")
        diff = r.get("difficulty", "unknown")
        cat_stats[cat]["total"] += 1
        diff_stats[diff]["total"] += 1
        if r.get("passed", False):
            cat_stats[cat]["passed"] += 1
            diff_stats[diff]["passed"] += 1

    return {
        "total_tasks": total_tasks,
        "total_candidates": total_cands,
        "compliant_count": compliant,
        "compliant_rate": compliant / total_cands if total_cands > 0 else 0.0,
        "compile_count": compile_pass,
        "compile_rate": compile_pass / total_cands if total_cands > 0 else 0.0,
        "verifier_count": verifier_pass,
        "verifier_rate": verifier_pass / total_cands if total_cands > 0 else 0.0,
        "behavioral_count": behavioral_pass,
        "behavioral_rate": behavioral_pass / total_cands if total_cands > 0 else 0.0,
        "pass1_count": fully_passed,
        "pass1_rate": fully_passed / total_tasks if total_tasks > 0 else 0.0,
        "by_category": dict(cat_stats),
        "by_difficulty": dict(diff_stats),
    }


def compute_repair_recovery(
    synthesis_results: List[Dict[str, Any]],
    repair_results: List[Dict[str, Any]],
) -> Dict[str, Any]:
    synth_passed_tasks = {r["task_id"] for r in synthesis_results if r.get("passed", False)}
    repair_passed_tasks = {r["task_id"] for r in repair_results if r.get("passed", False)}

    total_tasks = len({r["task_id"] for r in synthesis_results})
    failed_synth_tasks = {r["task_id"] for r in synthesis_results} - synth_passed_tasks

    recovered_tasks = failed_synth_tasks & repair_passed_tasks
    post_repair_total_passed = synth_passed_tasks | repair_passed_tasks

    return {
        "failed_synth_tasks_count": len(failed_synth_tasks),
        "recovered_tasks_count": len(recovered_tasks),
        "recovery_rate": len(recovered_tasks) / len(failed_synth_tasks) if failed_synth_tasks else 0.0,
        "post_repair_total_passed_count": len(post_repair_total_passed),
        "post_repair_total_rate": len(post_repair_total_passed) / total_tasks if total_tasks > 0 else 0.0,
    }


def build_evaluation_report(
    sft_synth_path: Path,
    base_synth_path: Optional[Path] = None,
    sft_repair_path: Optional[Path] = None,
    output_path: Optional[Path] = None,
) -> Dict[str, Any]:
    sft_records = load_results_file(sft_synth_path)
    sft_metrics = compute_rollout_metrics(sft_records)

    base_metrics = None
    if base_synth_path and base_synth_path.is_file():
        base_records = load_results_file(base_synth_path)
        base_metrics = compute_rollout_metrics(base_records)

    repair_metrics = None
    if sft_repair_path and sft_repair_path.is_file():
        repair_records = load_results_file(sft_repair_path)
        repair_metrics = compute_repair_recovery(sft_records, repair_records)

    report_data: Dict[str, Any] = {
        "baseline_calibration": CALIBRATION_BASELINE,
        "sft_synthesis": sft_metrics,
        "base_synthesis": base_metrics,
        "sft_repair": repair_metrics,
    }

    # Markdown formatting
    lines = [
        "# BPF-Guardian Evaluation & Benchmark Comparison Report",
        "",
        "## Summary Comparison",
        "| Metric | Calibration Baseline | Base Model | SFT Model | Absolute Delta (SFT vs Base) |",
        "|---|---|---|---|---|",
    ]

    base_pass1_str = f"{base_metrics['pass1_rate']:.1%}" if base_metrics else f"{CALIBRATION_BASELINE['pass1_rate']:.1%}"
    sft_pass1_str = f"{sft_metrics['pass1_rate']:.1%}"
    base_rate_val = base_metrics['pass1_rate'] if base_metrics else CALIBRATION_BASELINE['pass1_rate']
    delta_pass1 = sft_metrics['pass1_rate'] - base_rate_val
    delta_pass1_str = f"+{delta_pass1:.1%}" if delta_pass1 >= 0 else f"{delta_pass1:.1%}"

    lines.append(f"| **Functional Pass@1** | {CALIBRATION_BASELINE['pass1_rate']:.1%} (3/36) | {base_pass1_str} | **{sft_pass1_str}** | **{delta_pass1_str}** |")

    if base_metrics:
        lines.append(f"| Output Compliance | N/A | {base_metrics['compliant_rate']:.1%} | {sft_metrics['compliant_rate']:.1%} | {sft_metrics['compliant_rate'] - base_metrics['compliant_rate']:+.1%} |")
        lines.append(f"| Clang BPF Compilation | N/A | {base_metrics['compile_rate']:.1%} | {sft_metrics['compile_rate']:.1%} | {sft_metrics['compile_rate'] - base_metrics['compile_rate']:+.1%} |")
        lines.append(f"| Kernel Verifier Load | N/A | {base_metrics['verifier_rate']:.1%} | {sft_metrics['verifier_rate']:.1%} | {sft_metrics['verifier_rate'] - base_metrics['verifier_rate']:+.1%} |")
        lines.append(f"| Behavioral Pass | N/A | {base_metrics['behavioral_rate']:.1%} | {sft_metrics['behavioral_rate']:.1%} | {sft_metrics['behavioral_rate'] - base_metrics['behavioral_rate']:+.1%} |")
    else:
        lines.append(f"| Output Compliance | N/A | - | {sft_metrics['compliant_rate']:.1%} | - |")
        lines.append(f"| Clang BPF Compilation | N/A | - | {sft_metrics['compile_rate']:.1%} | - |")
        lines.append(f"| Kernel Verifier Load | N/A | - | {sft_metrics['verifier_rate']:.1%} | - |")
        lines.append(f"| Behavioral Pass | N/A | - | {sft_metrics['behavioral_rate']:.1%} | - |")

    if repair_metrics:
        lines.append(
            f"| Repair@1 Recovery | {CALIBRATION_BASELINE['repair1_rate']:.1%} (3/33) | - | {repair_metrics['recovery_rate']:.1%} ({repair_metrics['recovered_tasks_count']}/{repair_metrics['failed_synth_tasks_count']}) | - |"
        )
        lines.append(
            f"| Post-Repair Total Pass | {CALIBRATION_BASELINE['total_pass_rate']:.1%} (6/36) | - | **{repair_metrics['post_repair_total_rate']:.1%}** ({repair_metrics['post_repair_total_passed_count']}/{sft_metrics['total_tasks']}) | **{repair_metrics['post_repair_total_rate'] - CALIBRATION_BASELINE['total_pass_rate']:+.1%}** |"
        )

    lines.extend([
        "",
        "## SFT Category Breakdown (Pass@1)",
        "| Category | Tasks | Passed | Pass Rate |",
        "|---|---|---|---|",
    ])
    for cat, stat in sorted(sft_metrics["by_category"].items()):
        c_rate = (stat["passed"] / stat["total"]) if stat["total"] > 0 else 0.0
        lines.append(f"| `{cat}` | {stat['total']} | {stat['passed']} | {c_rate:.1%} |")

    lines.extend([
        "",
        "## SFT Difficulty Breakdown (Pass@1)",
        "| Difficulty | Tasks | Passed | Pass Rate |",
        "|---|---|---|---|",
    ])
    for diff, stat in sorted(sft_metrics["by_difficulty"].items()):
        d_rate = (stat["passed"] / stat["total"]) if stat["total"] > 0 else 0.0
        lines.append(f"| `{diff}` | {stat['total']} | {stat['passed']} | {d_rate:.1%} |")

    report_md = "\n".join(lines) + "\n"

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(report_md, encoding="utf-8")
        json_out = output_path.with_suffix(".json")
        json_out.write_text(json.dumps(report_data, indent=2) + "\n", encoding="utf-8")

    return report_data


def main() -> None:
    parser = argparse.ArgumentParser(description="BPF-Guardian Evaluation Summary Aggregator")
    parser.add_argument("--sft-results", type=Path, required=True, help="Path to SFT synthesis results.jsonl")
    parser.add_argument("--base-results", type=Path, default=None, help="Path to Base model synthesis results.jsonl")
    parser.add_argument("--sft-repair-results", type=Path, default=None, help="Path to SFT Repair@1 results.jsonl")
    parser.add_argument("--output", type=Path, default=PROJECT_ROOT / "runs" / "evaluation" / "evaluation_summary.md")
    args = parser.parse_args()

    print("=" * 70)
    print("BPF-Guardian Benchmark Evaluation Summarizer")
    print(f"SFT Results:        {args.sft_results}")
    print(f"Base Results:       {args.base_results}")
    print(f"Repair Results:     {args.sft_repair_results}")
    print(f"Output Report:      {args.output}")
    print("=" * 70)

    report = build_evaluation_report(
        sft_synth_path=args.sft_results,
        base_synth_path=args.base_results,
        sft_repair_path=args.sft_repair_results,
        output_path=args.output,
    )

    sft_p1 = report["sft_synthesis"]["pass1_rate"]
    print(f"\n[+] Evaluation Summary Generated successfully at {args.output}")
    print(f"    SFT Pass@1:           {sft_p1:.1%} ({report['sft_synthesis']['pass1_count']}/{report['sft_synthesis']['total_tasks']})")
    print(f"    Calibration Baseline: 8.3% (3/36)")


if __name__ == "__main__":
    main()
