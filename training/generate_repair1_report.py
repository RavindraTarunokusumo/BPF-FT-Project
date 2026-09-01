#!/usr/bin/env python3
"""
BPF-Guardian Synthesis Repair@1 and End-to-End Solve@2 Report Generator
Aggregates the controlled 1-turn repair evaluation of the 89 failed synthesis tasks:
1. Calculates Repair@1 recovery rate: recovered / 89.
2. Calculates End-to-End Solve@2 rate: (31 initial + recovered) / 120.
3. Computes breakdowns by original failure stage, application category, and difficulty.
4. Generates repair1_report.json and repair1_report.md.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def generate_repair1_report(
    synthesis_results_path: Path,
    repair_results_path: Path,
    manifest_path: Path,
    output_dir: Path,
) -> Dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)

    synth_records = [json.loads(l) for l in synthesis_results_path.read_text(encoding="utf-8").splitlines() if l.strip()]
    repair_records = [json.loads(l) for l in repair_results_path.read_text(encoding="utf-8").splitlines() if l.strip()]
    manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.is_file() else {}

    diag_types = manifest.get("diagnostic_type_per_task", {})

    total_synthesis_tasks = len(synth_records)
    initial_passed_tasks = {r["task_id"] for r in synth_records if r.get("passed", False)}
    initial_pass_count = len(initial_passed_tasks)

    failed_synth_records = [r for r in synth_records if not r.get("passed", False)]
    total_eligible_repairs = len(failed_synth_records)
    assert total_eligible_repairs == 89, f"Expected 89 eligible repairs, got {total_eligible_repairs}"

    repair_dict = {r["task_id"]: r for r in repair_records}
    recovered_tasks = {r["task_id"] for r in repair_records if r.get("passed", False)}
    recovered_count = len(recovered_tasks)

    solve2_passed_tasks = initial_passed_tasks | recovered_tasks
    solve2_count = len(solve2_passed_tasks)

    # Breakdowns
    by_stage: Dict[str, Dict[str, int]] = defaultdict(lambda: {"total": 0, "compile_pass": 0, "verifier_pass": 0, "recovered": 0})
    by_cat: Dict[str, Dict[str, int]] = defaultdict(lambda: {"total": 0, "initial_pass": 0, "repairs_eligible": 0, "recovered": 0, "solve2_pass": 0})
    by_diff: Dict[str, Dict[str, int]] = defaultdict(lambda: {"total": 0, "initial_pass": 0, "repairs_eligible": 0, "recovered": 0, "solve2_pass": 0})

    for s in synth_records:
        tid = s["task_id"]
        cat = s.get("category") or s.get("application_category", "unknown")
        diff = s.get("difficulty", "unknown")
        p = s.get("passed", False)

        by_cat[cat]["total"] += 1
        by_diff[diff]["total"] += 1
        if p:
            by_cat[cat]["initial_pass"] += 1
            by_diff[diff]["initial_pass"] += 1

    for tid, rep in repair_dict.items():
        stage = diag_types.get(tid, rep.get("diagnostic_stage", "unknown"))
        cat = rep.get("category", "unknown")
        diff = rep.get("difficulty", "unknown")
        p = rep.get("passed", False)
        comp = rep.get("compile", {}).get("pass", False)
        verif = rep.get("verifier", {}).get("pass", False)

        by_stage[stage]["total"] += 1
        if comp:
            by_stage[stage]["compile_pass"] += 1
        if verif:
            by_stage[stage]["verifier_pass"] += 1
        if p:
            by_stage[stage]["recovered"] += 1

        by_cat[cat]["repairs_eligible"] += 1
        by_diff[diff]["repairs_eligible"] += 1
        if p:
            by_cat[cat]["recovered"] += 1
            by_diff[diff]["recovered"] += 1

    for cat in by_cat:
        by_cat[cat]["solve2_pass"] = by_cat[cat]["initial_pass"] + by_cat[cat]["recovered"]
    for diff in by_diff:
        by_diff[diff]["solve2_pass"] = by_diff[diff]["initial_pass"] + by_diff[diff]["recovered"]

    report_data = {
        "evaluation_name": "Controlled Synthesis Repair@1 Evaluation (Qwen3-8B SFT v2)",
        "model": "Qwen/Qwen3-8B SFT v2",
        "checkpoint": manifest.get("checkpoint", "tinker://9461002d-2321-5858-8184-5604f9304283:train:0/sampler_weights/final"),
        "total_synthesis_tasks": total_synthesis_tasks,
        "initial_synthesis_pass1": {
            "passed": initial_pass_count,
            "total": total_synthesis_tasks,
            "rate": initial_pass_count / total_synthesis_tasks,
        },
        "repair1_metrics": {
            "eligible_failures": total_eligible_repairs,
            "recovered_tasks": recovered_count,
            "recovery_rate": recovered_count / total_eligible_repairs,
            "compilation_pass_count": sum(1 for r in repair_records if r.get("compile", {}).get("pass", False)),
            "kernel_verifier_pass_count": sum(1 for r in repair_records if r.get("verifier", {}).get("pass", False)),
        },
        "end_to_end_solve2": {
            "definition": "1 synthesis attempt followed by at most 1 diagnostic-guided repair attempt (deterministic Solve@2, not Pass@2 sampling)",
            "total_solved": solve2_count,
            "total_tasks": total_synthesis_tasks,
            "solve2_rate": solve2_count / total_synthesis_tasks,
            "absolute_gain_over_pass1": (solve2_count - initial_pass_count) / total_synthesis_tasks,
        },
        "breakdown_by_original_failure_stage": {k: dict(v) for k, v in by_stage.items()},
        "breakdown_by_category": {k: dict(v) for k, v in by_cat.items()},
        "breakdown_by_difficulty": {k: dict(v) for k, v in by_diff.items()},
    }

    # Generate Markdown report
    md_lines = [
        "# Qwen3-8B SFT v2: Controlled Synthesis Repair@1 & End-to-End Solve@2 Report",
        "",
        "## 1. Executive Summary",
        f"- **Initial Private Synthesis Pass@1**: **{initial_pass_count} / {total_synthesis_tasks}** ({initial_pass_count / total_synthesis_tasks:.1%})",
        f"- **Eligible Synthesis Failures Repaired**: **{total_eligible_repairs} tasks**",
        f"- **Repair@1 Recoveries**: **{recovered_count} / {total_eligible_repairs}** ({recovered_count / total_eligible_repairs:.1%})",
        f"- **End-to-End Solve@2**: **{solve2_count} / {total_synthesis_tasks}** (**{solve2_count / total_synthesis_tasks:.1%}**)",
        f"- **Absolute Solve@2 Gain over Pass@1**: **+{(solve2_count - initial_pass_count) / total_synthesis_tasks:.1%}** (+{recovered_count} tasks)",
        "",
        "> [!NOTE]",
        "> **Solve@2 Definition**: `Solve@2` represents a controlled multi-stage workflow: exactly one synthesis attempt followed by at most one diagnostic-guided repair attempt for failing candidates. It is **not** stochastic sampling-based `Pass@2`.",
        "",
        "## 2. Recovery by Original Failure Stage",
        "| Original Failure Stage | Eligible Tasks | Clang Compile | Verifier Pass | Recovered (Behavioral Pass) | Recovery Rate |",
        "|---|:---:|:---:|:---:|:---:|:---:|",
    ]

    for stage, s in sorted(by_stage.items()):
        rec_rate = (s["recovered"] / s["total"]) if s["total"] > 0 else 0.0
        md_lines.append(
            f"| `{stage}` | {s['total']} | {s['compile_pass']} ({s['compile_pass']/s['total']:.1%}) | {s['verifier_pass']} ({s['verifier_pass']/s['total']:.1%}) | **{s['recovered']}** | **{rec_rate:.1%}** |"
        )

    md_lines.extend([
        "",
        "## 3. End-to-End Solve@2 by Application Category",
        "| Category | Total Tasks | Initial Pass@1 | Repairs Eligible | Recovered | Solve@2 Solved | Solve@2 Rate | Solve@2 Gain |",
        "|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|",
    ])

    for cat, c in sorted(by_cat.items()):
        p1_rate = c["initial_pass"] / c["total"]
        s2_rate = c["solve2_pass"] / c["total"]
        gain = s2_rate - p1_rate
        md_lines.append(
            f"| `{cat}` | {c['total']} | {c['initial_pass']} ({p1_rate:.1%}) | {c['repairs_eligible']} | {c['recovered']} | **{c['solve2_pass']}** | **{s2_rate:.1%}** | **+{gain:.1%}** |"
        )

    md_lines.extend([
        "",
        "## 4. End-to-End Solve@2 by Difficulty Level",
        "| Difficulty Level | Total Tasks | Initial Pass@1 | Repairs Eligible | Recovered | Solve@2 Solved | Solve@2 Rate | Solve@2 Gain |",
        "|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|",
    ])

    for diff, d in sorted(by_diff.items()):
        p1_rate = d["initial_pass"] / d["total"]
        s2_rate = d["solve2_pass"] / d["total"]
        gain = s2_rate - p1_rate
        md_lines.append(
            f"| `{diff}` | {d['total']} | {d['initial_pass']} ({p1_rate:.1%}) | {d['repairs_eligible']} | {d['recovered']} | **{d['solve2_pass']}** | **{s2_rate:.1%}** | **+{gain:.1%}** |"
        )

    (output_dir / "repair1_report.json").write_text(json.dumps(report_data, indent=2) + "\n", encoding="utf-8")
    (output_dir / "repair1_report.md").write_text("\n".join(md_lines) + "\n", encoding="utf-8")

    print(f"[+] Repair@1 report generated at {output_dir / 'repair1_report.md'}")
    return report_data


def main():
    parser = argparse.ArgumentParser(description="Generate Synthesis Repair@1 & Solve@2 Report")
    parser.add_argument("--synthesis-results", type=Path, default=PROJECT_ROOT / "runs" / "evaluation" / "qwen3-8b-full-sft-v2" / "benchmark-synthesis-120" / "verification" / "results.jsonl")
    parser.add_argument("--repair-results", type=Path, default=PROJECT_ROOT / "runs" / "evaluation" / "qwen3-8b-full-sft-v2" / "benchmark-synthesis-120-repair1" / "verification" / "results.jsonl")
    parser.add_argument("--manifest", type=Path, default=PROJECT_ROOT / "runs" / "evaluation" / "qwen3-8b-full-sft-v2" / "benchmark-synthesis-120-repair1" / "manifest.json")
    parser.add_argument("--output-dir", type=Path, default=PROJECT_ROOT / "runs" / "evaluation" / "qwen3-8b-full-sft-v2" / "benchmark-synthesis-120-repair1")

    args = parser.parse_args()
    generate_repair1_report(
        synthesis_results_path=args.synthesis_results,
        repair_results_path=args.repair_results,
        manifest_path=args.manifest,
        output_dir=args.output_dir,
    )


if __name__ == "__main__":
    main()
