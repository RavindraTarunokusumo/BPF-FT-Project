#!/usr/bin/env python3
"""
BPF-Guardian Paired SFT v1 -> v2 Transition & McNemar Statistical Analysis
Performs matched pair transition analysis on the exact same benchmark tasks evaluated across SFT v1 and SFT v2:
1. Private Synthesis Benchmark (120 tasks).
2. Private Standalone Repair Benchmark (120 tasks).
3. Calibration Synthesis Suite (36 tasks).
4. Global Combined Evaluation (276 tasks).

Transition Categories:
- v1 fail -> v2 fail: Unresolved
- v1 fail -> v2 pass: Recovered capability (Gain)
- v1 pass -> v2 fail: Regression (Capability Loss)
- v1 pass -> v2 pass: Retained capability

Statistical Test:
Exact two-sided McNemar test on discordant pairs (b = v1 pass -> v2 fail, c = v1 fail -> v2 pass)
using the exact binomial distribution (Python standard library math.comb).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def compute_file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(65536):
            digest.update(chunk)
    return digest.hexdigest()


def exact_mcnemar_test(b: int, c: int) -> Tuple[int, int, float]:
    """
    Computes exact two-sided McNemar p-value using the binomial distribution.
    b: discordant pair (v1 pass -> v2 fail) [regressions]
    c: discordant pair (v1 fail -> v2 pass) [gains]
    """
    n = b + c
    if n == 0:
        return b, c, 1.0
    k = min(b, c)
    cum_prob = sum(math.comb(n, i) for i in range(k + 1)) * (0.5 ** n)
    p_value = min(1.0, 2.0 * cum_prob)
    return b, c, p_value


def load_results_dict(results_path: Path) -> Tuple[Dict[str, Dict[str, Any]], str]:
    if not results_path.is_file():
        raise FileNotFoundError(f"Missing results file: {results_path}")
    file_hash = compute_file_sha256(results_path)
    records = [json.loads(l) for l in results_path.read_text(encoding="utf-8").splitlines() if l.strip()]
    task_map = {}
    for r in records:
        if r.get("sample_index", 0) == 0:
            task_map[r["task_id"]] = r
    return task_map, file_hash


def analyze_suite_transitions(
    suite_name: str,
    v1_results_path: Path,
    v2_results_path: Path,
) -> Dict[str, Any]:
    v1_map, v1_hash = load_results_dict(v1_results_path)
    v2_map, v2_hash = load_results_dict(v2_results_path)

    common_tasks = sorted(set(v1_map.keys()) & set(v2_map.keys()))
    if len(common_tasks) != len(v1_map) or len(common_tasks) != len(v2_map):
        raise ValueError(
            f"Task set mismatch in {suite_name}: v1={len(v1_map)}, v2={len(v2_map)}, common={len(common_tasks)}"
        )

    transitions = {
        "fail_to_fail": [],  # unresolved
        "fail_to_pass": [],  # gain
        "pass_to_fail": [],  # regression
        "pass_to_pass": [],  # retained
    }

    by_cat = defaultdict(lambda: {"fail_to_fail": 0, "fail_to_pass": 0, "pass_to_fail": 0, "pass_to_pass": 0, "total": 0})
    by_diff = defaultdict(lambda: {"fail_to_fail": 0, "fail_to_pass": 0, "pass_to_fail": 0, "pass_to_pass": 0, "total": 0})

    for tid in common_tasks:
        r1 = v1_map[tid]
        r2 = v2_map[tid]
        p1 = bool(r1.get("passed", False))
        p2 = bool(r2.get("passed", False))

        cat = r2.get("category") or r2.get("application_category", "unknown")
        diff = r2.get("difficulty", "unknown")

        by_cat[cat]["total"] += 1
        by_diff[diff]["total"] += 1

        info = {
            "task_id": tid,
            "category": cat,
            "difficulty": diff,
            "v1_passed": p1,
            "v2_passed": p2,
            "v1_compile": r1.get("compile", {}).get("pass", False),
            "v2_compile": r2.get("compile", {}).get("pass", False),
            "v1_verifier": r1.get("verifier", {}).get("pass", False),
            "v2_verifier": r2.get("verifier", {}).get("pass", False),
        }

        if not p1 and not p2:
            transitions["fail_to_fail"].append(info)
            by_cat[cat]["fail_to_fail"] += 1
            by_diff[diff]["fail_to_fail"] += 1
        elif not p1 and p2:
            transitions["fail_to_pass"].append(info)
            by_cat[cat]["fail_to_pass"] += 1
            by_diff[diff]["fail_to_pass"] += 1
        elif p1 and not p2:
            transitions["pass_to_fail"].append(info)
            by_cat[cat]["pass_to_fail"] += 1
            by_diff[diff]["pass_to_fail"] += 1
        elif p1 and p2:
            transitions["pass_to_pass"].append(info)
            by_cat[cat]["pass_to_pass"] += 1
            by_diff[diff]["pass_to_pass"] += 1

    b = len(transitions["pass_to_fail"])  # regressions
    c = len(transitions["fail_to_pass"])  # gains
    _, _, p_value = exact_mcnemar_test(b, c)

    v1_pass_count = len(transitions["pass_to_pass"]) + len(transitions["pass_to_fail"])
    v2_pass_count = len(transitions["pass_to_pass"]) + len(transitions["fail_to_pass"])
    total_n = len(common_tasks)

    return {
        "suite_name": suite_name,
        "total_tasks": total_n,
        "v1_source_path": str(v1_results_path.relative_to(PROJECT_ROOT).as_posix()),
        "v1_source_sha256": v1_hash,
        "v2_source_path": str(v2_results_path.relative_to(PROJECT_ROOT).as_posix()),
        "v2_source_sha256": v2_hash,
        "v1_pass_count": v1_pass_count,
        "v1_pass_rate": v1_pass_count / total_n if total_n else 0.0,
        "v2_pass_count": v2_pass_count,
        "v2_pass_rate": v2_pass_count / total_n if total_n else 0.0,
        "transition_counts": {
            "fail_to_fail": len(transitions["fail_to_fail"]),
            "fail_to_pass": len(transitions["fail_to_pass"]),
            "pass_to_fail": len(transitions["pass_to_fail"]),
            "pass_to_pass": len(transitions["pass_to_pass"]),
        },
        "mcnemar_test": {
            "b_regressions_v1_pass_v2_fail": b,
            "c_gains_v1_fail_v2_pass": c,
            "discordant_pairs_total": b + c,
            "exact_p_value": p_value,
            "statistically_significant_p05": p_value < 0.05,
            "statistically_significant_p01": p_value < 0.01,
        },
        "breakdown_by_category": {k: dict(v) for k, v in by_cat.items()},
        "breakdown_by_difficulty": {k: dict(v) for k, v in by_diff.items()},
        "regressions_list": [t["task_id"] for t in transitions["pass_to_fail"]],
        "gains_list": [t["task_id"] for t in transitions["fail_to_pass"]],
    }


def run_paired_analysis(output_dir: Path) -> Dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)

    suites_config = [
        (
            "Private Synthesis Benchmark (120 Tasks)",
            PROJECT_ROOT / "runs" / "evaluation" / "qwen3-8b-full-sft-v1" / "benchmark-synthesis-120" / "verification" / "results.jsonl",
            PROJECT_ROOT / "runs" / "evaluation" / "qwen3-8b-full-sft-v2" / "benchmark-synthesis-120" / "verification" / "results.jsonl",
        ),
        (
            "Private Standalone Repair Benchmark (120 Tasks)",
            PROJECT_ROOT / "runs" / "evaluation" / "qwen3-8b-full-sft-v1" / "benchmark-repair-120" / "verification" / "results.jsonl",
            PROJECT_ROOT / "runs" / "evaluation" / "qwen3-8b-full-sft-v2" / "benchmark-repair-120" / "verification" / "results.jsonl",
        ),
        (
            "Calibration Synthesis Suite (36 Tasks)",
            PROJECT_ROOT / "runs" / "evaluation" / "qwen3-8b-full-sft-v1" / "rollout-001" / "verification" / "results.jsonl",
            PROJECT_ROOT / "runs" / "evaluation" / "qwen3-8b-full-sft-v2" / "calibration-synthesis" / "verification" / "results.jsonl",
        ),
    ]

    suite_results = []
    global_b = 0
    global_c = 0
    global_v1_pass = 0
    global_v2_pass = 0
    global_retained = 0
    global_unresolved = 0
    global_total = 0

    for name, v1_p, v2_p in suites_config:
        res = analyze_suite_transitions(name, v1_p, v2_p)
        suite_results.append(res)
        global_b += res["mcnemar_test"]["b_regressions_v1_pass_v2_fail"]
        global_c += res["mcnemar_test"]["c_gains_v1_fail_v2_pass"]
        global_v1_pass += res["v1_pass_count"]
        global_v2_pass += res["v2_pass_count"]
        global_retained += res["transition_counts"]["pass_to_pass"]
        global_unresolved += res["transition_counts"]["fail_to_fail"]
        global_total += res["total_tasks"]

    _, _, global_p = exact_mcnemar_test(global_b, global_c)

    global_summary = {
        "total_tasks": global_total,
        "v1_pass_count": global_v1_pass,
        "v1_pass_rate": global_v1_pass / global_total,
        "v2_pass_count": global_v2_pass,
        "v2_pass_rate": global_v2_pass / global_total,
        "transition_counts": {
            "fail_to_fail": global_unresolved,
            "fail_to_pass": global_c,
            "pass_to_fail": global_b,
            "pass_to_pass": global_retained,
        },
        "mcnemar_test": {
            "b_regressions": global_b,
            "c_gains": global_c,
            "discordant_pairs_total": global_b + global_c,
            "exact_p_value": global_p,
            "statistically_significant_p05": global_p < 0.05,
            "statistically_significant_p01": global_p < 0.01,
        },
    }

    report = {
        "analysis_title": "BPF-Guardian Paired SFT v1 -> SFT v2 Transition & McNemar Analysis",
        "global_summary": global_summary,
        "suites": suite_results,
    }

    # Generate Markdown
    md_lines = [
        "# Paired SFT v1 &rarr; SFT v2 Transition and McNemar Statistical Analysis",
        "",
        "## 1. Master Paired Transition Matrix",
        "| Evaluation Suite | Tasks | v1 Pass@1 | v2 Pass@1 | Retained (`pass->pass`) | Recovered / Gain (`fail->pass`) | Regression (`pass->fail`) | Unresolved (`fail->fail`) | Discordant Pairs ($b+c$) | McNemar $p$-value | Significant? |",
        "|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|",
    ]

    for s in suite_results:
        tc = s["transition_counts"]
        mc = s["mcnemar_test"]
        sig_str = "**Yes (p < 0.01)**" if mc["exact_p_value"] < 0.01 else ("**Yes (p < 0.05)**" if mc["exact_p_value"] < 0.05 else "No")
        md_lines.append(
            f"| **{s['suite_name']}** | {s['total_tasks']} | {s['v1_pass_count']} ({s['v1_pass_rate']:.1%}) | {s['v2_pass_count']} ({s['v2_pass_rate']:.1%}) | {tc['pass_to_pass']} | **+{tc['fail_to_pass']}** | -{tc['pass_to_fail']} | {tc['fail_to_fail']} | $b={mc['b_regressions_v1_pass_v2_fail']}, c={mc['c_gains_v1_fail_v2_pass']}$ | **p = {mc['exact_p_value']:.4e}** | {sig_str} |"
        )

    g_sig = "**Yes (p < 0.01)**" if global_p < 0.01 else ("**Yes (p < 0.05)**" if global_p < 0.05 else "No")
    md_lines.append(
        f"| **Global Total (All Suites)** | **{global_total}** | **{global_v1_pass} ({global_v1_pass/global_total:.1%})** | **{global_v2_pass} ({global_v2_pass/global_total:.1%})** | **{global_retained}** | **+{global_c}** | **-{global_b}** | **{global_unresolved}** | **$b={global_b}, c={global_c}$** | **p = {global_p:.4e}** | {g_sig} |"
    )

    md_lines.extend([
        "",
        "---",
        "",
        "## 2. Detailed Breakdown by Suite",
    ])

    for s in suite_results:
        md_lines.extend([
            f"### {s['suite_name']}",
            f"- **v1 Results File**: `{s['v1_source_path']}` (SHA-256: `{s['v1_source_sha256']}`)",
            f"- **v2 Results File**: `{s['v2_source_path']}` (SHA-256: `{s['v2_source_sha256']}`)",
            f"- **McNemar Test**: $b={s['mcnemar_test']['b_regressions_v1_pass_v2_fail']}$, $c={s['mcnemar_test']['c_gains_v1_fail_v2_pass']}$, exact $p = {s['mcnemar_test']['exact_p_value']:.5f}$",
            "",
            "#### Category Transitions",
            "| Category | Tasks | Retained (`pass->pass`) | Recovered (`fail->pass`) | Regression (`pass->fail`) | Unresolved (`fail->fail`) |",
            "|---|:---:|:---:|:---:|:---:|:---:|",
        ])

        for cat, c in sorted(s["breakdown_by_category"].items()):
            md_lines.append(
                f"| `{cat}` | {c['total']} | {c['pass_to_pass']} | +{c['fail_to_pass']} | -{c['pass_to_fail']} | {c['fail_to_fail']} |"
            )

        md_lines.extend([
            "",
            "#### Difficulty Transitions",
            "| Difficulty | Tasks | Retained (`pass->pass`) | Recovered (`fail->pass`) | Regression (`pass->fail`) | Unresolved (`fail->fail`) |",
            "|---|:---:|:---:|:---:|:---:|:---:|",
        ])

        for diff, d in sorted(s["breakdown_by_difficulty"].items()):
            md_lines.append(
                f"| `{diff}` | {d['total']} | {d['pass_to_pass']} | +{d['fail_to_pass']} | -{d['pass_to_fail']} | {d['fail_to_fail']} |"
            )

        if s["regressions_list"]:
            md_lines.extend([
                "",
                f"#### Regressed Tasks in {s['suite_name']} (v1 Passed &rarr; v2 Failed):",
            ])
            for reg in s["regressions_list"]:
                md_lines.append(f"- `{reg}`")
        else:
            md_lines.extend([
                "",
                f"#### Regressed Tasks in {s['suite_name']}: None (0 regressions)",
            ])

        md_lines.append("")

    (output_dir / "paired_v1_v2_comparison.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    (output_dir / "paired_v1_v2_comparison.md").write_text("\n".join(md_lines) + "\n", encoding="utf-8")

    print(f"[+] Paired transition comparison complete! Saved to {output_dir / 'paired_v1_v2_comparison.md'}")
    return report


def main():
    parser = argparse.ArgumentParser(description="Paired SFT v1 -> v2 Comparison and McNemar Test")
    parser.add_argument("--output-dir", type=Path, default=PROJECT_ROOT / "runs" / "evaluation" / "qwen3-8b-full-sft-v2")
    args = parser.parse_args()
    run_paired_analysis(args.output_dir)


if __name__ == "__main__":
    main()
