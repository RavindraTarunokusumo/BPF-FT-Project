#!/usr/bin/env python3
"""
Paired McNemar Statistical Significance Analysis for Phase N3 RLVR
Compares Baseline (Nemotron SFT v1) vs RL Candidate (Nemotron N3 RL Final / Step 20)
across Dev-48, Confirmation-60, and Protected Synthesis-120 suites.
"""

import argparse
import json
import math
from pathlib import Path
from typing import Dict, Any, List, Tuple


def compute_exact_mcnemar(b: int, c: int) -> Tuple[float, float]:
    """
    Computes McNemar test statistic and two-sided p-value.
    b: Baseline=1, Candidate=0 (baseline wins)
    c: Baseline=0, Candidate=1 (candidate wins)
    """
    n = b + c
    if n == 0:
        return 0.0, 1.0

    stat = (abs(b - c) - 1) ** 2 / n

    if n < 25:
        k = min(b, c)
        p_val = 2.0 * sum(math.comb(n, i) * (0.5 ** n) for i in range(k + 1))
        p_val = min(1.0, p_val)
    else:
        # Chi-square with 1 df approximation
        try:
            from scipy.stats import chi2
            p_val = float(chi2.sf(stat, 1))
        except ImportError:
            z = (abs(b - c) - 1.0) / math.sqrt(n)
            p_val = math.erfc(z / math.sqrt(2.0))
    return round(stat, 4), round(p_val, 4)


def analyze_suite_pair(
    base_results: List[Dict[str, Any]],
    cand_results: List[Dict[str, Any]],
    suite_name: str,
) -> Dict[str, Any]:
    base_map = {r["task_id"]: r for r in base_results}
    cand_map = {r["task_id"]: r for r in cand_results}

    common_ids = sorted(set(base_map.keys()) & set(cand_map.keys()))
    if not common_ids:
        return {"error": f"No common task IDs in suite {suite_name}"}

    # Pass@1 Comparison
    p1_11 = sum(1 for tid in common_ids if base_map[tid]["pass_at_1"] == 1.0 and cand_map[tid]["pass_at_1"] == 1.0)
    p1_10 = sum(1 for tid in common_ids if base_map[tid]["pass_at_1"] == 1.0 and cand_map[tid]["pass_at_1"] == 0.0)
    p1_01 = sum(1 for tid in common_ids if base_map[tid]["pass_at_1"] == 0.0 and cand_map[tid]["pass_at_1"] == 1.0)
    p1_00 = sum(1 for tid in common_ids if base_map[tid]["pass_at_1"] == 0.0 and cand_map[tid]["pass_at_1"] == 0.0)
    p1_stat, p1_p = compute_exact_mcnemar(b=p1_10, c=p1_01)

    # Solve@2 Comparison
    s2_11 = sum(1 for tid in common_ids if base_map[tid]["solve_at_2"] == 1.0 and cand_map[tid]["solve_at_2"] == 1.0)
    s2_10 = sum(1 for tid in common_ids if base_map[tid]["solve_at_2"] == 1.0 and cand_map[tid]["solve_at_2"] == 0.0)
    s2_01 = sum(1 for tid in common_ids if base_map[tid]["solve_at_2"] == 0.0 and cand_map[tid]["solve_at_2"] == 1.0)
    s2_00 = sum(1 for tid in common_ids if base_map[tid]["solve_at_2"] == 0.0 and cand_map[tid]["solve_at_2"] == 0.0)
    s2_stat, s2_p = compute_exact_mcnemar(b=s2_10, c=s2_01)

    # Breakdown of recoveries by failure type
    def breakdown_recoveries(results):
        turn1_comp = sum(1 for r in results if r["turn1_stage"] in ("compile", "compliance", "non_compliant"))
        turn1_ver = sum(1 for r in results if r["turn1_stage"] == "verifier")
        turn1_beh = sum(1 for r in results if r["turn1_stage"] == "behavioral")

        rec_comp = sum(1 for r in results if r.get("recovered") and r["turn1_stage"] in ("compile", "compliance", "non_compliant"))
        rec_ver = sum(1 for r in results if r.get("recovered") and r["turn1_stage"] == "verifier")
        rec_beh = sum(1 for r in results if r.get("recovered") and r["turn1_stage"] == "behavioral")

        return {
            "compile": {"fails": turn1_comp, "rec": rec_comp, "rate": round(rec_comp / turn1_comp, 4) if turn1_comp else 0.0},
            "verifier": {"fails": turn1_ver, "rec": rec_ver, "rate": round(rec_ver / turn1_ver, 4) if turn1_ver else 0.0},
            "behavioral": {"fails": turn1_beh, "rec": rec_beh, "rate": round(rec_beh / turn1_beh, 4) if turn1_beh else 0.0},
        }

    base_breakdown = breakdown_recoveries([base_map[tid] for tid in common_ids])
    cand_breakdown = breakdown_recoveries([cand_map[tid] for tid in common_ids])

    n = len(common_ids)
    return {
        "suite": suite_name,
        "n_tasks": n,
        "pass_at_1": {
            "baseline": {"count": p1_11 + p1_10, "rate": round((p1_11 + p1_10) / n, 4)},
            "candidate": {"count": p1_11 + p1_01, "rate": round((p1_11 + p1_01) / n, 4)},
            "contingency_table": {"n11": p1_11, "n10": p1_10, "n01": p1_01, "n00": p1_00},
            "mcnemar_stat": p1_stat,
            "p_value": p1_p,
            "significant_at_05": p1_p < 0.05,
        },
        "solve_at_2": {
            "baseline": {"count": s2_11 + s2_10, "rate": round((s2_11 + s2_10) / n, 4)},
            "candidate": {"count": s2_11 + s2_01, "rate": round((s2_11 + s2_01) / n, 4)},
            "contingency_table": {"n11": s2_11, "n10": s2_10, "n01": s2_01, "n00": s2_00},
            "mcnemar_stat": s2_stat,
            "p_value": s2_p,
            "significant_at_05": s2_p < 0.05,
        },
        "recovery_breakdown": {
            "baseline": base_breakdown,
            "candidate": cand_breakdown,
        },
    }


def main():
    parser = argparse.ArgumentParser(description="Compute paired McNemar tests between Baseline and Candidate")
    parser.add_argument("--base-dir", type=str, required=True, help="Baseline eval directory (nemotron-sft-v1)")
    parser.add_argument("--cand-dir", type=str, required=True, help="Candidate eval directory (nemotron-rl-n3-final)")
    parser.add_argument("--output-file", type=str, default=None, help="Output JSON path")
    args = parser.parse_args()

    base_dir = Path(args.base_dir)
    cand_dir = Path(args.cand_dir)

    base_master_file = base_dir / "master_summary.json"
    cand_master_file = cand_dir / "master_summary.json"

    assert base_master_file.exists(), f"Baseline master summary not found: {base_master_file}"
    assert cand_master_file.exists(), f"Candidate master summary not found: {cand_master_file}"

    base_master = json.loads(base_master_file.read_text(encoding="utf-8"))
    cand_master = json.loads(cand_master_file.read_text(encoding="utf-8"))

    common_suites = sorted(set(base_master.get("suites", {}).keys()) & set(cand_master.get("suites", {}).keys()))
    print(f"Comparing suites: {common_suites}\n")

    report = {"suites": {}}
    for sname in common_suites:
        b_res = base_master["suites"][sname]["results"]
        c_res = cand_master["suites"][sname]["results"]
        analysis = analyze_suite_pair(b_res, c_res, sname)
        report["suites"][sname] = analysis

        print(f"=== Suite: {sname} (N={analysis['n_tasks']}) ===")
        p1 = analysis["pass_at_1"]
        print(f"  Pass@1: Baseline={p1['baseline']['count']} ({p1['baseline']['rate']*100:.1f}%) | "
              f"Candidate={p1['candidate']['count']} ({p1['candidate']['rate']*100:.1f}%) | "
              f"McNemar p={p1['p_value']:.4f} (sig={p1['significant_at_05']})")

        s2 = analysis["solve_at_2"]
        print(f"  Solve@2: Baseline={s2['baseline']['count']} ({s2['baseline']['rate']*100:.1f}%) | "
              f"Candidate={s2['candidate']['count']} ({s2['candidate']['rate']*100:.1f}%) | "
              f"McNemar p={s2['p_value']:.4f} (sig={s2['significant_at_05']})")

        rb = analysis["recovery_breakdown"]
        print(f"  Behavioral Recovery: Baseline={rb['baseline']['behavioral']['rec']}/{rb['baseline']['behavioral']['fails']} "
              f"({rb['baseline']['behavioral']['rate']*100:.1f}%) vs "
              f"Candidate={rb['candidate']['behavioral']['rec']}/{rb['candidate']['behavioral']['fails']} "
              f"({rb['candidate']['behavioral']['rate']*100:.1f}%)")
        print()

    if args.output_file:
        out_p = Path(args.output_file)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"Report written to: {out_p}")


if __name__ == "__main__":
    main()
