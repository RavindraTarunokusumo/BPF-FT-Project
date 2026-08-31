"""
BPF-Guardian Reference Solution Verification Runner
Verifies that all 120 ground-truth solution.c files in data/benchmark/synthesis/
compile, load in the Linux kernel verifier, and pass 100% of their unit test fixtures.
"""
import json
import os
import sys
from pathlib import Path
from typing import Dict, Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from verifier.engine import BPFValidator

def main():
    validator = BPFValidator()
    bench_index = PROJECT_ROOT / "data" / "benchmark" / "synthesis" / "index.jsonl"
    tasks = [json.loads(l) for l in bench_index.read_text(encoding="utf-8").splitlines() if l.strip()]

    print(f"======================================================================")
    print(f"BPF-Guardian Reference Solution Verification (120 Synthesis Tasks)")
    print(f"======================================================================")

    results = []
    bench_base = PROJECT_ROOT / "data" / "benchmark" / "synthesis"

    compile_passed = 0
    verifier_passed = 0
    fully_passed = 0
    total_fixtures = 0
    passed_fixtures = 0

    for idx, t in enumerate(tasks, 1):
        task_id = t["task_id"]
        cat = t["application_category"]
        diff = t["difficulty"]

        task_dir = bench_base / cat / diff / task_id
        sol_c = task_dir / "solution.c"
        test_json = task_dir / "tests.json"

        task_spec = dict(t)
        if test_json.is_file():
            try:
                task_spec["tests"] = json.loads(test_json.read_text(encoding="utf-8")).get("tests", [])
            except Exception:
                task_spec["tests"] = []

        res = validator.validate_candidate(
            task_id=task_id,
            candidate_id="reference",
            source_path=sol_c,
            task_spec=task_spec,
            category=cat,
            level=diff,
        )

        c_pass = res.get("compile", {}).get("pass", False)
        v_pass = res.get("verifier", {}).get("pass", False)
        b_res = res.get("behavioral", {})
        tot_tests = b_res.get("total_tests", 0)
        p_tests = b_res.get("passed_tests", 0)
        f_pass = res.get("passed", False)

        if c_pass: compile_passed += 1
        if v_pass: verifier_passed += 1
        if f_pass: fully_passed += 1
        total_fixtures += tot_tests
        passed_fixtures += p_tests

        results.append(res)
        if idx % 10 == 0 or idx == len(tasks):
            print(f"  Verified {idx:3d}/120 reference solutions... ({fully_passed} fully passed so far, fixtures: {passed_fixtures}/{total_fixtures})", flush=True)

    out_file = PROJECT_ROOT / "runs" / "evaluation" / "qwen3-8b-full-sft-v1" / "synthesis_reference_verification.json"
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(json.dumps({
        "total_tasks": len(tasks),
        "compile_passed": compile_passed,
        "verifier_passed": verifier_passed,
        "fully_passed": fully_passed,
        "total_fixtures": total_fixtures,
        "passed_fixtures": passed_fixtures,
        "results": results,
    }, indent=2), encoding="utf-8")

    print("\n[+] Reference Verification Summary:")
    print(f"  Total Reference Programs: {len(tasks)}")
    print(f"  Compilation Pass:        {compile_passed}/{len(tasks)} ({compile_passed/len(tasks):.1%})")
    print(f"  Kernel Verifier Pass:    {verifier_passed}/{len(tasks)} ({verifier_passed/len(tasks):.1%})")
    print(f"  Full Pass Rate:          {fully_passed}/{len(tasks)} ({fully_passed/len(tasks):.1%})")
    print(f"  Total Fixtures Passed:   {passed_fixtures}/{total_fixtures} ({passed_fixtures/total_fixtures:.1%})")

if __name__ == "__main__":
    main()
