"""
Detailed Diagnostic Inspector for the 31 Verifier-Valid Synthesis Records
"""
import json
from pathlib import Path
from collections import defaultdict

PROJECT_ROOT = Path(__file__).resolve().parent.parent

def main():
    raw_dir = PROJECT_ROOT / "runs" / "evaluation" / "qwen3-8b-full-sft-v1" / "benchmark-synthesis-120" / "verification" / "raw"
    files = sorted(list(raw_dir.glob("*.json")))

    verifier_valid = []
    for f in files:
        d = json.loads(f.read_text(encoding="utf-8"))
        if d.get("verifier", {}).get("pass", False):
            verifier_valid.append(d)

    print(f"Total raw files: {len(files)}")
    print(f"Verifier valid records: {len(verifier_valid)}")

    bucket_0 = []
    bucket_1_49 = []
    bucket_50_99 = []
    bucket_100 = []

    total_fixtures_tested = 0
    total_fixtures_passed = 0

    no_tests_run = []

    print("\n--- Detailed Task Analysis (31 Verifier-Valid Records) ---")
    for idx, r in enumerate(verifier_valid, 1):
        task_id = r["task_id"]
        beh = r.get("behavioral", {})
        tests = beh.get("tests", [])
        tot = beh.get("total_tests", len(tests))
        passed = beh.get("passed_tests", sum(1 for t in tests if t.get("pass", False)))
        err = beh.get("error")

        if tot == 0:
            no_tests_run.append(task_id)
            rate = 0.0
        else:
            rate = passed / tot

        total_fixtures_tested += tot
        total_fixtures_passed += passed

        if tot == 0 or passed == 0:
            bucket_0.append((task_id, passed, tot, rate, err))
        elif rate < 0.50:
            bucket_1_49.append((task_id, passed, tot, rate, err))
        elif rate < 1.0:
            bucket_50_99.append((task_id, passed, tot, rate, err))
        else:
            bucket_100.append((task_id, passed, tot, rate, err))

        print(f"{idx:2d}. {task_id:55s} | Pass: {str(beh.get('pass', False)):5s} | Fixtures: {passed:2d}/{tot:2d} ({rate:5.1%}) | Error: {err}")

    print("\n--- Fixture Accuracy & Distribution ---")
    print(f"Total fixtures executed across 31 verifier-valid tasks: {total_fixtures_tested}")
    print(f"Total fixtures passed across 31 verifier-valid tasks:   {total_fixtures_passed} ({total_fixtures_passed / total_fixtures_tested:.1%})")
    print(f"Tasks with 0% fixtures passed:     {len(bucket_0)} / 31 ({len(bucket_0)/31:.1%})")
    print(f"Tasks with 1-49% fixtures passed:  {len(bucket_1_49)} / 31 ({len(bucket_1_49)/31:.1%})")
    print(f"Tasks with 50-99% fixtures passed: {len(bucket_50_99)} / 31 ({len(bucket_50_99)/31:.1%})")
    print(f"Tasks with 100% fixtures passed:   {len(bucket_100)} / 31 ({len(bucket_100)/31:.1%})")
    print(f"Tasks with 0 tests run (skipped):  {len(no_tests_run)} / 31")

if __name__ == "__main__":
    main()
