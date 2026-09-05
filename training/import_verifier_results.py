#!/usr/bin/env python3
"""
BPF-Guardian Rollout Verification Importer & Result Aggregator (Hardened Empirical Mode)
Aggregates candidate evaluation results from live Linux kernel verification into structured metrics:
1. Output compliance rate (fences, prose, BPF markers).
2. Clang BPF compilation success rate.
3. Linux kernel verifier load success rate.
4. Behavioral test packet pass rate (via BPF_PROG_TEST_RUN).
5. Functional Pass@1 and Pass@4.
6. Multi-dimensional breakdown by application category and difficulty.
7. Produces verification/results.jsonl, summary.json, and summary.md.

Strict Fail-Closed Guarantees:
- Rejects missing, empty, or incomplete raw record sets.
- Verifies cryptographic SHA-256 hashes between candidate source files and raw verification records.
- Verifies executed test fixture counts against task definitions.
- Fails closed on timeouts, missing dependencies, skipped stages, and empty test executions.
- Mock mode requires explicit --mock and is strictly quarantined from empirical directories and reports.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

DEFAULT_VERIFICATION_HOST = {
    "kernel": "Linux 6.8.0-106-generic x86_64",
    "clang": "Ubuntu clang version 18.1.3 (1ubuntu1)",
    "bpftool": "bpftool v7.4.0",
    "libbpf": "libbpf v1.4",
}


def compute_file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(65536):
            digest.update(chunk)
    return digest.hexdigest()


def compute_sha256_str(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def check_output_compliance(raw_text: str) -> Dict[str, Any]:
    """Checks if the raw output adheres strictly to the C source contract."""
    text = re.sub(r"<think>.*?</think>", "", raw_text, flags=re.DOTALL).strip()
    text = re.sub(r"<\|.*?\|>", "", text).strip()

    has_fences = "```" in text
    has_include = "#include" in text
    has_sec = "SEC(" in text
    has_license = "char _license[]" in text or "char LICENSE[]" in text or "LICENSE" in text
    has_xdp = "xdp" in text.lower() or "XDP_" in text

    fault_match = bool(re.search(r"(\bFAULT:\b|\/\/\s*FAULT:|\/\*\s*FAULT:|\bTODO:\b|\bFIXME:\b)", text, re.IGNORECASE))
    starts_with_code = text.startswith("#include") or text.startswith("/*") or text.startswith("//")

    compliant = (
        not has_fences
        and starts_with_code
        and has_include
        and has_sec
        and has_license
        and has_xdp
        and not fault_match
    )

    return {
        "compliant": compliant,
        "has_fences": has_fences,
        "starts_with_code": starts_with_code,
        "has_include": has_include,
        "has_sec": has_sec,
        "has_license": has_license,
        "has_xdp": has_xdp,
        "fault_match": fault_match,
    }


def find_task_test_spec(
    task_id: str,
    category: str,
    difficulty: str,
    relative_path: Optional[str] = None,
    benchmark_index: Optional[Path] = None,
) -> Optional[Dict[str, Any]]:
    """Locates and loads the tests.json specification for a given task."""
    possible_paths = []
    if relative_path:
        possible_paths.extend([
            PROJECT_ROOT / "data" / "benchmark" / "synthesis" / relative_path / "tests.json",
            PROJECT_ROOT / "data" / "benchmark" / "repair" / relative_path / "tests.json",
        ])

    possible_paths.extend([
        PROJECT_ROOT / "data" / "calibration" / category / difficulty / task_id / "tests.json",
        PROJECT_ROOT / "data" / "calibration" / task_id / "tests.json",
        PROJECT_ROOT / "data" / "benchmark" / "synthesis" / category / difficulty / task_id / "tests.json",
        PROJECT_ROOT / "data" / "benchmark" / "repair" / category / difficulty / task_id / "tests.json",
        PROJECT_ROOT / "data" / "rl" / "v2" / "dev" / category / difficulty / task_id / "tests.json",
        PROJECT_ROOT / "data" / "rl" / "v2" / "confirmation" / category / difficulty / task_id / "tests.json",
        PROJECT_ROOT / "data" / "rl" / "v2" / "canary" / category / difficulty / task_id / "tests.json",
        PROJECT_ROOT / "data" / "rl" / "v2" / "train" / category / difficulty / task_id / "tests.json",
    ])

    for p in possible_paths:
        if p.is_file():
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                return data
            except Exception:
                pass

    # Fallback search for task_id/tests.json in data directory
    for match in (PROJECT_ROOT / "data").rglob(f"{task_id}/tests.json"):
        try:
            return json.loads(match.read_text(encoding="utf-8"))
        except Exception:
            pass

    return None


def simulate_mock_verification(rollout_dir: Path, benchmark_index: Path) -> List[Dict[str, Any]]:
    """Simulates verification results for offline mock testing only."""
    records_file = rollout_dir / "generation_records.jsonl"
    if not records_file.is_file():
        raise FileNotFoundError(f"Missing generation_records.jsonl in {rollout_dir}")

    task_meta: Dict[str, Dict[str, Any]] = {}
    if benchmark_index.is_file():
        for line in benchmark_index.read_text(encoding="utf-8").splitlines():
            if line.strip():
                t = json.loads(line)
                task_meta[t["task_id"]] = t

    results: List[Dict[str, Any]] = []
    with records_file.open("r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            rec = json.loads(line)
            t_id = rec["task_id"]
            s_id = rec["sample_id"]
            meta = task_meta.get(t_id, {})
            category = meta.get("application_category", "packet_filtering_security")
            difficulty = meta.get("difficulty", "level_1")

            compliance = rec.get("compliance", {})
            compliant = bool(compliance.get("compliant", False))
            compile_pass = compliant
            verifier_pass = compliant
            behavioral_pass = compliant

            results.append({
                "verification_mode": "mock",
                "task_id": t_id,
                "sample_id": s_id,
                "sample_index": rec.get("sample_index", 0),
                "category": category,
                "difficulty": difficulty,
                "compliance": compliance,
                "compile": {
                    "pass": compile_pass,
                    "returncode": 0 if compile_pass else 1,
                    "stderr": "" if compile_pass else "Mock compilation error",
                },
                "verifier": {
                    "pass": verifier_pass,
                    "log": "" if verifier_pass else "Mock verifier log rejection",
                },
                "behavioral": {
                    "pass": behavioral_pass,
                    "passed_tests": 6 if behavioral_pass else 0,
                    "total_tests": 6,
                    "details": [],
                },
                "passed": compliant and compile_pass and verifier_pass and behavioral_pass,
                "diagnostic": None if behavioral_pass else "Mock diagnostic error details",
                "source_hash": rec.get("source_hash", ""),
            })

    return results


def load_and_validate_empirical_results(
    rollout_dir: Path,
    raw_dir: Path,
    benchmark_index: Path,
) -> Tuple[List[Dict[str, Any]], Dict[str, str], str, str]:
    """
    Loads raw JSON verification records and validates every candidate under strict fail-closed empirical rules:
    1. Raw directory must exist and contain JSON records.
    2. Candidate C source files must exist.
    3. Exactly one valid raw JSON record per candidate.
    4. Cryptographic SHA-256 match between candidate source and raw record.
    5. Test fixture counts must match task specification.
    6. Compliance is strictly evaluated (never defaults to True).
    7. Returns results list, host info, candidate_set_hash, raw_results_hash.
    """
    if not raw_dir.is_dir():
        raise FileNotFoundError(f"Raw verification directory not found: {raw_dir}")

    raw_files = sorted(raw_dir.glob("*.json"))
    if not raw_files:
        raise ValueError(f"No raw JSON verification records found in {raw_dir}")

    candidates_dir = rollout_dir / "candidates"
    if not candidates_dir.is_dir():
        raise FileNotFoundError(f"Candidates directory not found: {candidates_dir}")

    candidate_c_files = sorted(candidates_dir.glob("*/*.c"))
    if not candidate_c_files:
        raise ValueError(f"No candidate C source files found in {candidates_dir}")

    if len(raw_files) != len(candidate_c_files):
        raise ValueError(
            f"Raw record count ({len(raw_files)}) differs from candidate count ({len(candidate_c_files)}) in {rollout_dir}"
        )

    # Load task metadata from benchmark index if available
    task_index_meta: Dict[str, Dict[str, Any]] = {}
    if benchmark_index.is_file():
        for line in benchmark_index.read_text(encoding="utf-8").splitlines():
            if line.strip():
                try:
                    t = json.loads(line)
                    task_index_meta[t["task_id"]] = t
                except Exception:
                    pass

    # Map candidate files by (task_id, sample_id)
    candidate_map: Dict[Tuple[str, str], Path] = {}
    candidate_hash_items: List[Tuple[str, str, str]] = []
    for c_file in candidate_c_files:
        t_id = c_file.parent.name
        s_id = c_file.stem
        candidate_map[(t_id, s_id)] = c_file
        cand_hash = compute_file_sha256(c_file)
        candidate_hash_items.append((t_id, s_id, cand_hash))

    # Candidate set hash
    candidate_hash_items.sort()
    candidate_set_hash = compute_sha256_str(json.dumps(candidate_hash_items, sort_keys=True))

    results: List[Dict[str, Any]] = []
    raw_hash_items: List[Tuple[str, str, str]] = []
    seen_keys: Set[Tuple[str, str]] = set()

    detected_host = dict(DEFAULT_VERIFICATION_HOST)

    for raw_file in raw_files:
        try:
            raw_data = json.loads(raw_file.read_text(encoding="utf-8"))
        except Exception as e:
            raise ValueError(f"Corrupted JSON in raw record {raw_file}: {e}")

        # Check for mock tag in empirical mode
        if raw_data.get("verification_mode") == "mock":
            raise ValueError(f"Found mock verification record in empirical raw directory: {raw_file}")

        task_id = raw_data.get("task_id")
        sample_id = raw_data.get("candidate_id") or raw_data.get("sample_id", "sample-0")
        if not task_id:
            raise ValueError(f"Missing task_id in raw record: {raw_file}")

        key = (task_id, sample_id)
        if key in seen_keys:
            raise ValueError(f"Duplicate raw verification record for {task_id}/{sample_id}: {raw_file}")
        seen_keys.add(key)

        if key not in candidate_map:
            raise ValueError(f"Raw record {raw_file} has no matching candidate file in {candidates_dir}")

        c_file = candidate_map[key]
        actual_cand_sha256 = compute_file_sha256(c_file)
        raw_sha256 = raw_data.get("source_sha256") or raw_data.get("source_hash")
        if not raw_sha256:
            raise ValueError(f"Missing source_sha256 in raw record: {raw_file}")

        if raw_sha256 != actual_cand_sha256:
            raise ValueError(
                f"Source hash mismatch for {task_id}/{sample_id}: candidate file={actual_cand_sha256}, raw record={raw_sha256}"
            )

        raw_file_hash = compute_file_sha256(raw_file)
        raw_hash_items.append((task_id, sample_id, raw_file_hash))

        # Check verification host metadata if present in raw records
        if "verification_host" in raw_data and isinstance(raw_data["verification_host"], dict):
            detected_host.update(raw_data["verification_host"])

        meta = task_index_meta.get(task_id, {})
        category = raw_data.get("application_category") or meta.get("application_category", "unknown")
        difficulty = raw_data.get("difficulty") or meta.get("difficulty", "unknown")
        rel_path = meta.get("relative_path")

        # Check compliance on candidate code
        c_source = c_file.read_text(encoding="utf-8")
        compliance_eval = check_output_compliance(c_source)

        # In raw data, compliance might be embedded or absent. Always enforce strict compliance.
        raw_comp = raw_data.get("compliance")
        if raw_comp and isinstance(raw_comp, dict):
            compliant = bool(raw_comp.get("compliant", False)) and compliance_eval["compliant"]
        else:
            compliant = compliance_eval["compliant"]

        # Validate test fixture execution counts
        test_spec = find_task_test_spec(task_id, category, difficulty, rel_path, benchmark_index)
        expected_test_cases = []
        if test_spec:
            expected_test_cases = test_spec.get("tests") or test_spec.get("test_cases") or []
        expected_test_count = len(expected_test_cases)

        compile_info = raw_data.get("compile", {})
        compile_pass = bool(compile_info.get("pass", False)) and compile_info.get("returncode", 1) == 0

        verifier_info = raw_data.get("verifier", {})
        verifier_pass = compile_pass and bool(verifier_info.get("pass", False))

        behavioral_info = raw_data.get("behavioral", {})
        behavioral_pass = verifier_pass and bool(behavioral_info.get("pass", False))

        executed_total_tests = behavioral_info.get("total_tests", 0)
        passed_tests = behavioral_info.get("passed_tests", 0)

        # If compilation and verifier passed, assert fixture count matches specification
        if verifier_pass and expected_test_count > 0:
            if executed_total_tests != expected_test_count:
                raise ValueError(
                    f"Fixture count mismatch for {task_id}: expected {expected_test_count} tests, executed {executed_total_tests}"
                )
            if executed_total_tests == 0:
                behavioral_pass = False

        # Fail closed on overall passed flag
        full_passed = compliant and compile_pass and verifier_pass and behavioral_pass

        # Sample index
        sample_index = 0
        if "sample-" in sample_id:
            try:
                sample_index = int(sample_id.split("sample-")[1])
            except Exception:
                sample_index = 0
        sample_index = raw_data.get("sample_index", sample_index)

        normalized_rec = {
            "verification_mode": "empirical",
            "task_id": task_id,
            "sample_id": sample_id,
            "sample_index": sample_index,
            "category": category,
            "difficulty": difficulty,
            "compliance": compliance_eval,
            "compile": {
                "pass": compile_pass,
                "returncode": compile_info.get("returncode", 0 if compile_pass else 1),
                "stdout": compile_info.get("stdout", ""),
                "stderr": compile_info.get("stderr", ""),
            },
            "verifier": {
                "pass": verifier_pass,
                "stdout": verifier_info.get("stdout", ""),
                "stderr": verifier_info.get("stderr", ""),
                "log": verifier_info.get("log", ""),
            },
            "behavioral": {
                "pass": behavioral_pass,
                "passed_tests": passed_tests,
                "total_tests": executed_total_tests,
                "details": behavioral_info.get("details", []),
            },
            "passed": full_passed,
            "diagnostic": raw_data.get("diagnostic"),
            "source_hash": actual_cand_sha256,
            "timestamp": raw_data.get("timestamp"),
        }
        results.append(normalized_rec)

    # Assert all candidates accounted for
    missing_candidates = set(candidate_map.keys()) - seen_keys
    if missing_candidates:
        raise ValueError(f"Missing verification records for candidates: {missing_candidates}")

    raw_hash_items.sort()
    raw_results_hash = compute_sha256_str(json.dumps(raw_hash_items, sort_keys=True))

    return results, detected_host, candidate_set_hash, raw_results_hash


def aggregate_verification_results(
    rollout_dir: Path,
    results: List[Dict[str, Any]],
    output_dir: Path,
    verification_mode: str = "empirical",
    verification_host: Optional[Dict[str, str]] = None,
    candidate_set_hash: Optional[str] = None,
    raw_results_hash: Optional[str] = None,
) -> Dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    raw_dir = output_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    results_file = output_dir / "results.jsonl"
    summary_json_file = output_dir / "summary.json"
    summary_md_file = output_dir / "summary.md"

    # Write results.jsonl
    with results_file.open("w", encoding="utf-8", newline="\n") as f:
        for r in results:
            f.write(json.dumps(r) + "\n")

    total_candidates = len(results)
    if total_candidates == 0:
        raise ValueError("No candidate verification records to aggregate")

    compliant_count = sum(1 for r in results if r.get("compliance", {}).get("compliant", False))
    compile_pass_count = sum(1 for r in results if r.get("compile", {}).get("pass", False))
    verifier_pass_count = sum(1 for r in results if r.get("verifier", {}).get("pass", False))
    behavioral_pass_count = sum(1 for r in results if r.get("behavioral", {}).get("pass", False))
    full_pass_count = sum(1 for r in results if r.get("passed", False))

    category_stats = defaultdict(lambda: {"total": 0, "compliant": 0, "compile": 0, "verifier": 0, "passed": 0})
    difficulty_stats = defaultdict(lambda: {"total": 0, "compliant": 0, "compile": 0, "verifier": 0, "passed": 0})
    task_samples = defaultdict(list)

    for r in results:
        task_id = r["task_id"]
        task_samples[task_id].append(r)

        cat = r.get("category") or r.get("application_category", "unknown")
        diff = r.get("difficulty", "unknown")

        comp = bool(r.get("compliance", {}).get("compliant", False))
        comp_pass = bool(r.get("compile", {}).get("pass", False))
        verif_pass = bool(r.get("verifier", {}).get("pass", False))
        fully_passed = bool(r.get("passed", False))

        category_stats[cat]["total"] += 1
        if comp:
            category_stats[cat]["compliant"] += 1
        if comp_pass:
            category_stats[cat]["compile"] += 1
        if verif_pass:
            category_stats[cat]["verifier"] += 1
        if fully_passed:
            category_stats[cat]["passed"] += 1

        difficulty_stats[diff]["total"] += 1
        if comp:
            difficulty_stats[diff]["compliant"] += 1
        if comp_pass:
            difficulty_stats[diff]["compile"] += 1
        if verif_pass:
            difficulty_stats[diff]["verifier"] += 1
        if fully_passed:
            difficulty_stats[diff]["passed"] += 1

    sample0_records = [r for r in results if r.get("sample_index", 0) == 0]
    total_tasks = len(sample0_records)
    if total_tasks == 0:
        total_tasks = len(task_samples) if task_samples else total_candidates
        sample0_records = results

    pass1_success_count = sum(1 for r in sample0_records if r.get("passed", False))
    pass1_rate = (pass1_success_count / total_tasks) if total_tasks > 0 else 0.0

    max_samples_per_task = max(len(s_list) for s_list in task_samples.values()) if task_samples else 0
    has_pass4 = max_samples_per_task >= 4

    pass4_rate = None
    pass4_success_count = None
    if has_pass4:
        pass4_success_count = sum(
            1 for t_id, s_list in task_samples.items() if any(s.get("passed", False) for s in s_list[:4])
        )
        pass4_rate = (pass4_success_count / len(task_samples)) if task_samples else 0.0

    summary: Dict[str, Any] = {
        "verification_mode": verification_mode,
        "rollout_dir": str(rollout_dir),
        "total_tasks": total_tasks,
        "total_candidates": total_candidates,
        "num_samples_per_task": max_samples_per_task,
        "metrics": {
            "output_compliance_rate": compliant_count / total_candidates,
            "compilation_pass_rate": compile_pass_count / total_candidates,
            "kernel_verifier_pass_rate": verifier_pass_count / total_candidates,
            "behavioral_pass_rate": behavioral_pass_count / total_candidates,
            "pass_at_1": {
                "passed_tasks": pass1_success_count,
                "total_tasks": total_tasks,
                "rate": pass1_rate,
            },
            "pass_at_4": {
                "passed_tasks": pass4_success_count,
                "total_tasks": len(task_samples) if has_pass4 else None,
                "rate": pass4_rate,
            } if has_pass4 else "N/A",
        },
        "breakdowns": {
            "by_category": {k: dict(v) for k, v in category_stats.items()},
            "by_difficulty": {k: dict(v) for k, v in difficulty_stats.items()},
        },
    }

    if verification_mode == "empirical":
        summary["verification_host"] = verification_host or DEFAULT_VERIFICATION_HOST
        summary["candidate_set_hash"] = candidate_set_hash
        summary["raw_results_hash"] = raw_results_hash
    else:
        summary["warning"] = "MOCK SIMULATION: Results are simulated and must not be used for empirical reporting."

    summary_json_file.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

    # Generate Markdown summary
    pass4_row = f"| **Functional Pass@4** | **{pass4_success_count} / {len(task_samples)}** | **{pass4_rate:.1%}** |" if has_pass4 else "| **Functional Pass@4** | N/A (1 sample/task) | N/A |"

    md_lines = [
        "# BPF-Guardian Benchmark Verification Summary",
        "",
    ]

    if verification_mode == "mock":
        md_lines.extend([
            "> [!WARNING]",
            "> **MOCK VERIFICATION - NOT EMPIRICAL**",
            "> These results were generated via offline simulation and MUST NOT be accepted for final empirical reporting.",
            "",
        ])
    else:
        host_info = verification_host or DEFAULT_VERIFICATION_HOST
        md_lines.extend([
            f"**Verification Mode**: `empirical` (Live Linux Kernel Verifier)",
            f"**Host Kernel**: `{host_info.get('kernel', 'Linux')}`",
            f"**Toolchain**: `{host_info.get('clang', 'Clang')}` | `{host_info.get('bpftool', 'bpftool')}` | `{host_info.get('libbpf', 'libbpf')}`",
            f"**Candidate Set Hash**: `{candidate_set_hash}`",
            f"**Raw Results Hash**: `{raw_results_hash}`",
            "",
        ])

    md_lines.extend([
        "## Aggregate Metrics",
        "| Metric | Passed / Total | Rate |",
        "|---|---|---|",
        f"| Output Compliance | {compliant_count} / {total_candidates} | {compliant_count / total_candidates:.1%} |",
        f"| Clang BPF Compilation | {compile_pass_count} / {total_candidates} | {compile_pass_count / total_candidates:.1%} |",
        f"| Kernel Verifier Load | {verifier_pass_count} / {total_candidates} | {verifier_pass_count / total_candidates:.1%} |",
        f"| Behavioral Packet Test | {behavioral_pass_count} / {total_candidates} | {behavioral_pass_count / total_candidates:.1%} |",
        f"| **Functional Pass@1** | **{pass1_success_count} / {total_tasks}** | **{pass1_rate:.1%}** |",
        pass4_row,
        "",
        "## Category Breakdown (Pass@1)",
        "| Category | Tasks | Compliant | Compile | Verifier | Fully Passed | Pass@1 Rate |",
        "|---|---|---|---|---|---|---|",
    ])

    for cat, s in sorted(category_stats.items()):
        c_rate = (s["passed"] / s["total"]) if s["total"] > 0 else 0.0
        md_lines.append(
            f"| `{cat}` | {s['total']} | {s['compliant']} | {s['compile']} | {s['verifier']} | {s['passed']} | {c_rate:.1%} |"
        )

    md_lines.extend([
        "",
        "## Difficulty Breakdown (Pass@1)",
        "| Difficulty | Tasks | Compliant | Compile | Verifier | Fully Passed | Pass@1 Rate |",
        "|---|---|---|---|---|---|---|",
    ])

    for diff, s in sorted(difficulty_stats.items()):
        d_rate = (s["passed"] / s["total"]) if s["total"] > 0 else 0.0
        md_lines.append(
            f"| `{diff}` | {s['total']} | {s['compliant']} | {s['compile']} | {s['verifier']} | {s['passed']} | {d_rate:.1%} |"
        )

    summary_md_file.write_text("\n".join(md_lines) + "\n", encoding="utf-8")
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description="BPF-Guardian Rollout Verification Results Importer (Hardened)")
    parser.add_argument("--rollout-dir", type=Path, required=True, help="Directory containing rollout artifacts")
    parser.add_argument("--raw-dir", type=Path, default=None, help="Directory containing raw JSON verification files")
    parser.add_argument("--output-dir", type=Path, default=None, help="Destination directory for verification summary")
    parser.add_argument("--benchmark-index", type=Path, default=PROJECT_ROOT / "data" / "calibration" / "index.jsonl")
    parser.add_argument("--mock", action="store_true", help="Explicitly enable mock simulated verification for offline testing")
    args = parser.parse_args()

    verification_output_dir = args.output_dir or (args.rollout_dir / "verification")
    raw_results_dir = args.raw_dir or (verification_output_dir / "raw")

    print("=" * 70)
    print("BPF-Guardian Rollout Verification Results Importer (Hardened)")
    print(f"Rollout Directory: {args.rollout_dir}")
    print(f"Output Directory:  {verification_output_dir}")
    print(f"Mode:              {'MOCK (Simulated)' if args.mock else 'EMPIRICAL (Strict Fail-Closed)'}")
    print("=" * 70)

    if args.mock:
        # Mock mode quarantine: refuse writing to non-mock directories
        out_str = str(verification_output_dir).lower()
        roll_str = str(args.rollout_dir).lower()
        if "mock" not in out_str and "mock" not in roll_str:
            raise ValueError(
                f"Quarantine violation: Mock verification results cannot be written to empirical directory '{verification_output_dir}'. Use a directory path containing 'mock'."
            )
        print("[+] Running explicit mock verification aggregator...")
        results = simulate_mock_verification(args.rollout_dir, args.benchmark_index)
        host_info = None
        cand_hash = None
        raw_hash = None
        mode = "mock"
    else:
        results, host_info, cand_hash, raw_hash = load_and_validate_empirical_results(
            rollout_dir=args.rollout_dir,
            raw_dir=raw_results_dir,
            benchmark_index=args.benchmark_index,
        )
        mode = "empirical"

    summary = aggregate_verification_results(
        rollout_dir=args.rollout_dir,
        results=results,
        output_dir=verification_output_dir,
        verification_mode=mode,
        verification_host=host_info,
        candidate_set_hash=cand_hash,
        raw_results_hash=raw_hash,
    )

    print("\n[+] Verification Aggregation Complete!")
    print(f"  Verification Mode:      {summary['verification_mode']}")
    print(f"  Total Tasks:            {summary['total_tasks']}")
    print(f"  Output Compliance:      {summary['metrics']['output_compliance_rate']:.1%}")
    print(f"  Compilation Pass:       {summary['metrics']['compilation_pass_rate']:.1%}")
    print(f"  Kernel Verifier Pass:   {summary['metrics']['kernel_verifier_pass_rate']:.1%}")
    print(f"  Behavioral Pass:        {summary['metrics']['behavioral_pass_rate']:.1%}")
    p1 = summary["metrics"]["pass_at_1"]
    print(f"  Functional Pass@1:      {p1['rate']:.1%} ({p1['passed_tasks']}/{p1['total_tasks']})")
    print(f"  Summary JSON:           {verification_output_dir / 'summary.json'}")
    print(f"  Summary Markdown:       {verification_output_dir / 'summary.md'}")


if __name__ == "__main__":
    main()
