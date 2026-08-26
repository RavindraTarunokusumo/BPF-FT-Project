#!/usr/bin/env python3
"""
BPF-Guardian Controlled Repair Benchmark (Qwen3 8B)
Runs a diagnostic-guided single repair attempt (c00-r01) for all 33 failing calibration tasks.
Evaluates compilation recovery, verifier recovery, behavioral recovery, and Repair@1.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from verifier.engine import BPFValidator, compute_sha256

CALIB_ROOT = PROJECT_ROOT / "data" / "calibration"
RESULTS_DIR = CALIB_ROOT / "results"
RAW_RESULTS_DIR = RESULTS_DIR / "raw"


def load_env_api_key() -> str:
    """Loads OPENROUTER_API_KEY from environment or .env file."""
    api_key = os.environ.get("OPENROUTER_API_KEY")
    if api_key:
        return api_key.strip()

    env_path = PROJECT_ROOT / ".env"
    if env_path.exists():
        for line in env_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line.startswith("OPENROUTER_API_KEY="):
                return line.split("=", 1)[1].strip().strip('"').strip("'")

    return ""


def call_openrouter(
    prompt: str,
    system_prompt: str,
    api_key: str,
    model: str = "qwen/qwen3-8b",
    temperature: float = 0.0,
    max_retries: int = 3,
) -> str:
    """Calls OpenRouter Chat Completions API with exponential backoff."""
    url = "https://openrouter.ai/api/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://github.com/RavindraTarunokusumo/BPF-FT-Project",
        "X-Title": "BPF-Guardian Calibration Repair Evaluator",
    }

    payload = {
        "model": model,
        "temperature": temperature,
        "max_tokens": 2048,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt},
        ],
    }

    req_data = json.dumps(payload).encode("utf-8")

    for attempt in range(max_retries):
        try:
            req = urllib.request.Request(url, data=req_data, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=60) as resp:
                resp_json = json.loads(resp.read().decode("utf-8"))
                choice = resp_json["choices"][0]["message"]["content"]
                return choice
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="replace")
            print(f"[-] HTTP error {e.code} on attempt {attempt+1}: {err_body}", file=sys.stderr)
            if e.code in (429, 500, 502, 503, 504):
                time.sleep(2 ** attempt + 1)
                continue
            raise RuntimeError(f"OpenRouter API error ({e.code}): {err_body}")
        except Exception as e:
            print(f"[-] Network error on attempt {attempt+1}: {e}", file=sys.stderr)
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt + 1)
                continue
            raise RuntimeError(f"Failed to connect to OpenRouter: {e}")

    raise RuntimeError("Exceeded maximum retries calling OpenRouter API")


def extract_c_code(response_text: str) -> str:
    """Extracts C code from markdown code fences or returns sanitized text."""
    match = re.search(r"```(?:c|C|cpp)?\s*(.*?)\s*```", response_text, re.DOTALL)
    if match:
        return match.group(1).strip() + "\n"
    
    if "#include" in response_text:
        idx = response_text.find("#include")
        return response_text[idx:].strip() + "\n"

    return response_text.strip() + "\n"


SYSTEM_PROMPT = """You are an expert Linux kernel eBPF and XDP systems programmer.
You are fixing an XDP program that produced diagnostic errors during evaluation.

Requirements:
1. Provide the complete, corrected, and self-contained C source code.
2. Include all necessary Linux headers (<linux/bpf.h>, <linux/if_ether.h>, <linux/ip.h>, <linux/in.h>, <linux/tcp.h>, <linux/udp.h>, <bpf/bpf_helpers.h>, <bpf/bpf_endian.h>).
3. Place the program in SEC("xdp") and include char _license[] SEC("license") = "GPL";.
4. Enforce strict packet bounds checks before every memory dereference ((void *)(ptr + 1) > data_end must return XDP_PASS or safe action).
5. Return ONLY valid C source code enclosed in a single ```c ... ``` code block without conversational explanation."""


def format_repair_prompt(task_spec: Dict[str, Any], original_c: str, diagnostic: str) -> str:
    task_id = task_spec["task_id"]
    category = task_spec.get("application_category", "packet_filtering_security")
    difficulty = task_spec.get("difficulty", "level_1")
    instruction = task_spec["instruction"]
    reqs = task_spec.get("requirements", [])
    reqs_formatted = "\n".join(f"- {r}" for r in reqs)

    prompt = f"""Task ID: {task_id}
Category: {category}
Difficulty: {difficulty}

Original Instruction:
{instruction}

Technical Requirements:
{reqs_formatted}

Previous Implementation:
```c
{original_c.strip()}
```

Diagnostic Output:
```text
{diagnostic.strip()}
```

Please provide the corrected, complete, and self-contained C source code for this XDP program."""
    return prompt


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Qwen3 8B Controlled Repair Benchmark")
    parser.add_argument("--model", type=str, default="qwen/qwen3-8b", help="OpenRouter model ID")
    parser.add_argument("--category", type=str, default=None, help="Optional category filter")
    parser.add_argument("--level", type=str, default=None, help="Optional level filter")
    parser.add_argument("--force", action="store_true", help="Force re-generation of existing repairs")
    parser.add_argument("--dry-run", action="store_true", help="Simulate generation without calling API")
    args = parser.parse_args()

    api_key = load_env_api_key()
    if not api_key and not args.dry_run:
        print("[-] ERROR: OPENROUTER_API_KEY not found in environment or .env file", file=sys.stderr)
        sys.exit(1)

    RAW_RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    validator = BPFValidator()

    print("=" * 60)
    print("BPF-Guardian Controlled Repair Benchmark (Repair@1)")
    print(f"Model: {args.model}")
    print(f"Timestamp: {datetime.datetime.now(datetime.timezone.utc).isoformat()}")
    print("=" * 60)

    # Collect all tasks
    tasks = []
    for cat_dir in sorted(CALIB_ROOT.iterdir()):
        if not cat_dir.is_dir() or cat_dir.name in ("assignments", "results"):
            continue
        if args.category and cat_dir.name != args.category:
            continue

        for lvl_dir in sorted(cat_dir.iterdir()):
            if not lvl_dir.is_dir():
                continue
            if args.level and lvl_dir.name != args.level:
                continue

            for task_dir in sorted(lvl_dir.iterdir()):
                if not task_dir.is_dir():
                    continue
                task_json_file = task_dir / "task.json"
                if task_json_file.exists():
                    tasks.append((cat_dir.name, lvl_dir.name, task_dir))

    print(f"Found {len(tasks)} total calibration tasks.\n")

    summary_stats = {
        "model": args.model,
        "total_calibration_tasks": len(tasks),
        "zero_shot_passed_c00": 0,
        "failing_candidates_targeted": 0,
        "repairs_generated": 0,
        "compilation_recovery": 0,
        "verifier_recovery": 0,
        "behavioral_recovery": 0,
        "repair_at_1_rate": 0.0,
        "final_dataset_pass_count": 0,
        "final_dataset_pass_rate": 0.0,
        "by_category": {},
        "by_difficulty": {},
        "tasks": {},
    }

    for idx, (cat, lvl, task_dir) in enumerate(tasks, start=1):
        task_id = task_dir.name
        task_json_file = task_dir / "task.json"
        task_spec = json.loads(task_json_file.read_text(encoding="utf-8"))

        c00_file = task_dir / "c00.c"
        c00_val_file = RAW_RESULTS_DIR / f"{task_id}_c00.json"

        c01_file = task_dir / "c00-r01.c"
        c01_meta_file = task_dir / "c00-r01.meta.json"
        cand_id = f"{task_id}_c00_r01"
        c01_val_file = RAW_RESULTS_DIR / f"{cand_id}.json"

        # Check c00 validation status
        c00_passed = False
        c00_diagnostic = "No validation record found"
        if c00_val_file.exists():
            try:
                c00_data = json.loads(c00_val_file.read_text(encoding="utf-8"))
                c00_passed = c00_data.get("passed", False)
                c00_diagnostic = c00_data.get("diagnostic") or c00_data.get("compile", {}).get("stderr") or c00_data.get("verifier", {}).get("stderr") or "Validation failure"
            except Exception:
                pass

        if c00_passed:
            summary_stats["zero_shot_passed_c00"] += 1
            summary_stats["final_dataset_pass_count"] += 1
            print(f"[{idx}/{len(tasks)}] {cat} / {lvl} / {task_id} -> ALREADY PASSING at c00 (Skipping repair)")
            summary_stats["tasks"][task_id] = {
                "category": cat,
                "difficulty": lvl,
                "status": "pass_at_c00",
                "c00_passed": True,
                "repaired": False,
            }
            continue

        # Targeted for repair
        summary_stats["failing_candidates_targeted"] += 1
        print(f"[{idx}/{len(tasks)}] {cat} / {lvl} / {task_id} -> TARGETING REPAIR")

        original_c = c00_file.read_text(encoding="utf-8") if c00_file.exists() else ""

        # 1. Generate c00-r01.c
        if c01_file.exists() and not args.force:
            print(f"  [*] Using existing repair candidate {c01_file.name}")
            c_code = c01_file.read_text(encoding="utf-8")
        elif args.dry_run:
            print(f"  [*] DRY-RUN: Skipping repair generation")
            continue
        else:
            print(f"  [*] Querying {args.model} for repair...")
            repair_prompt = format_repair_prompt(task_spec, original_c, c00_diagnostic)
            try:
                raw_response = call_openrouter(repair_prompt, SYSTEM_PROMPT, api_key, model=args.model)
                c_code = extract_c_code(raw_response)
                summary_stats["repairs_generated"] += 1

                # Save c00-r01.c
                c01_file.write_text(c_code, encoding="utf-8")

                # Save metadata
                meta_data = {
                    "candidate_id": cand_id,
                    "task_id": task_id,
                    "application_category": cat,
                    "difficulty": lvl,
                    "authoring_harness": "openrouter",
                    "authoring_model": args.model,
                    "generation_prompt_version": "calibration-repair-v1",
                    "source_path": "c00-r01.c",
                    "parent_candidate_id": f"{task_id}_c00",
                    "repair_attempt": 1,
                    "claimed_status": "unvalidated",
                    "source_sha256": compute_sha256(c01_file),
                    "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                }
                c01_meta_file.write_text(json.dumps(meta_data, indent=2), encoding="utf-8")
                time.sleep(1.0)
            except Exception as e:
                print(f"  [-] Repair generation failed: {e}")
                continue

        # 2. Validate repair
        print(f"  [*] Running validation gates on repair...")
        val_result = validator.validate_candidate(
            task_id=task_id,
            candidate_id=cand_id,
            source_path=c01_file,
            task_spec=task_spec,
            category=cat,
            level=lvl,
        )

        c01_val_file.write_text(json.dumps(val_result, indent=2), encoding="utf-8")

        compile_ok = val_result["compile"]["pass"]
        verifier_ok = val_result["verifier"]["pass"]
        behavioral_ok = val_result["behavioral"]["pass"]
        passed = val_result["passed"]

        stage = "pass"
        if not compile_ok:
            stage = "compile_error"
        elif not verifier_ok:
            stage = "verifier_error"
        elif not behavioral_ok:
            stage = "behavioral_error"

        if compile_ok:
            summary_stats["compilation_recovery"] += 1
        if verifier_ok:
            summary_stats["verifier_recovery"] += 1
        if passed:
            summary_stats["behavioral_recovery"] += 1
            summary_stats["final_dataset_pass_count"] += 1

        status_tag = "[+] REPAIR SUCCESS (PASS)" if passed else f"[-] REPAIR FAILED ({stage})"
        print(f"  {status_tag} (compile={compile_ok}, verifier={verifier_ok}, tests={val_result['behavioral']['passed_tests']}/{val_result['behavioral']['total_tests']})")

        # Category stats
        if cat not in summary_stats["by_category"]:
            summary_stats["by_category"][cat] = {"targeted": 0, "repaired": 0, "compile_ok": 0, "verifier_ok": 0}
        summary_stats["by_category"][cat]["targeted"] += 1
        if compile_ok:
            summary_stats["by_category"][cat]["compile_ok"] += 1
        if verifier_ok:
            summary_stats["by_category"][cat]["verifier_ok"] += 1
        if passed:
            summary_stats["by_category"][cat]["repaired"] += 1

        # Difficulty stats
        if lvl not in summary_stats["by_difficulty"]:
            summary_stats["by_difficulty"][lvl] = {"targeted": 0, "repaired": 0, "compile_ok": 0, "verifier_ok": 0}
        summary_stats["by_difficulty"][lvl]["targeted"] += 1
        if compile_ok:
            summary_stats["by_difficulty"][lvl]["compile_ok"] += 1
        if verifier_ok:
            summary_stats["by_difficulty"][lvl]["verifier_ok"] += 1
        if passed:
            summary_stats["by_difficulty"][lvl]["repaired"] += 1

        summary_stats["tasks"][task_id] = {
            "category": cat,
            "difficulty": lvl,
            "status": "repaired_pass" if passed else f"repaired_fail_{stage}",
            "c00_passed": False,
            "c01_passed": passed,
            "stage": stage,
            "compile": compile_ok,
            "verifier": verifier_ok,
            "passed_tests": val_result["behavioral"]["passed_tests"],
            "total_tests": val_result["behavioral"]["total_tests"],
            "diagnostic": val_result.get("diagnostic"),
        }

    targeted = summary_stats["failing_candidates_targeted"]
    if targeted > 0:
        summary_stats["repair_at_1_rate"] = summary_stats["behavioral_recovery"] / targeted

    total_tasks = summary_stats["total_calibration_tasks"]
    if total_tasks > 0:
        summary_stats["final_dataset_pass_rate"] = summary_stats["final_dataset_pass_count"] / total_tasks

    # Save summary report
    summary_file = RESULTS_DIR / f"calibration_repair_{args.model.replace('/', '_')}_summary.json"
    summary_file.write_text(json.dumps(summary_stats, indent=2), encoding="utf-8")

    print("\n" + "=" * 60)
    print("CONTROLLED REPAIR BENCHMARK SUMMARY (Repair@1)")
    print("=" * 60)
    print(f"Model:                    {args.model}")
    print(f"Total Calibration Tasks:  {total_tasks}")
    print(f"Baseline Zero-Shot Pass:  {summary_stats['zero_shot_passed_c00']}/{total_tasks} ({summary_stats['zero_shot_passed_c00']/total_tasks*100:.1f}%)")
    print(f"Failed Candidates Sent:   {targeted}")
    print(f"Compilation Recovery:     {summary_stats['compilation_recovery']}/{targeted} ({summary_stats['compilation_recovery']/targeted*100:.1f}%)")
    print(f"Verifier Recovery:        {summary_stats['verifier_recovery']}/{targeted} ({summary_stats['verifier_recovery']/targeted*100:.1f}%)")
    print(f"Behavioral Repair@1:      {summary_stats['behavioral_recovery']}/{targeted} ({summary_stats['repair_at_1_rate']*100:.1f}%)")
    print(f"Post-Repair Total Pass:   {summary_stats['final_dataset_pass_count']}/{total_tasks} ({summary_stats['final_dataset_pass_rate']*100:.1f}%)")
    print("\nBreakdown by Category (Repaired / Targeted):")
    for c, stats in summary_stats["by_category"].items():
        print(f"  {c:<30} Repaired: {stats['repaired']}/{stats['targeted']} (compile: {stats['compile_ok']}/{stats['targeted']}, verifier: {stats['verifier_ok']}/{stats['targeted']})")
    print("\nBreakdown by Difficulty (Repaired / Targeted):")
    for d, stats in summary_stats["by_difficulty"].items():
        print(f"  {d:<30} Repaired: {stats['repaired']}/{stats['targeted']} (compile: {stats['compile_ok']}/{stats['targeted']}, verifier: {stats['verifier_ok']}/{stats['targeted']})")
    print(f"\n[+] Full repair results written to {summary_file}")
    print("=" * 60)


if __name__ == "__main__":
    main()
