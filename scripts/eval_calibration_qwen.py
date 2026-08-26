#!/usr/bin/env python3
"""
BPF-Guardian Calibration Evaluation Script
Runs single-attempt zero-shot synthesis for all 36 calibration tasks using Qwen3 8B via OpenRouter,
evaluates each generated candidate against the kernel verifier and behavioral test oracle,
and generates full Pass@1 calibration metrics and diagnostics.
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
        "X-Title": "BPF-Guardian Calibration Evaluator",
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
    # Look for ```c ... ```
    match = re.search(r"```(?:c|C|cpp)?\s*(.*?)\s*```", response_text, re.DOTALL)
    if match:
        return match.group(1).strip() + "\n"
    
    # If no markdown block, return text if it starts with #include
    if "#include" in response_text:
        # Find start of #include
        idx = response_text.find("#include")
        return response_text[idx:].strip() + "\n"

    return response_text.strip() + "\n"


SYSTEM_PROMPT = """You are an expert Linux kernel eBPF and XDP systems programmer.
Your task is to write a complete, self-contained, compilation-ready, and kernel-verifier-safe C program for an XDP hook.

Requirements:
1. Include all necessary Linux headers (<linux/bpf.h>, <linux/if_ether.h>, <linux/ip.h>, <linux/in.h>, <linux/tcp.h>, <linux/udp.h>, <bpf/bpf_helpers.h>, <bpf/bpf_endian.h>).
2. Place the XDP program in the SEC("xdp") section.
3. Include char _license[] SEC("license") = "GPL";.
4. Enforce strict packet bounds checks before every memory dereference (i.e., (void *)(ptr + 1) > data_end must return XDP_PASS or safe action).
5. For map-based programs, define maps in SEC(".maps") with struct bpf_map_def or modern BTF map definitions.
6. Return ONLY valid C source code enclosed in a single ```c ... ``` code block. Do not provide conversational filler."""


def format_user_prompt(task_spec: Dict[str, Any]) -> str:
    task_id = task_spec["task_id"]
    category = task_spec.get("application_category", "packet_filtering_security")
    difficulty = task_spec.get("difficulty", "level_1")
    instruction = task_spec["instruction"]
    reqs = task_spec.get("requirements", [])

    reqs_formatted = "\n".join(f"- {r}" for r in reqs)

    prompt = f"""Task ID: {task_id}
Category: {category}
Difficulty: {difficulty}

Instruction:
{instruction}

Detailed Technical Requirements:
{reqs_formatted}

Write the complete C source code for this XDP program."""
    return prompt


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Qwen3 8B Calibration Evaluation")
    parser.add_argument("--model", type=str, default="qwen/qwen3-8b", help="OpenRouter model ID (default: qwen/qwen3-8b)")
    parser.add_argument("--category", type=str, default=None, help="Optional category filter")
    parser.add_argument("--level", type=str, default=None, help="Optional level filter")
    parser.add_argument("--force", action="store_true", help="Force re-generation of existing candidates")
    parser.add_argument("--dry-run", action="store_true", help="Simulate generation without calling OpenRouter")
    args = parser.parse_args()

    api_key = load_env_api_key()
    if not api_key and not args.dry_run:
        print("[-] ERROR: OPENROUTER_API_KEY not found in environment or .env file", file=sys.stderr)
        sys.exit(1)

    RAW_RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    validator = BPFValidator()

    print("=" * 60)
    print("BPF-Guardian Calibration Evaluation Run (Qwen3 8B)")
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

    print(f"Found {len(tasks)} calibration tasks matching filters.\n")

    summary_stats = {
        "model": args.model,
        "total_tasks": len(tasks),
        "generated": 0,
        "format_valid": 0,
        "compile_passed": 0,
        "verifier_passed": 0,
        "behavioral_passed": 0,
        "pass_at_1_rate": 0.0,
        "by_category": {},
        "by_difficulty": {},
        "tasks": {},
    }

    for idx, (cat, lvl, task_dir) in enumerate(tasks, start=1):
        task_id = task_dir.name
        task_json_file = task_dir / "task.json"
        task_spec = json.loads(task_json_file.read_text(encoding="utf-8"))

        c00_file = task_dir / "c00.c"
        meta_file = task_dir / "c00.meta.json"
        cand_id = f"{task_id}_c00"
        raw_result_file = RAW_RESULTS_DIR / f"{cand_id}.json"

        print(f"[{idx}/{len(tasks)}] {cat} / {lvl} / {task_id}")

        # 1. Generation
        if c00_file.exists() and not args.force:
            print(f"  [*] Using existing candidate {c00_file.name}")
            c_code = c00_file.read_text(encoding="utf-8")
        elif args.dry_run:
            print(f"  [*] DRY-RUN: Skipping generation")
            continue
        else:
            print(f"  [*] Querying {args.model} via OpenRouter...")
            user_prompt = format_user_prompt(task_spec)
            try:
                raw_response = call_openrouter(user_prompt, SYSTEM_PROMPT, api_key, model=args.model)
                c_code = extract_c_code(raw_response)
                summary_stats["generated"] += 1

                # Save c00.c
                c00_file.write_text(c_code, encoding="utf-8")

                # Save meta
                meta_data = {
                    "candidate_id": cand_id,
                    "task_id": task_id,
                    "application_category": cat,
                    "difficulty": lvl,
                    "authoring_harness": "openrouter",
                    "authoring_model": args.model,
                    "generation_prompt_version": "calibration-v1",
                    "source_path": "c00.c",
                    "parent_candidate_id": None,
                    "repair_attempt": 0,
                    "claimed_status": "unvalidated",
                    "source_sha256": compute_sha256(c00_file),
                    "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                }
                meta_file.write_text(json.dumps(meta_data, indent=2), encoding="utf-8")
                time.sleep(1.0)  # Gentle rate limiting
            except Exception as e:
                print(f"  [-] Generation failed: {e}")
                continue

        # 2. Validation
        print(f"  [*] Running kernel validation gates...")
        val_result = validator.validate_candidate(
            task_id=task_id,
            candidate_id=cand_id,
            source_path=c00_file,
            task_spec=task_spec,
            category=cat,
            level=lvl,
        )

        raw_result_file.write_text(json.dumps(val_result, indent=2), encoding="utf-8")

        # Determine failure stage
        stage = "pass"
        if not val_result["compile"]["pass"]:
            stage = "compile_error"
        elif not val_result["verifier"]["pass"]:
            stage = "verifier_error"
        elif not val_result["behavioral"]["pass"]:
            stage = "behavioral_error"

        compile_ok = val_result["compile"]["pass"]
        verifier_ok = val_result["verifier"]["pass"]
        behavioral_ok = val_result["behavioral"]["pass"]
        passed = val_result["passed"]

        if compile_ok:
            summary_stats["compile_passed"] += 1
        if verifier_ok:
            summary_stats["verifier_passed"] += 1
        if behavioral_ok:
            summary_stats["behavioral_passed"] += 1

        status_tag = "[+] PASS" if passed else f"[-] FAIL ({stage})"
        print(f"  {status_tag} (compile={compile_ok}, verifier={verifier_ok}, tests={val_result['behavioral']['passed_tests']}/{val_result['behavioral']['total_tests']})")

        # Record category stats
        if cat not in summary_stats["by_category"]:
            summary_stats["by_category"][cat] = {"total": 0, "pass": 0, "compile": 0, "verifier": 0}
        summary_stats["by_category"][cat]["total"] += 1
        if compile_ok:
            summary_stats["by_category"][cat]["compile"] += 1
        if verifier_ok:
            summary_stats["by_category"][cat]["verifier"] += 1
        if passed:
            summary_stats["by_category"][cat]["pass"] += 1

        # Record difficulty stats
        if lvl not in summary_stats["by_difficulty"]:
            summary_stats["by_difficulty"][lvl] = {"total": 0, "pass": 0, "compile": 0, "verifier": 0}
        summary_stats["by_difficulty"][lvl]["total"] += 1
        if compile_ok:
            summary_stats["by_difficulty"][lvl]["compile"] += 1
        if verifier_ok:
            summary_stats["by_difficulty"][lvl]["verifier"] += 1
        if passed:
            summary_stats["by_difficulty"][lvl]["pass"] += 1

        summary_stats["tasks"][task_id] = {
            "category": cat,
            "difficulty": lvl,
            "stage": stage,
            "passed": passed,
            "passed_tests": val_result["behavioral"]["passed_tests"],
            "total_tests": val_result["behavioral"]["total_tests"],
            "diagnostic": val_result.get("diagnostic"),
        }

    total = summary_stats["total_tasks"]
    if total > 0:
        summary_stats["pass_at_1_rate"] = summary_stats["behavioral_passed"] / total

    # Save summary report
    summary_file = RESULTS_DIR / f"calibration_summary_{args.model.replace('/', '_')}.json"
    summary_file.write_text(json.dumps(summary_stats, indent=2), encoding="utf-8")

    print("\n" + "=" * 60)
    print("CALIBRATION BENCHMARK SUMMARY (Pass@1)")
    print("=" * 60)
    print(f"Model:                {args.model}")
    print(f"Total Tasks:          {total}")
    print(f"Compilation Pass:     {summary_stats['compile_passed']}/{total} ({summary_stats['compile_passed']/total*100:.1f}%)")
    print(f"Verifier Pass:        {summary_stats['verifier_passed']}/{total} ({summary_stats['verifier_passed']/total*100:.1f}%)")
    print(f"Behavioral Pass@1:    {summary_stats['behavioral_passed']}/{total} ({summary_stats['pass_at_1_rate']*100:.1f}%)")
    print("\nBreakdown by Category:")
    for c, stats in summary_stats["by_category"].items():
        print(f"  {c:<30} Pass@1: {stats['pass']}/{stats['total']} (compile: {stats['compile']}/{stats['total']}, verifier: {stats['verifier']}/{stats['total']})")
    print("\nBreakdown by Difficulty:")
    for d, stats in summary_stats["by_difficulty"].items():
        print(f"  {d:<30} Pass@1: {stats['pass']}/{stats['total']} (compile: {stats['compile']}/{stats['total']}, verifier: {stats['verifier']}/{stats['total']})")
    print(f"\n[+] Full results written to {summary_file}")
    print("=" * 60)


if __name__ == "__main__":
    main()
