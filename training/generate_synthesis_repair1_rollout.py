#!/usr/bin/env python3
"""
BPF-Guardian Controlled Synthesis Repair@1 Rollout Generator
Generates deterministic 1-turn diagnostic-guided repair completions for the 89 failed
candidates in the 120-Task Private Synthesis Benchmark using Qwen3-8B SFT v2.

Stage Diagnostics:
1. Compilation failure: task spec, previous code, exact Clang BPF command, Clang stderr.
2. Kernel verifier failure: task spec, previous code, exact Linux kernel verifier rejection log.
3. Behavioral failure: task spec, previous code, failing test case name, expected vs observed action (no gold solution leakage).

Inference Config:
- Checkpoint: tinker://9461002d-2321-5858-8184-5604f9304283:train:0/sampler_weights/final
- Renderer: qwen3_disable_thinking
- Temperature: 0.0
- Seed: 42
- Samples: 1
- Max tokens: 2048
"""

from __future__ import annotations

import argparse
import asyncio
import datetime
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Load .env if present
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

import tinker
from tinker_cookbook.renderers import get_renderer
from tinker_cookbook.tokenizer_utils import get_tokenizer

from training.import_verifier_results import check_output_compliance, compute_file_sha256, compute_sha256_str

DEFAULT_CHECKPOINT = "tinker://9461002d-2321-5858-8184-5604f9304283:train:0/sampler_weights/final"
DEFAULT_MODEL_NAME = "Qwen/Qwen3-8B"
DEFAULT_RENDERER_NAME = "qwen3_disable_thinking"

REPAIR_SYSTEM_PROMPT = """You are an expert Linux kernel eBPF and XDP systems programmer.
You are repairing an XDP C program that failed verification or testing.
Output requirements:
- Provide ONLY the corrected, complete, and self-contained XDP C source code.
- Do NOT include Markdown code fences (```c or ```), explanation, prose, or thinking blocks."""


def extract_c_source(raw_text: str) -> str:
    """Extracts clean C code from raw model output."""
    text = re.sub(r"<think>.*?</think>", "", raw_text, flags=re.DOTALL).strip()
    text = re.sub(r"<\|.*?\|>", "", text).strip()

    # If code is wrapped in markdown fences, extract inner content
    code_match = re.search(r"```(?:c|C)?\s*\n(.*?)```", text, re.DOTALL)
    if code_match:
        return code_match.group(1).strip()

    # Otherwise return raw text stripped
    return text.strip()


def build_diagnostic_message(raw_rec: Dict[str, Any]) -> Tuple[str, str]:
    """
    Constructs diagnostic string and diagnostic stage based on the first failing stage.
    """
    compile_info = raw_rec.get("compile", {})
    verifier_info = raw_rec.get("verifier", {})
    behavioral_info = raw_rec.get("behavioral", {})

    # Stage 1: Compilation Failure
    if not compile_info.get("pass", False) or compile_info.get("returncode", 1) != 0:
        clang_cmd = "clang -O2 -target bpf -D__TARGET_ARCH_x86 -I/usr/include -I/usr/include/x86_64-linux-gnu -c candidate.c -o candidate.o"
        stderr = compile_info.get("stderr", "").strip() or "Unknown compilation error"
        diag = f"Clang BPF Compilation Failed\nCommand: {clang_cmd}\n\nCompiler Diagnostic Output:\n{stderr}"
        return diag, "compilation"

    # Stage 2: Verifier Failure
    if not verifier_info.get("pass", False):
        log = verifier_info.get("log", "").strip() or verifier_info.get("stderr", "").strip() or "Program rejected by kernel verifier"
        diag = f"Linux Kernel BPF Verifier Rejected Program\n\nVerifier Log:\n{log}"
        return diag, "kernel_verifier"

    # Stage 3: Behavioral Failure
    if not behavioral_info.get("pass", False):
        details = behavioral_info.get("details", [])
        failing_tests = [d for d in details if not d.get("pass", True)]
        diag_lines = ["Behavioral Multi-Packet Test Suite Failed:"]
        for t in failing_tests:
            name = t.get("name", "unknown_test")
            desc = t.get("description", "")
            exp = t.get("expected", "UNKNOWN")
            act = t.get("actual", "UNKNOWN")
            diag_lines.append(f"- Test '{name}' ({desc}): Expected action {exp}, Observed action {act}")

        if not failing_tests:
            diag_lines.append(f"Total passed {behavioral_info.get('passed_tests', 0)} of {behavioral_info.get('total_tests', 0)} test cases.")

        diag = "\n".join(diag_lines)
        return diag, "behavioral"

    return "Unknown failure state", "unknown"


def format_repair_prompt(
    task_id: str,
    category: str,
    difficulty: str,
    instruction: str,
    requirements: List[str],
    faulty_c: str,
    diagnostic: str,
) -> List[Dict[str, str]]:
    reqs_formatted = "\n".join(f"- {r}" for r in requirements) if requirements else "- Return complete verifier-safe C code"

    user_content = f"""Task ID: {task_id}
Category: {category}
Difficulty: {difficulty}

Task Instruction:
{instruction}

Technical Requirements:
{reqs_formatted}

Previous Implementation:
{faulty_c.strip()}

Execution Diagnostic:
{diagnostic.strip()}

Provide the corrected, complete, and self-contained XDP C source code only."""

    return [
        {"role": "system", "content": REPAIR_SYSTEM_PROMPT},
        {"role": "user", "content": user_content},
    ]


async def run_synthesis_repair1_generation(
    synthesis_rollout_dir: Path,
    output_dir: Path,
    benchmark_index: Path,
    sampler_checkpoint: str = DEFAULT_CHECKPOINT,
    model_name: str = DEFAULT_MODEL_NAME,
    renderer_name: str = DEFAULT_RENDERER_NAME,
    temperature: float = 0.0,
    seed: int = 42,
    max_tokens: int = 2048,
    concurrency: int = 16,
    mock: bool = False,
) -> Dict[str, Any]:
    output_dir = output_dir.resolve()
    synthesis_rollout_dir = synthesis_rollout_dir.resolve()

    # Load synthesis verification results
    results_path = synthesis_rollout_dir / "verification" / "results.jsonl"
    if not results_path.is_file():
        raise FileNotFoundError(f"Missing results.jsonl in {results_path}")

    results_records = [json.loads(line) for line in results_path.read_text(encoding="utf-8").splitlines() if line.strip()]

    # Filter strictly failed candidates
    failed_candidates = [r for r in results_records if not r.get("passed", False)]
    print(f"[+] Total synthesis benchmark tasks: {len(results_records)}")
    print(f"[+] Initial passes: {len(results_records) - len(failed_candidates)}")
    print(f"[+] Failed candidates requiring Repair@1: {len(failed_candidates)}")

    assert len(failed_candidates) == 89, f"Expected exactly 89 failed candidates, got {len(failed_candidates)}"

    # Load benchmark index
    task_index_meta: Dict[str, Dict[str, Any]] = {}
    if benchmark_index.is_file():
        for line in benchmark_index.read_text(encoding="utf-8").splitlines():
            if line.strip():
                t = json.loads(line)
                task_index_meta[t["task_id"]] = t

    tokenizer = get_tokenizer(model_name)
    renderer = get_renderer(renderer_name, tokenizer)

    sampling_client = None
    if not mock:
        service_client = tinker.ServiceClient()
        print(f"[+] Connecting to Tinker sampling client with checkpoint: {sampler_checkpoint}")
        sampling_client = await service_client.create_sampling_client_async(model_path=sampler_checkpoint)

    output_dir.mkdir(parents=True, exist_ok=True)
    candidates_dir = output_dir / "candidates"
    candidates_dir.mkdir(parents=True, exist_ok=True)

    stop_seqs = renderer.get_stop_sequences()
    prompt_template_hash = compute_sha256_str(REPAIR_SYSTEM_PROMPT)

    sem = asyncio.Semaphore(concurrency)
    completed_count = 0

    async def process_one(idx: int, failed_cand: Dict[str, Any]):
        nonlocal completed_count
        task_id = failed_cand["task_id"]
        sample_id = failed_cand.get("sample_id", "sample-0")

        meta = task_index_meta.get(task_id, {})
        category = failed_cand.get("category") or meta.get("application_category", "packet_filtering_security")
        difficulty = failed_cand.get("difficulty") or meta.get("difficulty", "level_1")
        rel_path = meta.get("relative_path", f"{category}/{difficulty}/{task_id}")

        task_json_path = PROJECT_ROOT / "data" / "benchmark" / "synthesis" / rel_path / "task.json"
        if not task_json_path.is_file():
            task_json_path = PROJECT_ROOT / "data" / "benchmark" / "synthesis" / category / difficulty / task_id / "task.json"

        instruction = f"Write an XDP program for {task_id}"
        requirements = []
        if task_json_path.is_file():
            try:
                t_data = json.loads(task_json_path.read_text(encoding="utf-8"))
                instruction = t_data.get("instruction", instruction)
                requirements = t_data.get("requirements", [])
            except Exception:
                pass

        prev_cand_file = synthesis_rollout_dir / "candidates" / task_id / f"{sample_id}.c"
        if not prev_cand_file.is_file():
            raise FileNotFoundError(f"Missing previous candidate file: {prev_cand_file}")
        faulty_c = prev_cand_file.read_text(encoding="utf-8")

        diagnostic_str, diag_stage = build_diagnostic_message(failed_cand)

        messages = format_repair_prompt(
            task_id=task_id,
            category=category,
            difficulty=difficulty,
            instruction=instruction,
            requirements=requirements,
            faulty_c=faulty_c,
            diagnostic=diagnostic_str,
        )

        prompt_model_input = renderer.build_generation_prompt(messages)
        prompt_hash = compute_sha256_str(json.dumps(messages, sort_keys=True))

        task_cand_dir = candidates_dir / task_id
        task_cand_dir.mkdir(parents=True, exist_ok=True)
        cand_file = task_cand_dir / "sample-0.c"

        async with sem:
            if mock:
                raw_text = "// Mock repaired XDP program\n#include <linux/bpf.h>\n#include <bpf/bpf_helpers.h>\nSEC(\"xdp\") int xdp_p(struct xdp_md *ctx){return XDP_PASS;} char _license[] SEC(\"license\") = \"GPL\";"
                token_ids = [10, 20, 30]
                finish_reason = "STOP_SEQUENCE"
            else:
                sampling_params = tinker.SamplingParams(
                    max_tokens=max_tokens,
                    temperature=temperature,
                    seed=seed,
                    stop=stop_seqs,
                )
                sample_result = await sampling_client.sample_async(
                    prompt=prompt_model_input,
                    num_samples=1,
                    sampling_params=sampling_params,
                )
                sampled_seq = sample_result.sequences[0]
                token_ids = list(sampled_seq.tokens)
                raw_text = renderer.tokenizer.decode(token_ids)
                finish_reason = "STOP_SEQUENCE"

        compliance = check_output_compliance(raw_text)
        extracted_c = extract_c_source(raw_text)
        cand_file.write_text(extracted_c, encoding="utf-8", newline="\n")
        source_hash = compute_file_sha256(cand_file)

        completed_count += 1
        if completed_count % 10 == 0 or completed_count == len(failed_candidates):
            print(f"  [{completed_count}/{len(failed_candidates)}] Generated repair for {task_id} ({diag_stage})", flush=True)

        return (
            task_id,
            diag_stage,
            {
                "task_id": task_id,
                "sample_index": 0,
                "sample_id": "sample-0",
                "category": category,
                "difficulty": difficulty,
                "diagnostic_stage": diag_stage,
                "prompt_hash": prompt_hash,
                "candidate_path": cand_file.relative_to(PROJECT_ROOT).as_posix(),
                "source_hash": source_hash,
                "raw_response": raw_text,
                "num_generated_tokens": len(token_ids),
                "finish_reason": finish_reason,
                "compliance": compliance,
            },
            {
                "task_id": task_id,
                "prompt_hash": prompt_hash,
                "diagnostic_stage": diag_stage,
                "messages": messages,
            },
        )

    print(f"[+] Launching concurrent generation (concurrency={concurrency}) for {len(failed_candidates)} tasks...")
    tasks = [process_one(idx, cand) for idx, cand in enumerate(failed_candidates, start=1)]
    results = await asyncio.gather(*tasks)

    eligible_task_ids = [r[0] for r in results]
    diagnostic_types = {r[0]: r[1] for r in results}
    generation_records = [r[2] for r in results]
    prompts_records = [r[3] for r in results]

    # Sort deterministically by task_id
    generation_records.sort(key=lambda x: x["task_id"])
    prompts_records.sort(key=lambda x: x["task_id"])

    # Save prompts.jsonl and generation_records.jsonl
    (output_dir / "prompts.jsonl").write_text(
        "\n".join(json.dumps(p) for p in prompts_records) + "\n",
        encoding="utf-8",
    )
    (output_dir / "generation_records.jsonl").write_text(
        "\n".join(json.dumps(r) for r in generation_records) + "\n",
        encoding="utf-8",
    )

    # Compute candidate set hash
    cand_items = sorted([(r["task_id"], "sample-0", r["source_hash"]) for r in generation_records])
    candidate_set_hash = compute_sha256_str(json.dumps(cand_items, sort_keys=True))

    try:
        git_commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=PROJECT_ROOT, text=True).strip()
    except Exception:
        git_commit = "unknown"

    manifest = {
        "rollout_id": output_dir.name,
        "rollout_type": "controlled_synthesis_repair1",
        "parent_synthesis_run": str(synthesis_rollout_dir.relative_to(PROJECT_ROOT).as_posix()),
        "checkpoint": sampler_checkpoint,
        "base_model": model_name,
        "renderer": renderer_name,
        "sampling_configuration": {
            "temperature": temperature,
            "seed": seed,
            "num_samples": 1,
            "max_tokens": max_tokens,
        },
        "exact_eligible_task_ids": eligible_task_ids,
        "eligible_tasks_count": len(eligible_task_ids),
        "diagnostic_type_per_task": diagnostic_types,
        "prompt_template_hash": prompt_template_hash,
        "candidate_set_hash": candidate_set_hash,
        "generation_timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "verification_mode": "empirical",
        "code_commit": git_commit,
        "output_compliance_rate": sum(1 for g in generation_records if g["compliance"]["compliant"]) / len(generation_records) if generation_records else 0.0,
    }

    (output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"\n[+] Synthesis Repair@1 Generation Complete! {len(generation_records)} candidates generated.")
    print(f"    Manifest: {output_dir / 'manifest.json'}")
    return manifest


def main():
    parser = argparse.ArgumentParser(description="BPF-Guardian Controlled Synthesis Repair@1 Generator")
    parser.add_argument("--synthesis-rollout", type=Path, default=PROJECT_ROOT / "runs" / "evaluation" / "qwen3-8b-full-sft-v2" / "benchmark-synthesis-120")
    parser.add_argument("--output-dir", type=Path, default=PROJECT_ROOT / "runs" / "evaluation" / "qwen3-8b-full-sft-v2" / "benchmark-synthesis-120-repair1")
    parser.add_argument("--benchmark-index", type=Path, default=PROJECT_ROOT / "data" / "benchmark" / "synthesis" / "index.jsonl")
    parser.add_argument("--sampler-checkpoint", type=str, default=DEFAULT_CHECKPOINT)
    parser.add_argument("--model-name", type=str, default=DEFAULT_MODEL_NAME)
    parser.add_argument("--renderer-name", type=str, default=DEFAULT_RENDERER_NAME)
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--max-tokens", type=int, default=2048)
    parser.add_argument("--concurrency", type=int, default=16)
    parser.add_argument("--mock", action="store_true")

    args = parser.parse_args()
    asyncio.run(run_synthesis_repair1_generation(
        synthesis_rollout_dir=args.synthesis_rollout,
        output_dir=args.output_dir,
        benchmark_index=args.benchmark_index,
        sampler_checkpoint=args.sampler_checkpoint,
        model_name=args.model_name,
        renderer_name=args.renderer_name,
        temperature=args.temperature,
        seed=args.seed,
        max_tokens=args.max_tokens,
        concurrency=args.concurrency,
        mock=args.mock,
    ))


if __name__ == "__main__":
    main()
