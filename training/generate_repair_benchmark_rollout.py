#!/usr/bin/env python3
"""
BPF-Guardian 120-Task Repair Benchmark Rollout Generator
Evaluates the SFT model (or base model) on the 120-Task Private Repair Benchmark Dataset.
For each repair task:
1. Loads task metadata, faulty C program, and diagnostic output from data/benchmark/repair/
2. Builds diagnostic-guided repair prompt
3. Samples completion via Tinker SamplingClient
4. Writes candidate C source files and generation manifest to output directory
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

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

from training.generate_tinker_rollout import (
    DEFAULT_MODEL_NAME,
    DEFAULT_RENDERER_NAME,
    check_output_compliance,
    compute_sha256_str,
    extract_c_source,
    generate_mock_c_program,
)

REPAIR_SYSTEM_PROMPT = """You are an expert Linux kernel eBPF and XDP systems programmer.
You are fixing an XDP program that produced diagnostic errors during evaluation."""


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

Original Instruction:
{instruction}

Technical Requirements:
{reqs_formatted}

Previous Implementation:
```c
{faulty_c.strip()}
```

Diagnostic Output:
```text
{diagnostic.strip()}
```

Please provide the corrected, complete, and self-contained C source code for this XDP program."""

    return [
        {"role": "system", "content": REPAIR_SYSTEM_PROMPT},
        {"role": "user", "content": user_content},
    ]


async def run_repair_benchmark_rollout(
    benchmark_index: Path,
    output_dir: Path,
    model_name: str = DEFAULT_MODEL_NAME,
    sampler_checkpoint: Optional[str] = None,
    renderer_name: str = DEFAULT_RENDERER_NAME,
    temperature: float = 0.0,
    seed: int = 42,
    max_tokens: int = 2048,
    mock: bool = False,
) -> Dict[str, Any]:
    benchmark_index = benchmark_index.resolve()
    output_dir = output_dir.resolve()

    if not benchmark_index.is_file():
        raise FileNotFoundError(f"Repair benchmark index not found: {benchmark_index}")

    tasks: List[Dict[str, Any]] = []
    with benchmark_index.open("r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                tasks.append(json.loads(line))

    print(f"[+] Loaded {len(tasks)} repair benchmark tasks from {benchmark_index}")

    tokenizer = get_tokenizer(model_name)
    renderer = get_renderer(renderer_name, tokenizer)

    sampling_client = None
    if not mock:
        service_client = tinker.ServiceClient()
        if sampler_checkpoint:
            print(f"[+] Connecting to fine-tuned checkpoint: {sampler_checkpoint}")
            sampling_client = await service_client.create_sampling_client_async(model_path=sampler_checkpoint)
        else:
            print(f"[+] Connecting to base model: {model_name}")
            sampling_client = await service_client.create_sampling_client_async(base_model=model_name)

    output_dir.mkdir(parents=True, exist_ok=True)
    candidates_dir = output_dir / "candidates"
    candidates_dir.mkdir(parents=True, exist_ok=True)

    generation_records: List[Dict[str, Any]] = []
    prompts_records: List[Dict[str, Any]] = []

    stop_seqs = renderer.get_stop_sequences()

    bench_base = benchmark_index.parent

    for idx, task_meta in enumerate(tasks, start=1):
        task_id = task_meta["task_id"]
        category = task_meta.get("application_category", "packet_filtering_security")
        difficulty = task_meta.get("difficulty", "level_1")

        task_dir = bench_base / category / difficulty / task_id

        # Load task.json
        task_json_file = task_dir / "task.json"
        if not task_json_file.is_file():
            raise FileNotFoundError(f"Missing task.json for {task_id}: {task_json_file}")

        task_data = json.loads(task_json_file.read_text(encoding="utf-8"))
        instruction = task_data.get("instruction", f"Fix XDP program for {task_id}")
        requirements = task_data.get("requirements", [])

        # Load faulty.c
        faulty_file = task_dir / "faulty.c"
        faulty_c = faulty_file.read_text(encoding="utf-8") if faulty_file.is_file() else "// Faulty code"

        # Load diagnostic.txt
        diag_file = task_dir / "diagnostic.txt"
        diagnostic = diag_file.read_text(encoding="utf-8") if diag_file.is_file() else "Verifier failure"

        messages = format_repair_prompt(
            task_id=task_id,
            category=category,
            difficulty=difficulty,
            instruction=instruction,
            requirements=requirements,
            faulty_c=faulty_c,
            diagnostic=diagnostic,
        )

        prompt_model_input = renderer.build_generation_prompt(messages)
        prompt_hash = compute_sha256_str(json.dumps(messages, sort_keys=True))

        task_cand_dir = candidates_dir / task_id
        task_cand_dir.mkdir(parents=True, exist_ok=True)
        cand_file = task_cand_dir / "sample-0.c"

        if cand_file.is_file() and cand_file.stat().st_size > 0:
            extracted_c = cand_file.read_text(encoding="utf-8")
            raw_text = extracted_c
            token_ids = [0]
            finish_reason = "STOP_SEQUENCE"
        elif mock:
            raw_text = generate_mock_c_program(task_id, 0)
            token_ids = [100, 200, 300]
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
        source_hash = compute_sha256_str(extracted_c)

        if not cand_file.is_file() or cand_file.stat().st_size == 0:
            cand_file.write_text(extracted_c, encoding="utf-8", newline="\n")

        record = {
            "task_id": task_id,
            "sample_index": 0,
            "sample_id": "sample-0",
            "category": category,
            "difficulty": difficulty,
            "diagnostic_category": task_data.get("diagnostic_category", "compilation_error"),
            "prompt_hash": prompt_hash,
            "candidate_path": cand_file.relative_to(PROJECT_ROOT).as_posix(),
            "source_hash": source_hash,
            "raw_response": raw_text,
            "num_generated_tokens": len(token_ids),
            "finish_reason": finish_reason,
            "compliance": compliance,
        }
        generation_records.append(record)

        prompts_records.append({
            "task_id": task_id,
            "prompt_hash": prompt_hash,
            "messages": messages,
        })

        if idx % 10 == 0 or idx == len(tasks):
            print(f"    Progress: {idx}/{len(tasks)} repair benchmark tasks generated.", flush=True)

    # Write prompts.jsonl and generation_records.jsonl
    (output_dir / "prompts.jsonl").write_text(
        "\n".join(json.dumps(p) for p in prompts_records) + "\n",
        encoding="utf-8",
    )
    (output_dir / "generation_records.jsonl").write_text(
        "\n".join(json.dumps(r) for r in generation_records) + "\n",
        encoding="utf-8",
    )

    compliant_count = sum(1 for r in generation_records if r["compliance"]["compliant"])
    manifest = {
        "benchmark_index": str(benchmark_index),
        "benchmark_type": "repair_benchmark_120",
        "total_tasks": len(tasks),
        "total_samples": len(generation_records),
        "model_name": model_name,
        "sampler_checkpoint": sampler_checkpoint,
        "renderer_name": renderer_name,
        "temperature": temperature,
        "seed": seed,
        "max_tokens": max_tokens,
        "compliant_count": compliant_count,
        "compliance_rate": compliant_count / len(generation_records) if generation_records else 0.0,
        "total_generated_tokens": sum(r["num_generated_tokens"] for r in generation_records),
    }

    (output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"\n[+] Repair Benchmark Rollout Complete! Output in {output_dir}")
    return manifest


def main():
    parser = argparse.ArgumentParser(description="Generate 120-task repair benchmark rollout via Tinker")
    parser.add_argument("--benchmark-index", type=Path, default=PROJECT_ROOT / "data" / "benchmark" / "repair" / "index.jsonl")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--model-name", type=str, default=DEFAULT_MODEL_NAME)
    parser.add_argument("--sampler-checkpoint", type=str, default=None)
    parser.add_argument("--renderer-name", type=str, default=DEFAULT_RENDERER_NAME)
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--max-tokens", type=int, default=2048)
    parser.add_argument("--mock", action="store_true")

    args = parser.parse_args()
    asyncio.run(run_repair_benchmark_rollout(
        benchmark_index=args.benchmark_index,
        output_dir=args.output_dir,
        model_name=args.model_name,
        sampler_checkpoint=args.sampler_checkpoint,
        renderer_name=args.renderer_name,
        temperature=args.temperature,
        seed=args.seed,
        max_tokens=args.max_tokens,
        mock=args.mock,
    ))


if __name__ == "__main__":
    main()
