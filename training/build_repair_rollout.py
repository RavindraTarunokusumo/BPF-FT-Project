#!/usr/bin/env python3
"""
BPF-Guardian Diagnostic-Guided Repair@1 Rollout Generator
For each failed candidate from benchmark evaluation:
1. Extracts compiler, kernel verifier, or behavioral failure diagnostics.
2. Constructs a structured diagnostic-guided repair prompt.
3. Tracks full lineage (task_id, original candidate, failure reason, diagnostic hash).
4. Generates corrected candidates via Tinker SamplingClient (or mock mode).
5. Writes candidate source files and repair metadata into a new rollout directory.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

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


async def run_repair_rollout(
    synthesis_rollout_dir: Path,
    output_dir: Path,
    benchmark_index: Path,
    model_name: str = DEFAULT_MODEL_NAME,
    sampler_checkpoint: Optional[str] = None,
    renderer_name: str = DEFAULT_RENDERER_NAME,
    temperature: float = 0.0,
    seed: int = 42,
    max_tokens: int = 2048,
    mock: bool = False,
) -> Dict[str, Any]:
    verification_results_file = synthesis_rollout_dir / "verification" / "results.jsonl"
    if not verification_results_file.is_file():
        # Fallback to checking root of rollout or generation records
        raise FileNotFoundError(f"Verification results not found: {verification_results_file}")

    verification_records = [json.loads(line) for line in verification_results_file.read_text(encoding="utf-8").splitlines() if line.strip()]
    failed_candidates = [r for r in verification_records if not r.get("passed", False)]

    print(f"[+] Total synthesis candidates: {len(verification_records)}")
    print(f"[+] Failed candidates requiring repair: {len(failed_candidates)}")

    task_meta: Dict[str, Dict[str, Any]] = {}
    if benchmark_index.is_file():
        for line in benchmark_index.read_text(encoding="utf-8").splitlines():
            if line.strip():
                t = json.loads(line)
                task_meta[t["task_id"]] = t

    tokenizer = get_tokenizer(model_name)
    renderer = get_renderer(renderer_name, tokenizer)

    sampling_client = None
    if not mock and failed_candidates:
        service_client = tinker.ServiceClient()
        if sampler_checkpoint:
            print(f"[+] Connecting to fine-tuned checkpoint for repair: {sampler_checkpoint}")
            sampling_client = await service_client.create_sampling_client_async(model_path=sampler_checkpoint)
        else:
            print(f"[+] Connecting to base model for repair: {model_name}")
            sampling_client = await service_client.create_sampling_client_async(base_model=model_name)

    output_dir.mkdir(parents=True, exist_ok=True)
    candidates_dir = output_dir / "candidates"
    candidates_dir.mkdir(parents=True, exist_ok=True)

    lineage_records: List[Dict[str, Any]] = []
    repair_prompts: List[Dict[str, Any]] = []
    generation_records: List[Dict[str, Any]] = []

    for idx, failed_cand in enumerate(failed_candidates, start=1):
        task_id = failed_cand["task_id"]
        sample_id = failed_cand.get("sample_id", "sample-0")
        meta = task_meta.get(task_id, {})
        category = meta.get("application_category", failed_cand.get("category", "packet_filtering_security"))
        difficulty = meta.get("difficulty", failed_cand.get("difficulty", "level_1"))

        # Read faulty source
        faulty_file = synthesis_rollout_dir / "candidates" / task_id / f"{sample_id}.c"
        faulty_c = faulty_file.read_text(encoding="utf-8") if faulty_file.is_file() else "// Faulty program"

        diagnostic = failed_cand.get("diagnostic") or "Verifier or test execution failed."

        # Load task instruction & requirements
        instruction = f"Write an XDP program for {task_id}."
        reqs = ["Check packet bounds before every header dereference", "Return XDP_PASS on non-matching traffic"]

        task_json = PROJECT_ROOT / "data" / "calibration" / category / difficulty / task_id / "task.json"
        if task_json.is_file():
            try:
                t_data = json.loads(task_json.read_text(encoding="utf-8"))
                instruction = t_data.get("instruction", instruction)
                reqs = t_data.get("requirements", reqs)
            except Exception:
                pass

        diag_hash = compute_sha256_str(diagnostic)
        messages = format_repair_prompt(task_id, category, difficulty, instruction, reqs, faulty_c, diagnostic)
        prompt_model_input = renderer.build_generation_prompt(messages)
        prompt_hash = compute_sha256_str(json.dumps(messages, sort_keys=True))

        stop_seqs = renderer.get_stop_sequences()

        if mock:
            raw_text = generate_mock_c_program(task_id, 0)
            token_ids = [100, 200, 300]
            termination = "STOP_SEQUENCE"
        else:
            sampling_params = tinker.SamplingParams(
                max_tokens=max_tokens,
                temperature=temperature,
                seed=seed,
                stop=stop_seqs,
            )
            future = await sampling_client.sample_async(prompt=prompt_model_input, params=sampling_params)
            sample_result = await future.result_async()
            sampled_seq = sample_result.sequences[0]
            token_ids = sampled_seq.tokens
            raw_text = sampled_seq.text
            termination = getattr(sampled_seq, "finish_reason", "STOP_SEQUENCE")

        compliance = check_output_compliance(raw_text)
        extracted_c = extract_c_source(raw_text)
        source_hash = compute_sha256_str(extracted_c)

        task_cand_dir = candidates_dir / task_id
        task_cand_dir.mkdir(parents=True, exist_ok=True)
        cand_file = task_cand_dir / "sample-0.c"
        cand_file.write_text(extracted_c, encoding="utf-8", newline="\n")

        lineage = {
            "task_id": task_id,
            "original_rollout_dir": str(synthesis_rollout_dir),
            "original_sample_id": sample_id,
            "original_diagnostic": diagnostic,
            "diagnostic_hash": diag_hash,
            "repair_prompt_hash": prompt_hash,
            "repaired_source_hash": source_hash,
            "repair_round": 1,
        }
        lineage_records.append(lineage)

        repair_prompts.append({
            "task_id": task_id,
            "prompt_hash": prompt_hash,
            "messages": messages,
        })

        generation_records.append({
            "task_id": task_id,
            "sample_index": 0,
            "sample_id": "sample-0",
            "seed": seed,
            "temperature": temperature,
            "prompt_hash": prompt_hash,
            "raw_response": raw_text,
            "num_generated_tokens": len(token_ids),
            "termination": str(termination),
            "compliance": compliance,
            "extracted_c_source": extracted_c,
            "source_hash": source_hash,
        })

    # Save artifacts
    (output_dir / "lineage.jsonl").write_text(
        "".join(json.dumps(r) + "\n" for r in lineage_records), encoding="utf-8"
    )
    (output_dir / "repair_prompts.jsonl").write_text(
        "".join(json.dumps(p) + "\n" for p in repair_prompts), encoding="utf-8"
    )
    (output_dir / "generation_records.jsonl").write_text(
        "".join(json.dumps(g) + "\n" for g in generation_records), encoding="utf-8"
    )

    manifest = {
        "rollout_id": output_dir.name,
        "rollout_type": "diagnostic_repair_r1",
        "parent_rollout_dir": str(synthesis_rollout_dir),
        "model_name": model_name,
        "sampler_checkpoint": sampler_checkpoint,
        "renderer_name": renderer_name,
        "is_mock": mock,
        "repaired_tasks_count": len(lineage_records),
        "output_compliance_rate": sum(1 for g in generation_records if g["compliance"]["compliant"]) / len(generation_records) if generation_records else 0.0,
    }
    (output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    print(f"\n[+] Diagnostic Repair@1 Generation Complete!")
    print(f"    Repaired Tasks: {len(lineage_records)}")
    print(f"    Output Directory: {output_dir}")
    return manifest


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="BPF-Guardian Diagnostic Repair@1 Rollout Generator")
    parser.add_argument("--synthesis-rollout", type=Path, required=True, help="Path to synthesis rollout directory")
    parser.add_argument("--output-dir", type=Path, required=True, help="Destination directory for repair rollout")
    parser.add_argument("--benchmark-index", type=Path, default=PROJECT_ROOT / "data" / "calibration" / "index.jsonl")
    parser.add_argument("--model-name", type=str, default=DEFAULT_MODEL_NAME)
    parser.add_argument("--sampler-checkpoint", type=str, default=None)
    parser.add_argument("--renderer-name", type=str, default=DEFAULT_RENDERER_NAME)
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--max-tokens", type=int, default=2048)
    parser.add_argument("--mock", action="store_true", help="Generate mock repair programs without Tinker API")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    asyncio.run(
        run_repair_rollout(
            synthesis_rollout_dir=args.synthesis_rollout,
            output_dir=args.output_dir,
            benchmark_index=args.benchmark_index,
            model_name=args.model_name,
            sampler_checkpoint=args.sampler_checkpoint,
            renderer_name=args.renderer_name,
            temperature=args.temperature,
            seed=args.seed,
            max_tokens=args.max_tokens,
            mock=args.mock,
        )
    )


if __name__ == "__main__":
    main()
