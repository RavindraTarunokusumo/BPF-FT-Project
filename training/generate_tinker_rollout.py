#!/usr/bin/env python3
"""
BPF-Guardian Tinker Benchmark Rollout Generator
Generates candidate C programs from base Qwen3-8B or fine-tuned Tinker checkpoint:
1. Loads benchmark task specifications from index.jsonl / tasks.
2. Builds generation prompts using Tinker renderer (qwen3_disable_thinking).
3. Samples completions via Tinker SamplingClient (or mock mode for offline testing).
4. Supports deterministic Pass@1 (T=0.0) and fixed-seed Pass@4 (T=0.7).
5. Validates output compliance (fences, prose, BPF markers) separately without silent mutation.
6. Writes raw generation records, prompts, manifest, and candidate C files.
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
from typing import Any, Dict, List, Optional, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Safely load .env if present without printing or logging secrets
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
from tinker_cookbook import renderers
from tinker_cookbook.renderers import get_renderer
from tinker_cookbook.tokenizer_utils import get_tokenizer

DEFAULT_BENCHMARK_INDEX = PROJECT_ROOT / "data" / "calibration" / "index.jsonl"
DEFAULT_MODEL_NAME = "Qwen/Qwen3-8B"
DEFAULT_RENDERER_NAME = "qwen3_disable_thinking"
DEFAULT_MAX_NEW_TOKENS = 2048

SYNTHESIS_SYSTEM_PROMPT = """You are an expert Linux kernel eBPF and XDP systems programmer.
Write complete, self-contained, compilation-ready, and verifier-safe C source code for Linux XDP programs."""


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
        "has_fault_markers": fault_match,
    }


def extract_c_source(raw_text: str) -> str:
    """Extracts C code from response, stripping fences, thinking preambles, and ChatML tokens."""
    text = raw_text.strip()
    # Strip thinking blocks if any
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()
    # Strip ChatML special tokens
    text = re.sub(r"<\|im_end\|>.*$", "", text, flags=re.DOTALL).strip()
    text = re.sub(r"<\|.*?\|>", "", text).strip()

    match = re.search(r"```(?:c|C|cpp)?\s*(.*?)\s*```", text, re.DOTALL)
    if match:
        code = match.group(1).strip()
        code = re.sub(r"<\|.*?\|>", "", code).strip()
        return code + "\n"

    include_match = re.search(r"((?:/\*.*?\*/\s*|//.*?\n\s*)*#include\s+<.*)", text, re.DOTALL)
    if include_match:
        code = include_match.group(1).strip()
        code = re.sub(r"<\|.*?\|>", "", code).strip()
        return code + "\n"

    sec_match = re.search(r"(SEC\s*\(\s*\"xdp\"\s*\).*)", text, re.DOTALL)
    if sec_match:
        code = sec_match.group(1).strip()
        code = re.sub(r"<\|.*?\|>", "", code).strip()
        return code + "\n"

    text = re.sub(r"<\|.*?\|>", "", text).strip()
    return text + "\n"


def load_benchmark_tasks(index_path: Path) -> List[Dict[str, Any]]:
    tasks: List[Dict[str, Any]] = []
    if not index_path.is_file():
        raise FileNotFoundError(f"Benchmark index not found: {index_path}")

    with index_path.open("r", encoding="utf-8") as f:
        for line in f:
            line_str = line.strip()
            if not line_str:
                continue
            record = json.loads(line_str)
            tasks.append(record)
    return tasks


def build_task_prompt(task_meta: Dict[str, Any]) -> List[Dict[str, str]]:
    """Builds conversation messages for synthesis benchmark task."""
    task_id = task_meta["task_id"]
    category = task_meta.get("application_category", "packet_filtering_security")
    difficulty = task_meta.get("difficulty", "level_1")
    
    # Check if a specific task.json exists in calibration or inbox
    task_json_path = None
    for candidate_dir in [
        PROJECT_ROOT / "data" / "calibration" / category / difficulty / task_id / "task.json",
        PROJECT_ROOT / "data" / "inbox" / category / difficulty / task_id / "task.json",
    ]:
        if candidate_dir.is_file():
            task_json_path = candidate_dir
            break

    if task_json_path:
        task_data = json.loads(task_json_path.read_text(encoding="utf-8"))
        instruction = task_data.get("instruction", f"Write an XDP program for task {task_id}")
        reqs = task_data.get("requirements", [])
        reqs_str = "\n".join(f"- {r}" for r in reqs)
        user_content = f"""Task ID: {task_id}
Category: {category}
Difficulty: {difficulty}

Instruction:
{instruction}

Detailed Technical Requirements:
{reqs_str}

Write the complete C source code for this XDP program."""
    else:
        user_content = f"""Task ID: {task_id}
Category: {category}
Difficulty: {difficulty}

Instruction:
Write a complete, verifier-safe Linux XDP program for {task_id}. Check bounds before all packet accesses and return complete C source only.

Write the complete C source code for this XDP program."""

    return [
        {"role": "system", "content": SYNTHESIS_SYSTEM_PROMPT},
        {"role": "user", "content": user_content},
    ]


def generate_mock_c_program(task_id: str, sample_idx: int) -> str:
    """Generates synthetic valid C code for mock mode testing."""
    return f"""#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

SEC("xdp")
int xdp_prog_{task_id}_s{sample_idx}(struct xdp_md *ctx) {{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != __builtin_bswap16(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    return XDP_PASS;
}}

char _license[] SEC("license") = "GPL";
"""


async def generate_rollouts_for_task(
    task: Dict[str, Any],
    sampling_client: Any,
    renderer: Any,
    num_samples: int,
    temperature: float,
    base_seed: int,
    max_tokens: int,
    mock: bool = False,
) -> List[Dict[str, Any]]:
    task_id = task["task_id"]
    messages = build_task_prompt(task)
    prompt_model_input = renderer.build_generation_prompt(messages)
    prompt_msg_str = json.dumps(messages, sort_keys=True)
    prompt_hash = compute_sha256_str(prompt_msg_str)
    stop_seqs = renderer.get_stop_sequences()

    records: List[Dict[str, Any]] = []

    for sample_idx in range(num_samples):
        seed = base_seed + sample_idx
        sample_id = f"sample-{sample_idx}"

        if mock:
            raw_text = generate_mock_c_program(task_id, sample_idx)
            token_ids = [100, 200, 300]
            termination = "STOP_SEQUENCE"
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
            termination = "STOP_SEQUENCE"

        compliance = check_output_compliance(raw_text)
        extracted_c = extract_c_source(raw_text)
        source_hash = compute_sha256_str(extracted_c)

        records.append({
            "task_id": task_id,
            "sample_index": sample_idx,
            "sample_id": sample_id,
            "seed": seed,
            "temperature": temperature,
            "prompt_hash": prompt_hash,
            "prompt_messages": messages,
            "raw_response": raw_text,
            "generated_token_ids": token_ids,
            "num_generated_tokens": len(token_ids),
            "termination": str(termination),
            "compliance": compliance,
            "extracted_c_source": extracted_c,
            "source_hash": source_hash,
        })

    return records


async def run_benchmark_rollout(
    benchmark_index: Path,
    output_dir: Path,
    model_name: str = DEFAULT_MODEL_NAME,
    sampler_checkpoint: Optional[str] = None,
    renderer_name: str = DEFAULT_RENDERER_NAME,
    num_samples: int = 1,
    temperature: float = 0.0,
    seed: int = 42,
    max_tokens: int = DEFAULT_MAX_NEW_TOKENS,
    mock: bool = False,
) -> Dict[str, Any]:
    tasks = load_benchmark_tasks(benchmark_index)
    if not tasks:
        raise ValueError(f"No tasks found in benchmark index: {benchmark_index}")

    tokenizer = get_tokenizer(model_name)
    renderer = get_renderer(renderer_name, tokenizer)

    sampling_client = None
    if not mock:
        service_client = tinker.ServiceClient()
        if sampler_checkpoint:
            print(f"[+] Creating sampling client for fine-tuned checkpoint: {sampler_checkpoint}")
            sampling_client = await service_client.create_sampling_client_async(
                model_path=sampler_checkpoint
            )
        else:
            print(f"[+] Creating sampling client for base model: {model_name}")
            sampling_client = await service_client.create_sampling_client_async(
                base_model=model_name
            )

    output_dir.mkdir(parents=True, exist_ok=True)
    candidates_dir = output_dir / "candidates"
    candidates_dir.mkdir(parents=True, exist_ok=True)

    all_records: List[Dict[str, Any]] = []
    prompts_list: List[Dict[str, Any]] = []

    print(f"\n[+] Generating rollouts for {len(tasks)} benchmark tasks ({num_samples} sample(s)/task, T={temperature})...")

    for task_idx, task in enumerate(tasks, start=1):
        t_id = task["task_id"]
        task_records = await generate_rollouts_for_task(
            task=task,
            sampling_client=sampling_client,
            renderer=renderer,
            num_samples=num_samples,
            temperature=temperature,
            base_seed=seed,
            max_tokens=max_tokens,
            mock=mock,
        )

        task_cand_dir = candidates_dir / t_id
        task_cand_dir.mkdir(parents=True, exist_ok=True)

        for rec in task_records:
            sample_file = task_cand_dir / f"{rec['sample_id']}.c"
            sample_file.write_text(rec["extracted_c_source"], encoding="utf-8", newline="\n")
            all_records.append(rec)

        prompts_list.append({
            "task_id": t_id,
            "prompt_hash": task_records[0]["prompt_hash"],
            "messages": task_records[0]["prompt_messages"],
        })

        if task_idx % 10 == 0 or task_idx == len(tasks):
            print(f"    Progress: {task_idx}/{len(tasks)} tasks processed.")

    # Write generation records and prompts JSONL
    gen_records_file = output_dir / "generation_records.jsonl"
    with gen_records_file.open("w", encoding="utf-8", newline="\n") as f:
        for r in all_records:
            f.write(json.dumps(r) + "\n")

    prompts_file = output_dir / "prompts.jsonl"
    with prompts_file.open("w", encoding="utf-8", newline="\n") as f:
        for p in prompts_list:
            f.write(json.dumps(p) + "\n")

    # Compute rollout statistics
    total_samples = len(all_records)
    compliant_samples = sum(1 for r in all_records if r["compliance"]["compliant"])
    total_tokens = sum(r["num_generated_tokens"] for r in all_records)

    try:
        cand_dir_str = str(candidates_dir.resolve().relative_to(PROJECT_ROOT.resolve())).replace("\\", "/")
    except ValueError:
        cand_dir_str = str(candidates_dir.resolve()).replace("\\", "/")

    manifest = {
        "rollout_id": output_dir.name,
        "model_name": model_name,
        "sampler_checkpoint": sampler_checkpoint,
        "renderer_name": renderer_name,
        "is_mock": mock,
        "num_tasks": len(tasks),
        "num_samples_per_task": num_samples,
        "total_samples": total_samples,
        "temperature": temperature,
        "seed": seed,
        "max_tokens": max_tokens,
        "output_compliance_rate": (compliant_samples / total_samples) if total_samples > 0 else 0.0,
        "total_generated_tokens": total_tokens,
        "benchmark_index_path": str(benchmark_index),
        "candidates_dir": cand_dir_str,
    }

    manifest_file = output_dir / "manifest.json"
    manifest_file.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    print(f"\n[+] Benchmark Rollout Complete!")
    print(f"    Total Samples:           {total_samples}")
    print(f"    Output Compliance Rate:  {manifest['output_compliance_rate']:.1%}")
    print(f"    Total Generated Tokens:  {total_tokens:,}")
    print(f"    Candidates Directory:    {candidates_dir}")
    print(f"    Manifest Path:           {manifest_file}")

    return manifest


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="BPF-Guardian Benchmark Rollout Generator")
    parser.add_argument("--benchmark-index", type=Path, default=DEFAULT_BENCHMARK_INDEX)
    parser.add_argument("--output-dir", type=Path, required=True, help="Destination directory for rollout artifacts")
    parser.add_argument("--model-name", type=str, default=DEFAULT_MODEL_NAME)
    parser.add_argument("--sampler-checkpoint", type=str, default=None, help="Tinker sampler checkpoint URL")
    parser.add_argument("--renderer-name", type=str, default=DEFAULT_RENDERER_NAME)
    parser.add_argument("--num-samples", type=int, default=1, help="Samples per task (1 for Pass@1, 4 for Pass@4)")
    parser.add_argument("--temperature", type=float, default=0.0, help="Sampling temperature (0.0 for Pass@1)")
    parser.add_argument("--seed", type=int, default=42, help="Base random seed")
    parser.add_argument("--max-tokens", type=int, default=DEFAULT_MAX_NEW_TOKENS)
    parser.add_argument("--mock", action="store_true", help="Generate synthetic mock outputs without calling Tinker API")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    asyncio.run(
        run_benchmark_rollout(
            benchmark_index=args.benchmark_index,
            output_dir=args.output_dir,
            model_name=args.model_name,
            sampler_checkpoint=args.sampler_checkpoint,
            renderer_name=args.renderer_name,
            num_samples=args.num_samples,
            temperature=args.temperature,
            seed=args.seed,
            max_tokens=args.max_tokens,
            mock=args.mock,
        )
    )


if __name__ == "__main__":
    main()
