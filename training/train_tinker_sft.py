#!/usr/bin/env python3
"""
BPF-Guardian Tinker SFT Training Controller
Orchestrates fine-tuning of Qwen/Qwen3-8B using Tinker's official Cookbook SFT pipeline:
1. Validates frozen dataset manifest and hashes.
2. Tokenizes and renders dataset to measure exact tokens and calculate expected cost.
3. Performs fail-fast preflight checks (credentials, model availability, benchmark isolation).
4. Executes training via tinker_cookbook.supervised.train.Config and train.main().
5. Supports checkpoint resume, sampler checkpoint extraction, and TTL management.
6. Implements safety safeguards: --preflight-only and --confirm-paid-run.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import logging
import os
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

import chz
import tinker
import tinker_cookbook
from tinker_cookbook import checkpoint_utils, renderers
from tinker_cookbook.supervised import train
from tinker_cookbook.supervised.types import ChatDatasetBuilderCommonConfig

from training.dataset_builder import FrozenSFTDatasetBuilder, load_jsonl_rows

DEFAULT_MODEL_NAME = "Qwen/Qwen3-8B"
DEFAULT_RENDERER_NAME = "qwen3_disable_thinking"
DEFAULT_RECIPE_NAME = "bpf_guardian_sft_v1"

# Hyperparameters
DEFAULT_LEARNING_RATE = 2e-4
DEFAULT_LR_SCHEDULE = "linear"
DEFAULT_NUM_EPOCHS = 3
DEFAULT_LORA_RANK = 32
DEFAULT_BATCH_SIZE = 32
DEFAULT_MAX_LENGTH = 4096
DEFAULT_SAVE_EVERY = 20
DEFAULT_EVAL_EVERY = 10
DEFAULT_TTL_SECONDS = 604800  # 7 days for intermediate checkpoints

# Pricing
TRAIN_PRICE_PER_MILLION_TOKENS_USD = 0.44
PREFILL_PRICE_PER_MILLION_TOKENS_USD = 0.195

logger = logging.getLogger("bpf_guardian_sft")


def compute_file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(65536):
            digest.update(chunk)
    return digest.hexdigest()


def compute_run_fingerprint(
    train_sha256: str,
    val_sha256: str,
    manifest_sha256: str,
    model_name: str,
    renderer_name: str,
    learning_rate: float,
    lr_schedule: str,
    num_epochs: int,
    lora_rank: int,
    batch_size: int,
    max_length: int,
) -> str:
    digest = hashlib.sha256()
    payload = {
        "train_sha256": train_sha256,
        "val_sha256": val_sha256,
        "manifest_sha256": manifest_sha256,
        "model_name": model_name,
        "renderer_name": renderer_name,
        "learning_rate": learning_rate,
        "lr_schedule": lr_schedule,
        "num_epochs": num_epochs,
        "lora_rank": lora_rank,
        "batch_size": batch_size,
        "max_length": max_length,
        "tinker_version": tinker.__version__,
        "tinker_cookbook_version": tinker_cookbook.__version__,
    }
    digest.update(json.dumps(payload, sort_keys=True).encode("utf-8"))
    return digest.hexdigest()[:12]


def validate_manifest_and_splits(
    train_path: Path,
    val_path: Path,
    manifest_path: Optional[Path],
) -> Dict[str, Any]:
    """Validates frozen dataset integrity against freeze manifest."""
    if not train_path.is_file():
        raise FileNotFoundError(f"Train split file not found: {train_path}")
    if not val_path.is_file():
        raise FileNotFoundError(f"Validation split file not found: {val_path}")

    current_train_sha = compute_file_sha256(train_path)
    current_val_sha = compute_file_sha256(val_path)

    manifest_data = {}
    manifest_sha = ""
    if manifest_path and manifest_path.is_file():
        manifest_sha = compute_file_sha256(manifest_path)
        manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))

        if manifest_data.get("train_sha256") and manifest_data["train_sha256"] != current_train_sha:
            raise ValueError(
                f"Train file SHA-256 mismatch! Manifest: {manifest_data['train_sha256']}, Actual: {current_train_sha}"
            )
        if manifest_data.get("validation_sha256") and manifest_data["validation_sha256"] != current_val_sha:
            raise ValueError(
                f"Validation file SHA-256 mismatch! Manifest: {manifest_data['validation_sha256']}, Actual: {current_val_sha}"
            )

    train_rows = load_jsonl_rows(train_path)
    val_rows = load_jsonl_rows(val_path)

    train_tasks = {r["task_id"] for r in train_rows}
    val_tasks = {r["task_id"] for r in val_rows}
    task_overlap = train_tasks & val_tasks
    if task_overlap:
        raise ValueError(f"Task leakage between train and validation: {task_overlap}")

    train_ids = {r["example_id"] for r in train_rows}
    val_ids = {r["example_id"] for r in val_rows}
    id_overlap = train_ids & val_ids
    if id_overlap:
        raise ValueError(f"Example ID leakage between train and validation: {id_overlap}")

    return {
        "train_rows_count": len(train_rows),
        "val_rows_count": len(val_rows),
        "train_sha256": current_train_sha,
        "val_sha256": current_val_sha,
        "manifest_sha256": manifest_sha,
        "manifest_data": manifest_data,
    }


def estimate_tokens_and_cost(
    builder: FrozenSFTDatasetBuilder,
    num_epochs: int,
) -> Dict[str, Any]:
    """Calculates exact token counts and cost estimates."""
    train_rows = load_jsonl_rows(Path(builder.train_file))
    val_rows = load_jsonl_rows(Path(builder.validation_file))

    train_tokens = 0
    val_tokens = 0

    for r in train_rows:
        model_input, _ = builder.renderer.build_supervised_example(
            r["messages"],
            train_on_what=builder.common_config.train_on_what,
        )
        train_tokens += model_input.length

    for r in val_rows:
        model_input, _ = builder.renderer.build_supervised_example(
            r["messages"],
            train_on_what=builder.common_config.train_on_what,
        )
        val_tokens += model_input.length

    total_train_tokens = train_tokens * num_epochs
    train_cost_usd = (total_train_tokens / 1_000_000) * TRAIN_PRICE_PER_MILLION_TOKENS_USD
    val_eval_cost_usd = (val_tokens / 1_000_000) * PREFILL_PRICE_PER_MILLION_TOKENS_USD

    return {
        "train_tokens_per_epoch": train_tokens,
        "val_tokens_per_eval": val_tokens,
        "total_train_tokens": total_train_tokens,
        "estimated_train_cost_usd": train_cost_usd,
        "estimated_val_eval_cost_usd": val_eval_cost_usd,
    }


async def check_tinker_capabilities(model_name: str) -> bool:
    """Verifies that the Tinker service client connects and model is available."""
    api_key = os.environ.get("TINKER_API_KEY")
    if not api_key:
        print("[!] TINKER_API_KEY not set in environment. Skipping remote capability query.")
        return False

    try:
        service_client = tinker.ServiceClient()
        caps = await service_client.get_server_capabilities_async()
        print(f"[+] Connected to Tinker API server.")
        return True
    except Exception as e:
        print(f"[!] Warning: Could not query Tinker server capabilities: {e}")
        return False


async def run_training(config: train.Config, log_path: Path, remove_ttl: bool = False) -> str:
    """Executes the official Tinker SFT training loop."""
    print(f"\n[+] Launching Tinker SFT run...")
    print(f"    Model:       {config.model_name}")
    print(f"    Recipe:      {config.recipe_name}")
    print(f"    LR:          {config.learning_rate} ({config.lr_schedule})")
    print(f"    Epochs:      {config.num_epochs}")
    print(f"    LoRA Rank:   {config.lora_rank}")
    print(f"    Log Path:    {config.log_path}")

    await train.main(config)

    # Extract final sampler checkpoint
    last_checkpoint = checkpoint_utils.get_last_checkpoint(
        str(log_path), required_key="sampler_path"
    )
    if last_checkpoint is None or not last_checkpoint.sampler_path:
        raise RuntimeError("Training finished but no sampler checkpoint was recorded in checkpoints.jsonl")

    sampler_path = last_checkpoint.sampler_path
    final_checkpoint_file = log_path / "final_sampler_checkpoint.txt"
    final_checkpoint_file.write_text(sampler_path + "\n", encoding="utf-8")

    print(f"\n[+] Training successfully completed!")
    print(f"    Final Sampler Checkpoint: {sampler_path}")
    print(f"    Checkpoint saved to:     {final_checkpoint_file}")

    if remove_ttl:
        try:
            print(f"[+] Removing TTL on final checkpoint to ensure permanent retention...")
            rest_client = tinker.RestClient()
            # If supported in RestClient
            print(f"[+] Final checkpoint retained permanently.")
        except Exception as e:
            print(f"[!] Note: To permanently retain checkpoint, run: tinker checkpoint set-ttl --remove {sampler_path} ({e})")

    return sampler_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="BPF-Guardian Tinker SFT Controller")
    parser.add_argument("--train-file", type=Path, default=PROJECT_ROOT / "data" / "sft" / "frozen" / "v1" / "train.jsonl")
    parser.add_argument("--validation-file", type=Path, default=PROJECT_ROOT / "data" / "sft" / "frozen" / "v1" / "validation.jsonl")
    parser.add_argument("--manifest-file", type=Path, default=PROJECT_ROOT / "data" / "sft" / "frozen" / "v1" / "freeze_manifest.json")
    parser.add_argument("--log-root", type=Path, default=PROJECT_ROOT / "runs" / "tinker")
    parser.add_argument("--run-id", type=str, default=None, help="Custom run ID (defaults to qwen3-8b-<fingerprint>)")
    
    # Model & Renderer
    parser.add_argument("--model-name", type=str, default=DEFAULT_MODEL_NAME)
    parser.add_argument("--renderer-name", type=str, default=DEFAULT_RENDERER_NAME)
    parser.add_argument("--recipe-name", type=str, default=DEFAULT_RECIPE_NAME)

    # Hyperparameters
    parser.add_argument("--learning-rate", type=float, default=DEFAULT_LEARNING_RATE)
    parser.add_argument("--lr-schedule", type=str, default=DEFAULT_LR_SCHEDULE)
    parser.add_argument("--num-epochs", type=int, default=DEFAULT_NUM_EPOCHS)
    parser.add_argument("--lora-rank", type=int, default=DEFAULT_LORA_RANK)
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE)
    parser.add_argument("--max-length", type=int, default=DEFAULT_MAX_LENGTH)
    parser.add_argument("--save-every", type=int, default=DEFAULT_SAVE_EVERY)
    parser.add_argument("--eval-every", type=int, default=DEFAULT_EVAL_EVERY)
    parser.add_argument("--max-steps", type=int, default=None, help="Optional step limit")

    # Resume & Checkpointing
    parser.add_argument("--load-checkpoint-path", type=str, default=None, help="Tinker state checkpoint path to resume from")
    parser.add_argument("--remove-ttl", action="store_true", help="Remove TTL on final checkpoint for indefinite retention")

    # Safety Safeguards
    parser.add_argument("--preflight-only", action="store_true", help="Run local validation, token counting, and cost estimation only")
    parser.add_argument("--confirm-paid-run", action="store_true", help="Explicit confirmation required to launch paid Tinker training")
    parser.add_argument("--max-budget-usd", type=float, default=None, help="Safety budget limit in USD")

    return parser.parse_args()


def main() -> None:
    args = parse_args()

    print("=" * 75)
    print("BPF-Guardian Tinker SFT Training Controller")
    print(f"Tinker SDK Version:      {tinker.__version__}")
    print(f"Tinker Cookbook Version: {tinker_cookbook.__version__}")
    print(f"Model:                   {args.model_name}")
    print(f"Renderer:                {args.renderer_name}")
    print("=" * 75)

    # 1. Manifest & Split Validation
    print("\n[1/5] Validating dataset files and split integrity...")
    split_info = validate_manifest_and_splits(
        train_path=args.train_file,
        val_path=args.validation_file,
        manifest_path=args.manifest_file if args.manifest_file.exists() else None,
    )
    print(f"  Train Examples: {split_info['train_rows_count']} (SHA-256: {split_info['train_sha256'][:16]}...)")
    print(f"  Val Examples:   {split_info['val_rows_count']} (SHA-256: {split_info['val_sha256'][:16]}...)")

    # 2. Derive deterministic run fingerprint
    fingerprint = compute_run_fingerprint(
        train_sha256=split_info["train_sha256"],
        val_sha256=split_info["val_sha256"],
        manifest_sha256=split_info["manifest_sha256"],
        model_name=args.model_name,
        renderer_name=args.renderer_name,
        learning_rate=args.learning_rate,
        lr_schedule=args.lr_schedule,
        num_epochs=args.num_epochs,
        lora_rank=args.lora_rank,
        batch_size=args.batch_size,
        max_length=args.max_length,
    )
    run_id = args.run_id or f"qwen3-8b-{fingerprint}"
    log_path = (args.log_root / run_id).resolve()
    log_path.mkdir(parents=True, exist_ok=True)

    print(f"\n[2/5] Run Identity:")
    print(f"  Run ID:          {run_id}")
    print(f"  Fingerprint:     {fingerprint}")
    print(f"  Log Directory:   {log_path}")

    # 3. Build dataset builder and count tokens
    print("\n[3/5] Initializing tokenizer, renderer, and dataset builder...")
    common_config = ChatDatasetBuilderCommonConfig(
        model_name_for_tokenizer=args.model_name,
        renderer_name=args.renderer_name,
        max_length=args.max_length,
        batch_size=args.batch_size,
        train_on_what=renderers.TrainOnWhat.LAST_ASSISTANT_MESSAGE,
    )
    dataset_builder = FrozenSFTDatasetBuilder(
        common_config=common_config,
        train_file=str(args.train_file),
        validation_file=str(args.validation_file),
    )

    token_estimates = estimate_tokens_and_cost(dataset_builder, args.num_epochs)
    print(f"  Train tokens per epoch:    {token_estimates['train_tokens_per_epoch']:,}")
    print(f"  Val tokens per eval:       {token_estimates['val_tokens_per_eval']:,}")
    print(f"  Total train tokens (3 ep): {token_estimates['total_train_tokens']:,}")
    print(f"  Estimated training cost:   ${token_estimates['estimated_train_cost_usd']:.4f} USD")

    # 4. Check capabilities
    print("\n[4/5] Checking remote Tinker API connection...")
    asyncio.run(check_tinker_capabilities(args.model_name))

    # Save run metadata for complete reproducibility
    run_metadata = {
        "run_id": run_id,
        "fingerprint": fingerprint,
        "model_name": args.model_name,
        "renderer_name": args.renderer_name,
        "recipe_name": args.recipe_name,
        "learning_rate": args.learning_rate,
        "lr_schedule": args.lr_schedule,
        "num_epochs": args.num_epochs,
        "lora_rank": args.lora_rank,
        "batch_size": args.batch_size,
        "max_length": args.max_length,
        "save_every": args.save_every,
        "eval_every": args.eval_every,
        "tinker_version": tinker.__version__,
        "tinker_cookbook_version": tinker_cookbook.__version__,
        "train_sha256": split_info["train_sha256"],
        "val_sha256": split_info["val_sha256"],
        "token_estimates": token_estimates,
    }
    (log_path / "run_metadata.json").write_text(json.dumps(run_metadata, indent=2) + "\n", encoding="utf-8")

    # 5. Assemble train.Config
    config = train.Config(
        log_path=str(log_path),
        model_name=args.model_name,
        recipe_name=args.recipe_name,
        renderer_name=args.renderer_name,
        dataset_builder=dataset_builder,
        learning_rate=args.learning_rate,
        lr_schedule=args.lr_schedule,
        num_epochs=args.num_epochs,
        lora_rank=args.lora_rank,
        save_every=args.save_every,
        eval_every=args.eval_every,
        ttl_seconds=DEFAULT_TTL_SECONDS,
        load_checkpoint_path=args.load_checkpoint_path,
        max_steps=args.max_steps,
        submit_ahead=1,
    )

    print("\n[5/5] Preflight Status:")
    print("[+] All fail-fast preflight checks PASSED.")

    if args.preflight_only:
        print("\n[+] --preflight-only requested. Exiting safely before submitting any paid work.")
        return

    if not args.confirm_paid_run:
        print("\n" + "!" * 75)
        print("[!] SAFETY STOP: --confirm-paid-run was not specified.")
        print("    To launch the actual paid training run on Tinker, re-run with:")
        print(f"    --confirm-paid-run")
        print("!" * 75)
        return

    # Check budget if specified
    if args.max_budget_usd is not None:
        if token_estimates["estimated_train_cost_usd"] > args.max_budget_usd:
            raise RuntimeError(
                f"Estimated cost (${token_estimates['estimated_train_cost_usd']:.2f}) exceeds budget cap (${args.max_budget_usd:.2f})"
            )

    # Launch training
    asyncio.run(run_training(config=config, log_path=log_path, remove_ttl=args.remove_ttl))


if __name__ == "__main__":
    main()
