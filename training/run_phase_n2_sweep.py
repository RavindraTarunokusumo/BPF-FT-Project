#!/usr/bin/env python3
"""
Phase N2 Hyperparameter Sweep Driver: Nemotron-3.5-Lightning SFT v1
Orchestrates pre-registered SFT training sweep configurations:
  Run A: LoRA rank 32, LR 2e-4, schedule cosine
  Run B: LoRA rank 32, LR 4e-4, schedule cosine
  Run C: LoRA rank 64, LR 2e-4, schedule cosine
  Run D: LoRA rank 64, LR 4e-4, schedule cosine

Phase 1: Bounded 1-epoch canaries for all 4 configurations.
Phase 2: Checkpoint selection via completion-only validation NLL (in-domain & family-heldout).
Phase 3: Full 3-epoch expansion for the winning configuration.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Safely load .env
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

SWEEP_CONFIGS = [
    {"name": "Run A", "run_id": "nemotron-sft-canary-run-a-rank32-lr2e4", "lora_rank": 32, "learning_rate": 2e-4, "lr_schedule": "cosine"},
    {"name": "Run B", "run_id": "nemotron-sft-canary-run-b-rank32-lr4e4", "lora_rank": 32, "learning_rate": 4e-4, "lr_schedule": "cosine"},
    {"name": "Run C", "run_id": "nemotron-sft-canary-run-c-rank64-lr2e4", "lora_rank": 64, "learning_rate": 2e-4, "lr_schedule": "cosine"},
    {"name": "Run D", "run_id": "nemotron-sft-canary-run-d-rank64-lr4e4", "lora_rank": 64, "learning_rate": 4e-4, "lr_schedule": "cosine"},
]

RUNS_ROOT = PROJECT_ROOT / "runs" / "tinker"
SWEEP_ROOT = RUNS_ROOT / "nemotron-sft-sweep"
SWEEP_ROOT.mkdir(parents=True, exist_ok=True)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("nemotron_sweep")


def load_metrics_for_run(run_dir: Path) -> List[Dict[str, Any]]:
    metrics_file = run_dir / "metrics.jsonl"
    if not metrics_file.is_file():
        return []
    records = []
    with metrics_file.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return records


def parse_run_summary(run_dir: Path) -> Dict[str, Any]:
    metadata_file = run_dir / "run_metadata.json"
    ckpt_file = run_dir / "final_sampler_checkpoint.txt"
    metadata = {}
    if metadata_file.is_file():
        metadata = json.loads(metadata_file.read_text(encoding="utf-8"))

    final_sampler_ckpt = ""
    if ckpt_file.is_file():
        final_sampler_ckpt = ckpt_file.read_text(encoding="utf-8").strip()

    metrics = load_metrics_for_run(run_dir)
    eval_metrics = [m for m in metrics if "test/nll" in m or "val_heldout/nll" in m]
    
    final_test_nll = None
    final_heldout_nll = None
    final_train_nll = None
    if eval_metrics:
        last_eval = eval_metrics[-1]
        final_test_nll = last_eval.get("test/nll")
        final_heldout_nll = last_eval.get("val_heldout/nll")

    if metrics:
        final_train_nll = metrics[-1].get("train_mean_nll")

    return {
        "run_dir": str(run_dir),
        "run_id": run_dir.name,
        "metadata": metadata,
        "final_sampler_checkpoint": final_sampler_ckpt,
        "total_steps": len(metrics),
        "total_evals": len(eval_metrics),
        "final_train_nll": final_train_nll,
        "final_test_nll": final_test_nll,
        "final_heldout_nll": final_heldout_nll,
        "eval_trajectory": [
            {
                "step": m.get("step"),
                "test_nll": m.get("test/nll"),
                "test_bpb": m.get("test/bpb"),
                "heldout_nll": m.get("val_heldout/nll"),
                "heldout_bpb": m.get("val_heldout/bpb"),
                "train_nll": m.get("train_mean_nll"),
            }
            for m in eval_metrics
        ],
    }


async def run_training_subprocess(
    run_id: str,
    lora_rank: int,
    learning_rate: float,
    lr_schedule: str,
    num_epochs: int,
    eval_every: int = 10,
    save_every: int = 20,
    no_wandb: bool = True,
) -> int:
    cmd = [
        sys.executable,
        str(PROJECT_ROOT / "training" / "train_tinker_sft.py"),
        "--model-profile", "nemotron-3.5-lightning",
        "--run-id", run_id,
        "--lora-rank", str(lora_rank),
        "--learning-rate", str(learning_rate),
        "--lr-schedule", lr_schedule,
        "--num-epochs", str(num_epochs),
        "--eval-every", str(eval_every),
        "--save-every", str(save_every),
        "--confirm-paid-run",
    ]
    if no_wandb:
        cmd.append("--no-wandb")

    logger.info("Executing training command: %s", " ".join(cmd))
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        cwd=str(PROJECT_ROOT),
    )

    async for raw_line in proc.stdout:
        line = raw_line.decode("utf-8", errors="replace").rstrip()
        if line:
            print(f"[{run_id}] {line}", flush=True)

    await proc.wait()
    return proc.returncode


async def main_async() -> None:
    parser = argparse.ArgumentParser(description="Nemotron Phase N2 Sweep Driver")
    parser.add_argument("--canaries-only", action="store_true", help="Run only the 4 canary runs without expanding to full 3 epochs")
    parser.add_argument("--skip-canaries", action="store_true", help="Skip canaries and directly run full 3 epochs on specified config")
    parser.add_argument("--winner-config", type=str, default=None, help="Force specific winner config (Run A, Run B, Run C, or Run D)")
    parser.add_argument("--epochs-canary", type=int, default=1, help="Epochs for canaries (default: 1)")
    parser.add_argument("--epochs-full", type=int, default=3, help="Epochs for full run (default: 3)")
    args = parser.parse_args()

    canary_summaries: Dict[str, Any] = {}

    # Step 1: Run 4 Bounded Canaries
    if not args.skip_canaries:
        print("\n" + "=" * 80)
        print("PHASE N2: BOUNDED SFT HYPERPARAMETER SWEEP (CANARIES)")
        print("=" * 80)

        for cfg in SWEEP_CONFIGS:
            run_name = cfg["name"]
            run_id = cfg["run_id"]
            run_dir = RUNS_ROOT / run_id
            ckpt_file = run_dir / "final_sampler_checkpoint.txt"

            print(f"\n---> Evaluating {run_name}: LoRA Rank {cfg['lora_rank']}, LR {cfg['learning_rate']}, Schedule {cfg['lr_schedule']}")

            if ckpt_file.is_file() and ckpt_file.read_text(encoding="utf-8").strip():
                print(f"     Found existing completed canary: {ckpt_file.read_text(encoding='utf-8').strip()}")
            else:
                ret = await run_training_subprocess(
                    run_id=run_id,
                    lora_rank=cfg["lora_rank"],
                    learning_rate=cfg["learning_rate"],
                    lr_schedule=cfg["lr_schedule"],
                    num_epochs=args.epochs_canary,
                    eval_every=10,
                    save_every=20,
                )
                if ret != 0:
                    raise RuntimeError(f"Canary {run_name} failed with return code {ret}")

            summary = parse_run_summary(run_dir)
            canary_summaries[run_name] = {**cfg, **summary}

        # Tabulate results
        print("\n" + "=" * 80)
        print("CANARY EVALUATION RESULTS SUMMARY")
        print("=" * 80)
        header = f"{'Run':<8} | {'Rank':<5} | {'LR':<7} | {'Steps':<6} | {'Train NLL':<10} | {'Test NLL':<10} | {'Heldout NLL':<12}"
        print(header)
        print("-" * len(header))

        for name, res in canary_summaries.items():
            t_nll = f"{res['final_train_nll']:.5f}" if res['final_train_nll'] is not None else "N/A"
            v_nll = f"{res['final_test_nll']:.5f}" if res['final_test_nll'] is not None else "N/A"
            h_nll = f"{res['final_heldout_nll']:.5f}" if res['final_heldout_nll'] is not None else "N/A"
            print(f"{name:<8} | {res['lora_rank']:<5} | {res['learning_rate']:<7} | {res['total_steps']:<6} | {t_nll:<10} | {v_nll:<10} | {h_nll:<12}")

        (SWEEP_ROOT / "canary_results.json").write_text(json.dumps(canary_summaries, indent=2), encoding="utf-8")
        print(f"\n[+] Canary results saved to: {SWEEP_ROOT / 'canary_results.json'}")

        if args.canaries_only:
            print("\n[+] --canaries-only specified. Exiting.")
            return

    # Step 2: Determine Winning Configuration
    if args.winner_config:
        winning_cfg = next(c for c in SWEEP_CONFIGS if c["name"].lower() == args.winner_config.lower())
        print(f"\n[+] Using user-specified winning config: {winning_cfg['name']}")
    elif canary_summaries:
        # Rank by combined heldout NLL + test NLL
        def score_fn(item):
            res = item[1]
            h = res.get("final_heldout_nll") or 999.0
            t = res.get("final_test_nll") or 999.0
            return (h, t)
        
        sorted_canaries = sorted(canary_summaries.items(), key=score_fn)
        best_name, best_res = sorted_canaries[0]
        winning_cfg = next(c for c in SWEEP_CONFIGS if c["name"] == best_name)
        print(f"\n[+] Selected winning config based on validation NLL: {winning_cfg['name']} (Heldout NLL: {best_res['final_heldout_nll']:.5f}, In-domain NLL: {best_res['final_test_nll']:.5f})")
    else:
        # Default pre-registered Run A
        winning_cfg = SWEEP_CONFIGS[0]
        print(f"\n[+] Defaulting to Run A: {winning_cfg['name']}")

    # Step 3: Train Full 3-Epoch SFT Model
    full_run_id = f"nemotron-sft-v1-full-rank{winning_cfg['lora_rank']}-lr{str(winning_cfg['learning_rate']).replace('.', '')}"
    full_run_dir = RUNS_ROOT / full_run_id
    full_ckpt_file = full_run_dir / "final_sampler_checkpoint.txt"

    print("\n" + "=" * 80)
    print(f"PHASE N2: FULL 3-EPOCH SFT TRAINING ({winning_cfg['name']})")
    print(f"Run ID:    {full_run_id}")
    print(f"LoRA Rank: {winning_cfg['lora_rank']}")
    print(f"LR:        {winning_cfg['learning_rate']} ({winning_cfg['lr_schedule']})")
    print(f"Epochs:    {args.epochs_full}")
    print("=" * 80)

    if full_ckpt_file.is_file() and full_ckpt_file.read_text(encoding="utf-8").strip():
        final_sampler_ckpt = full_ckpt_file.read_text(encoding="utf-8").strip()
        print(f"\n[+] Found existing completed 3-epoch training run: {final_sampler_ckpt}")
    else:
        ret = await run_training_subprocess(
            run_id=full_run_id,
            lora_rank=winning_cfg["lora_rank"],
            learning_rate=winning_cfg["learning_rate"],
            lr_schedule=winning_cfg["lr_schedule"],
            num_epochs=args.epochs_full,
            eval_every=10,
            save_every=20,
        )
        if ret != 0:
            raise RuntimeError(f"Full 3-epoch training failed with return code {ret}")
        final_sampler_ckpt = full_ckpt_file.read_text(encoding="utf-8").strip()

    full_summary = parse_run_summary(full_run_dir)

    # Step 4: Write Complete Phase N2 Sweep Manifest
    sweep_manifest = {
        "model_profile": "nemotron-3.5-lightning",
        "foundation_model": "nvidia/NVIDIA-Nemotron-3.5-Lightning-30B-A3B-BF16",
        "renderer": "nemotron3_ultra_disable_thinking",
        "license": "OpenMDW-1.1",
        "revision": "a9904d24bcc1d289a1950fa9d2b978c47cf903b9",
        "canary_configurations": canary_summaries,
        "selected_winner": winning_cfg["name"],
        "full_run_summary": full_summary,
        "final_sampler_checkpoint": final_sampler_ckpt,
    }

    manifest_path = SWEEP_ROOT / "sweep_manifest.json"
    manifest_path.write_text(json.dumps(sweep_manifest, indent=2), encoding="utf-8")
    print(f"\n[+] Master Phase N2 SFT sweep manifest saved to: {manifest_path}")
    print(f"    Selected SFT Checkpoint: {final_sampler_ckpt}")


def main() -> None:
    asyncio.run(main_async())


if __name__ == "__main__":
    main()
