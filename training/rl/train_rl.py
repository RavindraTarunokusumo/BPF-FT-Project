"""
BPF-Guardian RLVR Phase 1: Master Training Controller
Runs on the Hostinger Linux VPS to orchestrate:
1. Sampling-only integration canary (Phase 7: zero optimizer steps, 12 tasks x 4 samples)
2. Five-step RL canary run (Phase 8: max 5 steps, checkpoint per step, dev eval)
3. Full pilot RL run (Phase 9: 50 steps, balanced 96 tasks, dev eval every 5 steps)
"""

from __future__ import annotations

import argparse
import asyncio
import datetime
import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Safely load environment variables from .env
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
from tinker_cookbook import checkpoint_utils, renderers
from tinker_cookbook.renderers import get_renderer
from tinker_cookbook.rl import train as rl_train
from tinker_cookbook.rl.train import KLReferenceConfig

from training.rl.bpf_env import build_task_prompt
from training.rl.config import (
    DEFAULT_BASE_MODEL,
    DEFAULT_DEV_DIR,
    DEFAULT_RENDERER_NAME,
    DEFAULT_RUN_DIR,
    DEFAULT_TRAIN_DIR,
    SFT_V2_CHECKPOINT,
    SFT_V2_SAMPLER_CHECKPOINT,
    BPFRLConfig,
)
from training.rl.dataset import BPFRLDatasetBuilder, load_protected_task_ids, load_tasks_from_dir
from training.rl.kernel_executor import KernelExecutor, check_output_compliance, extract_c_source
from training.rl.reward import compute_rlvr_reward

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("bpf_guardian_rl.train")


async def run_sampling_only_canary(
    canary_dir: Path,
    output_dir: Path,
    sampler_checkpoint: str = SFT_V2_SAMPLER_CHECKPOINT,
    group_size: int = 4,
    temperature: float = 0.8,
    max_tokens: int = 2048,
) -> Dict[str, Any]:
    """Phase 7: Sampling-only canary on 12 tasks without optimizer updates."""
    logger.info("Starting Phase 7 Sampling-Only Canary Run...")
    output_dir.mkdir(parents=True, exist_ok=True)
    records_dir = output_dir / "verifier_records"
    records_dir.mkdir(parents=True, exist_ok=True)

    tasks = load_tasks_from_dir(canary_dir)
    logger.info("Loaded %d canary tasks from %s", len(tasks), canary_dir)
    if len(tasks) == 0:
        raise ValueError(f"No canary tasks found in {canary_dir}")

    from tinker_cookbook.tokenizer_utils import get_tokenizer

    service = tinker.ServiceClient()
    logger.info("Connecting to Tinker Sampler: %s", sampler_checkpoint)
    sampler = service.create_sampling_client(sampler_checkpoint)
    tokenizer = get_tokenizer(DEFAULT_BASE_MODEL)
    renderer = get_renderer(DEFAULT_RENDERER_NAME, tokenizer=tokenizer)
    executor = KernelExecutor(records_dir=records_dir)

    all_results: List[Dict[str, Any]] = []
    t0 = time.time()

    for task_idx, task in enumerate(tasks, start=1):
        task_id = task["task_id"]
        cat = task.get("application_category", "")
        diff = task.get("difficulty", "")
        logger.info("[%d/%d] Sampling canary task: %s (%s, %s)", task_idx, len(tasks), task_id, cat, diff)

        messages = build_task_prompt(task)
        model_input = renderer.build_generation_prompt(messages)
        stop_seqs = renderer.get_stop_sequences()

        # Sample group of completions
        sample_params = tinker.SamplingParams(
            max_tokens=max_tokens,
            temperature=temperature,
            stop=stop_seqs,
        )

        sample_tasks = [
            sampler.sample_async(
                prompt=model_input,
                num_samples=1,
                sampling_params=sample_params,
            )
            for _ in range(group_size)
        ]

        responses = await asyncio.gather(*sample_tasks)

        for s_idx, resp in enumerate(responses):
            seq = resp.sequences[0]
            raw_text = renderer.tokenizer.decode(seq.tokens)
            rollout_id = f"canary_{task_id}_s{s_idx}"

            # Evaluate candidate on VPS kernel harness
            ver_res = await executor.evaluate_candidate(
                task=task,
                raw_completion=raw_text,
                rollout_id=rollout_id,
            )

            # Recompute reward
            reward_breakdown = compute_rlvr_reward(
                ver_res.to_dict(),
                expected_fixture_count=task.get("expected_fixture_count"),
            )

            entry = {
                "task_id": task_id,
                "category": cat,
                "difficulty": diff,
                "sample_index": s_idx,
                "rollout_id": rollout_id,
                "source_sha256": ver_res.source_sha256,
                "compile_pass": ver_res.compile["pass"],
                "verifier_pass": ver_res.verifier["pass"],
                "behavioral_pass": ver_res.behavioral["pass"],
                "total_reward": reward_breakdown.total_reward,
                "is_functionally_correct": reward_breakdown.is_functionally_correct,
                "stage_reached": reward_breakdown.stage_reached,
                "timing": ver_res.timing,
            }
            all_results.append(entry)

    duration = round(time.time() - t0, 2)
    total_rollouts = len(all_results)
    compile_passes = sum(1 for r in all_results if r["compile_pass"])
    verifier_passes = sum(1 for r in all_results if r["verifier_pass"])
    func_passes = sum(1 for r in all_results if r["is_functionally_correct"])
    avg_reward = sum(r["total_reward"] for r in all_results) / total_rollouts if total_rollouts else 0.0

    summary = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "phase": "phase_7_sampling_only_canary",
        "sampler_checkpoint": sampler_checkpoint,
        "tasks_evaluated": len(tasks),
        "total_rollouts": total_rollouts,
        "compile_rate": round(compile_passes / total_rollouts, 4) if total_rollouts else 0.0,
        "verifier_rate": round(verifier_passes / total_rollouts, 4) if total_rollouts else 0.0,
        "functional_pass_rate": round(func_passes / total_rollouts, 4) if total_rollouts else 0.0,
        "average_reward": round(avg_reward, 4),
        "duration_seconds": duration,
        "rollouts": all_results,
    }

    summary_path = output_dir / "sampling_canary_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    logger.info("Sampling canary complete: Compile=%.1f%%, Verifier=%.1f%%, Pass@1=%.1f%%, AvgReward=%.4f",
                summary["compile_rate"] * 100, summary["verifier_rate"] * 100,
                summary["functional_pass_rate"] * 100, avg_reward)
    return summary


def build_tinker_rl_config(
    cfg: BPFRLConfig,
    mode: str = "pilot",
) -> rl_train.Config:
    """Builds official tinker_cookbook.rl.train.Config object."""
    max_steps = cfg.canary_max_steps if mode == "canary" else cfg.pilot_max_steps
    save_every = cfg.canary_save_every if mode == "canary" else cfg.pilot_save_every
    eval_every = cfg.pilot_eval_every if mode == "pilot" else max_steps

    train_data_dir = cfg.canary_data_dir if mode == "canary" else cfg.train_data_dir

    dataset_builder = BPFRLDatasetBuilder(
        train_dir=train_data_dir,
        dev_dir=None,  # Dedicated eval runs via evaluate_rl.py at T=0.0 per RL_V1 spec
        group_size=cfg.group_size,
        renderer_name=cfg.renderer_name,
        records_dir=f"{cfg.run_dir}/verifier_records",
        batch_size=cfg.problem_groups_per_step,
    )

    kl_ref_config = KLReferenceConfig(
        base_model=cfg.base_model,
        load_checkpoint_path=cfg.kl_reference_checkpoint,
    )

    tinker_cfg = rl_train.Config(
        learning_rate=cfg.learning_rate,
        dataset_builder=dataset_builder,
        model_name=cfg.base_model,
        recipe_name=f"bpf_rlvr_{mode}",
        max_tokens=cfg.max_tokens,
        log_path=f"{cfg.run_dir}/{mode}",
        eval_every=0,
        save_every=save_every,
        load_checkpoint_path=cfg.load_checkpoint_path,
        renderer_name=cfg.renderer_name,
        wandb_project=cfg.wandb_project,
        wandb_name=f"{cfg.wandb_run_name}_{mode}",
        kl_penalty_coef=cfg.kl_penalty_coef,
        kl_reference_config=kl_ref_config,
        loss_fn=cfg.loss_fn,
        lora_rank=cfg.lora_rank,
        temperature=cfg.sampling_temperature,
        remove_constant_reward_groups=cfg.remove_constant_reward_groups,
        max_steps=max_steps,
    )

    return tinker_cfg


def main():
    parser = argparse.ArgumentParser(description="BPF-Guardian RLVR Training Controller")
    parser.add_argument("--mode", choices=["sampling_only", "canary", "pilot"], default="sampling_only")
    parser.add_argument("--canary-dir", type=str, default="data/rl/v1/canary")
    parser.add_argument("--train-dir", type=str, default="data/rl/v1/train")
    parser.add_argument("--dev-dir", type=str, default="data/rl/v1/dev")
    parser.add_argument("--output-dir", type=str, default="runs/tinker/qwen3-8b-bpf-rl-v1")
    parser.add_argument("--max-steps", type=int, default=None)
    parser.add_argument("--group-size", type=int, default=4)
    parser.add_argument("--temperature", type=float, default=0.8)
    parser.add_argument("--learning-rate", type=float, default=5e-6)
    parser.add_argument("--confirm-paid-run", action="store_true", help="Explicitly allow paid training run")
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    if args.mode == "sampling_only":
        summary = asyncio.run(
            run_sampling_only_canary(
                canary_dir=Path(args.canary_dir),
                output_dir=output_dir / "canary_sampling",
                group_size=args.group_size,
                temperature=args.temperature,
            )
        )
        print("Sampling Canary completed successfully. Results saved to:", output_dir / "canary_sampling")
        return

    # Paid training run
    if not args.confirm_paid_run:
        logger.warning("[!] --confirm-paid-run not specified. Exiting before launching training steps.")
        print("Preflight check passed. To launch paid training run, pass --confirm-paid-run.")
        return

    cfg = BPFRLConfig(
        canary_data_dir=args.canary_dir,
        train_data_dir=args.train_dir,
        dev_data_dir=args.dev_dir,
        run_dir=args.output_dir,
        group_size=args.group_size,
        sampling_temperature=args.temperature,
        learning_rate=args.learning_rate,
    )
    if args.max_steps:
        if args.mode == "canary":
            cfg.canary_max_steps = args.max_steps
        else:
            cfg.pilot_max_steps = args.max_steps

    tinker_cfg = build_tinker_rl_config(cfg, mode=args.mode)
    logger.info("Launching RL training mode '%s' (max_steps=%d)...", args.mode, tinker_cfg.max_steps)
    asyncio.run(rl_train.main(tinker_cfg))


if __name__ == "__main__":
    main()
