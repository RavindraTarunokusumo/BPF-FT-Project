"""
BPF-Guardian RLVR Phase N3: Master Training Controller (Nemotron-3.5-Lightning)
Orchestrates diagnostic-guided two-turn repair RL on Tinker and the Hostinger Linux VPS:
1. Two-turn sampling-only integration canary (12 tasks x 4 samples, 2 turns)
2. Five-step RL canary with checkpoint per step and optimizer verification
3. Full pilot RL run (30–50 steps) with BPFPrioritySampler and automated Dev evaluation
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

from training.model_profiles import get_model_profile
from training.rl.bpf_env import (
    REPAIR_SYSTEM_PROMPT,
    SYNTHESIS_SYSTEM_PROMPT,
    TwoTurnBPFEnv,
    TwoTurnBPFEnvGroupBuilder,
    build_task_prompt,
)
from training.rl.config import (
    DEFAULT_CANARY_DIR_N3,
    DEFAULT_CONFIRMATION_DIR_N3,
    DEFAULT_DEV_DIR_N3,
    DEFAULT_RUN_DIR_N3,
    DEFAULT_TRAIN_DIR_N3,
    NEMOTRON_BASE_MODEL,
    NEMOTRON_RENDERER_NAME,
    NEMOTRON_SFT_V1_CHECKPOINT,
    NEMOTRON_SFT_V1_SAMPLER_CHECKPOINT,
    BPFRLN3Config,
)
from training.rl.dataset import BPFRLDatasetBuilder, load_tasks_from_dir
from training.rl.kernel_executor import KernelExecutor, check_output_compliance, extract_c_source
from training.rl.reward import compute_rlvr_reward

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("bpf_guardian_rl.train_n3")


def install_n3_sampler_feedback_hook():
    """Hooks tinker_cookbook rollout collection to feed multi-turn outcomes into BPFPrioritySampler."""
    import tinker_cookbook.rl.rollouts as rollouts
    import tinker_cookbook.rl.train as rl_train

    orig_impl = rollouts._do_group_rollout_and_filter_constant_reward_impl

    async def hooked_impl(
        sampling_client: tinker.SamplingClient,
        env_group_builder: Any,
        max_tokens: int,
        temperature: float,
        do_remove_constant_reward_groups: bool,
        enable_logging: bool = True,
        strategy: Any = None,
        termination: Any = None,
    ):
        traj_group = await orig_impl(
            sampling_client=sampling_client,
            env_group_builder=env_group_builder,
            max_tokens=max_tokens,
            temperature=temperature,
            do_remove_constant_reward_groups=False,
            enable_logging=enable_logging,
            strategy=strategy,
            termination=termination,
        )
        if traj_group is None:
            return None

        rewards = traj_group.get_total_rewards()
        is_constant = rollouts.all_same(rewards)

        # In multi-turn, determine if any trajectory achieved solve_at_2 or functional pass
        full_pass = False
        for traj in traj_group.trajectories_G:
            if traj.transitions:
                last_m = traj.transitions[-1].metrics or {}
                if (
                    last_m.get("pass/solve_at_2", 0.0) == 1.0
                    or last_m.get("pass/pass_at_1", 0.0) == 1.0
                    or last_m.get("pass/functional", 0.0) == 1.0
                ):
                    full_pass = True
                    break

        sampler = getattr(env_group_builder, "sampler", None)
        task = getattr(env_group_builder, "task", None)
        if sampler is not None and task is not None:
            task_id = task.get("task_id")
            if task_id:
                sampler.update_outcome(
                    task_id=task_id,
                    rewards=rewards,
                    full_pass=full_pass,
                    is_constant_group=is_constant,
                )
                state_path = getattr(env_group_builder, "sampler_state_path", None)
                if state_path:
                    try:
                        sampler.save_state(Path(state_path))
                    except Exception as e:
                        logger.warning("Failed to save sampler state to %s: %s", state_path, e)

        if do_remove_constant_reward_groups and is_constant:
            return None

        return traj_group

    rollouts._do_group_rollout_and_filter_constant_reward_impl = hooked_impl
    rollouts.do_group_rollout_and_filter_constant_reward = hooked_impl
    rl_train.do_group_rollout_and_filter_constant_reward = hooked_impl
    logger.info("Installed two-turn BPFPrioritySampler outcome feedback hook in tinker_cookbook")


async def run_two_turn_sampling_canary(
    canary_dir: Path,
    output_dir: Path,
    sampler_checkpoint: str = NEMOTRON_SFT_V1_SAMPLER_CHECKPOINT,
    group_size: int = 4,
    temperature: float = 0.8,
    max_tokens: int = 2048,
) -> Dict[str, Any]:
    """Two-turn sampling-only canary on 12 tasks evaluating Turn 1 and Turn 2 repair without optimizer updates."""
    logger.info("Starting Phase N3 Two-Turn Sampling-Only Canary Run...")
    output_dir.mkdir(parents=True, exist_ok=True)
    records_dir = output_dir / "verifier_records"
    records_dir.mkdir(parents=True, exist_ok=True)

    tasks = load_tasks_from_dir(canary_dir)
    logger.info("Loaded %d canary tasks from %s", len(tasks), canary_dir)
    if len(tasks) == 0:
        raise ValueError(f"No canary tasks found in {canary_dir}")

    profile = get_model_profile("nemotron-3.5-lightning")
    tokenizer = profile.get_tokenizer()
    renderer = profile.get_renderer(tokenizer=tokenizer)
    executor = KernelExecutor(records_dir=records_dir)

    service = tinker.ServiceClient()
    logger.info("Connecting to Tinker Sampler: %s", sampler_checkpoint)
    sampler = service.create_sampling_client(sampler_checkpoint)

    all_results: List[Dict[str, Any]] = []
    t0 = time.time()

    turn1_passes = 0
    turn2_recoveries = 0
    total_rollouts = len(tasks) * group_size

    for task_idx, task in enumerate(tasks, start=1):
        task_id = task["task_id"]
        cat = task.get("application_category", "")
        diff = task.get("difficulty", "")
        logger.info("[%d/%d] Sampling canary task: %s (%s, %s)", task_idx, len(tasks), task_id, cat, diff)

        # Turn 1: Build synthesis prompt
        t1_messages = build_task_prompt(task)
        t1_input = renderer.build_generation_prompt(t1_messages)
        stop_seqs = renderer.get_stop_sequences()

        sample_params = tinker.SamplingParams(
            max_tokens=max_tokens,
            temperature=temperature,
            stop=stop_seqs,
        )

        sample_tasks = [
            sampler.sample_async(
                prompt=t1_input,
                num_samples=1,
                sampling_params=sample_params,
            )
            for _ in range(group_size)
        ]

        t1_responses = await asyncio.gather(*sample_tasks)

        for s_idx, resp in enumerate(t1_responses):
            seq = resp.sequences[0]
            t1_raw_text = renderer.tokenizer.decode(seq.tokens)
            rollout_id_t1 = f"canary_n3_{task_id}_s{s_idx}_t1"

            # Evaluate Turn 1 on VPS
            t1_ver = await executor.evaluate_candidate(
                task=task,
                raw_completion=t1_raw_text,
                rollout_id=rollout_id_t1,
            )
            t1_reward = compute_rlvr_reward(
                t1_ver.to_dict(),
                expected_fixture_count=task.get("expected_fixture_count"),
            )

            rollout_entry = {
                "task_id": task_id,
                "category": cat,
                "difficulty": diff,
                "sample_index": s_idx,
                "turn1_compile_pass": t1_ver.compile["pass"],
                "turn1_verifier_pass": t1_ver.verifier["pass"],
                "turn1_behavioral_pass": t1_ver.behavioral["pass"],
                "turn1_passed": t1_reward.is_functionally_correct,
                "turn1_stage": t1_reward.stage_reached,
                "pass_at_1": 1.0 if t1_reward.is_functionally_correct else 0.0,
                "solve_at_2": 1.0 if t1_reward.is_functionally_correct else 0.0,
                "recovered": False,
                "turn2_attempted": False,
            }

            if t1_reward.is_functionally_correct:
                turn1_passes += 1
                all_results.append(rollout_entry)
                continue

            # Turn 1 failed -> attempt Turn 2 repair
            rollout_entry["turn2_attempted"] = True
            diagnostic = t1_ver.diagnostic or "Verification failed"
            extracted_c1 = extract_c_source(t1_raw_text)

            reqs = task.get("requirements", [])
            reqs_formatted = "\n".join(f"- {r}" for r in reqs) if reqs else "- Return complete verifier-safe C code"
            repair_prompt = f"""Task ID: {task_id}
Category: {cat}
Difficulty: {diff}

Original Instruction:
{task.get("instruction", "")}

Technical Requirements:
{reqs_formatted}

Previous Implementation:
```c
{extracted_c1.strip()}
```

Diagnostic Output:
```text
{diagnostic.strip()}
```

Please provide the corrected, complete, and self-contained C source code for this XDP program."""

            t2_messages = [
                {"role": "system", "content": REPAIR_SYSTEM_PROMPT},
                {"role": "user", "content": repair_prompt},
            ]
            t2_input = renderer.build_generation_prompt(t2_messages)

            t2_resp = await sampler.sample_async(
                prompt=t2_input,
                num_samples=1,
                sampling_params=sample_params,
            )
            t2_raw_text = renderer.tokenizer.decode(t2_resp.sequences[0].tokens)
            rollout_id_t2 = f"canary_n3_{task_id}_s{s_idx}_t2"

            t2_ver = await executor.evaluate_candidate(
                task=task,
                raw_completion=t2_raw_text,
                rollout_id=rollout_id_t2,
            )
            t2_reward = compute_rlvr_reward(
                t2_ver.to_dict(),
                expected_fixture_count=task.get("expected_fixture_count"),
            )

            rollout_entry["turn2_compile_pass"] = t2_ver.compile["pass"]
            rollout_entry["turn2_verifier_pass"] = t2_ver.verifier["pass"]
            rollout_entry["turn2_behavioral_pass"] = t2_ver.behavioral["pass"]
            rollout_entry["turn2_passed"] = t2_reward.is_functionally_correct
            rollout_entry["turn2_stage"] = t2_reward.stage_reached

            if t2_reward.is_functionally_correct:
                turn2_recoveries += 1
                rollout_entry["solve_at_2"] = 1.0
                rollout_entry["recovered"] = True

            all_results.append(rollout_entry)

    duration = round(time.time() - t0, 2)
    pass_at_1_rate = turn1_passes / total_rollouts if total_rollouts else 0.0
    solve_at_2_rate = (turn1_passes + turn2_recoveries) / total_rollouts if total_rollouts else 0.0

    summary = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "phase": "phase_n3_two_turn_sampling_canary",
        "sampler_checkpoint": sampler_checkpoint,
        "tasks_evaluated": len(tasks),
        "total_rollouts": total_rollouts,
        "turn1_passes": turn1_passes,
        "turn2_recoveries": turn2_recoveries,
        "pass_at_1_rate": round(pass_at_1_rate, 4),
        "solve_at_2_rate": round(solve_at_2_rate, 4),
        "recovery_gain": round(solve_at_2_rate - pass_at_1_rate, 4),
        "duration_seconds": duration,
        "rollouts": all_results,
    }

    summary_path = output_dir / "two_turn_sampling_canary_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    logger.info(
        "Two-Turn Sampling Canary complete: Pass@1=%.1f%%, Solve@2=%.1f%% (Recovery Gain: +%.1f%%) in %.1fs",
        pass_at_1_rate * 100, solve_at_2_rate * 100, (solve_at_2_rate - pass_at_1_rate) * 100, duration,
    )
    return summary


def build_tinker_rl_n3_config(
    cfg: BPFRLN3Config,
    mode: str = "pilot",
) -> rl_train.Config:
    """Builds official tinker_cookbook.rl.train.Config object for Phase N3."""
    max_steps = cfg.canary_max_steps if mode == "canary" else cfg.pilot_max_steps
    save_every = cfg.canary_save_every if mode == "canary" else cfg.pilot_save_every

    train_data_dir = cfg.canary_data_dir if mode == "canary" else cfg.train_data_dir
    sampler_state_path = f"{cfg.run_dir}/{mode}/sampler_state.json"

    dataset_builder = BPFRLDatasetBuilder(
        train_dir=train_data_dir,
        dev_dir=None,  # Dedicated eval runs via evaluate_n3_rl.py at T=0.0 per RL spec
        group_size=cfg.group_size,
        renderer_name=cfg.renderer_name,
        records_dir=f"{cfg.run_dir}/verifier_records",
        batch_size=cfg.problem_groups_per_step,
        use_priority_sampler=cfg.use_priority_sampler,
        sampler_seed=cfg.sampler_seed,
        sampler_state_path=sampler_state_path,
        two_turn=True,
        model_profile_name="nemotron-3.5-lightning",
    )

    kl_ref_config = KLReferenceConfig(
        base_model=cfg.base_model,
        load_checkpoint_path=cfg.kl_reference_checkpoint,
    )

    tinker_cfg = rl_train.Config(
        learning_rate=cfg.learning_rate,
        dataset_builder=dataset_builder,
        model_name=cfg.base_model,
        recipe_name=f"bpf_n3_two_turn_{mode}",
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
        compute_post_kl=cfg.compute_post_kl,
        remove_constant_reward_groups=cfg.remove_constant_reward_groups,
        max_steps=max_steps,
    )

    return tinker_cfg


def main():
    parser = argparse.ArgumentParser(description="BPF-Guardian Phase N3 Two-Turn RLVR Master Controller")
    parser.add_argument("--mode", choices=["sampling_only", "canary", "pilot"], default="sampling_only")
    parser.add_argument("--canary-dir", type=str, default=None)
    parser.add_argument("--train-dir", type=str, default=None)
    parser.add_argument("--dev-dir", type=str, default=None)
    parser.add_argument("--output-dir", type=str, default=None)
    parser.add_argument("--max-steps", type=int, default=None)
    parser.add_argument("--group-size", type=int, default=4)
    parser.add_argument("--temperature", type=float, default=0.8)
    parser.add_argument("--learning-rate", type=float, default=3e-6)
    parser.add_argument("--disable-priority-sampler", action="store_true", help="Disable priority sampler")
    parser.add_argument("--confirm-paid-run", action="store_true", help="Explicitly allow paid training run")
    args = parser.parse_args()

    cfg = BPFRLN3Config(
        canary_data_dir=args.canary_dir or str(DEFAULT_CANARY_DIR_N3),
        train_data_dir=args.train_dir or str(DEFAULT_TRAIN_DIR_N3),
        dev_data_dir=args.dev_dir or str(DEFAULT_DEV_DIR_N3),
        run_dir=args.output_dir or str(DEFAULT_RUN_DIR_N3),
        group_size=args.group_size,
        sampling_temperature=args.temperature,
        learning_rate=args.learning_rate,
        use_priority_sampler=not args.disable_priority_sampler,
    )

    output_dir = Path(cfg.run_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    if args.mode == "sampling_only":
        summary = asyncio.run(
            run_two_turn_sampling_canary(
                canary_dir=Path(cfg.canary_data_dir),
                output_dir=output_dir / "canary_sampling",
                sampler_checkpoint=cfg.kl_reference_checkpoint,
                group_size=cfg.group_size,
                temperature=cfg.sampling_temperature,
            )
        )
        print("Two-Turn Sampling Canary completed successfully. Results saved to:", output_dir / "canary_sampling")
        return

    # Install outcome feedback hook
    if cfg.use_priority_sampler:
        install_n3_sampler_feedback_hook()

    # Preflight check for paid run
    if not args.confirm_paid_run:
        logger.warning("[!] --confirm-paid-run not specified. Exiting before launching training steps.")
        print("Preflight check passed. To launch paid training run, pass --confirm-paid-run.")
        return

    if args.max_steps:
        if args.mode == "canary":
            cfg.canary_max_steps = args.max_steps
        else:
            cfg.pilot_max_steps = args.max_steps

    tinker_cfg = build_tinker_rl_n3_config(cfg, mode=args.mode)
    logger.info(
        "Launching Phase N3 RL training mode '%s' (max_steps=%d, lr=%s, priority_sampler=%s)...",
        args.mode, tinker_cfg.max_steps, cfg.learning_rate, cfg.use_priority_sampler,
    )
    asyncio.run(rl_train.main(tinker_cfg))


if __name__ == "__main__":
    main()
