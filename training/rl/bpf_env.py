"""
BPF-Guardian RLVR Phase 1: Tinker Environment Implementation
Implements single-turn async BPFEnv and BPFEnvGroupBuilder using official Tinker RL abstractions:
RLDataset -> EnvGroupBuilder -> async Env -> grouped rollouts -> VPS empirical reward -> StepResult
"""

from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import json
import logging
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

import tinker
from tinker_cookbook import renderers
from tinker_cookbook.renderers import get_renderer
from tinker_cookbook.rl.types import (
    Action,
    ActionExtra,
    Env,
    EnvGroupBuilder,
    InitialObservationOverflow,
    Logs,
    Metrics,
    Observation,
    StepResult,
    StopCondition,
)

from training.rl.kernel_executor import KernelExecutor, check_output_compliance, extract_c_source
from training.rl.reward import InfrastructureRewardError, compute_rlvr_reward

logger = logging.getLogger("bpf_guardian_rl.env")

SYNTHESIS_SYSTEM_PROMPT = """You are an expert Linux kernel eBPF and XDP systems programmer.
Write complete, self-contained, compilation-ready, and verifier-safe C source code for Linux XDP programs."""

REPAIR_SYSTEM_PROMPT = """You are an expert Linux kernel eBPF and XDP systems programmer.
You are fixing an XDP program that produced diagnostic errors during evaluation."""


def build_task_prompt(task: Dict[str, Any]) -> List[Dict[str, str]]:
    task_id = task.get("task_id", "bpf_prog")
    category = task.get("application_category", "packet_filtering_security")
    difficulty = task.get("difficulty", "level_1")
    reqs = task.get("requirements", [])

    if task.get("learning_mode") == "repair" or "faulty_c" in task or "diagnostic" in task:
        instruction = task.get("instruction", f"Fix the XDP program for task {task_id}")
        reqs_formatted = "\n".join(f"- {r}" for r in reqs) if reqs else "- Return complete verifier-safe C code"
        faulty_c = task.get("faulty_c", "// Faulty code")
        diagnostic = task.get("diagnostic", "Verifier failure")
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

    # Synthesis mode
    instruction = task.get("instruction", f"Write an XDP program for task {task_id}")
    reqs_str = "\n".join(f"- {r}" for r in reqs)

    # For benchmark and calibration suites, match the original SFT v2 evaluation prompt exactly
    if task.get("split") in ("benchmark", "calibration"):
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
{instruction}

Detailed Technical Requirements:
{reqs_str}

Write the complete C source code for this XDP program. Complete, self-contained XDP C source only. No Markdown fences, prose, or thinking blocks."""

    return [
        {"role": "system", "content": SYNTHESIS_SYSTEM_PROMPT},
        {"role": "user", "content": user_content},
    ]


class BPFEnv(Env):
    """Single-turn RL environment evaluating an XDP synthesis candidate against the kernel harness."""

    def __init__(
        self,
        task: Dict[str, Any],
        renderer: Any,
        executor: KernelExecutor,
        group_index: int = 0,
        sample_index: int = 0,
    ):
        self.task = task
        self.task_id = task.get("task_id", "unknown_task")
        self.renderer = renderer
        self.executor = executor
        self.group_index = group_index
        self.sample_index = sample_index

    async def initial_observation(
        self,
    ) -> tuple[Observation, StopCondition] | InitialObservationOverflow:
        messages = build_task_prompt(self.task)
        model_input = self.renderer.build_generation_prompt(messages)
        stop_condition = self.renderer.get_stop_sequences()
        return model_input, stop_condition

    async def step(self, action: Action, *, extra: ActionExtra | None = None) -> StepResult:
        # Decode tokens to completion text
        tokenizer = self.renderer.tokenizer
        completion = tokenizer.decode(action)

        rollout_id = f"rl_{self.task_id}_g{self.group_index}_s{self.sample_index}_{uuid.uuid4().hex[:8]}"

        # Evaluate candidate empirically in kernel harness
        verification = await self.executor.evaluate_candidate(
            task=self.task,
            raw_completion=completion,
            rollout_id=rollout_id,
        )

        # Fail-closed handling for infrastructure errors
        if verification.infrastructure_error:
            msg = verification.error_message or "Infrastructure error during verification"
            logger.error("Infrastructure error in rollout %s: %s", rollout_id, msg)
            raise RuntimeError(f"INFRASTRUCTURE_ERROR: {msg}")

        # Compute bounded RLVR reward
        expected_fixtures = self.task.get("expected_fixture_count")
        try:
            reward_breakdown = compute_rlvr_reward(
                verification.to_dict(),
                expected_fixture_count=expected_fixtures,
            )
        except InfrastructureRewardError as e:
            logger.error("Infrastructure reward error in rollout %s: %s", rollout_id, e)
            raise RuntimeError(f"INFRASTRUCTURE_ERROR: {e}") from e

        metrics: Metrics = {
            "reward/total": float(reward_breakdown.total_reward),
            "reward/compliance": float(reward_breakdown.compliance_reward),
            "reward/compile": float(reward_breakdown.compile_reward),
            "reward/verifier": float(reward_breakdown.verifier_reward),
            "reward/fixture": float(reward_breakdown.fixture_reward),
            "reward/bonus": float(reward_breakdown.complete_bonus),
            "pass/functional": 1.0 if reward_breakdown.is_functionally_correct else 0.0,
            "pass/compile": 1.0 if verification.compile.get("pass", False) else 0.0,
            "pass/verifier": 1.0 if verification.verifier.get("pass", False) else 0.0,
            "pass/behavioral": 1.0 if verification.behavioral.get("pass", False) else 0.0,
        }

        logs: Logs = {
            "task_id": self.task_id,
            "rollout_id": rollout_id,
            "stage_reached": reward_breakdown.stage_reached,
            "total_reward": reward_breakdown.total_reward,
            "raw_log_path": verification.raw_log_path,
        }

        empty_obs = tinker.ModelInput.from_ints([])
        return StepResult(
            reward=reward_breakdown.total_reward,
            episode_done=True,
            next_observation=empty_obs,
            next_stop_condition=[],
            metrics=metrics,
            logs=logs,
        )


class BPFEnvGroupBuilder(EnvGroupBuilder):
    """Builds a group of independent environments for the same task to support group-relative advantages."""

    def __init__(
        self,
        task: Dict[str, Any],
        group_size: int = 4,
        renderer_name: str = "qwen3_disable_thinking",
        records_dir: str = "runs/tinker/qwen3-8b-bpf-rl-v1/verifier_records",
        group_index: int = 0,
        sampler: Optional[Any] = None,
        sampler_state_path: Optional[str] = None,
        task_sampling_prob: float = 0.0,
    ):
        self.task = task
        self.group_size = group_size
        self.renderer_name = renderer_name
        self.records_dir = records_dir
        self.group_index = group_index
        self.sampler = sampler
        self.sampler_state_path = sampler_state_path
        self.task_sampling_prob = task_sampling_prob

    async def make_envs(self) -> Sequence[Env]:
        from tinker_cookbook.tokenizer_utils import get_tokenizer
        tokenizer = get_tokenizer("Qwen/Qwen3-8B")
        renderer = get_renderer(self.renderer_name, tokenizer=tokenizer)
        executor = KernelExecutor(records_dir=Path(self.records_dir))
        return [
            BPFEnv(
                task=self.task,
                renderer=renderer,
                executor=executor,
                group_index=self.group_index,
                sample_index=i,
            )
            for i in range(self.group_size)
        ]

    def logging_tags(self) -> list[str]:
        cat = self.task.get("application_category", "general")
        diff = self.task.get("difficulty", "level_1")
        return [cat, diff, "rlvr", self.task.get("task_id", "")]
