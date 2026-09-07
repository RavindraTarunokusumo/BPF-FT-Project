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

from training.rl.config import DEFAULT_RENDERER_NAME
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
        renderer_name: str = DEFAULT_RENDERER_NAME,
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


class TwoTurnBPFEnv(Env):
    """Two-turn interactive RL environment for diagnostic-guided repair:
    Turn 1: Model generates initial XDP synthesis candidate.
    Harness evaluates candidate empirically on Linux VPS.
    - If passed: episode finishes with full reward (Pass@1=1, Solve@2=1).
    - If failed: environment injects standardized compiler, verifier, or fixture diagnostic.
    Turn 2: Model generates repaired C code.
    Harness evaluates repaired candidate independently on Linux VPS.
    - If passed: episode finishes with recovery reward (Pass@1=0, Solve@2=1, Recovered=1).
    - If failed: episode finishes with partial bounded credit (Pass@1=0, Solve@2=0).
    """

    def __init__(
        self,
        task: Dict[str, Any],
        renderer: Any,
        executor: KernelExecutor,
        group_index: int = 0,
        sample_index: int = 0,
        turn1_success_reward: float = 1.00,
        turn2_recovery_reward: float = 0.95,
    ):
        self.task = task
        self.task_id = task.get("task_id", "unknown_task")
        self.renderer = renderer
        self.executor = executor
        self.group_index = group_index
        self.sample_index = sample_index
        self.turn1_success_reward = turn1_success_reward
        self.turn2_recovery_reward = turn2_recovery_reward

        # Episode state
        self.turn: int = 1
        self.turn1_completion: str = ""
        self.turn1_reward_breakdown: Optional[Any] = None
        self.turn1_verification: Optional[Any] = None
        self.initial_messages: List[Dict[str, str]] = []

    async def initial_observation(
        self,
    ) -> tuple[Observation, StopCondition] | InitialObservationOverflow:
        self.turn = 1
        self.initial_messages = build_task_prompt(self.task)
        model_input = self.renderer.build_generation_prompt(self.initial_messages)
        stop_condition = self.renderer.get_stop_sequences()
        return model_input, stop_condition

    async def step(self, action: Action, *, extra: ActionExtra | None = None) -> StepResult:
        tokenizer = self.renderer.tokenizer
        completion = tokenizer.decode(action)

        if self.turn == 1:
            self.turn1_completion = completion
            rollout_id = f"rl_{self.task_id}_g{self.group_index}_s{self.sample_index}_t1_{uuid.uuid4().hex[:6]}"

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

            expected_fixtures = self.task.get("expected_fixture_count")
            try:
                reward_breakdown = compute_rlvr_reward(
                    verification.to_dict(),
                    expected_fixture_count=expected_fixtures,
                )
            except InfrastructureRewardError as e:
                logger.error("Infrastructure reward error in rollout %s: %s", rollout_id, e)
                raise RuntimeError(f"INFRASTRUCTURE_ERROR: {e}") from e

            self.turn1_verification = verification
            self.turn1_reward_breakdown = reward_breakdown

            if reward_breakdown.is_functionally_correct:
                # Solved on Turn 1!
                metrics: Metrics = {
                    "reward/total": float(self.turn1_success_reward),
                    "pass/pass_at_1": 1.0,
                    "pass/solve_at_2": 1.0,
                    "pass/recovered": 0.0,
                    "turn_1/compile_pass": 1.0,
                    "turn_1/verifier_pass": 1.0,
                    "turn_1/behavioral_pass": 1.0,
                    "turn_2/attempted": 0.0,
                }
                logs: Logs = {
                    "task_id": self.task_id,
                    "rollout_id": rollout_id,
                    "outcome": "turn1_pass",
                    "stage_reached": reward_breakdown.stage_reached,
                    "total_reward": self.turn1_success_reward,
                }
                empty_obs = tinker.ModelInput.from_ints([])
                return StepResult(
                    reward=self.turn1_success_reward,
                    episode_done=True,
                    next_observation=empty_obs,
                    next_stop_condition=[],
                    metrics=metrics,
                    logs=logs,
                )

            # Turn 1 failed -> transition to Turn 2 with empirical diagnostic
            self.turn = 2
            diagnostic = verification.diagnostic or "Verification failed."
            if len(diagnostic) > 4000:
                diagnostic = "...[truncated]...\n" + diagnostic[-4000:]
            extracted_c = extract_c_source(completion)

            task_id = self.task.get("task_id", "bpf_prog")
            category = self.task.get("application_category", "packet_filtering_security")
            difficulty = self.task.get("difficulty", "level_1")
            instruction = self.task.get("instruction", f"Fix the XDP program for task {task_id}")
            reqs = self.task.get("requirements", [])
            reqs_formatted = "\n".join(f"- {r}" for r in reqs) if reqs else "- Return complete verifier-safe C code"

            repair_user_content = f"""Task ID: {task_id}
Category: {category}
Difficulty: {difficulty}

Original Instruction:
{instruction}

Technical Requirements:
{reqs_formatted}

Previous Implementation:
```c
{extracted_c.strip()}
```

Diagnostic Output:
```text
{diagnostic.strip()}
```

Please provide the corrected, complete, and self-contained C source code for this XDP program."""

            repair_messages = [
                {"role": "system", "content": REPAIR_SYSTEM_PROMPT},
                {"role": "user", "content": repair_user_content},
            ]

            next_obs = self.renderer.build_generation_prompt(repair_messages)
            next_stop = self.renderer.get_stop_sequences()

            turn1_stage = reward_breakdown.stage_reached
            metrics = {
                "reward/total": 0.0,
                "pass/pass_at_1": 0.0,
                "pass/solve_at_2": 0.0,
                "pass/recovered": 0.0,
                "turn_1/compile_pass": 1.0 if verification.compile.get("pass", False) else 0.0,
                "turn_1/verifier_pass": 1.0 if verification.verifier.get("pass", False) else 0.0,
                "turn_1/behavioral_pass": 1.0 if verification.behavioral.get("pass", False) else 0.0,
                "turn_2/attempted": 1.0,
            }
            logs = {
                "task_id": self.task_id,
                "rollout_id": rollout_id,
                "outcome": "turn1_fail_transition_to_turn2",
                "turn1_stage": turn1_stage,
                "turn1_diagnostic": diagnostic[:200],
            }
            return StepResult(
                reward=0.0,
                episode_done=False,
                next_observation=next_obs,
                next_stop_condition=next_stop,
                metrics=metrics,
                logs=logs,
            )

        # Turn 2: evaluate repair
        rollout_id = f"rl_{self.task_id}_g{self.group_index}_s{self.sample_index}_t2_{uuid.uuid4().hex[:6]}"
        verification = await self.executor.evaluate_candidate(
            task=self.task,
            raw_completion=completion,
            rollout_id=rollout_id,
        )

        if verification.infrastructure_error:
            msg = verification.error_message or "Infrastructure error during verification"
            logger.error("Infrastructure error in rollout %s: %s", rollout_id, msg)
            raise RuntimeError(f"INFRASTRUCTURE_ERROR: {msg}")

        expected_fixtures = self.task.get("expected_fixture_count")
        try:
            reward_breakdown = compute_rlvr_reward(
                verification.to_dict(),
                expected_fixture_count=expected_fixtures,
            )
        except InfrastructureRewardError as e:
            logger.error("Infrastructure reward error in rollout %s: %s", rollout_id, e)
            raise RuntimeError(f"INFRASTRUCTURE_ERROR: {e}") from e

        turn1_stage = self.turn1_reward_breakdown.stage_reached if self.turn1_reward_breakdown else "unknown"
        recovered = reward_breakdown.is_functionally_correct

        if recovered:
            step_reward = self.turn2_recovery_reward
        else:
            step_reward = min(0.20, reward_breakdown.total_reward * 0.20)

        # Check recovery by stage
        rec_compile = 1.0 if (turn1_stage in ("compliance", "non_compliant") and recovered) else 0.0
        rec_verifier = 1.0 if (turn1_stage == "compile" and recovered) else 0.0
        rec_behavioral = 1.0 if (turn1_stage in ("verifier", "behavioral") and recovered) else 0.0

        metrics = {
            "reward/total": float(step_reward),
            "pass/pass_at_1": 0.0,
            "pass/solve_at_2": 1.0 if recovered else 0.0,
            "pass/recovered": 1.0 if recovered else 0.0,
            "turn_2/compile_pass": 1.0 if verification.compile.get("pass", False) else 0.0,
            "turn_2/verifier_pass": 1.0 if verification.verifier.get("pass", False) else 0.0,
            "turn_2/behavioral_pass": 1.0 if verification.behavioral.get("pass", False) else 0.0,
            "recovery/from_compile_failure": rec_compile,
            "recovery/from_verifier_failure": rec_verifier,
            "recovery/from_behavioral_failure": rec_behavioral,
        }
        logs = {
            "task_id": self.task_id,
            "rollout_id": rollout_id,
            "outcome": "turn2_recovery" if recovered else "turn2_fail",
            "turn1_stage": turn1_stage,
            "turn2_stage": reward_breakdown.stage_reached,
            "total_reward": step_reward,
        }
        empty_obs = tinker.ModelInput.from_ints([])
        return StepResult(
            reward=step_reward,
            episode_done=True,
            next_observation=empty_obs,
            next_stop_condition=[],
            metrics=metrics,
            logs=logs,
        )


class TwoTurnBPFEnvGroupBuilder(EnvGroupBuilder):
    """Builds a group of independent TwoTurnBPFEnv instances for the same task."""

    def __init__(
        self,
        task: Dict[str, Any],
        group_size: int = 4,
        model_profile_name: str = "nemotron-3.5-lightning",
        renderer_name: Optional[str] = None,
        records_dir: str = "runs/tinker/nemotron-bpf-rl-n3/verifier_records",
        group_index: int = 0,
        sampler: Optional[Any] = None,
        sampler_state_path: Optional[str] = None,
        task_sampling_prob: float = 0.0,
        turn1_success_reward: float = 1.00,
        turn2_recovery_reward: float = 0.95,
    ):
        self.task = task
        self.group_size = group_size
        self.model_profile_name = model_profile_name
        self.renderer_name = renderer_name
        self.records_dir = records_dir
        self.group_index = group_index
        self.sampler = sampler
        self.sampler_state_path = sampler_state_path
        self.task_sampling_prob = task_sampling_prob
        self.turn1_success_reward = turn1_success_reward
        self.turn2_recovery_reward = turn2_recovery_reward

    async def make_envs(self) -> Sequence[Env]:
        from training.model_profiles import get_model_profile
        profile = get_model_profile(self.model_profile_name)
        tokenizer = profile.get_tokenizer()
        renderer = profile.get_renderer(tokenizer=tokenizer)
        executor = KernelExecutor(records_dir=Path(self.records_dir))
        return [
            TwoTurnBPFEnv(
                task=self.task,
                renderer=renderer,
                executor=executor,
                group_index=self.group_index,
                sample_index=i,
                turn1_success_reward=self.turn1_success_reward,
                turn2_recovery_reward=self.turn2_recovery_reward,
            )
            for i in range(self.group_size)
        ]

    def logging_tags(self) -> list[str]:
        cat = self.task.get("application_category", "general")
        diff = self.task.get("difficulty", "level_1")
        return [cat, diff, "rlvr_two_turn", self.task.get("task_id", "")]

