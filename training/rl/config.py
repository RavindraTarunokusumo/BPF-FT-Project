"""
BPF-Guardian RLVR Phase 1 Configuration
Defines hyperparameters, runtime paths, and Tinker RL training loop parameters.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Any, Dict, Optional

# Default Checkpoints & Models
DEFAULT_BASE_MODEL = "Qwen/Qwen3-8B"
DEFAULT_RENDERER_NAME = "qwen3_disable_thinking"
SFT_V2_CHECKPOINT = "tinker://9461002d-2321-5858-8184-5604f9304283:train:0/weights/final"
SFT_V2_SAMPLER_CHECKPOINT = "tinker://9461002d-2321-5858-8184-5604f9304283:train:0/sampler_weights/final"

# Default Paths
DEFAULT_RUN_DIR = Path("runs/tinker/qwen3-8b-bpf-rl-v1")
DEFAULT_CANARY_DIR = Path("data/rl/v1/canary")
DEFAULT_TRAIN_DIR = Path("data/rl/v1/train")
DEFAULT_DEV_DIR = Path("data/rl/v1/dev")


@dataclasses.dataclass
class BPFRLConfig:
    # Model and Weights
    base_model: str = DEFAULT_BASE_MODEL
    load_checkpoint_path: str = SFT_V2_CHECKPOINT
    kl_reference_checkpoint: str = SFT_V2_SAMPLER_CHECKPOINT
    renderer_name: str = DEFAULT_RENDERER_NAME

    # LoRA and Sampling
    lora_rank: int = 32
    group_size: int = 4
    sampling_temperature: float = 0.8
    max_tokens: int = 2048

    # Optimization
    learning_rate: float = 5e-6
    loss_fn: str = "importance_sampling"
    kl_penalty_coef: float = 0.05
    remove_constant_reward_groups: bool = True
    problem_groups_per_step: int = 2

    # Verification Harness
    concurrent_verifications: int = 2
    compile_timeout_seconds: int = 30
    verifier_timeout_seconds: int = 30
    packet_timeout_seconds: int = 10

    # Steps and Schedules
    canary_max_steps: int = 5
    canary_save_every: int = 1
    pilot_max_steps: int = 50
    pilot_save_every: int = 5
    pilot_eval_every: int = 5

    # Directory Paths
    run_dir: str = str(DEFAULT_RUN_DIR).replace("\\", "/")
    canary_data_dir: str = str(DEFAULT_CANARY_DIR).replace("\\", "/")
    train_data_dir: str = str(DEFAULT_TRAIN_DIR).replace("\\", "/")
    dev_data_dir: str = str(DEFAULT_DEV_DIR).replace("\\", "/")

    # Wandb (optional)
    wandb_project: Optional[str] = "bpf-guardian-rlvr"
    wandb_run_name: Optional[str] = "qwen3-8b-rl-v1"

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)
