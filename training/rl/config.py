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

# Default Paths (Phase 1)
DEFAULT_RUN_DIR = Path("runs/tinker/qwen3-8b-bpf-rl-v1")
DEFAULT_CANARY_DIR = Path("data/rl/v1/canary")
DEFAULT_TRAIN_DIR = Path("data/rl/v1/train")
DEFAULT_DEV_DIR = Path("data/rl/v1/dev")

# Default Paths (Phase 2)
DEFAULT_RUN_DIR_V2 = Path("runs/tinker/qwen3-8b-bpf-rl-v2")
DEFAULT_CANARY_DIR_V2 = Path("data/rl/v2/canary")
DEFAULT_TRAIN_DIR_V2 = Path("data/rl/v2/train")
DEFAULT_DEV_DIR_V2 = Path("data/rl/v2/dev")
DEFAULT_CONFIRMATION_DIR_V2 = Path("data/rl/v2/confirmation")


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
    lr_schedule_type: str = "constant"
    loss_fn: str = "importance_sampling"
    kl_penalty_coef: float = 0.05
    compute_post_kl: bool = False
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
    early_stopping_patience: int = 3

    # Sampler settings
    use_priority_sampler: bool = False
    sampler_seed: int = 42

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


@dataclasses.dataclass
class BPFRLV2Config(BPFRLConfig):
    """Phase 2 Controlled Generalization Experiment Configuration."""

    learning_rate: float = 3e-6
    lr_schedule_type: str = "constant"  # Constant scalar learning rate (no scheduler supported in Tinker API)
    compute_post_kl: bool = True
    pilot_max_steps: int = 60
    pilot_save_every: int = 5
    pilot_eval_every: int = 5
    early_stopping_patience: int = 3
    use_priority_sampler: bool = True
    sampler_seed: int = 42

    # Phase 2 Paths
    run_dir: str = str(DEFAULT_RUN_DIR_V2).replace("\\", "/")
    canary_data_dir: str = str(DEFAULT_CANARY_DIR_V2).replace("\\", "/")
    train_data_dir: str = str(DEFAULT_TRAIN_DIR_V2).replace("\\", "/")
    dev_data_dir: str = str(DEFAULT_DEV_DIR_V2).replace("\\", "/")
    confirmation_data_dir: str = str(DEFAULT_CONFIRMATION_DIR_V2).replace("\\", "/")

    # Wandb
    wandb_run_name: Optional[str] = "qwen3-8b-rl-v2"
