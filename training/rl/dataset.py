"""
BPF-Guardian RLVR Phase 1: RL Dataset and DatasetBuilder
Loads and batches RL tasks into Tinker EnvGroupBuilder batches with strict benchmark isolation.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set

import chz
from tinker_cookbook.rl.types import EnvGroupBuilder, RLDataset, RLDatasetBuilder

from training.rl.bpf_env import BPFEnvGroupBuilder
from training.rl.config import DEFAULT_RENDERER_NAME
from training.rl.sampler import BPFPrioritySampler

logger = logging.getLogger("bpf_guardian_rl.dataset")

PROTECTED_INDEX_PATHS = [
    Path("data/calibration/index.jsonl"),
    Path("data/benchmark/synthesis/index.jsonl"),
    Path("data/benchmark/repair/index.jsonl"),
]


def load_protected_task_ids() -> Set[str]:
    """Loads all protected benchmark task IDs to prevent benchmark contamination."""
    protected: Set[str] = set()
    for p in PROTECTED_INDEX_PATHS:
        if p.is_file():
            for line in p.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line:
                    entry = json.loads(line)
                    protected.add(entry["task_id"])
    return protected


def load_tasks_from_dir(tasks_dir: Path) -> List[Dict[str, Any]]:
    """Loads task definitions from an RL dataset directory (index.jsonl or task.json files)."""
    tasks: List[Dict[str, Any]] = []
    index_file = tasks_dir / "index.jsonl"

    if index_file.is_file():
        for line in index_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                task_spec = json.loads(line)
                # Check for detailed task.json or tests.json if separate
                task_id = task_spec["task_id"]
                cat = task_spec.get("application_category", "")
                diff = task_spec.get("difficulty", "")
                task_json = tasks_dir / cat / diff / task_id / "task.json"
                tests_json = tasks_dir / cat / diff / task_id / "tests.json"

                if task_json.is_file():
                    loaded_task = json.loads(task_json.read_text(encoding="utf-8"))
                    task_spec.update(loaded_task)
                if tests_json.is_file():
                    tests_data = json.loads(tests_json.read_text(encoding="utf-8"))
                    task_spec["tests"] = tests_data.get("tests") or tests_data.get("test_cases", [])

                faulty_file = tasks_dir / cat / diff / task_id / "faulty.c"
                diag_file = tasks_dir / cat / diff / task_id / "diagnostic.txt"
                if faulty_file.is_file():
                    task_spec["faulty_c"] = faulty_file.read_text(encoding="utf-8")
                if diag_file.is_file():
                    task_spec["diagnostic"] = diag_file.read_text(encoding="utf-8")

                tasks.append(task_spec)
    else:
        # Scan for task.json files directly
        for task_json in tasks_dir.glob("*/*/*/task.json"):
            loaded_task = json.loads(task_json.read_text(encoding="utf-8"))
            tests_json = task_json.parent / "tests.json"
            if tests_json.is_file():
                tests_data = json.loads(tests_json.read_text(encoding="utf-8"))
                loaded_task["tests"] = tests_data.get("tests") or tests_data.get("test_cases", [])
            faulty_file = task_json.parent / "faulty.c"
            diag_file = task_json.parent / "diagnostic.txt"
            if faulty_file.is_file():
                loaded_task["faulty_c"] = faulty_file.read_text(encoding="utf-8")
            if diag_file.is_file():
                loaded_task["diagnostic"] = diag_file.read_text(encoding="utf-8")
            tasks.append(loaded_task)

    return tasks


class BPFRLDataset(RLDataset):
    """Dataset producing batches of BPFEnvGroupBuilder instances."""

    def __init__(
        self,
        tasks: List[Dict[str, Any]],
        group_size: int = 4,
        renderer_name: str = DEFAULT_RENDERER_NAME,
        records_dir: str = "runs/tinker/qwen3-8b-bpf-rl-v1/verifier_records",
        batch_size: int = 2,
        sampler: Optional[BPFPrioritySampler] = None,
        sampler_state_path: Optional[str] = None,
    ):
        self.tasks = tasks
        self.group_size = group_size
        self.renderer_name = renderer_name
        self.records_dir = records_dir
        self.batch_size = max(1, batch_size)
        self.sampler = sampler
        self.sampler_state_path = sampler_state_path

    def get_batch(self, index: int) -> Sequence[EnvGroupBuilder]:
        n = len(self.tasks)
        if n == 0:
            return []

        if self.sampler is not None:
            sampled_items = self.sampler.sample_batch(self.batch_size)
            batch_tasks = [task for task, _prob in sampled_items]
            batch_probs = [prob for _task, prob in sampled_items]
        else:
            batch_tasks = [self.tasks[(index * self.batch_size + i) % n] for i in range(self.batch_size)]
            batch_probs = [1.0 / n] * len(batch_tasks)

        return [
            BPFEnvGroupBuilder(
                task=task,
                group_size=self.group_size,
                renderer_name=self.renderer_name,
                records_dir=self.records_dir,
                group_index=index * self.batch_size + i,
                sampler=self.sampler,
                sampler_state_path=self.sampler_state_path,
                task_sampling_prob=batch_probs[i],
            )
            for i, task in enumerate(batch_tasks)
        ]

    def __len__(self) -> int:
        return 1000000  # Supports arbitrary max_steps without truncating at 1 epoch


@chz.chz
class BPFRLDatasetBuilder(RLDatasetBuilder):
    """Builder for constructing BPF RL training and optional test/dev datasets."""

    train_dir: str = "data/rl/v1/train"
    dev_dir: str | None = "data/rl/v1/dev"
    group_size: int = 4
    renderer_name: str = DEFAULT_RENDERER_NAME
    records_dir: str = "runs/tinker/qwen3-8b-bpf-rl-v1/verifier_records"
    batch_size: int = 2
    use_priority_sampler: bool = True
    sampler_seed: int = 42
    sampler_state_path: str | None = None

    async def __call__(self) -> tuple[RLDataset, RLDataset | None]:
        train_path = Path(self.train_dir)
        if not train_path.exists():
            raise FileNotFoundError(f"RL train dataset directory not found: {self.train_dir}")

        train_tasks = load_tasks_from_dir(train_path)
        protected_ids = load_protected_task_ids()

        # Strict fail-closed isolation check
        for t in train_tasks:
            tid = t.get("task_id", "")
            if tid in protected_ids:
                raise ValueError(
                    f"CRITICAL: Protected benchmark task '{tid}' found in RL training set! "
                    "RL datasets must be strictly disjoint from evaluation benchmarks."
                )

        sampler: Optional[BPFPrioritySampler] = None
        if self.use_priority_sampler:
            if self.sampler_state_path and Path(self.sampler_state_path).is_file():
                sampler = BPFPrioritySampler.load_state(Path(self.sampler_state_path), tasks=train_tasks)
                logger.info(
                    "Resumed BPFPrioritySampler from %s (step %d) on %d training tasks",
                    self.sampler_state_path, sampler.step, len(train_tasks)
                )
            else:
                sampler = BPFPrioritySampler(tasks=train_tasks, seed=self.sampler_seed)
                logger.info(
                    "Initialized BPFPrioritySampler (seed=%d) with %d training tasks across 12 cells",
                    self.sampler_seed, len(train_tasks)
                )

        train_dataset = BPFRLDataset(
            tasks=train_tasks,
            group_size=self.group_size,
            renderer_name=self.renderer_name,
            records_dir=self.records_dir,
            batch_size=self.batch_size,
            sampler=sampler,
            sampler_state_path=self.sampler_state_path,
        )

        dev_dataset: Optional[RLDataset] = None
        if self.dev_dir:
            dev_path = Path(self.dev_dir)
            if dev_path.exists():
                dev_tasks = load_tasks_from_dir(dev_path)
                for t in dev_tasks:
                    tid = t.get("task_id", "")
                    if tid in protected_ids:
                        raise ValueError(
                            f"CRITICAL: Protected benchmark task '{tid}' found in RL dev set!"
                        )

                # Ensure train and dev are disjoint
                train_ids = {t["task_id"] for t in train_tasks}
                dev_ids = {t["task_id"] for t in dev_tasks}
                overlap = train_ids & dev_ids
                if overlap:
                    raise ValueError(f"Train and dev task sets overlap: {overlap}")

                # Dev dataset NEVER consumes priority sampler; evaluates sequentially at T=0.0
                dev_dataset = BPFRLDataset(
                    tasks=dev_tasks,
                    group_size=1,  # Dev evaluation uses single sample per task at T=0.0
                    renderer_name=self.renderer_name,
                    records_dir=self.records_dir,
                    batch_size=self.batch_size,
                    sampler=None,
                    sampler_state_path=None,
                )

        return train_dataset, dev_dataset
