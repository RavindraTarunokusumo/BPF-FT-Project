"""
BPF-Guardian RLVR Phase 2: Seeded Train-Only Priority Sampler
Implements difficulty-aware, category-balanced priority sampling for RL training:
1. Two-phase difficulty progression schedule (Steps 1-15: 25/40/35; Steps 16-60: 10/40/50)
2. Category balance floor (each category has equal base probability within difficulty)
3. Minimum exposure floor for all 12 category x difficulty cells
4. Train-only outcome tracking: rolling reward, full-pass rate, and mixed-group rate
5. Saturated task downweighting (>90% full-pass rate)
6. Exact deterministic resume serialization (sampler_state.json)
"""

from __future__ import annotations

import json
import logging
import math
import random
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

logger = logging.getLogger("bpf_guardian_rl.sampler")

CATEGORIES = [
    "packet_filtering_security",
    "network_routing_forwarding",
    "packet_inspection_telemetry",
    "protocol_transformation",
]

DIFFICULTIES = [
    "level_1",
    "level_2",
    "level_3",
]


class BPFPrioritySampler:
    """Seeded, difficulty-aware priority sampler for BPF RL training."""

    def __init__(
        self,
        tasks: List[Dict[str, Any]],
        seed: int = 42,
        min_task_prob_floor: float = 0.001,
        saturation_threshold: float = 0.90,
        saturation_penalty: float = 0.80,
        window_size: int = 10,
    ):
        self.tasks = tasks
        self.task_map: Dict[str, Dict[str, Any]] = {t["task_id"]: t for t in tasks}
        self.seed = seed
        self.rng = random.Random(seed)
        self.step = 0
        self.min_task_prob_floor = min_task_prob_floor
        self.saturation_threshold = saturation_threshold
        self.saturation_penalty = saturation_penalty
        self.window_size = window_size

        # Index tasks by (category, difficulty)
        self.cells: Dict[Tuple[str, str], List[str]] = {}
        self.task_to_cell: Dict[str, Tuple[str, str]] = {}
        for cat in CATEGORIES:
            for diff in DIFFICULTIES:
                self.cells[(cat, diff)] = []

        for t in self.tasks:
            tid = t["task_id"]
            cat = t.get("application_category", "packet_filtering_security")
            diff = t.get("difficulty", "level_1")
            key = (cat, diff)
            if key not in self.cells:
                self.cells[key] = []
            self.cells[key].append(tid)
            self.task_to_cell[tid] = key

        # Exposure tracking
        self.task_exposure_counts: Dict[str, int] = {t["task_id"]: 0 for t in self.tasks}
        self.stratum_exposure_counts: Dict[str, int] = {d: 0 for d in DIFFICULTIES}
        self.category_exposure_counts: Dict[str, int] = {c: 0 for c in CATEGORIES}

        # Rolling history per task: list of (mean_reward, full_pass, is_constant)
        self.task_history: Dict[str, List[Dict[str, Any]]] = {t["task_id"]: [] for t in self.tasks}

        # Cached computed metrics
        self.rolling_task_reward: Dict[str, float] = {t["task_id"]: 0.0 for t in self.tasks}
        self.rolling_full_pass_rate: Dict[str, float] = {t["task_id"]: 0.0 for t in self.tasks}
        self.rolling_constant_group_rate: Dict[str, float] = {t["task_id"]: 0.0 for t in self.tasks}
        self.rolling_mixed_group_rate: Dict[str, float] = {t["task_id"]: 0.0 for t in self.tasks}

        # Latest computed weights
        self.current_weights: Dict[str, float] = {}
        self._update_weights()

    def get_difficulty_distribution(self, step: int) -> Dict[str, float]:
        """Returns the target difficulty distribution based on training step:
        - Steps 1-15:  Level 1: 25%, Level 2: 40%, Level 3: 35%
        - Steps 16-60: Level 1: 10%, Level 2: 40%, Level 3: 50%
        """
        if step <= 15:
            return {"level_1": 0.25, "level_2": 0.40, "level_3": 0.35}
        else:
            return {"level_1": 0.10, "level_2": 0.40, "level_3": 0.50}

    def update_outcome(
        self,
        task_id: str,
        rewards: Sequence[float],
        full_pass: bool,
        is_constant_group: bool,
    ) -> None:
        """Records outcome from a training rollout group.
        Strictly train-only: never call with dev, confirmation, or protected outcomes!
        """
        if task_id not in self.task_map:
            return

        mean_reward = float(sum(rewards) / len(rewards)) if rewards else 0.0
        record = {
            "mean_reward": mean_reward,
            "full_pass": bool(full_pass),
            "is_constant": bool(is_constant_group),
            "is_mixed": not bool(is_constant_group),
        }

        hist = self.task_history[task_id]
        hist.append(record)
        if len(hist) > self.window_size:
            hist.pop(0)

        # Update metrics
        n = len(hist)
        self.rolling_task_reward[task_id] = sum(r["mean_reward"] for r in hist) / n
        self.rolling_full_pass_rate[task_id] = sum(1.0 for r in hist if r["full_pass"]) / n
        self.rolling_constant_group_rate[task_id] = sum(1.0 for r in hist if r["is_constant"]) / n
        self.rolling_mixed_group_rate[task_id] = sum(1.0 for r in hist if r["is_mixed"]) / n

        # Update exposure
        self.task_exposure_counts[task_id] += 1
        cat, diff = self.task_to_cell[task_id]
        self.stratum_exposure_counts[diff] += 1
        self.category_exposure_counts[cat] += 1

        self._update_weights()

    def _update_weights(self) -> None:
        """Recalculates sampling probability for every task based on:
        1. Step difficulty progression
        2. Category balance floor (uniform categories within difficulty)
        3. Inverse full-pass rate downweighting for saturated tasks
        4. Boost for tasks with mixed-group learning signal
        5. Hard minimum exposure floor
        """
        diff_dist = self.get_difficulty_distribution(self.step)
        raw_weights: Dict[str, float] = {}

        for diff, diff_w in diff_dist.items():
            cat_w = diff_w / len(CATEGORIES)  # Equal balance across categories

            for cat in CATEGORIES:
                cell_tasks = self.cells.get((cat, diff), [])
                if not cell_tasks:
                    continue

                task_base_w = cat_w / len(cell_tasks)

                for tid in cell_tasks:
                    w = task_base_w
                    fp_rate = self.rolling_full_pass_rate.get(tid, 0.0)
                    mixed_rate = self.rolling_mixed_group_rate.get(tid, 0.0)

                    # Downweight saturated tasks (>90% full-pass)
                    if fp_rate >= self.saturation_threshold:
                        w *= (1.0 - self.saturation_penalty)

                    # Upweight tasks providing mixed-reward gradient signals
                    if mixed_rate > 0.0:
                        w *= (1.0 + 0.5 * mixed_rate)

                    # Ensure minimum exposure floor
                    raw_weights[tid] = max(w, self.min_task_prob_floor)

        # Normalize to valid probability distribution
        total_w = sum(raw_weights.values())
        if total_w > 0:
            self.current_weights = {tid: w / total_w for tid, w in raw_weights.items()}
        else:
            uniform_p = 1.0 / len(self.tasks) if self.tasks else 0.0
            self.current_weights = {t["task_id"]: uniform_p for t in self.tasks}

    def sample_batch(self, batch_size: int) -> List[Tuple[Dict[str, Any], float]]:
        """Samples a batch of tasks according to current priority weights.
        Returns list of (task_dict, assigned_probability).
        Deterministic given current RNG state.
        """
        if not self.tasks:
            return []

        task_ids = list(self.current_weights.keys())
        weights = [self.current_weights[tid] for tid in task_ids]

        # Sample without replacement if batch_size <= len(task_ids)
        # Using cumulative weights with internal rng
        selected_ids: List[str] = []
        remaining_ids = list(task_ids)
        remaining_weights = list(weights)

        for _ in range(batch_size):
            if not remaining_ids:
                # Reset if batch exceeds remaining
                remaining_ids = list(task_ids)
                remaining_weights = list(weights)

            tot = sum(remaining_weights)
            if tot <= 0:
                picked = self.rng.choice(remaining_ids)
            else:
                probs = [w / tot for w in remaining_weights]
                r = self.rng.random()
                cum = 0.0
                picked = remaining_ids[-1]
                for tid, p in zip(remaining_ids, probs):
                    cum += p
                    if r <= cum:
                        picked = tid
                        break

            selected_ids.append(picked)
            idx = remaining_ids.index(picked)
            remaining_ids.pop(idx)
            remaining_weights.pop(idx)

        # Advance internal step
        self.step += 1
        self._update_weights()

        result = []
        for tid in selected_ids:
            task = self.task_map[tid]
            prob = self.current_weights.get(tid, 0.0)
            result.append((task, prob))

        return result

    def to_dict(self) -> Dict[str, Any]:
        """Serializes sampler state for exact deterministic resume."""
        return {
            "seed": self.seed,
            "rng_state": self.rng.getstate(),
            "step": self.step,
            "min_task_prob_floor": self.min_task_prob_floor,
            "saturation_threshold": self.saturation_threshold,
            "saturation_penalty": self.saturation_penalty,
            "window_size": self.window_size,
            "task_exposure_counts": self.task_exposure_counts,
            "stratum_exposure_counts": self.stratum_exposure_counts,
            "category_exposure_counts": self.category_exposure_counts,
            "task_history": self.task_history,
            "rolling_task_reward": self.rolling_task_reward,
            "rolling_full_pass_rate": self.rolling_full_pass_rate,
            "rolling_constant_group_rate": self.rolling_constant_group_rate,
            "rolling_mixed_group_rate": self.rolling_mixed_group_rate,
            "current_weights": self.current_weights,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any], tasks: List[Dict[str, Any]]) -> BPFPrioritySampler:
        """Restores sampler state from dictionary."""
        sampler = cls(
            tasks=tasks,
            seed=data["seed"],
            min_task_prob_floor=data.get("min_task_prob_floor", 0.001),
            saturation_threshold=data.get("saturation_threshold", 0.90),
            saturation_penalty=data.get("saturation_penalty", 0.80),
            window_size=data.get("window_size", 10),
        )
        sampler.step = data["step"]
        # Restore RNG state
        raw_rng = data["rng_state"]
        # Ensure tuple types for rng state
        if isinstance(raw_rng, list):
            raw_rng = (raw_rng[0], tuple(raw_rng[1]), raw_rng[2])
        sampler.rng.setstate(raw_rng)

        sampler.task_exposure_counts = data.get("task_exposure_counts", sampler.task_exposure_counts)
        sampler.stratum_exposure_counts = data.get("stratum_exposure_counts", sampler.stratum_exposure_counts)
        sampler.category_exposure_counts = data.get("category_exposure_counts", sampler.category_exposure_counts)
        sampler.task_history = data.get("task_history", sampler.task_history)
        sampler.rolling_task_reward = data.get("rolling_task_reward", sampler.rolling_task_reward)
        sampler.rolling_full_pass_rate = data.get("rolling_full_pass_rate", sampler.rolling_full_pass_rate)
        sampler.rolling_constant_group_rate = data.get("rolling_constant_group_rate", sampler.rolling_constant_group_rate)
        sampler.rolling_mixed_group_rate = data.get("rolling_mixed_group_rate", sampler.rolling_mixed_group_rate)
        sampler.current_weights = data.get("current_weights", sampler.current_weights)
        return sampler

    def save_state(self, path: Path) -> None:
        """Saves deterministic sampler state to JSON file."""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")
        logger.info("Saved sampler state to %s (step %d)", path, self.step)

    @classmethod
    def load_state(cls, path: Path, tasks: List[Dict[str, Any]]) -> BPFPrioritySampler:
        """Loads deterministic sampler state from JSON file."""
        data = json.loads(path.read_text(encoding="utf-8"))
        sampler = cls.from_dict(data, tasks)
        logger.info("Loaded sampler state from %s (resumed at step %d)", path, sampler.step)
        return sampler
