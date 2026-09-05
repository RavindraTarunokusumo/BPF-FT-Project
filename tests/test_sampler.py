"""
Unit tests for BPFPrioritySampler:
1. Difficulty schedule transitions (Steps 1-15 vs Steps 16-60)
2. Category balance floor
3. Saturated task downweighting (>90% full-pass)
4. Mixed-group reward signal boosting
5. Minimum probability floor for all cells
6. Deterministic sampling and exact state serialization / resume
"""

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock
import pytest

from training.rl.dataset import BPFRLDataset
from training.rl.sampler import BPFPrioritySampler, CATEGORIES, DIFFICULTIES
from training.rl.train_rl import install_sampler_feedback_hook


def create_synthetic_task_pool(tasks_per_cell: int = 12):
    """Creates a synthetic 144-task pool matching RL v2 train split structure."""
    tasks = []
    for cat in CATEGORIES:
        for diff in DIFFICULTIES:
            for i in range(1, tasks_per_cell + 1):
                tid = f"rl_v2_train_{cat}_{diff}_{i:02d}"
                tasks.append({
                    "task_id": tid,
                    "application_category": cat,
                    "difficulty": diff,
                    "task_family": f"fam_{cat}_{diff}",
                })
    return tasks


def test_difficulty_schedule():
    tasks = create_synthetic_task_pool(2)
    sampler = BPFPrioritySampler(tasks=tasks, seed=42)

    # Step 0-15 should be Phase 1 schedule (25/40/35)
    d1 = sampler.get_difficulty_distribution(0)
    assert d1["level_1"] == pytest.approx(0.25)
    assert d1["level_2"] == pytest.approx(0.40)
    assert d1["level_3"] == pytest.approx(0.35)

    d15 = sampler.get_difficulty_distribution(15)
    assert d15["level_1"] == pytest.approx(0.25)

    # Step 16+ should be Phase 2 schedule (10/40/50)
    d16 = sampler.get_difficulty_distribution(16)
    assert d16["level_1"] == pytest.approx(0.10)
    assert d16["level_2"] == pytest.approx(0.40)
    assert d16["level_3"] == pytest.approx(0.50)


def test_category_balance_floor():
    tasks = create_synthetic_task_pool(4)
    sampler = BPFPrioritySampler(tasks=tasks, seed=42)

    # All categories should have identical initial aggregate weight
    cat_weights = {cat: 0.0 for cat in CATEGORIES}
    for tid, w in sampler.current_weights.items():
        cat = sampler.task_map[tid]["application_category"]
        cat_weights[cat] += w

    for cat in CATEGORIES:
        assert cat_weights[cat] == pytest.approx(0.25, rel=1e-3)


def test_saturated_task_downweighting():
    tasks = create_synthetic_task_pool(4)
    sampler = BPFPrioritySampler(tasks=tasks, seed=42, saturation_threshold=0.90, saturation_penalty=0.80)

    target_task = tasks[0]["task_id"]
    peer_task = tasks[1]["task_id"]  # Same cell

    init_target_w = sampler.current_weights[target_task]
    init_peer_w = sampler.current_weights[peer_task]
    assert init_target_w == pytest.approx(init_peer_w)

    # Feed 10 consecutive full-pass outcomes for target_task
    for _ in range(10):
        sampler.update_outcome(
            task_id=target_task,
            rewards=[1.0, 1.0, 1.0, 1.0],
            full_pass=True,
            is_constant_group=True,
        )

    assert sampler.rolling_full_pass_rate[target_task] == 1.0
    # Weight of saturated task must be substantially lower than peer
    new_target_w = sampler.current_weights[target_task]
    new_peer_w = sampler.current_weights[peer_task]
    assert new_target_w < new_peer_w * 0.35


def test_mixed_group_boost():
    tasks = create_synthetic_task_pool(4)
    sampler = BPFPrioritySampler(tasks=tasks, seed=42)

    target_task = tasks[0]["task_id"]
    peer_task = tasks[1]["task_id"]

    # Feed mixed-reward outcomes (active learning gradient)
    for _ in range(10):
        sampler.update_outcome(
            task_id=target_task,
            rewards=[0.25, 1.0, 0.25, 1.0],
            full_pass=False,
            is_constant_group=False,
        )

    assert sampler.rolling_mixed_group_rate[target_task] == 1.0
    new_target_w = sampler.current_weights[target_task]
    new_peer_w = sampler.current_weights[peer_task]
    assert new_target_w > new_peer_w


def test_minimum_exposure_floor():
    tasks = create_synthetic_task_pool(4)
    floor = 0.002
    sampler = BPFPrioritySampler(tasks=tasks, seed=42, min_task_prob_floor=floor)

    for tid, w in sampler.current_weights.items():
        assert w >= floor * 0.5  # Allow minor normalization scaling


def test_deterministic_sampling_and_resume():
    tasks = create_synthetic_task_pool(4)

    # Sampler 1: run 10 steps
    s1 = BPFPrioritySampler(tasks=tasks, seed=12345)
    batches_s1 = []
    for _ in range(5):
        batches_s1.append(s1.sample_batch(batch_size=2))

    # Save state
    with tempfile.TemporaryDirectory() as tmpdir:
        state_file = Path(tmpdir) / "sampler_state.json"
        s1.save_state(state_file)

        # Resume into new sampler instance
        s_resumed = BPFPrioritySampler.load_state(state_file, tasks=tasks)

        # Run 5 more steps on both
        next_s1 = [s1.sample_batch(batch_size=2) for _ in range(5)]
        next_resumed = [s_resumed.sample_batch(batch_size=2) for _ in range(5)]

        # Verify exact equality of sampled task sequence
        for b1, b2 in zip(next_s1, next_resumed):
            ids1 = [t[0]["task_id"] for t in b1]
            ids2 = [t[0]["task_id"] for t in b2]
            assert ids1 == ids2
            probs1 = [t[1] for t in b1]
            probs2 = [t[1] for t in b2]
            assert probs1 == probs2


def test_dataset_uses_priority_sampler():
    tasks = create_synthetic_task_pool(2)
    sampler = BPFPrioritySampler(tasks=tasks, seed=42)
    dataset = BPFRLDataset(
        tasks=tasks,
        group_size=4,
        batch_size=2,
        sampler=sampler,
    )

    # Initial sampler step
    assert sampler.step == 0
    builders = dataset.get_batch(0)
    assert len(builders) == 2
    # Sampler step should advance after batch sampling
    assert sampler.step == 1

    # Builders should hold sampler reference and assigned sampling probability
    assert builders[0].sampler is sampler
    assert builders[0].task_sampling_prob > 0.0
    assert builders[1].sampler is sampler
    assert builders[1].task_sampling_prob > 0.0


def test_dataset_round_robin_fallback():
    tasks = create_synthetic_task_pool(2)
    dataset = BPFRLDataset(
        tasks=tasks,
        group_size=4,
        batch_size=2,
        sampler=None,
    )
    builders = dataset.get_batch(0)
    assert len(builders) == 2
    assert builders[0].task["task_id"] == tasks[0]["task_id"]
    assert builders[1].task["task_id"] == tasks[1]["task_id"]
    assert builders[0].sampler is None
    assert builders[0].task_sampling_prob == pytest.approx(1.0 / len(tasks))


@pytest.mark.asyncio
async def test_sampler_feedback_hook():
    tasks = create_synthetic_task_pool(2)
    sampler = BPFPrioritySampler(tasks=tasks, seed=42)
    target_task = tasks[0]

    # Install feedback hook
    install_sampler_feedback_hook()

    import tinker_cookbook.rl.rollouts as rollouts

    # Mock the underlying orig implementation
    mock_traj = MagicMock()
    mock_transition = MagicMock()
    mock_transition.reward = 1.0
    mock_transition.metrics = {"pass/functional": 1.0, "reward/bonus": 0.05}
    mock_traj.transitions = [mock_transition]

    mock_traj_group = MagicMock()
    mock_traj_group.trajectories_G = [mock_traj, mock_traj, mock_traj, mock_traj]
    mock_traj_group.final_rewards_G = [0.0, 0.0, 0.0, 0.0]
    mock_traj_group.get_total_rewards.return_value = [1.0, 1.0, 1.0, 1.0]

    # Create dummy builder
    builder = MagicMock()
    builder.task = target_task
    builder.sampler = sampler
    builder.sampler_state_path = None

    # Replace orig_impl with async mock returning mock_traj_group
    with pytest.MonkeyPatch.context() as mp:
        async def fake_orig(*args, **kwargs):
            return mock_traj_group

        mp.setattr(rollouts, "_do_group_rollout_and_filter_constant_reward_impl", fake_orig)
        install_sampler_feedback_hook()

        # Call hooked function with do_remove_constant_reward_groups=True
        # Since rewards are all 1.0, it's constant, so it should return None
        res = await rollouts.do_group_rollout_and_filter_constant_reward(
            sampling_client=MagicMock(),
            env_group_builder=builder,
            max_tokens=2048,
            temperature=0.8,
            do_remove_constant_reward_groups=True,
        )

        assert res is None  # filtered because all rewards are 1.0 (constant)
        # BUT sampler must have received the outcome update!
        assert sampler.task_exposure_counts[target_task["task_id"]] == 1
        assert sampler.rolling_full_pass_rate[target_task["task_id"]] == 1.0
        assert sampler.rolling_constant_group_rate[target_task["task_id"]] == 1.0

