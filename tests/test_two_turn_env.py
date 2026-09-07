"""
Unit tests for TwoTurnBPFEnv and TwoTurnBPFEnvGroupBuilder in Phase N3.
Verifies:
1. Turn 1 functional pass terminates episode with Pass@1=1, Solve@2=1, Reward=1.00.
2. Turn 1 failure transitions to Turn 2 with episode_done=False, Reward=0.0, injecting diagnostic.
3. Turn 2 recovery terminates episode with Pass@1=0, Solve@2=1, Recovered=1, Reward=0.95.
4. Turn 2 double-failure terminates episode with Pass@1=0, Solve@2=0, Recovered=0, bounded partial reward.
5. Infrastructure errors fail closed without returning numeric reward.
"""

import asyncio
import sys
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import tinker
from training.rl.bpf_env import TwoTurnBPFEnv, TwoTurnBPFEnvGroupBuilder
from training.rl.kernel_executor import VerificationResult
from training.rl.reward import InfrastructureRewardError


class MockTokenizer:
    def decode(self, tokens):
        return "// Decoded C source code"


class MockRenderer:
    def __init__(self):
        self.tokenizer = MockTokenizer()

    def build_generation_prompt(self, messages):
        return tinker.ModelInput.from_ints([101, 102])

    def get_stop_sequences(self):
        return ["<|endoftext|>"]


def make_mock_verification(
    rollout_id: str = "r1",
    task_id: str = "test_xdp_drop",
    compile_pass: bool = True,
    verifier_pass: bool = True,
    behavioral_pass: bool = True,
    total_tests: int = 2,
    passed_tests: int = 2,
    diagnostic: str = None,
    infrastructure_error: bool = False,
    error_message: str = None,
) -> VerificationResult:
    return VerificationResult(
        rollout_id=rollout_id,
        task_id=task_id,
        source_sha256="abc",
        task_sha256="xyz",
        output_compliance={"compliant": True},
        compile={"attempted": True, "pass": compile_pass},
        verifier={"attempted": compile_pass, "pass": verifier_pass},
        behavioral={
            "attempted": verifier_pass,
            "pass": behavioral_pass,
            "total_tests": total_tests,
            "passed_tests": passed_tests,
            "details": [{"pass": True}] * passed_tests + [{"pass": False}] * (total_tests - passed_tests),
        },
        cleanup_passed=not infrastructure_error,
        infrastructure_error=infrastructure_error,
        error_message=error_message,
        timeout_stage=None,
        raw_log_path="/fake/log/path",
        timing={"total_seconds": 0.1},
        passed=compile_pass and verifier_pass and behavioral_pass,
        diagnostic=diagnostic,
    )


class TestTwoTurnBPFEnv(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.task = {
            "task_id": "test_xdp_drop",
            "application_category": "packet_filtering_security",
            "difficulty": "level_1",
            "instruction": "Drop all TCP packets on port 80",
            "requirements": ["Return XDP_DROP for TCP dport 80"],
            "expected_fixture_count": 2,
            "tests": [
                {"name": "test_drop", "expected_action": "XDP_DROP", "weight": 1.0},
                {"name": "test_pass", "expected_action": "XDP_PASS", "weight": 1.0},
            ],
        }
        self.renderer = MockRenderer()
        self.mock_executor = MagicMock()

    async def test_initial_observation(self):
        env = TwoTurnBPFEnv(task=self.task, renderer=self.renderer, executor=self.mock_executor)
        obs, stop_cond = await env.initial_observation()
        self.assertEqual(env.turn, 1)
        self.assertEqual(stop_cond, ["<|endoftext|>"])
        self.assertIsInstance(obs, tinker.ModelInput)

    async def test_turn1_success(self):
        env = TwoTurnBPFEnv(task=self.task, renderer=self.renderer, executor=self.mock_executor)
        await env.initial_observation()

        # Mock successful verification on Turn 1
        self.mock_executor.evaluate_candidate = AsyncMock(
            return_value=make_mock_verification(
                compile_pass=True,
                verifier_pass=True,
                behavioral_pass=True,
                total_tests=2,
                passed_tests=2,
            )
        )

        step_res = await env.step([1, 2, 3])
        self.assertTrue(step_res.episode_done)
        self.assertEqual(step_res.reward, 1.00)
        self.assertEqual(step_res.metrics["pass/pass_at_1"], 1.0)
        self.assertEqual(step_res.metrics["pass/solve_at_2"], 1.0)
        self.assertEqual(step_res.metrics["pass/recovered"], 0.0)

    async def test_turn1_fail_transition_to_turn2_and_recovery(self):
        env = TwoTurnBPFEnv(task=self.task, renderer=self.renderer, executor=self.mock_executor)
        await env.initial_observation()

        # Step 1: Turn 1 fails behavioral tests
        self.mock_executor.evaluate_candidate = AsyncMock(
            return_value=make_mock_verification(
                compile_pass=True,
                verifier_pass=True,
                behavioral_pass=False,
                total_tests=2,
                passed_tests=1,
                diagnostic="Behavioral tests failed: expected XDP_DROP got XDP_PASS",
            )
        )

        step_res_1 = await env.step([10, 20])
        self.assertFalse(step_res_1.episode_done)
        self.assertEqual(step_res_1.reward, 0.0)
        self.assertEqual(step_res_1.metrics["pass/pass_at_1"], 0.0)
        self.assertEqual(env.turn, 2)
        self.assertIsInstance(step_res_1.next_observation, tinker.ModelInput)

        # Step 2: Turn 2 succeeds (recovery)
        self.mock_executor.evaluate_candidate = AsyncMock(
            return_value=make_mock_verification(
                compile_pass=True,
                verifier_pass=True,
                behavioral_pass=True,
                total_tests=2,
                passed_tests=2,
            )
        )

        step_res_2 = await env.step([30, 40])
        self.assertTrue(step_res_2.episode_done)
        self.assertEqual(step_res_2.reward, 0.95)
        self.assertEqual(step_res_2.metrics["pass/pass_at_1"], 0.0)
        self.assertEqual(step_res_2.metrics["pass/solve_at_2"], 1.0)
        self.assertEqual(step_res_2.metrics["pass/recovered"], 1.0)
        self.assertEqual(step_res_2.metrics["recovery/from_behavioral_failure"], 1.0)

    async def test_turn2_failure_bounded_credit(self):
        env = TwoTurnBPFEnv(task=self.task, renderer=self.renderer, executor=self.mock_executor)
        await env.initial_observation()

        # Step 1: Turn 1 compile failure
        self.mock_executor.evaluate_candidate = AsyncMock(
            return_value=make_mock_verification(
                compile_pass=False,
                verifier_pass=False,
                behavioral_pass=False,
                total_tests=0,
                passed_tests=0,
                diagnostic="Compilation error: syntax error",
            )
        )
        step_res_1 = await env.step([10])
        self.assertFalse(step_res_1.episode_done)

        # Step 2: Turn 2 also fails (only passes compile and verifier, not fixtures)
        self.mock_executor.evaluate_candidate = AsyncMock(
            return_value=make_mock_verification(
                compile_pass=True,
                verifier_pass=True,
                behavioral_pass=False,
                total_tests=2,
                passed_tests=0,
            )
        )
        step_res_2 = await env.step([20])
        self.assertTrue(step_res_2.episode_done)
        self.assertLessEqual(step_res_2.reward, 0.20)
        self.assertEqual(step_res_2.metrics["pass/pass_at_1"], 0.0)
        self.assertEqual(step_res_2.metrics["pass/solve_at_2"], 0.0)
        self.assertEqual(step_res_2.metrics["pass/recovered"], 0.0)

    async def test_fail_closed_infrastructure_error(self):
        env = TwoTurnBPFEnv(task=self.task, renderer=self.renderer, executor=self.mock_executor)
        await env.initial_observation()

        self.mock_executor.evaluate_candidate = AsyncMock(
            return_value=make_mock_verification(
                infrastructure_error=True,
                error_message="VPS SSH drop",
            )
        )

        with self.assertRaises(RuntimeError) as ctx:
            await env.step([1])
        self.assertIn("INFRASTRUCTURE_ERROR", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
