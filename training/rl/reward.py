"""
BPF-Guardian RLVR Phase 1: Reward Function
Computes bounded multi-stage verifiable rewards from empirical kernel verification results.

Reward structure (Total max 1.00):
- Structural output compliance: 0.02
- Successful BPF compilation:   0.08
- Kernel verifier acceptance:   0.15
- Weighted fixture pass rate:   0.70
- Complete-suite bonus:         0.05

Stage gates:
- Compilation credit requires successful compilation.
- Verifier credit requires compilation AND successful kernel verifier load.
- Behavioral credit requires verifier acceptance.
- Full-suite bonus requires 100% of required fixtures to pass.
- Empty fixture suite receives 0.0 behavioral credit.
- Infrastructure errors MUST NOT produce training reward (fail-closed).
"""

from __future__ import annotations

import dataclasses
from typing import Any, Dict, List, Optional


@dataclasses.dataclass(frozen=True)
class RewardBreakdown:
    compliance_reward: float
    compile_reward: float
    verifier_reward: float
    fixture_reward: float
    complete_bonus: float
    total_reward: float
    is_functionally_correct: bool
    is_infrastructure_error: bool
    stage_reached: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "compliance_reward": round(self.compliance_reward, 4),
            "compile_reward": round(self.compile_reward, 4),
            "verifier_reward": round(self.verifier_reward, 4),
            "fixture_reward": round(self.fixture_reward, 4),
            "complete_bonus": round(self.complete_bonus, 4),
            "total_reward": round(self.total_reward, 4),
            "is_functionally_correct": self.is_functionally_correct,
            "is_infrastructure_error": self.is_infrastructure_error,
            "stage_reached": self.stage_reached,
        }


# Constant reward weights
WEIGHT_COMPLIANCE = 0.02
WEIGHT_COMPILE = 0.08
WEIGHT_VERIFIER = 0.15
WEIGHT_FIXTURES = 0.70
WEIGHT_BONUS = 0.05
MAX_REWARD = 1.00


def compute_rlvr_reward(
    result: Dict[str, Any],
    expected_fixture_count: Optional[int] = None,
) -> RewardBreakdown:
    """Computes the bounded RLVR reward from an empirical verification result.

    Args:
        result: Dict matching VerificationResult schema
        expected_fixture_count: Optional expected count of fixtures for fail-closed validation

    Returns:
        RewardBreakdown with scalar components and total reward
    """
    # 0. Infrastructure failure check
    is_infra_error = result.get("infrastructure_error", False)
    if is_infra_error:
        return RewardBreakdown(
            compliance_reward=0.0,
            compile_reward=0.0,
            verifier_reward=0.0,
            fixture_reward=0.0,
            complete_bonus=0.0,
            total_reward=0.0,
            is_functionally_correct=False,
            is_infrastructure_error=True,
            stage_reached="infrastructure_error",
        )

    compliance_pass = bool(result.get("output_compliance", {}).get("compliant", False))
    compile_pass = bool(result.get("compile", {}).get("pass", False))
    verifier_pass = bool(result.get("verifier", {}).get("pass", False))
    behavioral = result.get("behavioral", {})

    total_fixtures = behavioral.get("total_tests", 0)
    passed_fixtures = behavioral.get("passed_tests", 0)
    fixtures_details = behavioral.get("details", [])

    # Validate fixture count consistency
    if expected_fixture_count is not None and expected_fixture_count > 0:
        if total_fixtures != expected_fixture_count:
            # Fixture count mismatch is an infrastructure failure
            return RewardBreakdown(
                compliance_reward=0.0,
                compile_reward=0.0,
                verifier_reward=0.0,
                fixture_reward=0.0,
                complete_bonus=0.0,
                total_reward=0.0,
                is_functionally_correct=False,
                is_infrastructure_error=True,
                stage_reached="fixture_count_mismatch",
            )

    # 1. Output compliance
    r_comp = WEIGHT_COMPLIANCE if compliance_pass else 0.0
    stage = "compliance" if compliance_pass else "non_compliant"

    # 2. Compilation (Gate: Must compile successfully)
    if compile_pass:
        r_compile = WEIGHT_COMPILE
        stage = "compile"
    else:
        r_compile = 0.0

    # 3. Kernel Verifier (Gate: Must have compiled AND passed verifier)
    if compile_pass and verifier_pass:
        r_verifier = WEIGHT_VERIFIER
        stage = "verifier"
    else:
        r_verifier = 0.0

    # 4. Behavioral execution (Gate: Must have passed verifier)
    r_fixtures = 0.0
    r_bonus = 0.0
    is_all_passed = False

    if compile_pass and verifier_pass and total_fixtures > 0:
        stage = "behavioral"
        # Compute weighted fixture fraction
        total_weight = 0.0
        earned_weight = 0.0

        for f in fixtures_details:
            # Default weight is 1.0; can be customized by test category
            f_weight = float(f.get("weight", 1.0))
            total_weight += f_weight
            if f.get("pass", False):
                earned_weight += f_weight

        if total_weight > 0.0:
            fraction = earned_weight / total_weight
        else:
            fraction = passed_fixtures / total_fixtures if total_fixtures > 0 else 0.0

        r_fixtures = WEIGHT_FIXTURES * fraction

        # Complete-suite bonus: only when 100% of fixtures pass
        if passed_fixtures == total_fixtures and passed_fixtures > 0:
            r_bonus = WEIGHT_BONUS
            is_all_passed = True
            stage = "full_pass"

    total = min(MAX_REWARD, r_comp + r_compile + r_verifier + r_fixtures + r_bonus)

    return RewardBreakdown(
        compliance_reward=r_comp,
        compile_reward=r_compile,
        verifier_reward=r_verifier,
        fixture_reward=r_fixtures,
        complete_bonus=r_bonus,
        total_reward=total,
        is_functionally_correct=is_all_passed,
        is_infrastructure_error=False,
        stage_reached=stage,
    )
