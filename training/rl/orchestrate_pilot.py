"""
BPF-Guardian RLVR Phase 2: Master Pilot Training & Dev Evaluation Orchestrator
Executes the Phase 2 pilot training loop in 5-step increments, evaluating checkpoints on
the 48-task Dev set at T=0.0 every 5 steps.
Monitors early stopping (patience=3) and selects the best checkpoint by Dev functional pass.
"""

from __future__ import annotations

import argparse
import datetime
import json
import logging
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("bpf_guardian_rl.orchestrator")


def load_checkpoints(checkpoints_file: Path) -> Dict[str, Dict[str, Any]]:
    checkpoints = {}
    if checkpoints_file.is_file():
        for line in checkpoints_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                entry = json.loads(line)
                checkpoints[entry["name"]] = entry
    return checkpoints


def run_cmd(cmd: List[str], cwd: Path) -> None:
    logger.info("Executing: %s", " ".join(cmd))
    proc = subprocess.run(cmd, cwd=cwd)
    if proc.returncode != 0:
        raise RuntimeError(f"Command failed with exit code {proc.returncode}")


def main():
    parser = argparse.ArgumentParser(description="Phase 2 Pilot Orchestrator")
    parser.add_argument("--max-steps", type=int, default=60, help="Maximum training steps (default: 60)")
    parser.add_argument("--step-increment", type=int, default=5, help="Evaluation cadence in steps (default: 5)")
    parser.add_argument("--patience", type=int, default=3, help="Early stopping patience in evaluations (default: 3)")
    parser.add_argument("--output-dir", type=str, default="runs/tinker/qwen3-8b-bpf-rl-v2", help="Output run dir")
    parser.add_argument("--dev-dir", type=str, default="data/rl/v2/dev", help="Dev dataset dir")
    parser.add_argument("--baseline-summary", type=str, default="runs/tinker/qwen3-8b-bpf-rl-v2/dev_sft_v2_baseline/summary.json")
    args = parser.parse_args()

    python_bin = sys.executable
    output_dir = Path(args.output_dir)
    pilot_dir = output_dir / "pilot"
    checkpoints_file = pilot_dir / "checkpoints.jsonl"
    baseline_summary_file = Path(args.baseline_summary)

    if not baseline_summary_file.is_file():
        raise FileNotFoundError(f"Baseline Dev summary not found at {baseline_summary_file}")
    baseline_data = json.loads(baseline_summary_file.read_text(encoding="utf-8"))
    baseline_pass = baseline_data["pass_count"]
    total_dev = baseline_data["total_tasks"]
    logger.info("Loaded SFT v2 Dev Baseline: %d/%d (%.1f%%)", baseline_pass, total_dev, baseline_data["pass_rate"] * 100)

    trajectory: List[Dict[str, Any]] = []
    best_step: Optional[int] = None
    best_pass: int = baseline_pass
    best_avg_reward: float = baseline_data.get("average_reward", 0.0)
    best_checkpoint_info: Optional[Dict[str, Any]] = None
    patience_counter = 0

    report_file = output_dir / "pilot_trajectory_report.json"
    completed_steps = set()
    if report_file.is_file():
        try:
            existing_report = json.loads(report_file.read_text(encoding="utf-8"))
            trajectory = existing_report.get("trajectory", [])
            best_step = existing_report.get("best_step")
            best_pass = existing_report.get("best_pass", baseline_pass)
            best_checkpoint_info = existing_report.get("best_checkpoint")
            patience_counter = existing_report.get("patience_used", 0)
            completed_steps = {r["step"] for r in trajectory}
            logger.info("Resuming existing pilot trajectory with %d completed steps: %s", len(completed_steps), sorted(completed_steps))
        except Exception as e:
            logger.warning("Could not load existing trajectory: %s", e)

    step_targets = list(range(args.step_increment, args.max_steps + 1, args.step_increment))
    logger.info("Starting Pilot orchestration across target steps: %s", step_targets)

    for target_step in step_targets:
        if target_step in completed_steps:
            logger.info("Step %d already evaluated in previous run. Skipping.", target_step)
            continue
        logger.info("=" * 60)
        logger.info("PHASE 2 PILOT: TRAINING UP TO STEP %d / %d", target_step, args.max_steps)
        logger.info("=" * 60)

        # 1. Run training step increment
        train_cmd = [
            python_bin,
            str(PROJECT_ROOT / "training/rl/train_rl.py"),
            "--phase", "2",
            "--mode", "pilot",
            "--confirm-paid-run",
            "--max-steps", str(target_step),
        ]
        t_start = time.time()
        run_cmd(train_cmd, cwd=PROJECT_ROOT)
        train_duration = time.time() - t_start

        # 2. Locate checkpoint
        ckpt_name = f"{target_step:06d}"
        ckpts = load_checkpoints(checkpoints_file)
        if ckpt_name not in ckpts:
            if "final" in ckpts and ckpts["final"].get("batch") == target_step:
                ckpt_info = ckpts["final"]
            else:
                raise RuntimeError(f"Checkpoint '{ckpt_name}' not found in {checkpoints_file}. Available: {list(ckpts.keys())}")
        else:
            ckpt_info = ckpts[ckpt_name]

        sampler_checkpoint = ckpt_info["sampler_path"]
        logger.info("Step %d checkpoint saved: %s", target_step, sampler_checkpoint)

        # 3. Run Dev evaluation at T=0.0
        logger.info("Evaluating step %d checkpoint on Dev set (%d tasks at T=0.0)...", target_step, total_dev)
        eval_name = f"dev_step_{target_step:06d}"
        eval_cmd = [
            python_bin,
            str(PROJECT_ROOT / "training/rl/evaluate_rl.py"),
            "--data-dir", args.dev_dir,
            "--eval-name", eval_name,
            "--sampler-checkpoint", sampler_checkpoint,
            "--output-dir", str(output_dir),
            "--temperature", "0.0",
            "--compare-with", str(baseline_summary_file),
        ]
        run_cmd(eval_cmd, cwd=PROJECT_ROOT)

        # 4. Read eval summary and paired comparison
        eval_summary_path = output_dir / eval_name / "summary.json"
        eval_summary = json.loads(eval_summary_path.read_text(encoding="utf-8"))
        comparison_path = output_dir / eval_name / "comparison.json"
        comparison = json.loads(comparison_path.read_text(encoding="utf-8"))

        current_pass = eval_summary["pass_count"]
        current_reward = eval_summary["average_reward"]
        net_gain = comparison["net_gain"]

        record = {
            "step": target_step,
            "train_duration_seconds": round(train_duration, 1),
            "checkpoint_name": ckpt_name,
            "sampler_path": sampler_checkpoint,
            "state_path": ckpt_info.get("state_path"),
            "pass_count": current_pass,
            "pass_rate": eval_summary["pass_rate"],
            "compile_rate": eval_summary["compile_rate"],
            "verifier_rate": eval_summary["verifier_rate"],
            "compliance_rate": eval_summary["compliance_rate"],
            "average_reward": current_reward,
            "net_gain_vs_baseline": net_gain,
            "fail_to_pass": comparison["fail_to_pass"],
            "pass_to_fail": comparison["pass_to_fail"],
            "mcnemar_stat": comparison["mcnemar_stat"],
            "mcnemar_p_value": comparison["mcnemar_p_value"],
        }
        trajectory.append(record)

        # Print step summary
        logger.info(
            "[Step %02d Result] Pass: %d/%d (%.1f%%) [Baseline %d/%d] | Net: %+d (F->P: %d, P->F: %d) | Verifier: %.1f%% | AvgReward: %.4f",
            target_step, current_pass, total_dev, eval_summary["pass_rate"] * 100,
            baseline_pass, total_dev, net_gain, comparison["fail_to_pass"], comparison["pass_to_fail"],
            eval_summary["verifier_rate"] * 100, current_reward,
        )

        # 5. Checkpoint selection logic
        is_improvement = (current_pass > best_pass) or (current_pass == best_pass and current_reward > best_avg_reward + 0.005)
        if is_improvement:
            logger.info("*** New best checkpoint at step %d: %d/%d (+%d over baseline, reward %.4f) ***",
                        target_step, current_pass, total_dev, current_pass - baseline_pass, current_reward)
            best_step = target_step
            best_pass = current_pass
            best_avg_reward = current_reward
            best_checkpoint_info = record
            patience_counter = 0
        else:
            patience_counter += 1
            logger.info("No improvement at step %d. Current best remains step %s (%d/%d). Patience: %d/%d",
                        target_step, best_step, best_pass, total_dev, patience_counter, args.patience)

        # Save ongoing trajectory report
        ongoing_report = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "baseline_pass": baseline_pass,
            "total_dev_tasks": total_dev,
            "best_step": best_step,
            "best_pass": best_pass,
            "best_checkpoint": best_checkpoint_info,
            "patience_used": patience_counter,
            "trajectory": trajectory,
        }
        (output_dir / "pilot_trajectory_report.json").write_text(json.dumps(ongoing_report, indent=2), encoding="utf-8")

        # 6. Check early stopping
        if patience_counter >= args.patience:
            logger.warning("Early stopping triggered at step %d: %d consecutive evaluations without improvement.",
                           target_step, args.patience)
            break

    # Final report
    logger.info("=" * 60)
    logger.info("PILOT ORCHESTRATION COMPLETE")
    logger.info("=" * 60)
    logger.info("Best Selected Checkpoint: Step %s", best_step)
    if best_checkpoint_info:
        logger.info("  Dev Functional Pass: %d/%d (%.1f%%)", best_pass, total_dev, (best_pass / total_dev) * 100)
        logger.info("  Gain over Baseline: %+d tasks (%+.2f%%)", best_pass - baseline_pass, ((best_pass - baseline_pass) / total_dev) * 100)
        logger.info("  Sampler Path: %s", best_checkpoint_info["sampler_path"])
        logger.info("  State Path:   %s", best_checkpoint_info["state_path"])
        advancement_met = (best_pass - baseline_pass) >= 3
        logger.info("  Dev Advancement Gate (>= +3/48): %s", "PASSED" if advancement_met else "NOT MET")
    print(f"\nSelected best checkpoint: Step {best_step} ({best_pass}/{total_dev})")


if __name__ == "__main__":
    main()
