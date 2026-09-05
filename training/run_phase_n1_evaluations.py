#!/usr/bin/env python3
"""
BPF-Guardian Phase N1: Untuned Nemotron Empirical Baseline Driver
================================================================
Orchestrates Phase N1 evaluation of unmodified Nemotron-3.5-Lightning:
1. Samples candidates via Tinker SamplingClient across 5 benchmark suites:
   - 36-task Calibration benchmark (data/calibration)
   - 120-task Private Synthesis benchmark (data/benchmark/synthesis)
   - 120-task Standalone Repair benchmark (data/benchmark/repair)
   - 48-task RL v2 Dev set (data/rl/v2/dev)
   - 60-task RL v2 Confirmation set (data/rl/v2/confirmation)
   Total: 384 deterministic evaluation tasks (T=0.0, seed=42, max_new_tokens=2048)
2. Samples 12-task stratified sensitivity check (data/benchmark/sensitivity_12, T=1.0, top_p=0.95)
3. Syncs candidate C source code to the Hostinger Linux VPS
4. Executes 100% empirical Clang compilation, bpftool verifier loading, and BPF_PROG_TEST_RUN
5. Imports verification results and computes paired McNemar transitions against Qwen baselines
6. Generates comprehensive Phase N1 report and audits N1 decision gate
"""

from __future__ import annotations

import argparse
import asyncio
import datetime
import json
import logging
import math
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Load .env if present
env_file = PROJECT_ROOT / ".env"
if env_file.is_file():
    for line in env_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            k = k.strip()
            v = v.strip().strip("\"'")
            if k not in os.environ:
                os.environ[k] = v

import tinker
from training.generate_repair_benchmark_rollout import run_repair_benchmark_rollout
from training.generate_tinker_rollout import run_benchmark_rollout
from training.model_profiles import get_model_profile

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("bpf_guardian_n1")

VPS_HOST = "187.124.178.70"
VPS_USER = "root"
SSH_KEY = Path.home() / ".ssh" / "hostinger.pem"
REMOTE_PROJECT_ROOT = "/root/BPF-FT-Project"

SUITES: Dict[str, Dict[str, Any]] = {
    "calibration-36": {
        "type": "synthesis",
        "index": PROJECT_ROOT / "data" / "calibration" / "index.jsonl",
        "total": 36,
        "temperature": 0.0,
        "top_p": None,
    },
    "synthesis-120": {
        "type": "synthesis",
        "index": PROJECT_ROOT / "data" / "benchmark" / "synthesis" / "index.jsonl",
        "total": 120,
        "temperature": 0.0,
        "top_p": None,
    },
    "repair-120": {
        "type": "repair",
        "index": PROJECT_ROOT / "data" / "benchmark" / "repair" / "index.jsonl",
        "total": 120,
        "temperature": 0.0,
        "top_p": None,
    },
    "rl-v2-dev-48": {
        "type": "synthesis",
        "index": PROJECT_ROOT / "data" / "rl" / "v2" / "dev" / "index.jsonl",
        "total": 48,
        "temperature": 0.0,
        "top_p": None,
    },
    "rl-v2-confirmation-60": {
        "type": "synthesis",
        "index": PROJECT_ROOT / "data" / "rl" / "v2" / "confirmation" / "index.jsonl",
        "total": 60,
        "temperature": 0.0,
        "top_p": None,
    },
    "sensitivity-12": {
        "type": "synthesis",
        "index": PROJECT_ROOT / "data" / "benchmark" / "sensitivity_12" / "index.jsonl",
        "total": 12,
        "temperature": 1.0,
        "top_p": 0.95,
    },
}


def compute_exact_mcnemar(b: int, c: int) -> Tuple[float, float]:
    """Computes two-sided McNemar test statistic and exact binomial p-value.
    b: Baseline passed, Candidate failed (regressions)
    c: Baseline failed, Candidate passed (recoveries)
    """
    total = b + c
    if total == 0:
        return 0.0, 1.0

    stat = (abs(b - c) - 1.0) ** 2 / total
    k = min(b, c)
    p_val = 2.0 * sum(math.comb(total, i) * (0.5**total) for i in range(k + 1))
    p_val = min(1.0, max(0.0, p_val))
    return stat, p_val


def run_ssh_command(cmd: str) -> Tuple[int, str, str]:
    """Runs a command on the Hostinger Linux VPS via SSH."""
    ssh_cmd = [
        "ssh",
        "-o", "ConnectTimeout=15",
        "-o", "BatchMode=yes",
        "-i", str(SSH_KEY),
        f"{VPS_USER}@{VPS_HOST}",
        cmd,
    ]
    res = subprocess.run(ssh_cmd, capture_output=True, text=True)
    return res.returncode, res.stdout, res.stderr


import posixpath


def sync_directory_to_vps(local_dir: Path, remote_dir: str) -> None:
    """Syncs a local directory to the VPS via tar over SSH."""
    logger.info("Syncing %s -> VPS %s...", local_dir, remote_dir)
    remote_parent = posixpath.dirname(remote_dir)
    run_ssh_command(f"mkdir -p '{remote_parent}'")
    
    tar_cmd = ["tar", "-czf", "-", "-C", str(local_dir.parent), local_dir.name]
    ssh_target = ["ssh", "-i", str(SSH_KEY), f"{VPS_USER}@{VPS_HOST}", f"tar -xzf - -C '{remote_parent}'"]
    
    p1 = subprocess.Popen(tar_cmd, stdout=subprocess.PIPE)
    p2 = subprocess.Popen(ssh_target, stdin=p1.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    p1.stdout.close()
    out, err = p2.communicate()
    if p2.returncode != 0:
        raise RuntimeError(f"Sync failed: {err.decode('utf-8')}")


def sync_directory_from_vps(remote_dir: str, local_dir: Path) -> None:
    """Syncs a directory back from VPS via tar over SSH."""
    logger.info("Fetching VPS %s -> %s...", remote_dir, local_dir)
    local_dir.parent.mkdir(parents=True, exist_ok=True)
    remote_parent = posixpath.dirname(remote_dir)
    remote_name = posixpath.basename(remote_dir)
    
    ssh_src = ["ssh", "-i", str(SSH_KEY), f"{VPS_USER}@{VPS_HOST}", f"tar -czf - -C '{remote_parent}' '{remote_name}'"]
    tar_dest = ["tar", "-xzf", "-", "-C", str(local_dir.parent)]
    
    p1 = subprocess.Popen(ssh_src, stdout=subprocess.PIPE)
    p2 = subprocess.Popen(tar_dest, stdin=p1.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    p1.stdout.close()
    out, err = p2.communicate()
    if p2.returncode != 0:
        raise RuntimeError(f"Sync from VPS failed: {err.decode('utf-8')}")


async def sample_suite(
    suite_name: str,
    suite_info: Dict[str, Any],
    output_base_dir: Path,
    profile_name: str = "nemotron-3.5-lightning",
    seed: int = 42,
    mock: bool = False,
) -> Path:
    """Generates rollout completions for one evaluation suite."""
    out_dir = output_base_dir / suite_name
    out_dir.mkdir(parents=True, exist_ok=True)
    
    manifest_file = out_dir / "manifest.json"
    gen_records_file = out_dir / "generation_records.jsonl"
    if manifest_file.is_file() and gen_records_file.is_file():
        logger.info("Rollout for '%s' already exists at %s, skipping sampling.", suite_name, out_dir)
        return out_dir

    temp = suite_info.get("temperature", 0.0)
    top_p = suite_info.get("top_p")
    prof = get_model_profile(profile_name)

    logger.info(
        ">>> Sampling suite '%s' (%d tasks, T=%.2f, top_p=%s, Profile=%s)...",
        suite_name,
        suite_info["total"],
        temp,
        str(top_p),
        profile_name,
    )
    
    if suite_info["type"] == "repair":
        await run_repair_benchmark_rollout(
            benchmark_index=suite_info["index"],
            output_dir=out_dir,
            model_name=prof.model_name,
            renderer_name=prof.renderer_name,
            temperature=temp,
            seed=seed,
            max_tokens=2048,
            mock=mock,
            top_p=top_p,
        )
    else:
        await run_benchmark_rollout(
            benchmark_index=suite_info["index"],
            output_dir=out_dir,
            num_samples=1,
            temperature=temp,
            seed=seed,
            max_tokens=2048,
            mock=mock,
            profile=prof,
            top_p=top_p,
        )

    return out_dir


def verify_suite_on_vps(suite_name: str, local_suite_dir: Path) -> Dict[str, Any]:
    """Executes live empirical kernel verification on the Hostinger Linux VPS."""
    logger.info(">>> Verifying suite '%s' live on Hostinger Linux VPS...", suite_name)
    
    remote_suite_dir = f"{REMOTE_PROJECT_ROOT}/runs/evaluation/nemotron-3.5-lightning-base/{suite_name}"
    
    # 1. Sync candidate programs to VPS
    sync_directory_to_vps(local_suite_dir, remote_suite_dir)
    
    # 2. Run rollout verification script on VPS
    vps_cmd = f"bash {REMOTE_PROJECT_ROOT}/scripts/run_rollout_verification.sh {remote_suite_dir}"
    code, stdout, stderr = run_ssh_command(vps_cmd)
    logger.info("VPS verification output for %s (last 500 chars):\n%s", suite_name, stdout[-500:] if len(stdout) > 500 else stdout)
    if code != 0:
        logger.error("VPS verification failed (code %d):\n%s", code, stderr)
        raise RuntimeError(f"VPS verification failed for {suite_name}: {stderr}")
        
    # 3. Fetch verification results back
    sync_directory_from_vps(f"{remote_suite_dir}/verification", local_suite_dir / "verification")
    
    summary_path = local_suite_dir / "verification" / "summary.json"
    if not summary_path.is_file():
        raise FileNotFoundError(f"Missing summary.json for {suite_name}")
        
    return json.loads(summary_path.read_text(encoding="utf-8"))


def load_task_results(suite_dir: Path) -> Dict[str, bool]:
    """Loads per-task boolean pass/fail status from verification results.jsonl."""
    results_file = suite_dir / "verification" / "results.jsonl"
    task_outcomes: Dict[str, bool] = {}
    if not results_file.is_file():
        return task_outcomes
    for line in results_file.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rec = json.loads(line)
            task_outcomes[rec["task_id"]] = rec.get("passed", False)
    return task_outcomes


def load_qwen_baseline_results() -> Dict[str, Dict[str, bool]]:
    """Loads per-task pass/fail status for Qwen baselines."""
    baselines: Dict[str, Dict[str, bool]] = {
        "qwen_base": {},
        "qwen_sft_v2": {},
    }
    
    # Qwen Base Calibration
    qwen_base_calib = PROJECT_ROOT / "data" / "calibration" / "results" / "calibration_summary_qwen_qwen3-8b.json"
    if qwen_base_calib.is_file():
        data = json.loads(qwen_base_calib.read_text(encoding="utf-8"))
        for tid, tinfo in data.get("tasks", {}).items():
            baselines["qwen_base"][tid] = (tinfo.get("status") == "passed" or tinfo.get("stage") == "passed")

    # Qwen SFT v2 suites
    suite_map = [
        ("calibration-36", PROJECT_ROOT / "runs" / "evaluation" / "qwen3-8b-full-sft-v2" / "calibration-synthesis" / "verification" / "results.jsonl"),
        ("synthesis-120", PROJECT_ROOT / "runs" / "evaluation" / "qwen3-8b-full-sft-v2" / "benchmark-synthesis-120" / "verification" / "results.jsonl"),
        ("repair-120", PROJECT_ROOT / "runs" / "evaluation" / "qwen3-8b-full-sft-v2" / "benchmark-repair-120" / "verification" / "results.jsonl"),
    ]
    for _, res_path in suite_map:
        if res_path.is_file():
            for line in res_path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    rec = json.loads(line)
                    baselines["qwen_sft_v2"][rec["task_id"]] = rec.get("passed", False)

    # Qwen SFT v2 Dev & Confirmation
    dev_summary = PROJECT_ROOT / "runs" / "tinker" / "qwen3-8b-bpf-rl-v2" / "dev_sft_v2_baseline" / "summary.json"
    if dev_summary.is_file():
        d = json.loads(dev_summary.read_text(encoding="utf-8"))
        for item in d.get("results", []):
            baselines["qwen_sft_v2"][item["task_id"]] = item.get("passed", False)

    conf_summary = PROJECT_ROOT / "runs" / "tinker" / "qwen3-8b-bpf-rl-v2" / "baseline_confirmation" / "confirmation_sft_v2_baseline" / "summary.json"
    if conf_summary.is_file():
        d = json.loads(conf_summary.read_text(encoding="utf-8"))
        for item in d.get("results", []):
            baselines["qwen_sft_v2"][item["task_id"]] = item.get("passed", False)

    return baselines


async def run_phase_n1(
    output_root: Path = PROJECT_ROOT / "runs" / "evaluation" / "nemotron-3.5-lightning-base",
    mock: bool = False,
    skip_sampling: bool = False,
    suites_to_run: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Runs complete Phase N1 untuned baseline evaluation."""
    output_root.mkdir(parents=True, exist_ok=True)
    active_suites = {k: v for k, v in SUITES.items() if suites_to_run is None or k in suites_to_run}
    
    suite_results: Dict[str, Any] = {}
    
    # 1. Sampling phase
    for name, info in active_suites.items():
        if not skip_sampling:
            await sample_suite(
                suite_name=name,
                suite_info=info,
                output_base_dir=output_root,
                seed=42,
                mock=mock,
            )
            
    # 2. VPS verification phase
    for name in active_suites:
        local_dir = output_root / name
        results = verify_suite_on_vps(name, local_dir)
        suite_results[name] = results
        
    # 3. Master summary report & McNemar analysis
    baselines = load_qwen_baseline_results()
    all_candidate_tasks: Dict[str, bool] = {}
    for name in active_suites:
        task_outcomes = load_task_results(output_root / name)
        all_candidate_tasks.update(task_outcomes)

    mcnemar_vs_sft_v2: Dict[str, Any] = {}
    qwen_sft_tasks = baselines["qwen_sft_v2"]
    common_tasks = set(all_candidate_tasks.keys()).intersection(qwen_sft_tasks.keys())
    
    n00 = sum(1 for tid in common_tasks if not qwen_sft_tasks[tid] and not all_candidate_tasks[tid])
    n01 = sum(1 for tid in common_tasks if not qwen_sft_tasks[tid] and all_candidate_tasks[tid]) # recoveries
    n10 = sum(1 for tid in common_tasks if qwen_sft_tasks[tid] and not all_candidate_tasks[tid]) # regressions
    n11 = sum(1 for tid in common_tasks if qwen_sft_tasks[tid] and all_candidate_tasks[tid])
    stat, pval = compute_exact_mcnemar(n10, n01)
    
    mcnemar_vs_sft_v2 = {
        "common_tasks": len(common_tasks),
        "contingency": {
            "n00_both_fail": n00,
            "n01_nemotron_recovered": n01,
            "n10_nemotron_regressed": n10,
            "n11_both_pass": n11,
        },
        "mcnemar_stat": stat,
        "p_value": pval,
        "net_gain": n01 - n10,
    }

    # Protected suites combination
    prot_suites = ["calibration-36", "synthesis-120", "repair-120"]
    prot_passed = 0
    prot_total = 0
    for ps in prot_suites:
        if ps in suite_results:
            p_data = suite_results[ps].get("metrics", {}).get("pass_at_1", {})
            prot_passed += p_data.get("passed_tasks", 0)
            prot_total += p_data.get("total_tasks", 0)

    master_summary = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "model_profile": "nemotron-3.5-lightning",
        "model_name": "nvidia/NVIDIA-Nemotron-3.5-Lightning-30B-A3B-BF16",
        "revision": "a9904d24bcc1d289a1950fa9d2b978c47cf903b9",
        "license": "OpenMDW-1.1",
        "total_suites_evaluated": len(suite_results),
        "suites": suite_results,
        "protected_combined": {
            "passed": prot_passed,
            "total": prot_total,
            "rate": prot_passed / prot_total if prot_total > 0 else 0.0,
            "target_gate": "143/276 (SFT gate)",
            "qwen_sft_v2_baseline": "137/276 (49.6%)",
            "qwen_base_baseline": "14/276 (5.1%)",
        },
        "mcnemar_vs_qwen_sft_v2": mcnemar_vs_sft_v2,
    }
    
    (output_root / "master_summary.json").write_text(json.dumps(master_summary, indent=2) + "\n", encoding="utf-8")
    logger.info("Phase N1 evaluation complete! Master summary saved to %s", output_root / "master_summary.json")
    return master_summary


def main():
    parser = argparse.ArgumentParser(description="BPF-Guardian Phase N1 Evaluation Driver")
    parser.add_argument("--output-root", type=Path, default=PROJECT_ROOT / "runs" / "evaluation" / "nemotron-3.5-lightning-base")
    parser.add_argument("--mock", action="store_true", help="Generate synthetic mock rollouts for offline testing")
    parser.add_argument("--skip-sampling", action="store_true", help="Skip sampling and verify existing candidates")
    parser.add_argument("--suites", nargs="+", default=None, help="Specific suites to run (e.g. calibration-36)")
    args = parser.parse_args()
    
    asyncio.run(
        run_phase_n1(
            output_root=args.output_root,
            mock=args.mock,
            skip_sampling=args.skip_sampling,
            suites_to_run=args.suites,
        )
    )


if __name__ == "__main__":
    main()
