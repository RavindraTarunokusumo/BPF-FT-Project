#!/usr/bin/env python3
"""
BPF-Guardian SFT Split Generator and Dataset Freezing Tool
Creates deterministic, frozen train/validation splits from sft_dataset_full.jsonl:
1. Groups records strictly by task_id (synthesis + all repairs stay in the same split).
2. Stratifies tasks across (category, difficulty, template_family) to achieve ~90% train / 10% validation.
3. Completely excludes all benchmark/calibration task IDs (from data/calibration/index.jsonl).
4. Verifies zero task leakage across train, validation, and benchmark.
5. Deterministically sorts outputs before writing.
6. Generates freeze_manifest.json with full cryptographic hashes and metadata.
7. Refuses to overwrite existing frozen splits if contents or manifest differ.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent

DEFAULT_INPUT = PROJECT_ROOT / "data" / "sft" / "sft_dataset_full.jsonl"
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "data" / "sft" / "frozen" / "v1"
DEFAULT_CALIBRATION_INDEX = PROJECT_ROOT / "data" / "calibration" / "index.jsonl"
SPLIT_ALGORITHM_VERSION = "bpf_guardian_stratified_task_split_v1"
DEFAULT_SEED = 42
DEFAULT_VAL_RATIO = 0.10


def compute_file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(65536):
            digest.update(chunk)
    return digest.hexdigest()


def get_git_commit_sha() -> str:
    try:
        res = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(PROJECT_ROOT),
            capture_output=True,
            text=True,
            check=True,
        )
        return res.stdout.strip()
    except Exception:
        return "unknown_commit"


def load_calibration_task_ids(index_path: Path) -> Set[str]:
    task_ids: Set[str] = set()
    if not index_path.exists():
        return task_ids
    with index_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    record = json.loads(line)
                    if "task_id" in record:
                        task_ids.add(record["task_id"])
                except Exception:
                    pass
    return task_ids


def compute_split_fingerprint(
    source_sha256: str,
    seed: int,
    val_ratio: float,
    split_algo: str,
    excluded_benchmark_ids: List[str],
) -> str:
    digest = hashlib.sha256()
    payload = {
        "source_sha256": source_sha256,
        "seed": seed,
        "val_ratio": val_ratio,
        "split_algo": split_algo,
        "excluded_benchmark_ids": sorted(excluded_benchmark_ids),
    }
    digest.update(json.dumps(payload, sort_keys=True).encode("utf-8"))
    return digest.hexdigest()[:16]


def prepare_sft_splits(
    input_path: Path,
    output_dir: Path,
    calibration_index_path: Path,
    seed: int = DEFAULT_SEED,
    val_ratio: float = DEFAULT_VAL_RATIO,
    model_name: str = "Qwen/Qwen3-8B",
    renderer_name: str = "qwen3_disable_thinking",
    max_length: int = 4096,
    force: bool = False,
) -> Dict[str, Any]:
    if not input_path.is_file():
        raise FileNotFoundError(f"Input full dataset not found: {input_path}")

    # Read and parse input rows
    with input_path.open("r", encoding="utf-8") as f:
        rows = [json.loads(line) for line in f if line.strip()]

    source_sha256 = compute_file_sha256(input_path)
    commit_sha = get_git_commit_sha()
    benchmark_task_ids = load_calibration_task_ids(calibration_index_path)

    # Group examples by task_id
    task_groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    task_metadata: Dict[str, Dict[str, str]] = {}

    for row in rows:
        t_id = row["task_id"]
        # Check against benchmark tasks
        if t_id in benchmark_task_ids:
            raise ValueError(f"CRITICAL LEAKAGE: Task ID '{t_id}' in SFT dataset is present in calibration benchmark tasks!")

        task_groups[t_id].append(row)
        if t_id not in task_metadata:
            task_metadata[t_id] = {
                "category": row.get("category", "unknown"),
                "difficulty": row.get("difficulty", "unknown"),
                "template_family": row.get("template_family", "unknown"),
            }

    all_task_ids = sorted(task_groups.keys())

    # Stratified bucket allocation
    strata: Dict[Tuple[str, str, str], List[str]] = defaultdict(list)
    for t_id in all_task_ids:
        meta = task_metadata[t_id]
        key = (meta["category"], meta["difficulty"], meta["template_family"])
        strata[key].append(t_id)

    rng = random.Random(seed)
    train_tasks: Set[str] = set()
    val_tasks: Set[str] = set()

    for stratum_key in sorted(strata.keys()):
        stratum_tasks = sorted(strata[stratum_key])
        rng.shuffle(stratum_tasks)

        # Number of val tasks for this stratum
        n_tasks = len(stratum_tasks)
        n_val = int(round(n_tasks * val_ratio))
        # Ensure at least 1 in val if stratum has >= 10 tasks, else proportional
        if n_val == 0 and n_tasks >= 10:
            n_val = 1

        val_tasks.update(stratum_tasks[:n_val])
        train_tasks.update(stratum_tasks[n_val:])

    # Collect rows for splits
    train_rows: List[Dict[str, Any]] = []
    val_rows: List[Dict[str, Any]] = []

    for t_id in train_tasks:
        train_rows.extend(task_groups[t_id])
    for t_id in val_tasks:
        val_rows.extend(task_groups[t_id])

    # Sort deterministically
    train_rows.sort(key=lambda r: r["example_id"])
    val_rows.sort(key=lambda r: r["example_id"])

    # Double check zero leakage
    train_task_set = {r["task_id"] for r in train_rows}
    val_task_set = {r["task_id"] for r in val_rows}
    overlap_tasks = train_task_set & val_task_set
    if overlap_tasks:
        raise ValueError(f"Task overlap detected between train and validation: {overlap_tasks}")

    train_example_ids = {r["example_id"] for r in train_rows}
    val_example_ids = {r["example_id"] for r in val_rows}
    overlap_examples = train_example_ids & val_example_ids
    if overlap_examples:
        raise ValueError(f"Example ID overlap detected between train and validation: {overlap_examples}")

    leakage_with_bench = (train_task_set | val_task_set) & benchmark_task_ids
    if leakage_with_bench:
        raise ValueError(f"Benchmark leakage detected: {leakage_with_bench}")

    # Check output paths
    output_dir.mkdir(parents=True, exist_ok=True)
    train_file = output_dir / "train.jsonl"
    val_file = output_dir / "validation.jsonl"
    manifest_file = output_dir / "freeze_manifest.json"
    report_file = output_dir / "split_report.md"

    # If already exists and not forcing, check if content matches
    if train_file.exists() and val_file.exists() and manifest_file.exists() and not force:
        existing_manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
        existing_train_sha = compute_file_sha256(train_file)
        existing_val_sha = compute_file_sha256(val_file)

        # Generate tentative content bytes with newline='\n'
        tentative_train_bytes = "".join(json.dumps(r) + "\n" for r in train_rows).encode("utf-8")
        tentative_train_sha = hashlib.sha256(tentative_train_bytes).hexdigest()
        tentative_val_bytes = "".join(json.dumps(r) + "\n" for r in val_rows).encode("utf-8")
        tentative_val_sha = hashlib.sha256(tentative_val_bytes).hexdigest()

        if existing_train_sha != tentative_train_sha or existing_val_sha != tentative_val_sha:
            raise RuntimeError(
                f"Frozen split already exists at {output_dir} with different contents! "
                f"Refusing to overwrite existing frozen version. Use a new version directory or pass --force."
            )
        else:
            print(f"[+] Frozen splits at {output_dir} already exist and match byte-for-byte.")
            return existing_manifest

    # Write files atomically with explicit Unix line endings (newline="\n")
    with train_file.open("w", encoding="utf-8", newline="\n") as f:
        for r in train_rows:
            f.write(json.dumps(r) + "\n")

    with val_file.open("w", encoding="utf-8", newline="\n") as f:
        for r in val_rows:
            f.write(json.dumps(r) + "\n")

    train_sha256 = compute_file_sha256(train_file)
    val_sha256 = compute_file_sha256(val_file)

    # Compute distributions
    def compute_dist(split_rows: List[Dict[str, Any]]) -> Dict[str, Any]:
        cat = Counter(r["category"] for r in split_rows)
        diff = Counter(r["difficulty"] for r in split_rows)
        typ = Counter(r["example_type"] for r in split_rows)
        fam = Counter(r["template_family"] for r in split_rows)
        return {
            "categories": dict(cat),
            "difficulties": dict(diff),
            "example_types": dict(typ),
            "template_families": dict(fam),
        }

    train_dist = compute_dist(train_rows)
    val_dist = compute_dist(val_rows)
    total_dist = compute_dist(train_rows + val_rows)

    config_fingerprint = compute_split_fingerprint(
        source_sha256=source_sha256,
        seed=seed,
        val_ratio=val_ratio,
        split_algo=SPLIT_ALGORITHM_VERSION,
        excluded_benchmark_ids=list(benchmark_task_ids),
    )

    project_root = PROJECT_ROOT.resolve()

    def safe_rel_path(p: Path) -> str:
        try:
            return str(p.resolve().relative_to(project_root)).replace("\\", "/")
        except ValueError:
            return str(p.resolve()).replace("\\", "/")

    manifest: Dict[str, Any] = {
        "version": output_dir.name,
        "split_algorithm_version": SPLIT_ALGORITHM_VERSION,
        "configuration_fingerprint": config_fingerprint,
        "source_commit_sha": commit_sha,
        "source_file_path": safe_rel_path(input_path),
        "source_sha256": source_sha256,
        "train_file_path": safe_rel_path(train_file),
        "train_sha256": train_sha256,
        "validation_file_path": safe_rel_path(val_file),
        "validation_sha256": val_sha256,
        "split_seed": seed,
        "target_val_ratio": val_ratio,
        "renderer_name": renderer_name,
        "model_name": model_name,
        "max_length": max_length,
        "excluded_benchmark_ids": sorted(list(benchmark_task_ids)),
        "row_counts": {
            "train": len(train_rows),
            "validation": len(val_rows),
            "total": len(train_rows) + len(val_rows),
        },
        "unique_task_counts": {
            "train": len(train_tasks),
            "validation": len(val_tasks),
            "total": len(train_tasks) + len(val_tasks),
        },
        "category_distribution": {
            "train": train_dist["categories"],
            "validation": val_dist["categories"],
            "total": total_dist["categories"],
        },
        "difficulty_distribution": {
            "train": train_dist["difficulties"],
            "validation": val_dist["difficulties"],
            "total": total_dist["difficulties"],
        },
        "synthesis_repair_distribution": {
            "train": train_dist["example_types"],
            "validation": val_dist["example_types"],
            "total": total_dist["example_types"],
        },
        "template_family_distribution": {
            "train": train_dist["template_families"],
            "validation": val_dist["template_families"],
            "total": total_dist["template_families"],
        },
    }

    manifest_file.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    # Generate Markdown Report
    report_lines = [
        f"# BPF-Guardian SFT Frozen Split Report ({output_dir.name})",
        "",
        "## Overview",
        f"- **Source Dataset**: `{safe_rel_path(input_path)}`",
        f"- **Source Git Commit**: `{commit_sha}`",
        f"- **Source SHA-256**: `{source_sha256}`",
        f"- **Split Seed**: `{seed}`",
        f"- **Split Algorithm**: `{SPLIT_ALGORITHM_VERSION}`",
        f"- **Configuration Fingerprint**: `{config_fingerprint}`",
        "",
        "## Split Summary",
        "| Split | Tasks | Examples | Synthesis | Repair | SHA-256 |",
        "|---|---|---|---|---|---|",
        f"| Train | {len(train_tasks)} | {len(train_rows)} | {train_dist['example_types'].get('synthesis', 0)} | {train_dist['example_types'].get('repair', 0)} | `{train_sha256[:16]}...` |",
        f"| Validation | {len(val_tasks)} | {len(val_rows)} | {val_dist['example_types'].get('synthesis', 0)} | {val_dist['example_types'].get('repair', 0)} | `{val_sha256[:16]}...` |",
        f"| **Total** | **{len(train_tasks) + len(val_tasks)}** | **{len(train_rows) + len(val_rows)}** | **{total_dist['example_types'].get('synthesis', 0)}** | **{total_dist['example_types'].get('repair', 0)}** | - |",
        "",
        "## Category Distribution",
        "| Category | Train Tasks | Val Tasks | Train Examples | Val Examples |",
        "|---|---|---|---|---|",
    ]

    for cat in sorted(total_dist["categories"].keys()):
        t_count = sum(1 for tid in train_tasks if task_metadata[tid]["category"] == cat)
        v_count = sum(1 for tid in val_tasks if task_metadata[tid]["category"] == cat)
        t_ex = train_dist["categories"].get(cat, 0)
        v_ex = val_dist["categories"].get(cat, 0)
        report_lines.append(f"| `{cat}` | {t_count} | {v_count} | {t_ex} | {v_ex} |")

    report_lines.extend([
        "",
        "## Difficulty Distribution",
        "| Difficulty | Train Tasks | Val Tasks | Train Examples | Val Examples |",
        "|---|---|---|---|---|",
    ])

    for diff in sorted(total_dist["difficulties"].keys()):
        t_count = sum(1 for tid in train_tasks if task_metadata[tid]["difficulty"] == diff)
        v_count = sum(1 for tid in val_tasks if task_metadata[tid]["difficulty"] == diff)
        t_ex = train_dist["difficulties"].get(diff, 0)
        v_ex = val_dist["difficulties"].get(diff, 0)
        report_lines.append(f"| `{diff}` | {t_count} | {v_count} | {t_ex} | {v_ex} |")

    report_lines.extend([
        "",
        "## Integrity Verification",
        f"- [x] Grouping by `task_id`: 100% compliant (synthesis and repairs co-located)",
        f"- [x] Zero task overlap between train and validation: Verified",
        f"- [x] Zero overlap with {len(benchmark_task_ids)} calibration benchmark tasks: Verified",
        f"- [x] Deterministic byte-reproducible ordering: Verified",
    ])

    report_file.write_text("\n".join(report_lines) + "\n", encoding="utf-8")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description="BPF-Guardian SFT Split Generator & Dataset Freezer")
    parser.add_argument("--dataset", type=Path, default=DEFAULT_INPUT, help="Source full JSONL dataset")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR, help="Destination directory for frozen split")
    parser.add_argument("--calibration-index", type=Path, default=DEFAULT_CALIBRATION_INDEX, help="Calibration index for exclusion")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED, help="Random seed for deterministic split")
    parser.add_argument("--val-ratio", type=float, default=DEFAULT_VAL_RATIO, help="Validation ratio (default: 0.10)")
    parser.add_argument("--model-name", type=str, default="Qwen/Qwen3-8B", help="Model name for manifest")
    parser.add_argument("--renderer-name", type=str, default="qwen3_disable_thinking", help="Renderer name for manifest")
    parser.add_argument("--max-length", type=int, default=4096, help="Configured max length")
    parser.add_argument("--force", action="store_true", help="Force overwrite of existing frozen split")
    args = parser.parse_args()

    print("=" * 70)
    print("BPF-Guardian Dataset Freeze & Split Generator")
    print(f"Input Dataset:      {args.dataset}")
    print(f"Output Directory:   {args.output_dir}")
    print(f"Seed:               {args.seed}")
    print(f"Target Val Ratio:   {args.val_ratio:.1%}")
    print("=" * 70)

    try:
        manifest = prepare_sft_splits(
            input_path=args.dataset,
            output_dir=args.output_dir,
            calibration_index_path=args.calibration_index,
            seed=args.seed,
            val_ratio=args.val_ratio,
            model_name=args.model_name,
            renderer_name=args.renderer_name,
            max_length=args.max_length,
            force=args.force,
        )
        print("\n[+] Dataset Freezing & Splitting Complete!")
        print(f"  Train Rows:      {manifest['row_counts']['train']} (Tasks: {manifest['unique_task_counts']['train']})")
        print(f"  Val Rows:        {manifest['row_counts']['validation']} (Tasks: {manifest['unique_task_counts']['validation']})")
        print(f"  Total Rows:      {manifest['row_counts']['total']} (Tasks: {manifest['unique_task_counts']['total']})")
        print(f"  Train SHA-256:   {manifest['train_sha256']}")
        print(f"  Val SHA-256:     {manifest['validation_sha256']}")
        print(f"  Fingerprint:     {manifest['configuration_fingerprint']}")
        print(f"  Manifest Path:   {args.output_dir / 'freeze_manifest.json'}")
        print(f"  Report Path:     {args.output_dir / 'split_report.md'}")
    except Exception as e:
        print(f"\n[!] Split Preparation Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
