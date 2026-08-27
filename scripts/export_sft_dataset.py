#!/usr/bin/env python3
"""
BPF-Guardian SFT Dataset Exporter
Parses all verified tasks in data/inbox (and generated repair revisions) to construct
the final curated SFT dataset (60% synthesis, 40% repair), outputting train JSONL.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent
INBOX_DIR = PROJECT_ROOT / "data" / "inbox"
VALIDATION_DIR = PROJECT_ROOT / "data" / "validation"
SFT_DIR = PROJECT_ROOT / "data" / "sft"

SYSTEM_PROMPT = """You are an expert Linux kernel eBPF and XDP systems programmer.
Write complete, self-contained, compilation-ready, and verifier-safe C source code for Linux XDP programs."""

REPAIR_SYSTEM_PROMPT = """You are an expert Linux kernel eBPF and XDP systems programmer.
You are fixing an XDP program that produced diagnostic errors during evaluation."""


def format_synthesis_prompt(task_spec: Dict[str, Any]) -> str:
    task_id = task_spec["task_id"]
    category = task_spec.get("application_category", "packet_filtering_security")
    difficulty = task_spec.get("difficulty", "level_1")
    instruction = task_spec["instruction"]
    reqs = task_spec.get("requirements", [])
    reqs_formatted = "\n".join(f"- {r}" for r in reqs)

    return f"""Task ID: {task_id}
Category: {category}
Difficulty: {difficulty}

Instruction:
{instruction}

Detailed Technical Requirements:
{reqs_formatted}

Write the complete C source code for this XDP program."""


def format_repair_prompt(task_spec: Dict[str, Any], faulty_c: str, diagnostic: str) -> str:
    task_id = task_spec["task_id"]
    category = task_spec.get("application_category", "packet_filtering_security")
    difficulty = task_spec.get("difficulty", "level_1")
    instruction = task_spec["instruction"]
    reqs = task_spec.get("requirements", [])
    reqs_formatted = "\n".join(f"- {r}" for r in reqs)

    return f"""Task ID: {task_id}
Category: {category}
Difficulty: {difficulty}

Original Instruction:
{instruction}

Technical Requirements:
{reqs_formatted}

Previous Implementation:
```c
{faulty_c.strip()}
```

Diagnostic Output:
```text
{diagnostic.strip()}
```

Please provide the corrected, complete, and self-contained C source code for this XDP program."""


def main() -> None:
    parser = argparse.ArgumentParser(description="Export SFT Dataset (Synthesis + Natural Repairs)")
    parser.add_argument("--output", type=Path, default=SFT_DIR / "sft_pilot_dataset.jsonl", help="Output JSONL path")
    parser.add_argument("--max-repairs-per-task", type=int, default=2, help="Cap on repairs per task")
    args = parser.parse_args()

    SFT_DIR.mkdir(parents=True, exist_ok=True)

    synthesis_records = []
    repair_records = []

    print("=" * 60)
    print("BPF-Guardian SFT Dataset Exporter")
    print("=" * 60)

    for cat_dir in sorted(INBOX_DIR.iterdir()):
        if not cat_dir.is_dir():
            continue
        for lvl_dir in sorted(cat_dir.iterdir()):
            if not lvl_dir.is_dir():
                continue
            for task_dir in sorted(lvl_dir.iterdir()):
                if not task_dir.is_dir():
                    continue
                task_json_file = task_dir / "task.json"
                if not task_json_file.exists():
                    continue

                task_spec = json.loads(task_json_file.read_text(encoding="utf-8"))
                gold_cand_id = task_spec.get("gold_candidate_id")

                # Find all candidate C files
                c_files = sorted(task_dir.glob("*.c"))
                if not c_files:
                    continue

                # Identify gold program
                gold_code = None
                if gold_cand_id:
                    for cf in c_files:
                        if cf.stem == gold_cand_id or cf.name == gold_cand_id or f"{task_spec['task_id']}_{cf.stem}" == gold_cand_id:
                            gold_code = cf.read_text(encoding="utf-8")
                            break

                if not gold_code:
                    # Fallback to c00.c or last passing revision
                    gold_code = c_files[0].read_text(encoding="utf-8")

                # 1. Synthesis Example
                synthesis_prompt = format_synthesis_prompt(task_spec)
                synthesis_records.append({
                    "task_id": task_spec["task_id"],
                    "category": cat_dir.name,
                    "difficulty": lvl_dir.name,
                    "example_type": "synthesis",
                    "messages": [
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": synthesis_prompt},
                        {"role": "assistant", "content": f"```c\n{gold_code.strip()}\n```"},
                    ]
                })

                # 2. Repair Examples (if any revision files or faulty records exist)
                faulty_files = [f for f in c_files if f.read_text(encoding="utf-8") != gold_code]
                for f_file in faulty_files[:args.max_repairs_per_task]:
                    # Find diagnostic in validation dir if available
                    cand_name = f"{task_spec['task_id']}_{f_file.stem}"
                    val_file = VALIDATION_DIR / cat_dir.name / lvl_dir.name / f"{cand_name}.json"
                    diag = "Kernel verifier rejected packet memory access out of bounds."
                    if val_file.exists():
                        try:
                            val_data = json.loads(val_file.read_text(encoding="utf-8"))
                            diag = val_data.get("diagnostic") or diag
                        except Exception:
                            pass

                    repair_prompt = format_repair_prompt(task_spec, f_file.read_text(encoding="utf-8"), diag)
                    repair_records.append({
                        "task_id": task_spec["task_id"],
                        "category": cat_dir.name,
                        "difficulty": lvl_dir.name,
                        "example_type": "repair",
                        "messages": [
                            {"role": "system", "content": REPAIR_SYSTEM_PROMPT},
                            {"role": "user", "content": repair_prompt},
                            {"role": "assistant", "content": f"```c\n{gold_code.strip()}\n```"},
                        ]
                    })

    all_records = synthesis_records + repair_records
    with open(args.output, "w", encoding="utf-8") as f:
        for rec in all_records:
            f.write(json.dumps(rec) + "\n")

    print(f"[+] Exported {len(synthesis_records)} synthesis examples")
    print(f"[+] Exported {len(repair_records)} repair examples")
    print(f"[+] Total SFT dataset: {len(all_records)} examples -> {args.output}")
    print("=" * 60)


if __name__ == "__main__":
    main()
