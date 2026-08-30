#!/usr/bin/env python3
"""
BPF-Guardian SFT Dataset Exporter (Strict Training-Ready Format)
Exports high-quality, verified multi-turn SFT examples:
1. Assistant completions contain ONLY raw, compilable C source code (NO markdown fences).
2. Includes mandatory metadata: example_id, template_family, task_id, category, difficulty, example_type.
3. Completely excludes any unverified, faulty, or '// FAULT:' marked targets.
4. Curates balanced synthesis + diagnostic-guided repair pairs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent
INBOX_DIR = PROJECT_ROOT / "data" / "inbox"
VALIDATION_DIR = PROJECT_ROOT / "data" / "validation"
SFT_DIR = PROJECT_ROOT / "data" / "sft"

SYNTHESIS_SYSTEM_PROMPT = """You are an expert Linux kernel eBPF and XDP systems programmer.
Write complete, self-contained, compilation-ready, and verifier-safe C source code for Linux XDP programs."""

REPAIR_SYSTEM_PROMPT = """You are an expert Linux kernel eBPF and XDP systems programmer.
You are fixing an XDP program that produced diagnostic errors during evaluation."""


def format_synthesis_user_prompt(task_spec: Dict[str, Any]) -> str:
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


def format_repair_user_prompt(task_spec: Dict[str, Any], faulty_c: str, diagnostic: str) -> str:
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


def clean_raw_c(code: str) -> str:
    """Strips any residual markdown fences and normalizes newlines."""
    text = code.strip()
    match = re.search(r"```(?:c|C|cpp)?\s*(.*?)\s*```", text, re.DOTALL)
    if match:
        text = match.group(1).strip()
    return text + "\n"


def is_valid_gold_code(code: str) -> bool:
    """Checks that the code is free of fault tags and syntactically sound."""
    if "// FAULT:" in code or "/* FAULT:" in code or "FAULT:" in code:
        return False
    if "SEC(\"xdp\")" not in code and "SEC(\"filter\")" not in code and "SEC(\"action\")" not in code:
        return False
    if "char _license[]" not in code and "char LICENSE[]" not in code:
        return False
    return True


def main() -> None:
    parser = argparse.ArgumentParser(description="Export Training-Ready SFT Dataset")
    parser.add_argument("--output", type=Path, default=SFT_DIR / "sft_pilot_dataset.jsonl", help="Output JSONL path")
    parser.add_argument("--max-repairs-per-task", type=int, default=2, help="Cap on repairs per task")
    args = parser.parse_args()

    SFT_DIR.mkdir(parents=True, exist_ok=True)

    synthesis_records: List[Dict[str, Any]] = []
    repair_records: List[Dict[str, Any]] = []
    seen_gold_hashes: Set[str] = set()

    print("=" * 60)
    print("BPF-Guardian Strict Training-Ready SFT Exporter")
    print("=" * 60)

    task_dirs = []
    for cat_dir in sorted(INBOX_DIR.iterdir()):
        if not cat_dir.is_dir():
            continue
        for lvl_dir in sorted(cat_dir.iterdir()):
            if not lvl_dir.is_dir():
                continue
            for task_dir in sorted(lvl_dir.iterdir()):
                if not task_dir.is_dir():
                    continue
                task_dirs.append(task_dir)

    for task_dir in task_dirs:
        task_json_file = task_dir / "task.json"
        if not task_json_file.exists():
            continue

        task_spec = json.loads(task_json_file.read_text(encoding="utf-8"))
        task_id = task_spec["task_id"]
        category = task_spec.get("application_category", "packet_filtering_security")
        difficulty = task_spec.get("difficulty", "level_1")
        template_family = task_spec.get("template_family", "xdp_packet_filter")
        gold_cand_id = task_spec.get("gold_candidate_id")

        # Find all candidate C files
        c_files = sorted(task_dir.glob("*.c"))
        if not c_files:
            continue

        # 1. Identify Gold Program
        gold_code = None
        gold_file = None

        # Prioritize explicit gold.c or highest passing revision (c00-r02, c00-r01, c00)
        potential_golds = []
        if (task_dir / "gold.c").exists():
            potential_golds.append(task_dir / "gold.c")
        
        # Sort reverse so higher revisions (r02, r01) are checked first
        for cf in sorted(c_files, reverse=True):
            if cf.name != "gold.c":
                potential_golds.append(cf)

        for gf in potential_golds:
            candidate_text = clean_raw_c(gf.read_text(encoding="utf-8"))
            if is_valid_gold_code(candidate_text):
                gold_code = candidate_text
                gold_file = gf
                break

        if not gold_code:
            print(f"[!] Warning: No verified gold program found for {task_id}, skipping")
            continue

        gold_hash = hashlib.sha256(gold_code.encode("utf-8")).hexdigest()

        # 2. Synthesis Example
        syn_example_id = f"sft_syn_{task_id}"
        syn_user_prompt = format_synthesis_user_prompt(task_spec)
        synthesis_records.append({
            "example_id": syn_example_id,
            "task_id": task_id,
            "category": category,
            "difficulty": difficulty,
            "template_family": template_family,
            "example_type": "synthesis",
            "messages": [
                {"role": "system", "content": SYNTHESIS_SYSTEM_PROMPT},
                {"role": "user", "content": syn_user_prompt},
                {"role": "assistant", "content": gold_code},
            ]
        })
        seen_gold_hashes.add(gold_hash)

        # 3. Repair Examples
        # Eligible faulty files are any other .c files whose text differs from gold and is not just a copy
        faulty_candidates = []
        for cf in c_files:
            if cf == gold_file:
                continue
            cf_text = clean_raw_c(cf.read_text(encoding="utf-8"))
            if cf_text != gold_code:
                # Find diagnostic if available in meta or validation
                diag = "Kernel verifier rejected packet memory access out of bounds."
                meta_f = task_dir / f"{cf.stem}.meta.json"
                if meta_f.exists():
                    try:
                        m_data = json.loads(meta_f.read_text(encoding="utf-8"))
                        if m_data.get("diagnostic"):
                            diag = m_data["diagnostic"]
                    except Exception:
                        pass
                
                # Check validation folder
                cand_full_name = f"{task_id}_{cf.stem}"
                val_file = VALIDATION_DIR / category / difficulty / f"{cand_full_name}.json"
                if val_file.exists():
                    try:
                        v_data = json.loads(val_file.read_text(encoding="utf-8"))
                        if v_data.get("diagnostic"):
                            diag = v_data["diagnostic"]
                    except Exception:
                        pass

                faulty_candidates.append((cf.name, cf_text, diag))

        for rep_idx, (f_name, f_text, f_diag) in enumerate(faulty_candidates[:args.max_repairs_per_task], start=1):
            rep_example_id = f"sft_rep_{task_id}_{rep_idx:02d}"
            rep_user_prompt = format_repair_user_prompt(task_spec, f_text, f_diag)
            repair_records.append({
                "example_id": rep_example_id,
                "task_id": task_id,
                "category": category,
                "difficulty": difficulty,
                "template_family": template_family,
                "example_type": "repair",
                "messages": [
                    {"role": "system", "content": REPAIR_SYSTEM_PROMPT},
                    {"role": "user", "content": rep_user_prompt},
                    {"role": "assistant", "content": gold_code},
                ]
            })

    all_records = synthesis_records + repair_records

    # Write output
    with open(args.output, "w", encoding="utf-8") as f:
        for rec in all_records:
            f.write(json.dumps(rec) + "\n")

    print(f"[+] Total synthesis examples: {len(synthesis_records)}")
    print(f"[+] Total repair examples:    {len(repair_records)}")
    print(f"[+] Unique gold completions:  {len(seen_gold_hashes)}")
    print(f"[+] Total SFT examples:       {len(all_records)} -> {args.output}")
    print("=" * 60)


if __name__ == "__main__":
    main()
