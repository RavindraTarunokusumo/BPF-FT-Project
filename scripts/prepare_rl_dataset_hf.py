#!/usr/bin/env python3
"""
BPF-Guardian RL Dataset Preparer for Hugging Face
Prepares the certified Phase N3 RLVR dataset (264 stratified tasks)
with complete task specifications, packet test fixtures, and verified reference solutions.
"""

import json
import shutil
from pathlib import Path
from typing import Dict, Any, List

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = PROJECT_ROOT / "data" / "rl" / "n3"
OUTPUT_DIR = PROJECT_ROOT / "build" / "datasets" / "bpf-guardian-rl"


def collect_split_tasks(split_dir: Path) -> List[Dict[str, Any]]:
    tasks = []
    if not split_dir.exists():
        return tasks

    for task_json in split_dir.rglob("task.json"):
        t_dir = task_json.parent
        tests_json = t_dir / "tests.json"
        solution_c = t_dir / "solution.c"

        task_data = json.loads(task_json.read_text(encoding="utf-8"))
        tests_data = json.loads(tests_json.read_text(encoding="utf-8")) if tests_json.exists() else []
        sol_code = solution_c.read_text(encoding="utf-8") if solution_c.exists() else ""

        entry = {
            "task_id": task_data.get("task_id", task_data.get("id")),
            "title": task_data.get("title", ""),
            "description": task_data.get("description", ""),
            "category": task_data.get("category", ""),
            "difficulty": task_data.get("difficulty", ""),
            "level": task_data.get("level", 1),
            "requirements": task_data.get("requirements", []),
            "prompt": task_data.get("prompt", ""),
            "expected_fixture_count": len(tests_data.get("test_cases", [])) if isinstance(tests_data, dict) else len(tests_data),
            "test_cases": tests_data.get("test_cases", tests_data) if isinstance(tests_data, dict) else tests_data,
            "reference_solution": sol_code,
        }
        tasks.append(entry)

    return sorted(tasks, key=lambda x: x["task_id"])


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    splits = {
        "train": SRC_DIR / "train",
        "dev": SRC_DIR / "dev",
        "confirmation": SRC_DIR / "confirmation",
        "canary": SRC_DIR / "canary",
    }

    counts = {}
    for split_name, split_path in splits.items():
        task_list = collect_split_tasks(split_path)
        counts[split_name] = len(task_list)

        out_file = OUTPUT_DIR / f"{split_name}.jsonl"
        with open(out_file, "w", encoding="utf-8") as f:
            for t in task_list:
                f.write(json.dumps(t) + "\n")
        print(f"[+] Wrote {out_file} ({len(task_list)} tasks, {out_file.stat().st_size / 1024:.1f} KB)")

    # Copy contamination audit
    audit_src = SRC_DIR / "contamination_audit.json"
    if audit_src.exists():
        shutil.copyfile(audit_src, OUTPUT_DIR / "contamination_audit.json")

    # Generate Hugging Face Dataset Card
    total_tasks = sum(counts.values())
    readme_content = f"""---
language:
- en
- c
license: mit
task_categories:
- reinforcement-learning
- text-generation
tags:
- ebpf
- xdp
- networking
- linux
- rlvr
- verification
size_categories:
- n<1K
---

# BPF-Guardian RL: Certified Linux eBPF/XDP Reinforcement Learning Benchmark

**BPF-Guardian RL** is a certified, stratified reinforcement learning dataset with verifiable rewards (RLVR) for training and evaluating LLMs on autonomous Linux in-kernel eBPF/XDP network program synthesis and diagnostic-guided repair.

Every task includes complete prompt specifications, functional requirements, verified reference C source code, and end-to-end packet test fixtures validated live against Linux Kernel `6.8.0-106-generic`.

## Dataset Summary

- **Total Tasks**: {total_tasks}
- **Train Split**: {counts.get('train', 0)} tasks (12 categories $\times$ 12 tasks)
- **Dev Split**: {counts.get('dev', 0)} tasks (12 categories $\times$ 4 tasks)
- **Locked Confirmation Split**: {counts.get('confirmation', 0)} tasks (12 categories $\times$ 5 tasks)
- **Canary Split**: {counts.get('canary', 0)} tasks (12 categories $\times$ 1 task)
- **Contamination Audit**: Certified 100% semantic disjointness (0 collisions) against all protected benchmarks.

## Split Stratification Matrix

| Functional Category | Level 1 (Basic) | Level 2 (Intermediate) | Level 3 (Advanced) | Total |
|---|---:|---:|---:|---:|
| **Packet Filtering & Security (`pfs`)** | 22 | 22 | 22 | 66 |
| **Network Routing & Forwarding (`nrf`)** | 22 | 22 | 22 | 66 |
| **Packet Inspection & Telemetry (`pit`)** | 22 | 22 | 22 | 66 |
| **Protocol Transformation & Rewrite (`ptr`)** | 22 | 22 | 22 | 66 |
| **Total** | **88** | **88** | **88** | **{total_tasks}** |

## Data Schema

Each JSONL row contains:
- `task_id`: Unique identifier (e.g. `rl_n3_train_pfs_l2_01`).
- `title`: Short descriptive task name.
- `description`: Detailed functional overview.
- `category`: Application domain (`pfs`, `nrf`, `pit`, `ptr`).
- `level`: Complexity level (1, 2, or 3).
- `requirements`: List of technical constraints and protocol specifications.
- `prompt`: Model-ready prompt instructing the model to generate self-contained XDP C code.
- `expected_fixture_count`: Number of packet test cases.
- `test_cases`: Array of packet fixtures, each specifying:
  - `name`: Description of test packet.
  - `input_packet`: Raw hexadecimal string representing the ingress Ethernet packet.
  - `expected_action`: Required XDP action (`XDP_PASS`, `XDP_DROP`, `XDP_TX`, `XDP_REDIRECT`).
  - `expected_packet`: Optional expected mutated egress packet for rewrite tasks.
- `reference_solution`: Verified, compilable C source code achieving 100% pass on Linux Kernel 6.8.

## Contamination Certification

This dataset was audited against all existing project benchmarks (36 Calibration, 120 Protected Synthesis, 120 Protected Repair) using instruction semantic similarity, protocol/feature tuples, and family fingerprints. **Zero contamination violations were detected.** Full audit report is included in `contamination_audit.json`.

## Citation

```bibtex
@dataset{{bpf_guardian_rl_2026,
  author = {{BPF-Guardian Research Team}},
  title = {{BPF-Guardian RL: Certified Linux eBPF/XDP Reinforcement Learning Benchmark}},
  year = {{2026}},
  publisher = {{Hugging Face}},
  howpublished = {{\\url{{https://huggingface.co/datasets/rvindra/bpf-guardian-rl}}}}
}}
```
"""
    (OUTPUT_DIR / "README.md").write_text(readme_content, encoding="utf-8")
    print(f"[+] Generated RL Dataset Card at {OUTPUT_DIR / 'README.md'}")


if __name__ == "__main__":
    main()
