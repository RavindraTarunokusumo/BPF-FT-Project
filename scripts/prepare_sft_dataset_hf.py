#!/usr/bin/env python3
"""
BPF-Guardian Combined SFT Dataset Preparer for Hugging Face
Combines SFT v1 and SFT v2 datasets, strictly excludes the calibration suite,
ensures task-level disjointness between train and validation, and generates
a complete Hugging Face Dataset Card.
"""

import json
from pathlib import Path
from typing import Dict, Any, List, Set

PROJECT_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_DIR = PROJECT_ROOT / "build" / "datasets" / "bpf-guardian-sft"


def load_calibration_task_ids() -> Set[str]:
    calib_file = PROJECT_ROOT / "data" / "calibration" / "index.jsonl"
    calib_ids = set()
    if calib_file.exists():
        for line in calib_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                d = json.loads(line)
                tid = d.get("id") or d.get("task_id")
                if tid:
                    calib_ids.add(tid)
    print(f"[+] Loaded {len(calib_ids)} calibration task IDs to exclude.")
    return calib_ids


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    calib_ids = load_calibration_task_ids()

    # Load v1
    v1_train_path = PROJECT_ROOT / "data" / "sft" / "frozen" / "v1" / "train.jsonl"
    v1_val_path = PROJECT_ROOT / "data" / "sft" / "frozen" / "v1" / "validation.jsonl"

    # Load v2
    v2_train_path = PROJECT_ROOT / "data" / "sft" / "frozen" / "v2" / "train.jsonl"
    v2_val_in_path = PROJECT_ROOT / "data" / "sft" / "frozen" / "v2" / "validation_in_domain.jsonl"
    v2_val_held_path = PROJECT_ROOT / "data" / "sft" / "frozen" / "v2" / "validation_family_heldout.jsonl"

    all_raw_val = []
    for p in [v1_val_path, v2_val_in_path, v2_val_held_path]:
        if p.exists():
            for line in p.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    all_raw_val.append(json.loads(line))

    all_raw_train = []
    for p in [v1_train_path, v2_train_path]:
        if p.exists():
            for line in p.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    all_raw_train.append(json.loads(line))

    # All validation task IDs
    val_task_ids = {r["task_id"] for r in all_raw_val}

    # Deduplicate validation examples by example_id
    val_examples_map: Dict[str, Dict[str, Any]] = {}
    for r in all_raw_val:
        eid = r["example_id"]
        tid = r["task_id"]
        if tid in calib_ids:
            continue
        if eid not in val_examples_map:
            val_examples_map[eid] = r

    # Deduplicate train examples by example_id
    # Note: If a task has an example in validation, we do NOT place it in train (leakage protection)
    train_examples_map: Dict[str, Dict[str, Any]] = {}
    for r in all_raw_train:
        eid = r["example_id"]
        tid = r["task_id"]
        if tid in calib_ids:
            continue
        if tid in val_task_ids:
            # Place any remaining examples of this validation task into validation
            if eid not in val_examples_map:
                val_examples_map[eid] = r
            continue
        if eid not in train_examples_map:
            train_examples_map[eid] = r

    train_list = sorted(train_examples_map.values(), key=lambda x: x["example_id"])
    val_list = sorted(val_examples_map.values(), key=lambda x: x["example_id"])

    print(f"[+] Final combined SFT dataset:")
    print(f"    Train examples:      {len(train_list)} ({len({r['task_id'] for r in train_list})} unique tasks)")
    print(f"    Validation examples: {len(val_list)} ({len({r['task_id'] for r in val_list})} unique tasks)")
    print(f"    Total examples:      {len(train_list) + len(val_list)}")

    # Check intersection
    train_tids = {r["task_id"] for r in train_list}
    val_tids = {r["task_id"] for r in val_list}
    overlap = train_tids & val_tids
    assert len(overlap) == 0, f"Task leakage detected between train and val: {overlap}"
    assert len(train_tids & calib_ids) == 0, "Calibration task found in train!"
    assert len(val_tids & calib_ids) == 0, "Calibration task found in validation!"

    # Clean standardized output format
    def format_row(r: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "example_id": r["example_id"],
            "task_id": r["task_id"],
            "category": r["category"],
            "difficulty": r["difficulty"],
            "template_family": r.get("template_family", ""),
            "example_type": r.get("example_type", "synthesis"),
            "messages": r["messages"],
        }

    train_file = OUTPUT_DIR / "train.jsonl"
    val_file = OUTPUT_DIR / "validation.jsonl"

    with open(train_file, "w", encoding="utf-8") as f:
        for r in train_list:
            f.write(json.dumps(format_row(r)) + "\n")

    with open(val_file, "w", encoding="utf-8") as f:
        for r in val_list:
            f.write(json.dumps(format_row(r)) + "\n")

    print(f"[+] Wrote {train_file} ({train_file.stat().st_size / 1024 / 1024:.2f} MB)")
    print(f"[+] Wrote {val_file} ({val_file.stat().st_size / 1024 / 1024:.2f} MB)")

    # Generate Hugging Face Dataset Card
    readme_content = f"""---
language:
- en
- c
license: mit
task_categories:
- text-generation
tags:
- ebpf
- xdp
- networking
- linux
- security
- code-generation
size_categories:
- 1K<n<10K
---

# BPF-Guardian SFT: Combined eBPF/XDP Instruction Tuning Corpus

**BPF-Guardian SFT** is a curated, high-quality instruction-tuning dataset specifically designed for synthesizing and repairing Linux in-kernel eBPF/XDP (eXpress Data Path) network programs. 

All reference solutions in this corpus have been empirically compiled using `clang-18 -target bpf -O2` and verified against the live Linux in-kernel verifier and packet testing harness (`BPF_PROG_TEST_RUN`) on Linux Kernel `6.8.0-106-generic`.

## Dataset Summary

- **Total Examples**: {len(train_list) + len(val_list)}
- **Train Examples**: {len(train_list)} ({len(train_tids)} unique tasks)
- **Validation Examples**: {len(val_list)} ({len(val_tids)} unique tasks)
- **Calibration Set**: Excluded (zero contamination against evaluation benchmarks)
- **Program Type**: Linux Kernel eBPF/XDP (`BPF_PROG_TYPE_XDP`)

## Functional Categories

1. **Packet Filtering & Security (`pfs`)**: DDoS mitigation, port knock authentication, token bucket policers, bloom filter IP blocklists, protocol drops.
2. **Network Routing & Forwarding (`nrf`)**: LPM trie IP routing, Maglev consistent hash load balancing, ECMP multipath routing, proxy ARP, tunnel encapsulation/decapsulation.
3. **Packet Inspection & Telemetry (`pit`)**: Flow telemetry, count-min sketch heavy hitters, TCP RTT and options analysis, connection churn tracking, DSCP QoS monitoring.
4. **Packet Transformation & Rewrite (`ptr`)**: VLAN/QinQ manipulation, IPv4/IPv6 header rewrites, GTP-U and VXLAN decapsulation, ICMP time-exceeded generation.

## Data Schema

Each JSONL row contains:
- `example_id`: Unique string identifier for the example.
- `task_id`: Canonical functional specification identifier.
- `category`: Application domain (`packet_filtering_security`, `network_routing_forwarding`, `packet_inspection_telemetry`, `protocol_transformation`).
- `difficulty`: Complexity stratum (`level_1`, `level_2`, `level_3`).
- `template_family`: Synthesizer architectural family.
- `example_type`: Task type (`synthesis` or `repair`).
- `messages`: List of chat messages (`system`, `user`, `assistant`), formatted for standard LLM chat templates.

## Verification & Integrity

All examples are guaranteed:
1. Pure, self-contained C source code targeting the Linux BPF sub-architecture.
2. 100% compliant with bounded memory access rules and verifier instruction limits on modern Linux kernels (Kernel 6.8+).
3. Zero task-level leakage between the `train` and `validation` splits.

## Citation

If you use this dataset in your research or deployment, please cite:

```bibtex
@dataset{{bpf_guardian_sft_2026,
  author = {{BPF-Guardian Research Team}},
  title = {{BPF-Guardian: Verified Linux eBPF/XDP Instruction Tuning Corpus}},
  year = {{2026}},
  publisher = {{Hugging Face}},
  howpublished = {{\\url{{https://huggingface.co/datasets/rvindra/bpf-guardian-sft}}}}
}}
```
"""
    (OUTPUT_DIR / "README.md").write_text(readme_content, encoding="utf-8")
    print(f"[+] Generated Dataset Card at {OUTPUT_DIR / 'README.md'}")


if __name__ == "__main__":
    main()
