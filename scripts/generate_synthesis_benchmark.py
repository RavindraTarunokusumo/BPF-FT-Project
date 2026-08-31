"""
Master Generator Driver for the 120-Task Private Synthesis Benchmark Dataset.
Generates:
  data/benchmark/synthesis/<category>/<difficulty>/<task_id>/task.json
  data/benchmark/synthesis/<category>/<difficulty>/<task_id>/tests.json
  data/benchmark/synthesis/<category>/<difficulty>/<task_id>/solution.c
  data/benchmark/synthesis/<category>/<difficulty>/<task_id>/fixtures/<test_name>.bin
  data/benchmark/synthesis/index.jsonl
"""

from __future__ import annotations

import binascii
import hashlib
import json
import os
import shutil
import sys
from typing import Any, Dict, List

sys.path.insert(0, os.path.abspath("."))

from scripts.synthesis_benchmark_gen.defs_packet_filtering_security import get_packet_filtering_security_tasks
from scripts.synthesis_benchmark_gen.defs_packet_inspection_telemetry import get_packet_inspection_telemetry_tasks
from scripts.synthesis_benchmark_gen.defs_protocol_transformation import get_protocol_transformation_tasks
from scripts.synthesis_benchmark_gen.defs_network_routing_forwarding import get_network_routing_forwarding_tasks


def sha256_file(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()


def generate_benchmark():
    base_output_dir = os.path.abspath("data/benchmark/synthesis")
    print(f"Target Directory: {base_output_dir}")

    # Gather tasks
    pfs_tasks = get_packet_filtering_security_tasks()
    pit_tasks = get_packet_inspection_telemetry_tasks()
    ptr_tasks = get_protocol_transformation_tasks()
    nrf_tasks = get_network_routing_forwarding_tasks()

    all_tasks = pfs_tasks + pit_tasks + ptr_tasks + nrf_tasks
    print(f"Loaded {len(all_tasks)} task definitions across 4 categories.")
    assert len(all_tasks) == 120, f"Expected 120 tasks, got {len(all_tasks)}"

    # Clean existing directory if present to avoid stale files
    if os.path.exists(base_output_dir):
        shutil.rmtree(base_output_dir)
    os.makedirs(base_output_dir, exist_ok=True)

    index_entries: List[Dict[str, Any]] = []

    for task in all_tasks:
        task_id = task["task_id"]
        category = task["application_category"]
        difficulty = task["difficulty"]

        task_dir = os.path.join(base_output_dir, category, difficulty, task_id)
        fixtures_dir = os.path.join(task_dir, "fixtures")
        os.makedirs(fixtures_dir, exist_ok=True)

        # 1. Write solution.c
        solution_c_path = os.path.join(task_dir, "solution.c")
        with open(solution_c_path, "w", encoding="utf-8") as f:
            f.write(task["solution_c"].strip() + "\n")

        # 2. Process tests and write binary fixtures
        processed_tests: List[Dict[str, Any]] = []
        fixture_hashes: Dict[str, str] = {}

        for t in task["tests"]:
            test_name = t["name"]
            pkt_hex = t["packet_hex"]
            pkt_bytes = bytes.fromhex(pkt_hex)
            fixture_filename = f"{test_name}.bin"
            fixture_path = os.path.join(fixtures_dir, fixture_filename)

            with open(fixture_path, "wb") as f:
                f.write(pkt_bytes)

            fix_hash = hashlib.sha256(pkt_bytes).hexdigest()
            fixture_hashes[fixture_filename] = fix_hash

            test_entry = {
                "name": test_name,
                "description": t.get("description", ""),
                "fixture_file": f"fixtures/{fixture_filename}",
                "packet_hex": pkt_hex,
                "packet_len": len(pkt_bytes),
                "expected_action": t.get("expected_action", "XDP_PASS"),
                "expected_output_hex": t.get("expected_output_hex"),
            }
            processed_tests.append(test_entry)

        # 3. Write tests.json
        tests_json_path = os.path.join(task_dir, "tests.json")
        tests_data = {
            "task_id": task_id,
            "main_validator": task.get("main_validator", "packet_action"),
            "test_count": len(processed_tests),
            "test_cases": processed_tests
        }
        with open(tests_json_path, "w", encoding="utf-8") as f:
            json.dump(tests_data, f, indent=2)

        # 4. Write task.json
        task_json_path = os.path.join(task_dir, "task.json")
        task_metadata = {
            "task_id": task_id,
            "application_category": category,
            "difficulty": difficulty,
            "task_family": task.get("task_family", ""),
            "template_family": task.get("template_family", ""),
            "semantic_signature": task.get("semantic_signature", ""),
            "split": task.get("split", "benchmark"),
            "learning_mode": task.get("learning_mode", "synthesis"),
            "instruction": task["instruction"],
            "requirements": task["requirements"],
            "test_fixtures": [
                {
                    "name": t["name"],
                    "fixture_file": t["fixture_file"],
                    "expected_action": t["expected_action"]
                }
                for t in processed_tests
            ]
        }
        with open(task_json_path, "w", encoding="utf-8") as f:
            json.dump(task_metadata, f, indent=2)

        # Compute file digests
        sol_sha = sha256_file(solution_c_path)
        tests_sha = sha256_file(tests_json_path)
        task_sha = sha256_file(task_json_path)

        # Relative path for index
        rel_task_dir = os.path.relpath(task_dir, base_output_dir).replace("\\", "/")

        index_entry = {
            "task_id": task_id,
            "application_category": category,
            "difficulty": difficulty,
            "task_family": task.get("task_family", ""),
            "template_family": task.get("template_family", ""),
            "semantic_signature": task.get("semantic_signature", ""),
            "split": task.get("split", "benchmark"),
            "learning_mode": task.get("learning_mode", "synthesis"),
            "relative_path": rel_task_dir,
            "test_count": len(processed_tests),
            "checksums": {
                "task_json": task_sha,
                "tests_json": tests_sha,
                "solution_c": sol_sha,
                "fixtures": fixture_hashes
            }
        }
        index_entries.append(index_entry)

    # 5. Write index.jsonl
    index_jsonl_path = os.path.join(base_output_dir, "index.jsonl")
    with open(index_jsonl_path, "w", encoding="utf-8") as f:
        for entry in index_entries:
            f.write(json.dumps(entry) + "\n")

    print(f"Successfully generated 120 tasks and {index_jsonl_path}!")


if __name__ == "__main__":
    generate_benchmark()
