#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate-id", required=True)
    parser.add_argument("--task-id", required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    manifest = {
        "schema_version": 1,
        "candidate_id": args.candidate_id,
        "task_id": args.task_id,
        "source_path": str(args.source),
        "source_sha256": hashlib.sha256(args.source.read_bytes()).hexdigest(),
        "authoring_harness": "acceptance_suite",
        "authoring_model": None,
        "generation_prompt_version": "acceptance-v1",
        "parent_candidate_id": None,
        "repair_attempt": 0,
        "claimed_status": "unvalidated",
    }
    args.output.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
