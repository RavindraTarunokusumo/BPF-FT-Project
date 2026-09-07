#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("result", type=Path)
    parser.add_argument("expected_decision", choices=["pass", "fail", "error", "skipped"])
    parser.add_argument("expected_stage", nargs="?", default=None)
    args = parser.parse_args()

    result = json.loads(args.result.read_text(encoding="utf-8"))
    actual_decision = result.get("decision")
    if actual_decision != args.expected_decision:
        raise SystemExit(
            f"{args.result}: expected decision {args.expected_decision}, got {actual_decision}"
        )

    if args.expected_stage is not None:
        actual_stage = result.get("first_failed_stage")
        if actual_stage != args.expected_stage:
            raise SystemExit(
                f"{args.result}: expected stage {args.expected_stage}, got {actual_stage}"
            )

    cleanup = result.get("cleanup", {})
    if actual_decision != "skipped":
        if cleanup.get("ok") is not True or cleanup.get("remaining_objects") != []:
            raise SystemExit(f"{args.result}: cleanup audit did not pass: {cleanup}")

    print(f"PASS assertion: {args.result.name} -> {actual_decision}")


if __name__ == "__main__":
    main()
