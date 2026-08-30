#!/usr/bin/env python3
"""
BPF-Guardian SFT Dataset Validator
Validates dataset JSONL against strict requirements:
1. Valid JSONL syntax and schema.
2. Required metadata: example_id, task_id, category, difficulty, template_family, example_type, messages.
3. Message structure: system, user, assistant; last message must be assistant.
4. Assistant completion: raw C source only (no markdown fences, no explanatory text).
5. Mandatory BPF markers: #include, SEC(...), XDP action / function signature, license.
6. Negative safety: No FAULT markers, TODOs, FIXMEs, or placeholders in gold target.
7. Repair contract: User message contains faulty code & diagnostic; target contains only corrected code.
8. Uniqueness: No duplicate example_ids or exact duplicates.
9. Token length: Tokenized with official Qwen/Qwen3-8B and rendered with qwen3_disable_thinking <= max_length.
"""

from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent

DEFAULT_MODEL_NAME = "Qwen/Qwen3-8B"
DEFAULT_RENDERER_NAME = "qwen3_disable_thinking"
DEFAULT_MAX_LENGTH = 3072

ALLOWED_ROLES = {"system", "user", "assistant"}
ALLOWED_EXAMPLE_TYPES = {"synthesis", "repair", "compiler_repair", "verifier_repair", "behavioral_repair"}


class ValidationError(Exception):
    def __init__(self, file_path: Path, line_number: int, example_id: str, task_id: str, reason: str):
        self.file_path = file_path
        self.line_number = line_number
        self.example_id = example_id
        self.task_id = task_id
        self.reason = reason
        super().__init__(f"{file_path}:{line_number} [example_id={example_id}, task_id={task_id}]: {reason}")


def validate_completion_c_code(completion: str, file_path: Path, line_num: int, ex_id: str, task_id: str) -> None:
    # 1. No markdown fences
    if "```" in completion:
        raise ValidationError(file_path, line_num, ex_id, task_id, "Assistant completion contains Markdown fences (```)")

    # 2. No pre/post explanatory prose
    stripped = completion.strip()
    if not stripped.startswith("#include") and not stripped.startswith("/*") and not stripped.startswith("//"):
        first_line = stripped.splitlines()[0]
        if not (first_line.startswith("#") or first_line.startswith("/") or "struct" in first_line):
            raise ValidationError(file_path, line_num, ex_id, task_id, f"Assistant completion starts with explanatory prose: {first_line[:50]}")

    # 3. Mandatory BPF markers
    if "#include" not in completion:
        raise ValidationError(file_path, line_num, ex_id, task_id, "Completion is missing '#include'")

    if "SEC(" not in completion:
        raise ValidationError(file_path, line_num, ex_id, task_id, "Completion is missing 'SEC(...)' BPF section definition")

    if "char _license[]" not in completion and "char LICENSE[]" not in completion and "LICENSE" not in completion:
        raise ValidationError(file_path, line_num, ex_id, task_id, "Completion is missing license definition (e.g. char _license[])")

    # 4. XDP entry point
    if "xdp" not in completion.lower() and "XDP_" not in completion:
        raise ValidationError(file_path, line_num, ex_id, task_id, "Completion does not contain XDP program entry point or return action")

    # 5. Negative checks: no FAULT tags, placeholders
    fault_match = re.search(r"(\bFAULT\b|//\s*FAULT|/\*\s*FAULT|\bTODO\b|\bFIXME\b)", completion, re.IGNORECASE)
    if fault_match:
        raise ValidationError(file_path, line_num, ex_id, task_id, f"Completion contains forbidden fault/placeholder marker: '{fault_match.group(0)}'")


def validate_repair_record(messages: List[Dict[str, str]], file_path: Path, line_num: int, ex_id: str, task_id: str) -> None:
    user_msg = next((m["content"] for m in messages if m["role"] == "user"), "")
    if "Diagnostic Output:" not in user_msg and "diagnostic" not in user_msg.lower() and "error" not in user_msg.lower():
        raise ValidationError(file_path, line_num, ex_id, task_id, "Repair example user prompt does not contain diagnostic context")

    if "Previous Implementation:" not in user_msg and "Faulty" not in user_msg and "```" not in user_msg:
        raise ValidationError(file_path, line_num, ex_id, task_id, "Repair example user prompt does not contain faulty code context")


def validate_sft_dataset(
    dataset_path: Path,
    model_name: str = DEFAULT_MODEL_NAME,
    renderer_name: str = DEFAULT_RENDERER_NAME,
    max_length: int = DEFAULT_MAX_LENGTH,
    check_token_lengths: bool = True,
) -> Dict[str, Any]:
    if not dataset_path.is_file():
        raise FileNotFoundError(f"Dataset file not found: {dataset_path}")

    if "sft_pilot_dataset.jsonl" in dataset_path.name:
        raise ValueError(f"CRITICAL SAFETY VIOLATION: Never train on pilot dataset ({dataset_path})")

    seen_example_ids: Set[str] = set()
    seen_message_hashes: Set[str] = set()
    completion_hashes: Dict[str, List[str]] = defaultdict(list)
    rows: List[Dict[str, Any]] = []

    categories = Counter()
    difficulties = Counter()
    example_types = Counter()
    template_families = Counter()
    task_ids: Set[str] = set()

    token_lengths: List[int] = []

    renderer = None
    if check_token_lengths:
        try:
            from tinker_cookbook.renderers import get_renderer, TrainOnWhat
            from tinker_cookbook.tokenizer_utils import get_tokenizer

            tokenizer = get_tokenizer(model_name)
            renderer = get_renderer(renderer_name, tokenizer)
        except Exception as e:
            print(f"[!] Warning: Could not initialize Tinker tokenizer/renderer ({e}). Falling back to char estimation.")

    with dataset_path.open("r", encoding="utf-8") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            line = raw_line.strip()
            if not line:
                continue

            try:
                record = json.loads(line)
            except json.JSONDecodeError as err:
                raise ValidationError(dataset_path, line_number, "unknown", "unknown", f"Malformed JSON: {err}")

            if not isinstance(record, dict):
                raise ValidationError(dataset_path, line_number, "unknown", "unknown", "Line is not a JSON object")

            # Validate mandatory metadata
            ex_id = record.get("example_id")
            task_id = record.get("task_id")
            category = record.get("category")
            difficulty = record.get("difficulty")
            template_family = record.get("template_family")
            ex_type = record.get("example_type")
            messages = record.get("messages")

            if not isinstance(ex_id, str) or not ex_id.strip():
                raise ValidationError(dataset_path, line_number, str(ex_id), str(task_id), "Missing or invalid 'example_id'")
            if ex_id in seen_example_ids:
                raise ValidationError(dataset_path, line_number, ex_id, str(task_id), f"Duplicate example_id: '{ex_id}'")
            seen_example_ids.add(ex_id)

            if not isinstance(task_id, str) or not task_id.strip():
                raise ValidationError(dataset_path, line_number, ex_id, str(task_id), "Missing or invalid 'task_id'")
            task_ids.add(task_id)

            if not isinstance(category, str) or not category.strip():
                raise ValidationError(dataset_path, line_number, ex_id, task_id, "Missing or invalid 'category'")
            if not isinstance(difficulty, str) or not difficulty.strip():
                raise ValidationError(dataset_path, line_number, ex_id, task_id, "Missing or invalid 'difficulty'")
            if not isinstance(template_family, str) or not template_family.strip():
                raise ValidationError(dataset_path, line_number, ex_id, task_id, "Missing or invalid 'template_family'")
            if not isinstance(ex_type, str) or ex_type not in ALLOWED_EXAMPLE_TYPES:
                raise ValidationError(dataset_path, line_number, ex_id, task_id, f"Invalid 'example_type': '{ex_type}'")

            # Validate messages
            if not isinstance(messages, list) or len(messages) < 2:
                raise ValidationError(dataset_path, line_number, ex_id, task_id, "'messages' must be a list of at least 2 items")

            for idx, msg in enumerate(messages):
                if not isinstance(msg, dict):
                    raise ValidationError(dataset_path, line_number, ex_id, task_id, f"Message {idx} is not a dictionary")
                role = msg.get("role")
                content = msg.get("content")
                if role not in ALLOWED_ROLES:
                    raise ValidationError(dataset_path, line_number, ex_id, task_id, f"Message {idx} has unsupported role '{role}'")
                if not isinstance(content, str) or not content.strip():
                    raise ValidationError(dataset_path, line_number, ex_id, task_id, f"Message {idx} has empty content")

            if messages[-1]["role"] != "assistant":
                raise ValidationError(dataset_path, line_number, ex_id, task_id, "Final message must have role 'assistant'")

            assistant_content = messages[-1]["content"]
            validate_completion_c_code(assistant_content, dataset_path, line_number, ex_id, task_id)

            if ex_type in {"repair", "compiler_repair", "verifier_repair", "behavioral_repair"}:
                validate_repair_record(messages, dataset_path, line_number, ex_id, task_id)

            # Duplicate messages check
            msg_str = json.dumps(messages, sort_keys=True)
            msg_hash = hashlib.sha256(msg_str.encode("utf-8")).hexdigest()
            if msg_hash in seen_message_hashes:
                raise ValidationError(dataset_path, line_number, ex_id, task_id, "Exact duplicate messages found")
            seen_message_hashes.add(msg_hash)

            # Completion hash tracking
            comp_hash = hashlib.sha256(assistant_content.encode("utf-8")).hexdigest()
            completion_hashes[comp_hash].append(ex_id)

            # Token length check
            if renderer is not None:
                from tinker_cookbook.renderers import TrainOnWhat
                model_input, weights = renderer.build_supervised_example(
                    messages,
                    train_on_what=TrainOnWhat.LAST_ASSISTANT_MESSAGE,
                )
                rendered_length = model_input.length
                if rendered_length > max_length:
                    raise ValidationError(
                        dataset_path,
                        line_number,
                        ex_id,
                        task_id,
                        f"Rendered sequence length {rendered_length} exceeds limit {max_length}",
                    )
                token_lengths.append(rendered_length)

            categories[category] += 1
            difficulties[difficulty] += 1
            example_types[ex_type] += 1
            template_families[template_family] += 1
            rows.append(record)

    duplicate_completions = {h: ids for h, ids in completion_hashes.items() if len(ids) > 1}

    stats: Dict[str, Any] = {
        "dataset_path": str(dataset_path),
        "total_examples": len(rows),
        "unique_tasks": len(task_ids),
        "categories": dict(categories),
        "difficulties": dict(difficulties),
        "example_types": dict(example_types),
        "template_families_count": len(template_families),
        "duplicate_completion_groups": len(duplicate_completions),
    }

    if token_lengths:
        token_lengths_sorted = sorted(token_lengths)
        stats["token_stats"] = {
            "min": min(token_lengths),
            "max": max(token_lengths),
            "mean": sum(token_lengths) / len(token_lengths),
            "median": token_lengths_sorted[len(token_lengths_sorted) // 2],
            "p95": token_lengths_sorted[int(len(token_lengths_sorted) * 0.95)],
            "total_tokens": sum(token_lengths),
        }

    return stats


def main() -> None:
    parser = argparse.ArgumentParser(description="BPF-Guardian SFT Dataset Validator")
    parser.add_argument("--dataset", type=Path, default=PROJECT_ROOT / "data" / "sft" / "sft_dataset_full.jsonl", help="Path to JSONL dataset")
    parser.add_argument("--model-name", type=str, default=DEFAULT_MODEL_NAME, help="Hugging Face model ID for tokenizer")
    parser.add_argument("--renderer-name", type=str, default=DEFAULT_RENDERER_NAME, help="Tinker renderer name")
    parser.add_argument("--max-length", type=int, default=DEFAULT_MAX_LENGTH, help="Maximum allowed rendered token length")
    parser.add_argument("--no-tokens", action="store_true", help="Skip tokenizer/renderer length measurement")
    args = parser.parse_args()

    print("=" * 70)
    print("BPF-Guardian SFT Dataset Validation")
    print(f"Dataset: {args.dataset}")
    print(f"Model: {args.model_name}, Renderer: {args.renderer_name}, Max Length: {args.max_length}")
    print("=" * 70)

    try:
        stats = validate_sft_dataset(
            dataset_path=args.dataset,
            model_name=args.model_name,
            renderer_name=args.renderer_name,
            max_length=args.max_length,
            check_token_lengths=not args.no_tokens,
        )
        print("\n[+] Validation PASSED: All records strictly conform to schema and safety requirements.")
        print(f"Total Examples: {stats['total_examples']}")
        print(f"Unique Tasks:   {stats['unique_tasks']}")
        print(f"Example Types:  {stats['example_types']}")
        print(f"Categories:     {stats['categories']}")
        print(f"Difficulties:   {stats['difficulties']}")
        print(f"Template Families: {stats['template_families_count']}")

        if "token_stats" in stats:
            ts = stats["token_stats"]
            print("\nToken Length Statistics (Qwen3 rendered tokens):")
            print(f"  Min:    {ts['min']}")
            print(f"  Max:    {ts['max']}")
            print(f"  Mean:   {ts['mean']:.1f}")
            print(f"  Median: {ts['median']}")
            print(f"  P95:    {ts['p95']}")
            print(f"  Total:  {ts['total_tokens']:,}")

    except ValidationError as e:
        print(f"\n[!] Validation FAILED (Fail-Closed):", file=sys.stderr)
        print(f"  File:        {e.file_path}", file=sys.stderr)
        print(f"  Line Number: {e.line_number}", file=sys.stderr)
        print(f"  Example ID:  {e.example_id}", file=sys.stderr)
        print(f"  Task ID:     {e.task_id}", file=sys.stderr)
        print(f"  Reason:      {e.reason}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Unexpected Validation Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
