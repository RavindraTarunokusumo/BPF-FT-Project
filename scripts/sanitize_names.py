#!/usr/bin/env python3
"""
Sanitizes repository to remove specific model/harness names:
1. Moves data/inbox/antigravity/batch-001 to data/inbox/batch-001
2. Renames task directories xdp_antigravity_b01_* -> xdp_b01_*
3. Updates task.json, *.meta.json, validation records, scripts, and project plan
"""

from __future__ import annotations

import json
import os
import re
import shutil
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def main() -> None:
    # 1. Move inbox directory if data/inbox/antigravity exists
    old_inbox_antigravity = PROJECT_ROOT / "data" / "inbox" / "antigravity"
    new_inbox_root = PROJECT_ROOT / "data" / "inbox"
    old_batch_dir = old_inbox_antigravity / "batch-001"
    new_batch_dir = new_inbox_root / "batch-001"

    if old_batch_dir.exists():
        new_inbox_root.mkdir(parents=True, exist_ok=True)
        if new_batch_dir.exists():
            shutil.rmtree(new_batch_dir)
        shutil.move(str(old_batch_dir), str(new_batch_dir))
        print(f"[+] Moved {old_batch_dir} -> {new_batch_dir}")
        if old_inbox_antigravity.exists():
            shutil.rmtree(old_inbox_antigravity, ignore_errors=True)

    # 2. Rename task directories inside data/inbox/batch-001
    if new_batch_dir.exists():
        for task_dir in list(new_batch_dir.iterdir()):
            if task_dir.is_dir() and "xdp_antigravity_" in task_dir.name:
                new_task_name = task_dir.name.replace("xdp_antigravity_", "xdp_")
                new_task_path = task_dir.parent / new_task_name
                if new_task_path.exists():
                    shutil.rmtree(new_task_path)
                task_dir.rename(new_task_path)
                print(f"[+] Renamed dir {task_dir.name} -> {new_task_name}")

    # 3. Update task.json and *.meta.json inside data/inbox/batch-001
    if new_batch_dir.exists():
        for task_dir in sorted(new_batch_dir.iterdir()):
            if not task_dir.is_dir():
                continue
            
            # task.json
            task_json = task_dir / "task.json"
            if task_json.exists():
                text = task_json.read_text(encoding="utf-8")
                text = text.replace("xdp_antigravity_", "xdp_")
                text = text.replace("/inbox/antigravity/", "/inbox/")
                task_json.write_text(text, encoding="utf-8")
                print(f"[+] Updated {task_json.relative_to(PROJECT_ROOT)}")

            # *.meta.json
            for meta_file in sorted(task_dir.glob("*.meta.json")):
                data = json.loads(meta_file.read_text(encoding="utf-8"))
                if "candidate_id" in data:
                    data["candidate_id"] = data["candidate_id"].replace("xdp_antigravity_", "xdp_")
                if "task_id" in data:
                    data["task_id"] = data["task_id"].replace("xdp_antigravity_", "xdp_")
                if "parent_candidate_id" in data and data["parent_candidate_id"]:
                    data["parent_candidate_id"] = data["parent_candidate_id"].replace("xdp_antigravity_", "xdp_")
                if "failure_diagnostic" in data and data["failure_diagnostic"]:
                    data["failure_diagnostic"] = data["failure_diagnostic"].replace("xdp_antigravity_", "xdp_").replace("/inbox/antigravity/", "/inbox/")
                data["authoring_harness"] = "agent"
                data["authoring_model"] = "instruction_model"
                meta_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
                print(f"[+] Updated {meta_file.relative_to(PROJECT_ROOT)}")

    # 4. Rename and update validation records in data/validation/batch-001
    val_dir = PROJECT_ROOT / "data" / "validation" / "batch-001"
    if val_dir.exists():
        for val_file in list(val_dir.glob("*.json")):
            text = val_file.read_text(encoding="utf-8")
            text = text.replace("xdp_antigravity_", "xdp_")
            text = text.replace("/inbox/antigravity/", "/inbox/")
            
            new_file_name = val_file.name.replace("xdp_antigravity_", "xdp_")
            new_file_path = val_file.parent / new_file_name
            if val_file != new_file_path:
                val_file.unlink()
            new_file_path.write_text(text, encoding="utf-8")
            print(f"[+] Updated validation record {new_file_name}")

    # 5. Update scripts
    for script_name in [
        "scripts/validate_candidates.py",
        "scripts/generate_initial_batch.py",
        "scripts/generate_round1_repairs.py",
        "scripts/generate_round2_repairs.py",
        "scripts/update_gold_candidates.py",
    ]:
        script_path = PROJECT_ROOT / script_name
        if script_path.exists():
            text = script_path.read_text(encoding="utf-8")
            text = text.replace("xdp_antigravity_", "xdp_")
            text = text.replace("/inbox/antigravity/", "/inbox/")
            text = text.replace('PROJECT_ROOT / "data" / "inbox" / "antigravity"', 'PROJECT_ROOT / "data" / "inbox"')
            text = text.replace('INBOX_DIR = PROJECT_ROOT / "data" / "inbox" / "antigravity"', 'INBOX_DIR = PROJECT_ROOT / "data" / "inbox"')
            text = text.replace('"authoring_harness": "antigravity"', '"authoring_harness": "agent"')
            text = text.replace('"authoring_model": "gemini-3.7-flash"', '"authoring_model": "instruction_model"')
            script_path.write_text(text, encoding="utf-8")
            print(f"[+] Updated {script_name}")

    # 6. Update project plan
    plan_path = PROJECT_ROOT / "BPF_Guardian_Tinker_Qwen3_8B_Project_Plan.md"
    if plan_path.exists():
        plan_text = plan_path.read_text(encoding="utf-8")
        plan_text = plan_text.replace("Claude Code, Codex, Antigravity, and the Grok coding harness", "Coding harnesses and autonomous agents")
        plan_text = plan_text.replace("Claude Code, Codex, Antigravity, and Grok", "Coding-agent harnesses")
        plan_text = plan_text.replace("Claude Code, Codex, Antigravity, Grok", "Coding-agent harnesses")
        plan_text = plan_text.replace('| Claude Code | Complete task/reference/test bundles | Difficult verifier repairs |', '| Harness Tier A | Complete task/reference/test bundles | Difficult verifier repairs |')
        plan_text = plan_text.replace('| Codex | Bounds checks, byte order, maps, and evaluator review | Find reward and test loopholes |', '| Harness Tier B | Bounds checks, byte order, maps, and evaluator review | Find reward and test loopholes |')
        plan_text = plan_text.replace('| Antigravity | Systematic task diversity and repository-scale variants | Coverage and clarity review |', '| Harness Tier C | Systematic task diversity and repository-scale variants | Coverage and clarity review |')
        plan_text = plan_text.replace('| Grok | Adversarial candidates, mutations, and unusual failure modes | Diagnostic-based repair |', '| Harness Tier D | Adversarial candidates, mutations, and unusual failure modes | Diagnostic-based repair |')
        plan_text = plan_text.replace('"authoring_harness": "codex"', '"authoring_harness": "agent"')
        plan_path.write_text(plan_text, encoding="utf-8")
        print(f"[+] Updated {plan_path.name}")

    print("Sanitization complete.")


if __name__ == "__main__":
    main()
