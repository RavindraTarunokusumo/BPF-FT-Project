#!/usr/bin/env python3
"""
Upload updated Model Card and assets to Hugging Face model repo.
"""

import socket
orig_getaddrinfo = socket.getaddrinfo
def getaddrinfo_v4(*args, **kwargs):
    responses = orig_getaddrinfo(*args, **kwargs)
    return [r for r in responses if r[0] == socket.AF_INET]
socket.getaddrinfo = getaddrinfo_v4

import os
from pathlib import Path
from huggingface_hub import HfApi

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Load .env
env_file = PROJECT_ROOT / ".env"
if env_file.exists():
    for line in env_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ[k.strip()] = v.strip().strip("\"'")

token = os.environ.get("HF_TOKEN") or os.environ.get("HUGGINGFACE_TOKEN")
if not token:
    raise ValueError("No HF_TOKEN found in environment")

api = HfApi(token=token)
repo_id = "rvindra/nemotron-3.5-lightning-bpf-guardian"

# Upload to main and rl-n3
from export_and_upload_model_hf import generate_model_card, upload_with_retries

temp_dir = PROJECT_ROOT / "build" / "models" / "nemotron-3.5-lightning-bpf-guardian"
temp_dir.mkdir(parents=True, exist_ok=True)
generate_model_card(temp_dir, branch="main")

readme_path = temp_dir / "README.md"
assets_dir = PROJECT_ROOT / "docs" / "assets"

for branch in ["main", "rl-n3"]:
    print(f"[+] Uploading updated README.md & assets to {repo_id} (branch: {branch})...")
    upload_with_retries(
        api,
        folder_path=str(temp_dir),
        repo_id=repo_id,
        repo_type="model",
        revision=branch,
        commit_message="docs(model_card): update terminology to specialized coding model and modest benchmark references"
    )

print("[✓] Finished updating Hugging Face model cards and assets successfully!")
