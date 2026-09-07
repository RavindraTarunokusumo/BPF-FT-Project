#!/usr/bin/env python3
"""
Export Nemotron PEFT LoRA Adapters from Tinker and Upload to Hugging Face Hub
Exports:
1. SFT v1 Checkpoint (Winner of Phase N2)
2. RL N3 Checkpoint (Winner of Phase N3 Multi-Turn RLVR)
Uploads to:
- rvindra/nemotron-3.5-lightning-bpf-guardian
"""

import socket
orig_getaddrinfo = socket.getaddrinfo
def getaddrinfo_v4(*args, **kwargs):
    responses = orig_getaddrinfo(*args, **kwargs)
    return [r for r in responses if r[0] == socket.AF_INET]
socket.getaddrinfo = getaddrinfo_v4

import json
import os
import shutil
import sys
import time
from pathlib import Path
from huggingface_hub import HfApi

sys.stdout.reconfigure(line_buffering=True)
sys.stderr.reconfigure(line_buffering=True)

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Load .env
env_file = PROJECT_ROOT / ".env"
if env_file.exists():
    for line in env_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ[k.strip()] = v.strip().strip("\"'")

sys.path.insert(0, str(PROJECT_ROOT))

from training.export_tinker_adapter import export_adapter

BASE_MODEL = "nvidia/NVIDIA-Nemotron-3.5-Lightning-30B-A3B-BF16"
SFT_CHECKPOINT = "tinker://8dd51b37-9331-52a3-b929-3a8ad0b731c2:train:0/sampler_weights/final"
RL_CHECKPOINT = "tinker://ce5306da-21ee-5f14-b455-99b0662f9b45:train:0/sampler_weights/final"

BUILD_MODEL_DIR = PROJECT_ROOT / "build" / "models" / "nemotron-3.5-lightning-bpf-guardian"


def generate_model_card(output_dir: Path, branch: str = "main") -> None:
    # Copy visual asset charts to model repo assets/
    assets_dir = output_dir / "assets"
    assets_dir.mkdir(parents=True, exist_ok=True)
    for img_name in ["performance_hero_bar.png", "performance_progression.png", "domain_breakdown.png"]:
        src = PROJECT_ROOT / "docs" / "assets" / img_name
        if src.exists():
            shutil.copyfile(src, assets_dir / img_name)

    readme_content = r"""---
language:
- en
- code
license: mit
base_model: nvidia/NVIDIA-Nemotron-3.5-Lightning-30B-A3B-BF16
library_name: peft
tags:
- ebpf
- xdp
- networking
- linux
- lora
- code-generation
- reinforcement-learning
- rlvr
pipeline_tag: text-generation
---

# Nemotron-3.5-Lightning-30B BPF-Guardian: Verified In-Kernel eBPF/XDP Generation

**Nemotron-3.5-Lightning-30B BPF-Guardian** is a specialized eBPF/XDP coding model and PEFT LoRA adapter for `nvidia/NVIDIA-Nemotron-3.5-Lightning-30B-A3B-BF16`, trained and verified against live Linux In-Kernel Verifiers (`BPF_PROG_LOAD`) and dynamic packet execution harnesses (`BPF_PROG_TEST_RUN`) on Linux Kernel `6.8.0-106-generic`.

It achieves our best result to date on the project's held-out in-kernel eBPF/XDP benchmark, outperforming dense 8B baselines by **+90.3% relative gain** on protected synthesis benchmarks.

> 🚀 **Interactive Visual Showcase**: [Launch Live Architecture & Workflow Dashboard ↗](https://ravindratarunokusumo.github.io/BPF-FT-Project/)  
> *(Displays live interactive pipeline diagrams, dataset breakdowns, benchmark figures, and in-kernel test logs)*

---

## Visual Performance Progression

![BPF-Guardian Benchmark Performance Across Training Stages](assets/performance_hero_bar.png)

![4-Panel Detailed Suite Breakdown](assets/performance_progression.png)

![Domain Robustness and Complexity Scaling](assets/domain_breakdown.png)

---

## Performance Highlights (Live Linux Kernel 6.8 VPS Execution)

| Evaluation Benchmark | Benchmark Size | Base Nemotron 30B | Prior Baseline (Qwen3-8B SFT v2) | Nemotron BPF-Guardian SFT v1 | Nemotron BPF-Guardian RL (Solve@2) | Relative Improvement |
|---|---:|---:|---:|---:|---:|---:|
| **Protected Private Synthesis** | 120 tasks | 0 / 120 (0.0%) | 31 / 120 (25.8%) | 54 / 120 (45.0%) | **59 / 120 (49.2%)** | **+90.3%** |
| **Protected Standalone Repair** | 120 tasks | 79 / 120 (65.8%) | 85 / 120 (70.8%) | **91 / 120 (75.8%)** | **91 / 120 (75.8%)** | **+7.1%** |
| **Confirmation Suite** | 60 tasks | 20 / 60 (33.3%) | 33 / 60 (55.0%) | 42 / 60 (70.0%) | **44 / 60 (73.3%)** | **+33.3%** |
| **N3 Stratified Dev Suite** | 48 tasks | &mdash; | 18 / 48 (37.5%) | 24 / 48 (50.0%) | **23 / 48 (47.9%)** | **+27.7%** |
| **Combined Protected Suite** | **276 tasks** | 79 / 276 (28.6%) | 137 / 276 (49.6%) | **168 / 276 (60.9%)** | **172 / 276 (62.3%)** | **+25.6%** |

*All results verified with zero mock verifiers using `clang-18 -target bpf -O2` and kernel execution on Linux 6.8.0-106-generic. Paired McNemar test on combined suite confirms statistical significance ($p = 1.38 \times 10^{-5}$, $p < 0.0001$).*

---

## Available Checkpoints & Branches

- **`main`**: **Nemotron SFT v1** checkpoint (optimized for standalone synthesis and repair, 75.8% repair pass rate, 168/276 on combined benchmark).
- **`rl-n3`**: **Nemotron RL N3** checkpoint (optimized for two-turn interactive repair with compiler/verifier feedback, **49.2% Solve@2** on protected synthesis, **73.3%** on confirmation).

---

## Live In-Kernel Verification Pipeline

Every generated XDP program undergoes strict 4-stage validation:

```
[Candidate C Code]
       │
       ▼
1. Structural Lint & Sanitization (SEC("xdp") header, helper verification)
       │
       ▼
2. Compilation (clang-18 -target bpf -O2 -g -Wall -Werror)
       │
       ▼
3. In-Kernel Verifier Check (bpftool prog load into Linux 6.8.0-106-generic)
       │
       ▼
4. Dynamic Packet Execution (BPF_PROG_TEST_RUN socket test fixtures)
       │
       ├── PASS: Reward = 1.0 (Pass@1)
       └── FAIL: Extract standardized compiler / verifier / assertion diff diagnostic
             │
             ▼
[Turn 2: Repaired Code] ──► Re-run Stages 1-4 ──► PASS: Reward = 0.9 (Solve@2)
```

---

## Published Datasets

- **[`rvindra/bpf-guardian-sft`](https://huggingface.co/datasets/rvindra/bpf-guardian-sft)**: Combined instruction-tuning corpus merging v1 and v2 synthesis and repair datasets (**2,320 examples**: 1,913 train / 407 val). Strictly audited with 0% calibration benchmark overlap.
- **[`rvindra/bpf-guardian-rl`](https://huggingface.co/datasets/rvindra/bpf-guardian-rl)**: Certified **264-task RLVR benchmark** with raw packet hex fixtures and expected XDP verdicts. Packaged with formal `contamination_audit.json`.

---

## Functional Capabilities

The model synthesizes pure, self-contained, and kernel-verified C code across four core network programming domains:
1. **Packet Filtering & Security (`pfs`)**: DDoS defenses, port knocking state machines, token bucket policers, bloom filters.
2. **Network Routing & Forwarding (`nrf`)**: Maglev consistent hashing, ECMP multipath routers, LPM trie routing, proxy ARP, tunnel encapsulation.
3. **Packet Inspection & Telemetry (`pit`)**: Heavy hitters (Count-Min Sketch), flow telemetry, TCP RTT and options analysis.
4. **Packet Transformation & Rewrite (`ptr`)**: VLAN/QinQ manipulation, GTP-U/VXLAN decapsulation, IPv4/IPv6 header rewrites.

---

## Usage with PEFT & Transformers

```python
import torch
from transformers import AutoTokenizer, AutoModelForCausalLM
from peft import PeftModel

base_model_id = "nvidia/NVIDIA-Nemotron-3.5-Lightning-30B-A3B-BF16"
peft_model_id = "rvindra/nemotron-3.5-lightning-bpf-guardian"

tokenizer = AutoTokenizer.from_pretrained(base_model_id)
base_model = AutoModelForCausalLM.from_pretrained(
    base_model_id,
    torch_dtype=torch.bfloat16,
    device_map="auto"
)

# Load SFT model (revision="main") or RL model (revision="rl-n3")
model = PeftModel.from_pretrained(base_model, peft_model_id, revision="rl-n3")

prompt = \"\"\"You are an expert Linux kernel eBPF developer. Write a complete, self-contained XDP C program that inspects incoming IPv4 TCP packets, extracts the destination port, and drops packets targeting port 8080.
Output ONLY the raw C source code. Do not wrap with markdown code fences.\"\"\"

messages = [
    {"role": "system", "content": "You are an expert Linux kernel eBPF developer. Output ONLY valid, compilable C code."},
    {"role": "user", "content": prompt}
]

inputs = tokenizer.apply_chat_template(messages, return_tensors="pt", add_generation_prompt=True).to("cuda")
outputs = model.generate(inputs, max_new_tokens=2048, do_sample=False)
print(tokenizer.decode(outputs[0][inputs.shape[1]:], skip_special_tokens=True))
```

---

## Training Methodology

- **Base Architecture**: Nemotron-3.5-Lightning (30B Total Parameters, 3.5B Active Parameters per token MoE).
- **LoRA Configuration**: Rank 32, Alpha 64, Target Modules: all attention and MLP projections (`q_proj`, `k_proj`, `v_proj`, `o_proj`, `gate_proj`, `up_proj`, `down_proj`).
- **SFT Stage**: 3 epochs on 1,600 verified instruction-tuning examples with family-heldout cross-validation.
- **RL Stage**: 30 steps of Importance Sampling RLVR with live Linux kernel verifier rewards and $\beta = 0.05$ KL regularization.

---

## Acknowledgements

- **Compute**: Fine-tuned and evaluated via [Thinking Machines](https://thinkingmachines.ai/).

---

## Citation

```bibtex
@misc{nemotron_bpf_guardian_2026,
  author = {Tarunokusumo, Ravindra},
  title = {Nemotron-3.5-Lightning BPF-Guardian: Verified In-Kernel eBPF/XDP Generation},
  year = {2026},
  publisher = {Hugging Face},
  howpublished = {\url{https://huggingface.co/rvindra/nemotron-3.5-lightning-bpf-guardian}}
}
```
"""
    (output_dir / "README.md").write_text(readme_content, encoding="utf-8")


def upload_with_retries(api, **kwargs):
    max_retries = 5
    for attempt in range(1, max_retries + 1):
        try:
            print(f"[+] Upload attempt {attempt}/{max_retries}...")
            return api.upload_folder(**kwargs)
        except Exception as e:
            print(f"[-] Upload attempt {attempt} failed: {e}")
            if attempt == max_retries:
                raise
            time.sleep(3 * attempt)


def main():
    print("=" * 70)
    print("Exporting and Uploading Nemotron Models to Hugging Face Hub")
    print("=" * 70)

    BUILD_MODEL_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Export SFT v1 (Primary / main branch)
    print("\n[+] Exporting SFT v1 Adapter from Tinker...")
    export_adapter(
        checkpoint_url=SFT_CHECKPOINT,
        output_dir=BUILD_MODEL_DIR,
        base_model=BASE_MODEL,
        lora_rank=32,
    )

    generate_model_card(BUILD_MODEL_DIR)

    api = HfApi()

    # Upload to main branch
    print(f"\n[+] Uploading SFT v1 to rvindra/nemotron-3.5-lightning-bpf-guardian (branch: main)...")
    upload_with_retries(
        api,
        folder_path=str(BUILD_MODEL_DIR),
        repo_id="rvindra/nemotron-3.5-lightning-bpf-guardian",
        repo_type="model",
        commit_message="Initial release: Nemotron-3.5-Lightning BPF-Guardian SFT v1 adapter (1.47 GB)",
    )
    print("[+] Successfully uploaded SFT v1 to main branch!")

    # 2. Export RL N3 checkpoint to separate staging directory
    rl_build_dir = PROJECT_ROOT / "build" / "models" / "nemotron-rl-n3"
    rl_build_dir.mkdir(parents=True, exist_ok=True)

    print("\n[+] Exporting RL N3 Adapter from Tinker...")
    export_adapter(
        checkpoint_url=RL_CHECKPOINT,
        output_dir=rl_build_dir,
        base_model=BASE_MODEL,
        lora_rank=32,
    )
    generate_model_card(rl_build_dir)

    # Create 'rl-n3' branch and upload
    print(f"\n[+] Creating 'rl-n3' branch on rvindra/nemotron-3.5-lightning-bpf-guardian...")
    try:
        api.create_branch(
            repo_id="rvindra/nemotron-3.5-lightning-bpf-guardian",
            branch="rl-n3",
            repo_type="model",
            exist_ok=True,
        )
    except Exception as e:
        print(f"[-] Branch notice: {e}")

    print(f"[+] Uploading RL N3 to rvindra/nemotron-3.5-lightning-bpf-guardian (branch: rl-n3)...")
    upload_with_retries(
        api,
        folder_path=str(rl_build_dir),
        repo_id="rvindra/nemotron-3.5-lightning-bpf-guardian",
        repo_type="model",
        revision="rl-n3",
        commit_message="Release: Nemotron-3.5-Lightning BPF-Guardian RL N3 multi-turn repair adapter (1.47 GB)",
    )
    print("[+] Successfully uploaded RL N3 to branch 'rl-n3'!")


if __name__ == "__main__":
    main()
