# BPF-Guardian Master Evaluation Summary & Empirical Benchmark Report

**Checkpoint**: `tinker://9461002d-2321-5858-8184-5604f9304283:train:0/sampler_weights/final`  
**Base Model**: `Qwen/Qwen3-8B`  
**Renderer**: `qwen3_disable_thinking`  
**Sampling Configuration**: `temperature=0.0`, `seed=42`, `num_samples=1`, `max_tokens=2048`  
**Live Verification Host**: Linux VPS (`Linux 6.8.0-106-generic x86_64`, Clang 18, `bpftool v7.4.0`, `BPF_PROG_TEST_RUN`)

---

## 1. Master Empirical Summary (Pre-SFT vs SFT v1 vs SFT v2)

| Benchmark Suite | Pre-SFT Baseline | SFT v1 Model | SFT v2 Model (Final) | Absolute Gain (v2 vs v1) | Paired McNemar $p$-value |
|---|:---:|:---:|:---:|:---:|:---:|
| **Output Compliance Rate** | 22.2% (8/36) | 100.0% (276/276) | **100.0%** (276/276) | +0.0% | N/A |
| **Calibration Suite (Pass@1)** | 8.3% (3/36) | 55.6% (20/36) | **58.3%** (21/36) | **+2.7%** | $p = 1.0000$ |
| **Private Synthesis Benchmark (120 Tasks)** | 0.0% (0/120) | 15.8% (19/120) | **25.8%** (31/120) | **+10.0%** | **$p = 0.0169$** |
| &bull; *Clang BPF Compilation* | 11.7% (14/120) | 40.8% (49/120) | **54.2%** (65/120) | **+13.4%** | $p = 0.0039$ |
| &bull; *Kernel Verifier Acceptance* | 4.2% (5/120) | 25.8% (31/120) | **38.3%** (46/120) | **+12.5%** | $p = 0.0077$ |
| **Private Standalone Repair Benchmark (120 Tasks)** | 9.1% (11/120) | 62.5% (75/120) | **70.8%** (85/120) | **+8.3%** | **$p = 0.0213$** |
| &bull; *Clang BPF Compilation* | 32.5% (39/120) | 84.2% (101/120) | **91.7%** (110/120) | **+7.5%** | $p = 0.0269$ |
| &bull; *Kernel Verifier Acceptance* | 25.0% (30/120) | 80.0% (96/120) | **88.3%** (106/120) | **+8.3%** | $p = 0.0159$ |
| **Global Functional Pass@1 (276 Tasks)** | **5.1%** (14/276) | **41.3%** (114/276) | **49.6%** (137/276) | **+8.3%** | **$p = 0.0014$** |

---

## 2. Controlled Synthesis Repair@1 & Solve@2

- **Initial Synthesis Pass@1**: **31 / 120** (25.8%)
- **Eligible Synthesis Failures Repaired**: **89 tasks**
- **Repair@1 Recoveries**: **12 / 89** (13.5%)
- **End-to-End Solve@2**: **43 / 120** (**35.8%**)
- **Absolute Solve@2 Gain**: **+10.0%** (+12 solved tasks)

---

## 3. Finalization Decision

> **SFT v2 is frozen as the final supervised-training checkpoint for this project. Further supervised fine-tuning is not recommended unless a future blind lockbox or controlled execution evaluation demonstrates a clear unmet objective.**

For detailed paired transition tables, failure breakdowns, and reproduction commands, see:
- [Consolidated SFT v2 Evaluation Report](file:///c:/Users/rvind/OneDrive/Desktop/Projects/BPF-FT-Project/runs/evaluation/qwen3-8b-full-sft-v2/benchmark_private_120_evaluation.md)
- [Paired SFT v1 $\to$ v2 Comparison & McNemar Analysis](file:///c:/Users/rvind/OneDrive/Desktop/Projects/BPF-FT-Project/runs/evaluation/qwen3-8b-full-sft-v2/paired_v1_v2_comparison.md)
- [Controlled Synthesis Repair@1 Report](file:///c:/Users/rvind/OneDrive/Desktop/Projects/BPF-FT-Project/runs/evaluation/qwen3-8b-full-sft-v2/benchmark-synthesis-120-repair1/repair1_report.md)
