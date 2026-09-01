# Qwen3-8B SFT v2: Empirical Linux Kernel Benchmark Evaluation Report

**Evaluation Date**: 2026-09-02  
**Evaluated Checkpoint**: `tinker://9461002d-2321-5858-8184-5604f9304283:train:0/sampler_weights/final`  
**Base Model**: `Qwen/Qwen3-8B`  
**Renderer**: `qwen3_disable_thinking`  
**Sampling Configuration**: `temperature=0.0`, `seed=42`, `num_samples=1`, `max_tokens=2048`  
**Verification Host**: Hostinger Remote Linux VPS (`Linux srv1534562 6.8.0-106-generic x86_64`, Clang 18, `bpftool v7.3`, `BPF_PROG_TEST_RUN`)  
**Evaluation Scope**: Calibration Suite (36 tasks) + Private Synthesis Benchmark (120 tasks) + Private Repair Benchmark (120 tasks) = **276 Total Evaluation Tasks**

---

## 1. Master Empirical Comparison Matrix (Pre-SFT Baseline vs. SFT v1 vs. SFT v2)

All evaluations were executed live against the Linux 6.8 kernel verifier and actual packet test harness on the dedicated verification VPS:

| Evaluation Suite / Metric | Pre-SFT Baseline | SFT v1 Model | SFT v2 Model (Current) | Absolute Gain (v2 vs. v1) | Absolute Gain (v2 vs. Baseline) |
|---|:---:|:---:|:---:|:---:|:---:|
| **Output Compliance Rate** | 22.2% (8/36) | 100.0% (276/276) | **100.0%** (276/276) | +0.0% | **+77.8%** |
| **Calibration Set (Synthesis Pass@1)** | 8.3% (3/36) | 55.6% (20/36) | **58.3%** (21/36) | **+2.7%** | **+50.0%** |
| **Private Synthesis Benchmark (120 Tasks)** | 0.0% (0/120) | 15.8% (19/120) | **25.8%** (31/120) | **+10.0%** | **+25.8%** |
| &bull; *Clang BPF Compilation* | 11.7% (14/120) | 40.8% (49/120) | **54.2%** (65/120) | **+13.4%** | **+42.5%** |
| &bull; *Kernel Verifier Pass* | 4.2% (5/120) | 25.8% (31/120) | **38.3%** (46/120) | **+12.5%** | **+34.1%** |
| **Private Repair Benchmark (120 Tasks)** | 9.1% (11/120) | 62.5% (75/120) | **70.8%** (85/120) | **+8.3%** | **+61.7%** |
| &bull; *Clang BPF Compilation* | 32.5% (39/120) | 84.2% (101/120) | **91.7%** (110/120) | **+7.5%** | **+59.2%** |
| &bull; *Kernel Verifier Pass* | 25.0% (30/120) | 80.0% (96/120) | **88.3%** (106/120) | **+8.3%** | **+63.3%** |
| **Global Functional Pass@1 (All 276 Tasks)** | **5.1%** (14/276) | **41.3%** (114/276) | **50.0%** (138/276) | **+8.7%** | **+44.9%** |

---

## 2. 120-Task Private Synthesis Benchmark Breakdown (SFT v2)

The 120-Task Private Synthesis Benchmark measures zero-shot C code generation across novel protocols (VXLAN, GENEVE, GRE, GTP-U, SRv6, Q-in-Q, LPM Tries, Token-bucket rate policers).

### 2.1 By Application Category (Pass@1)
| Application Category | Total Tasks | Output Compliant | Clang BPF Compile | Kernel Verifier | Behavioral Pass | Pass@1 Rate (v2) | Pass@1 Rate (v1) | Delta |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **`packet_inspection_telemetry`** | 30 | 30 (100.0%) | 15 (50.0%) | 13 (43.3%) | 13 | **43.3%** (13/30) | 26.7% (8/30) | **+16.6%** |
| **`network_routing_forwarding`** | 30 | 30 (100.0%) | 17 (56.7%) | 17 (56.7%) | 8 | **26.7%** (8/30) | 20.0% (6/30) | **+6.7%** |
| **`packet_filtering_security`** | 30 | 30 (100.0%) | 15 (50.0%) | 11 (36.7%) | 5 | **16.7%** (5/30) | 13.3% (4/30) | **+3.4%** |
| **`protocol_transformation`** | 30 | 30 (100.0%) | 18 (60.0%) | 5 (16.7%) | 5 | **16.7%** (5/30) | 3.3% (1/30) | **+13.4%** |
| **Total Synthesis** | **120** | **120 (100.0%)** | **65 (54.2%)** | **46 (38.3%)** | **31** | **25.8%** (31/120) | **15.8%** (19/120) | **+10.0%** |

### 2.2 By Difficulty Level (Pass@1)
| Difficulty Level | Total Tasks | Compliant | Clang Compile | Kernel Verifier | Fully Passed | Pass@1 Rate (v2) | Pass@1 Rate (v1) | Delta |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| `level_1` (Basic) | 40 | 40 (100.0%) | 21 (52.5%) | 18 (45.0%) | 13 | **32.5%** (13/40) | 25.0% (10/40) | **+7.5%** |
| `level_2` (Nested/Options) | 40 | 40 (100.0%) | 20 (50.0%) | 12 (30.0%) | 7 | **17.5%** (7/40) | 12.5% (5/40) | **+5.0%** |
| `level_3` (Stateful/Maps) | 40 | 40 (100.0%) | 24 (60.0%) | 16 (40.0%) | 11 | **27.5%** (11/40) | 10.0% (4/40) | **+17.5%** |

---

## 3. 120-Task Private Repair Benchmark Breakdown (SFT v2)

The 120-Task Private Repair Benchmark presents faulty implementations paired with real Clang compiler errors, Linux kernel verifier rejection logs, or multi-packet test failure traces.

### 3.1 By Application Category (Pass@1)
| Application Category | Total Tasks | Output Compliant | Clang Compile | Kernel Verifier | Behavioral Pass | Pass@1 Rate (v2) | Pass@1 Rate (v1) | Delta |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **`packet_inspection_telemetry`** | 30 | 30 (100.0%) | 30 (100.0%) | 29 (96.7%) | 24 | **80.0%** (24/30) | 80.0% (24/30) | +0.0% |
| **`packet_filtering_security`** | 30 | 30 (100.0%) | 28 (93.3%) | 28 (93.3%) | 23 | **76.7%** (23/30) | 70.0% (21/30) | **+6.7%** |
| **`protocol_transformation`** | 30 | 30 (100.0%) | 28 (93.3%) | 25 (83.3%) | 22 | **73.3%** (22/30) | 53.3% (16/30) | **+20.0%** |
| **`network_routing_forwarding`** | 30 | 30 (100.0%) | 24 (80.0%) | 24 (80.0%) | 16 | **53.3%** (16/30) | 46.7% (14/30) | **+6.6%** |
| **Total Repair** | **120** | **120 (100.0%)** | **110 (91.7%)** | **106 (88.3%)** | **85** | **70.8%** (85/120) | **62.5%** (75/120) | **+8.3%** |

### 3.2 By Difficulty Level (Pass@1)
| Difficulty Level | Total Tasks | Compliant | Clang Compile | Kernel Verifier | Fully Passed | Pass@1 Rate (v2) | Pass@1 Rate (v1) | Delta |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| `level_1` (Basic) | 40 | 40 (100.0%) | 39 (97.5%) | 37 (92.5%) | 26 | **65.0%** (26/40) | 57.5% (23/40) | **+7.5%** |
| `level_2` (Nested/Options) | 40 | 40 (100.0%) | 35 (87.5%) | 33 (82.5%) | 32 | **80.0%** (32/40) | 72.5% (29/40) | **+7.5%** |
| `level_3` (Stateful/Maps) | 40 | 40 (100.0%) | 36 (90.0%) | 36 (90.0%) | 27 | **67.5%** (27/40) | 57.5% (23/40) | **+10.0%** |

---

## 4. Key Empirical Takeaways

1. **Massive Zero-Shot Synthesis Improvement (+10.0% absolute)**:
   - In SFT v1, the model achieved 15.8% Pass@1 on the 120-task private synthesis benchmark.
   - SFT v2 boosted this to **25.8% Pass@1 (31/120 tasks)**, with Clang compilation reaching **54.2%** and kernel verifier loads reaching **38.3%**.
   - Protocol transformation synthesis jumped from **3.3% &rarr; 16.7%** (+13.4%), and Level 3 complex map synthesis jumped from **10.0% &rarr; 27.5%** (+17.5%).
2. **Diagnostic Repair Accuracy Reaches 70.8% (+8.3% absolute)**:
   - The model repaired **85 out of 120 faulty programs** on the first attempt when provided with compiler or verifier diagnostic feedback.
   - Clang BPF compilation on repair candidates reached **91.7%** (110/120) and kernel verifier acceptance reached **88.3%** (106/120).
3. **Flawless Formatting Discipline**:
   - 100.0% output compliance across all 276 tasks with 0 markdown fences, valid license symbols, and proper kernel headers.
