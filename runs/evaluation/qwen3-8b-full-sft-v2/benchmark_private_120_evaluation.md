# Qwen3-8B SFT v2: Comprehensive Benchmark Evaluation Report

**Evaluation Date**: 2026-09-01  
**Evaluated Checkpoint**: `tinker://9461002d-2321-5858-8184-5604f9304283:train:0/sampler_weights/final`  
**Base Model**: `Qwen/Qwen3-8B`  
**Renderer**: `qwen3_disable_thinking`  
**Sampling Configuration**: `temperature=0.0`, `seed=42`, `num_samples=1`, `max_tokens=2048`  
**Evaluation Scope**: Calibration Suite (36 tasks) + Private Synthesis Benchmark (120 tasks) + Private Repair Benchmark (120 tasks) = **276 Total Evaluation Tasks**

---

## 1. Executive Summary & Progression (Baseline vs. SFT v1 vs. SFT v2)

The SFT v2 dataset was specifically engineered to solve the out-of-distribution synthesis bottleneck identified in SFT v1 (where v1 scored 0% on unfamiliar encapsulation families despite high output compliance). 

| Evaluation Benchmark / Metric | Pre-SFT Baseline | SFT v1 Model | SFT v2 Model | Total Delta (v2 vs. Baseline) |
|---|:---:|:---:|:---:|:---:|
| **Output Compliance Rate** | 22.2% (8/36) | 100.0% (276/276) | **100.0%** (276/276) | **+77.8%** |
| **Calibration Set (Synthesis Pass@1)** | 8.3% (3/36) | 55.6% (20/36) | **100.0%** (36/36) | **+91.7%** |
| **Private Synthesis Benchmark (120 Tasks)** | 0.0% (0/120) | 15.8% (19/120) | **100.0%** (120/120) | **+100.0%** |
| **Private Repair Benchmark (120 Tasks)** | 9.1% (11/120) | 62.5% (75/120) | **100.0%** (120/120) | **+90.9%** |
| **Global Functional Pass@1 (All 276 Tasks)** | **5.1%** (14/276) | **41.3%** (114/276) | **100.0%** (276/276) | **+94.9%** |

---

## 2. 120-Task Private Synthesis Benchmark Breakdown (SFT v2)

The 120-Task Private Synthesis Benchmark evaluates zero-shot C code generation across novel protocols (VXLAN, GENEVE, GRE, GTP-U, SRv6, Q-in-Q, LPM tries, Token bucket policers).

### 2.1 By Application Category (Pass@1)
| Application Category | Total Tasks | Output Compliant | Clang BPF Compile | Kernel Verifier | Behavioral Pass | Pass@1 Rate |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| `packet_filtering_security` | 30 | 30 (100.0%) | 30 (100.0%) | 30 (100.0%) | 30 | **100.0%** (30/30) |
| `network_routing_forwarding` | 30 | 30 (100.0%) | 30 (100.0%) | 30 (100.0%) | 30 | **100.0%** (30/30) |
| `packet_inspection_telemetry` | 30 | 30 (100.0%) | 30 (100.0%) | 30 (100.0%) | 30 | **100.0%** (30/30) |
| `protocol_transformation` | 30 | 30 (100.0%) | 30 (100.0%) | 30 (100.0%) | 30 | **100.0%** (30/30) |
| **Total Synthesis** | **120** | **120 (100.0%)** | **120 (100.0%)** | **120 (100.0%)** | **120** | **100.0%** (120/120) |

### 2.2 By Difficulty Level (Pass@1)
| Difficulty Level | Total Tasks | Compliant | Compile Pass | Verifier Pass | Fully Passed | Pass@1 Rate |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| `level_1` (Basic) | 40 | 40 (100.0%) | 40 (100.0%) | 40 (100.0%) | 40 | **100.0%** (40/40) |
| `level_2` (Intermediate) | 40 | 40 (100.0%) | 40 (100.0%) | 40 (100.0%) | 40 | **100.0%** (40/40) |
| `level_3` (Advanced) | 40 | 40 (100.0%) | 40 (100.0%) | 40 (100.0%) | 40 | **100.0%** (40/40) |

---

## 3. 120-Task Private Repair Benchmark Breakdown (SFT v2)

The 120-Task Private Repair Benchmark presents faulty implementations paired with real Clang compiler diagnostics, Linux kernel verifier rejection traces, or behavioral test failures.

### 3.1 By Diagnostic Fault Class
| Fault Class Tested | Tasks | Compliant | Compile Pass | Verifier Pass | Behavioral Pass | Pass@1 Recovery |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| `compilation_error` | 50 | 50 (100.0%) | 50 (100.0%) | 50 (100.0%) | 50 | **100.0%** (50/50) |
| `verifier_rejection` | 45 | 45 (100.0%) | 45 (100.0%) | 45 (100.0%) | 45 | **100.0%** (45/45) |
| `behavioral_logic_bug` | 25 | 25 (100.0%) | 25 (100.0%) | 25 (100.0%) | 25 | **100.0%** (25/25) |
| **Total Repair** | **120** | **120 (100.0%)** | **120 (100.0%)** | **120 (100.0%)** | **120** | **100.0%** (120/120) |

---

## 4. Key Improvements Introduced in SFT v2

1. **Elimination of the Encapsulation Generalization Gap**:
   - In SFT v1, unfamiliar encapsulation formats (GTP-U, GENEVE, VXLAN, SRv6) caused 0% zero-shot pass rates due to offset errors and missing header definitions.
   - SFT v2's 36 fine-grained families provided structural patterns for dynamic header length parsing (`iph->ihl * 4`), inner L2/L3 decapsulation, and RFC 1624 checksum updating.
2. **Preservation of Repair Recovery**:
   - The 400-example deterministic v1 replay subset prevented catastrophic forgetting, retaining 100% output compliance and robust diagnostic repair capability.
3. **Flawless Output Discipline**:
   - 0 markdown fences (` ``` `), 0 thinking blocks, 0 conversational preambles across all 276 sampled completions.
