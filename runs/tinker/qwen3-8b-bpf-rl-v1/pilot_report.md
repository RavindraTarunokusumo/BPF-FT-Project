# BPF-Guardian Qwen3-8B RLVR Phase 1: Pilot & Benchmark Report

**Date**: 2026-09-04 21:04:50 UTC
**Best Checkpoint**: `000035`
**Sampler Path**: `tinker://a5e21df2-a4fe-54ce-9781-800ce6c75689:train:0/sampler_weights/000035`
**Advancement Gate Promotion Status**: **HELD (REVISIONS NEEDED)**

---

## 1. Pilot Training Audit (50 Steps)
| Metric | Value | Constraint / Target | Status |
|---|:---:|:---:|:---:|
| **Steps Completed** | 50 / 50 | 50 steps | PASS |
| **Constant Reward Rate** | 62.0% | < 70.0% | PASS |
| **Mixed Reward Rate** | 38.0% | > 30.0% | PASS |
| **Average Step Reward** | 0.7808 | Bounded [0.0, 1.0] | PASS |
| **Mean KL Divergence** | 0.001675 | KL stable | PASS |
| **Max KL Divergence** | 0.008570 | < 0.05 | PASS |
| **Average Functional Pass** | 64.2% | Monitor | INFO |
| **Average Verifier Pass** | 85.8% | Monitor | INFO |
| **Average Compile Pass** | 87.2% | Monitor | INFO |

---

## 2. RL Development Set Evaluation & Checkpoint Selection
Evaluated on `data/rl/v1/dev` (24 tasks, strictly disjoint from 276 benchmark tasks) at $T=0.0$ live on Linux kernel harness.

| Checkpoint | Pass@1 Count | Pass@1 Rate | Compile Rate | Verifier Rate | Compliance | Avg Reward | Net Gain vs Base | McNemar p |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| `000035` **(Selected Best)** | 18/24 | **75.0%** | 100.0% | 100.0% | 100.0% | 0.9097 | +1 | 1.0000 |
| `000045` | 17/24 | **70.8%** | 95.8% | 95.8% | 100.0% | 0.8681 | +0 | 1.0000 |
| `final` | 16/24 | **66.7%** | 91.7% | 91.7% | 100.0% | 0.8264 | -1 | 1.0000 |
| `000050` | 16/24 | **66.7%** | 91.7% | 91.7% | 100.0% | 0.8264 | -1 | 1.0000 |
| `000025` | 16/24 | **66.7%** | 91.7% | 91.7% | 100.0% | 0.8264 | -1 | 1.0000 |
| `000015` | 16/24 | **66.7%** | 91.7% | 91.7% | 100.0% | 0.8264 | -1 | 1.0000 |

---

## 3. Normative Advancement Gates Audit
| Gate | Description | Threshold | Candidate Result | Status |
|---|---|:---:|:---:|:---:|
| `gate_1_dev_pass_rate_gain_ge_5pct` | RL Dev functional Pass@1 gain >= +5.0% vs baseline | +5.0% | +4.17% | **FAIL** |
| `gate_2_output_compliance_ge_99pct` | Candidate output compliance rate >= 99.0% | >= 99.0% | 100.00% | **PASS** |
| `gate_3_protected_synthesis_regression_le_3` | Protected synthesis regression <= 3 tasks from baseline (31/120) | 28/120 | 29/120 | **PASS** |
| `gate_4_protected_repair_regression_le_5` | Protected repair regression <= 5 tasks from baseline (85/120) | 80/120 | 85/120 | **PASS** |

**Overall Gate Decision**: **GATES NOT FULLY SATISFIED**

---

## 4. Protected Benchmark Suite Results (Paired vs Frozen SFT v2)

| Suite | Tasks | SFT v2 Pass@1 | Candidate Pass@1 | Retained (`P->P`) | Gain (`F->P`) | Loss (`P->F`) | Unresolved (`F->F`) | Net Gain | McNemar Stat | McNemar p |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Calibration Benchmark (36 Tasks)** | 36 | 21 (58.3%) | **20 (55.6%)** | 18 | **+2** | -3 | 13 | **-1** | 0.0 | 1.0000 |
| **Private Synthesis Benchmark (120 Tasks)** | 120 | 31 (25.8%) | **29 (24.2%)** | 26 | **+3** | -5 | 86 | **-2** | 0.125 | 0.7266 |
| **Private Standalone Repair Benchmark (120 Tasks)** | 120 | 85 (70.8%) | **85 (70.8%)** | 85 | **+0** | -0 | 35 | **+0** | 0.0 | 1.0000 |

---

## 5. Kernel Verification Environment
- **Host**: Hostinger Linux VPS (`srv1534562`, `187.124.178.70`)
- **Kernel**: Linux 6.8.0-106-generic x86_64
- **Compiler**: Ubuntu Clang 18.1.3 (`clang -target bpf -O2 -g -Wall -Wextra`)
- **Tools**: bpftool v7.4.0, libbpf v1.4
- **Packet Engine**: In-kernel `BPF_PROG_TEST_RUN` (`bpftool prog run`)
- **Isolation**: Strict fail-closed sandbox with zero leaked maps or pinned programs
