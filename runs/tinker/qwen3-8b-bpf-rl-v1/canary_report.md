# BPF-Guardian RLVR Phase 1: Canary RL Run Report (Phase 8)

**Date**: 2026-09-04  
**Cluster Session**: `ec3de88d-bdf3-5377-a187-cfe33e0457e7`  
**Base Model**: `Qwen/Qwen3-8B`  
**Initialization Checkpoint**: `tinker://9461002d-2321-5858-8184-5604f9304283:train:0/weights/final`  
**KL Reference Checkpoint**: `tinker://9461002d-2321-5858-8184-5604f9304283:train:0/sampler_weights/final`  
**Final Checkpoint**: `tinker://ec3de88d-bdf3-5377-a187-cfe33e0457e7:train:0/sampler_weights/final`  

---

## 1. Canary Run Configuration & Architecture

| Parameter | Value | Rationale |
| :--- | :--- | :--- |
| **Mode** | `canary` | Integration validation of RL optimization pipeline |
| **Max Steps** | 5 | Short burn-in to verify convergence, KL stability, and save mechanics |
| **Learning Rate** | 5e-6 | Small learning rate to prevent early policy collapse |
| **LoRA Rank** | 32 | Sufficient capacity for fine-grained eBPF syntax & safety adaptations |
| **Batch Size (Groups/Step)** | 2 | 2 problem tasks per optimizer step |
| **Group Size (Samples/Task)** | 4 | 4 rollouts per task for group-relative advantage estimation |
| **Sampling Temperature** | 0.8 (train), 0.0 (eval) | Exploration during rollouts; greedy evaluation on dev set |
| **KL Penalty** | 0.05 | Strict regularization against frozen SFT v2 reference policy |
| **Loss Function** | `importance_sampling` | Standard PPO / GRPO importance-weighted advantage loss |
| **Constant Reward Filtering** | `True` | Removes zero-gradient trajectory groups |
| **Verifier Backend** | Linux 6.8.0 kernel (`srv1534562`) | Live kernel verification (`bpftool`) + packet execution (`BPF_PROG_TEST_RUN`) |

---

## 2. Step-by-Step Training Telemetry

All 5 optimizer steps completed with zero infrastructure errors and zero dropped batches.

| Step | Batch | Done Frac | Reward (Mean) | Compile Pass | Verifier Pass | Behavioral Pass | KL Divergence | Step Time | Checkpoint Saved |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| **0** | 0 | 20% | 1.0000 | 100.0% | 100.0% | 100.0% | +0.000168 | 78.36s | `000001` |
| **1** | 1 | 40% | 0.7167 | 100.0% | 100.0% | 0.0% | +0.001501 | 19.53s | `000002` |
| **2** | 2 | 60% | 1.0000 | 100.0% | 100.0% | 100.0% | -0.000400 | 24.19s | `000003` |
| **3** | 3 | 80% | 0.5750 | 62.5% | 62.5% | 50.0% | +0.000266 | 25.64s | `000004` |
| **4** | 4 | 100% | 0.2500 | 25.0% | 25.0% | 25.0% | +0.000957 | 31.46s | `000005`, `final` |

---

## 3. Pre-Canary vs Post-Canary Dev Evaluation (T=0.0)

Both evaluations were executed at **$T=0.0$** across the 24 balanced Development tasks (`data/rl/v1/dev`):

| Metric | Baseline (`dev_baseline`) | Post-Canary (`dev_post_canary`) | Delta |
| :--- | :---: | :---: | :---: |
| **Evaluated Tasks** | 24 | 24 | 0 |
| **Functional Pass Rate** | **70.83%** (17/24) | **66.67%** (16/24) | -4.16% (-1 task) |
| **Compile Pass Rate** | 91.67% (22/24) | 91.67% (22/24) | 0.0% |
| **Verifier Pass Rate** | 91.67% (22/24) | 91.67% (22/24) | 0.0% |
| **Output Compliance Rate** | **100.0%** (24/24) | **100.0%** (24/24) | 0.0% |
| **Average Reward** | 0.8431 | 0.8264 | -0.0167 |
| **Duration** | 278.7s | 265.1s | -13.6s |

### Paired Transition Matrix (N=24)
- **Fail -> Fail**: 7 tasks
- **Fail -> Pass (Recoveries)**: 0 tasks
- **Pass -> Fail (Regressions)**: 1 task (`rl_dev_pfs_l3_02`)
- **Pass -> Pass (Preserved)**: 16 tasks
- **Net Gain**: -1 task
- **McNemar Test**: chi2 = 0.0000, p = 1.000000

---

## 4. VPS Kernel Verifier & Cleanup Audit

1. **BPF Map Lifecycle Audit**:
   - `bpftool map list` executed before, during, and after the run.
   - Result: 0 leaked BPF maps (only root system `hid_jmp_table` persists).
2. **Process Integrity**:
   - `ps aux | grep -E "clang|bpftool"` verified 0 orphan or zombie compiler/verifier processes.
3. **Fail-Closed Verification**:
   - All 40 training rollouts and 24 post-canary evaluation rollouts completed with 100% fail-closed verification on Linux 6.8.0-106-generic.
   - Zero infrastructure errors.

---

## 5. Conclusion & Clearance for Phase 9 Pilot RL
Phase 8 is **PASSED** and cleared for the 50-step Pilot RL run.
