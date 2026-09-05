# Qwen3-8B BPF RLVR Phase 2: Findings, Benchmark Audits, and Promotion Decision

**Date**: September 5, 2026  
**Experiment**: BPF-Guardian RLVR Phase 2 ("Controlled Generalization Experiment")  
**Base Model**: `Qwen/Qwen3-8B`  
**Starting Checkpoint**: `tinker://9461002d-2321-5858-8184-5604f9304283:train:0/weights/final` (SFT v2)  
**KL Reference**: `tinker://9461002d-2321-5858-8184-5604f9304283:train:0/sampler_weights/final` (SFT v2 Sampler)  
**Archived RL Phase 1 Checkpoint**: `tinker://a5e21df2-a4fe-54ce-9781-800ce6c75689:train:0/sampler_weights/000035` (unpromoted)  
**Selected RL Phase 2 Candidate**: `tinker://9af95d8c-46ca-5964-a2c8-60aeaac88997:train:0/sampler_weights/000010` (Step `000010`)  
**Execution Environment**: Hostinger Linux VPS (`187.124.178.70`), Kernel `6.8.0-106-generic #106-Ubuntu SMP PREEMPT_DYNAMIC`  

---

## 1. Executive Summary & Promotion Decision

### Decision
> **RETAIN SFT v2 AS THE PRODUCTION DEFAULT. ARCHIVE PHASE 2 AS AN EXPERIMENTAL PILOT.**

Per normative promotion requirements in `docs/rl-phase2-handoff.md`, candidate promotion requires passing all operational and efficacy gates. Although Phase 2 successfully corrected Phase 1's catastrophic protected regressions and achieved net positive gains across synthesis and confirmation, it fell short of the strict Dev selection gate ($\ge +3/48$ tasks required; $+1/48$ observed) and the Locked Confirmation gate ($\ge +3/60$ tasks required; $+2/60$ observed).

Consequently, **SFT v2 remains the default production checkpoint**. Phase 2 checkpoint `000010` is preserved in the experiment archive.

### High-Level Scorecard

| Evaluation Suite | Size | SFT v2 Baseline | Phase 1 (`000035`) | Phase 2 (`000010`) | Net vs SFT v2 | Paired Transitions (F→P / P→F) | Exact McNemar $p$ | Gate Status |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| **RL v2 Development Set** ($T=0.0$) | 48 | 22/48 (45.8%) | N/A | **23/48 (47.9%)** | **+1** | 1 / 0 | 1.0000 | **NOT MET** ($\ge +3$ req.) |
| **Locked Confirmation Set** ($T=0.0$) | 60 | 33/60 (55.0%) | N/A | **35/60 (58.3%)** | **+2** | 2 / 0 | 0.5000 | **NOT MET** ($\ge +3$ req.) |
| **Protected Calibration** ($T=0.0$) | 36 | 21/36 (58.3%) | 20/36 (55.6%) | **20/36 (55.6%)** | **-1** | 0 / 1 | 1.0000 | **PASSED** ($\ge 20$ req.) |
| **Protected Private Synthesis** ($T=0.0$) | 120 | 31/120 (25.8%) | 29/120 (24.2%) | **34/120 (28.3%)** | **+3** | 3 / 0 | 0.2500 | **PASSED** ($> 31$ req.) |
| **Protected Standalone Repair** ($T=0.0$) | 120 | 85/120 (70.8%) | 85/120 (70.8%) | **84/120 (70.0%)** | **-1** | 0 / 1 | 1.0000 | **PASSED** ($\ge 83$ req.) |
| **Protected Combined Benchmark** ($T=0.0$) | 276 | 137/276 (49.6%) | 134/276 (48.6%) | **138/276 (50.0%)** | **+1** | 3 / 2 | 1.0000 | **PASSED** ($\ge 137$ req.) |

---

## 2. Experimental Rigor & Operational Integrity

### 100% Empirical Linux Kernel Verification
- **Zero Mock Verifier Records**: 100% of candidate completions across all splits (baselines, canaries, training iterations, and final evaluations) were compiled using `clang-18 -target bpf -O2` and verified in-kernel using `BPF_PROG_LOAD` and `BPF_PROG_TEST_RUN` on Linux VPS kernel `6.8.0-106-generic`.
- **Zero Execution on Windows / Tinker**: All BPF compilation, verifier checks, and packet test execution occurred exclusively on the Hostinger Linux VPS.
- **Total Empirical Job Accounting**:
  - Reference Solution Validation: 264 tasks (746 fixtures, 100% pass)
  - Baseline Evaluations: 108 rollouts (48 Dev + 60 Confirmation)
  - Integration Canaries: 88 rollouts (48 sampling canary + 40 training canary)
  - Pilot Training: 200 rollouts (25 steps $\times$ 2 groups $\times$ 4 samples)
  - Pilot Dev Evaluations: 240 rollouts (5 evaluations $\times$ 48 tasks)
  - Final Protected & Confirmation Evaluations: 336 rollouts (60 Conf + 36 Cal + 120 Syn + 120 Rep)
  - **Total Empirical Rollouts**: **972 rollouts** (1,236 total kernel execution jobs)
  - **Infrastructure Errors**: **0**

### Fail-Closed Infrastructure Hardening
- Reusable reward module (`training/rl/reward.py`) raised `InfrastructureRewardError` on any execution anomaly or fixture mismatch.
- `BPFEnv.step()` re-raised `RuntimeError("INFRASTRUCTURE_ERROR: ...")`, guaranteeing no infrastructure failure was ever scored as a numeric reward ($0.0$).

### Benchmark Contamination Audit
- Fingerprinted across normalized instruction text, requirements, protocol/feature tuples, family IDs, fixture schemas, and prompts.
- **564 total tasks audited**: 264 RL v2 tasks (`canary`: 12, `train`: 144, `dev`: 48, `confirmation`: 60) against 300 existing tasks (36 calibration, 120 synthesis, 120 repair, 24 RL v1 dev).
- **0 contamination violations detected (100.0% semantic disjointness)**. Certified in `data/rl/v2/contamination_audit.json`.

---

## 3. RL v2 Architecture & Training-Only Priority Sampler

### Seeded Priority Sampler (`BPFPrioritySampler`)
To address the 62.0% constant-reward group rate observed in Phase 1, Phase 2 replaced deterministic round-robin batching with a train-only priority sampler:
1. **Difficulty Progression Schedule**:
   - Steps 1–15: Level 1: 25%, Level 2: 40%, Level 3: 35%
   - Steps 16–60: Level 1: 10%, Level 2: 40%, Level 3: 50%
2. **Category Balance Floor**: Uniform 25% allocation across all 4 application categories within difficulty strata.
3. **Outcome-Aware Downweighting**: Saturated tasks achieving $\ge 90\%$ rolling full-pass rate penalized by 80% weight reduction.
4. **Active Learning Gradient Boost**: Tasks producing mixed-reward groups within a rolling 10-step window boosted by up to $+50\%$.
5. **Deterministic Resume**: Sampler state serialized at every step (`sampler_state.json`), capturing RNG state, exposure counts, and rolling pass rates.

### Training Configuration
- **Learning Rate**: Constant scalar $\eta = 3.0 \times 10^{-6}$ (explicitly recorded; no undocumented decay claimed).
- **Group Size**: 4 completions per problem group; 2 problem groups per step (8 rollouts per gradient step).
- **Objective**: Importance sampling with KL penalty coefficient $\beta = 0.05$ against frozen SFT v2 sampler.
- **Post-KL Monitoring**: `compute_post_kl: True` enabled in configuration.
- **Online Early Stopping**: Automated stopping with patience of 3 evaluations ($15$ steps).

---

## 4. Phase 2 Pilot Run Trajectory & Checkpoint Selection

Training proceeded in 5-step increments with automated Dev evaluations ($T=0.0$) every 5 steps:

| Step | Completed Rollouts | Dev Pass@1 | Compile Rate | Verifier Rate | Structural Compliance | Mean Reward | Net vs Baseline | Paired (F→P / P→F) | Exact McNemar $p$ | Action / Status |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| **0 (SFT v2)** | 0 | 22/48 (45.8%) | 62.5% | 50.0% | 100.0% | 0.5121 | — | — | — | Baseline Established |
| **5** | 40 | 22/48 (45.8%) | 64.6% | 50.0% | 100.0% | 0.5138 | +0 | 0 / 0 | 1.0000 | Patience 1/3 |
| **10** | 80 | **23/48 (47.9%)** | **62.5%** | **50.0%** | **100.0%** | **0.5160** | **+1** | **1 / 0** | **1.0000** | **Selected Best Checkpoint** |
| **15** | 120 | 22/48 (45.8%) | 62.5% | 47.9% | 100.0% | 0.4973 | +0 | 1 / 1 | 1.0000 | Patience 1/3 |
| **20** | 160 | 23/48 (47.9%) | 64.6% | 50.0% | 100.0% | 0.5177 | +1 | 2 / 1 | 1.0000 | Patience 2/3 (tie broken to earlier step 10) |
| **25** | 200 | 22/48 (45.8%) | 66.7% | 50.0% | 100.0% | 0.5154 | +0 | 0 / 0 | 1.0000 | **Early Stopping Triggered (Patience 3/3)** |

### Checkpoint Selection
- Primary metric: Dev functional Pass@1. Step 10 and Step 20 both reached $23/48$ ($+1$ task over baseline).
- Per protocol tie-breaking rule (earlier checkpoint preferred when within margin), **Step 10** (`000010`) was selected:
  - Checkpoint: `tinker://9af95d8c-46ca-5964-a2c8-60aeaac88997:train:0/weights/000010`
  - Sampler: `tinker://9af95d8c-46ca-5964-a2c8-60aeaac88997:train:0/sampler_weights/000010`

---

## 5. Locked Confirmation & Protected Benchmark Results

### Locked 60-Task Confirmation Set ($T=0.0$)
The confirmation set remained completely sealed during training and was evaluated once on the SFT v2 baseline and once on selected checkpoint `000010`:

| Metric | SFT v2 Baseline | Checkpoint `000010` | Delta | Paired Transition | Exact McNemar $p$ |
|---|---:|---:|---:|---|---:|
| **Functional Pass@1** | **33/60 (55.0%)** | **35/60 (58.3%)** | **+2 tasks (+3.33%)** | **F→P: 2, P→F: 0** | **0.5000** |
| Compilation Pass | 40/60 (66.7%) | 41/60 (68.3%) | +1 task (+1.67%) | — | — |
| Verifier Pass | 33/60 (55.0%) | 35/60 (58.3%) | +2 tasks (+3.33%) | — | — |
| Compliance | 60/60 (100.0%) | 60/60 (100.0%) | 0.0% | — | — |
| Mean Reward | 0.5683 | 0.5997 | +0.0314 | — | — |

- **Paired Contingency**: $\text{Fail}\to\text{Fail}: 25$, $\text{Fail}\to\text{Pass}: 2$, $\text{Pass}\to\text{Fail}: 0$, $\text{Pass}\to\text{Pass}: 33$.
- **Zero Confirmation Regressions**: All 33 baseline passing confirmation tasks were retained ($100.0\%$).
- **Statistical Assessment**: No statistically significant difference was detected ($p = 0.5000$).

---

### Protected Calibration Synthesis (36 Tasks, $T=0.0$)

| Metric | SFT v2 Baseline | Phase 1 (`000035`) | Checkpoint `000010` | Delta vs SFT v2 | Paired (F→P / P→F) | Exact McNemar $p$ |
|---|---:|---:|---:|---:|---:|---:|
| **Functional Pass@1** | **21/36 (58.3%)** | 20/36 (55.6%) | **20/36 (55.6%)** | **-1 task** | **0 / 1** | **1.0000** |
| Compilation Pass | 28/36 (77.8%) | 28/36 (77.8%) | 28/36 (77.8%) | 0 | — | — |
| Verifier Pass | 26/36 (72.2%) | 26/36 (72.2%) | 26/36 (72.2%) | 0 | — | — |
| Mean Reward | 0.7028 | 0.6962 | 0.6968 | -0.0060 | — | — |

- **Regression**: `ptr_l3_icmp_echo_reply` (`protocol_transformation`, `level_3`).
- **Statistical Assessment**: No statistically significant difference was detected ($p = 1.0000$).

---

### Protected Private Synthesis (120 Tasks, $T=0.0$)

| Metric | SFT v2 Baseline | Phase 1 (`000035`) | Checkpoint `000010` | Delta vs SFT v2 | Paired (F→P / P→F) | Exact McNemar $p$ |
|---|---:|---:|---:|---:|---:|---:|
| **Functional Pass@1** | **31/120 (25.8%)** | 29/120 (24.2%) | **34/120 (28.3%)** | **+3 tasks (+2.50%)** | **3 / 0** | **0.2500** |
| Compilation Pass | 65/120 (54.2%) | 65/120 (54.2%) | 67/120 (55.8%) | +2 tasks | — | — |
| Verifier Pass | 50/120 (41.7%) | 49/120 (40.8%) | 51/120 (42.5%) | +1 task | — | — |
| Mean Reward | 0.4072 | 0.4031 | 0.4157 | +0.0085 | — | — |

- **Key Finding**: In stark contrast to Phase 1 (which suffered 5 regressions and dropped to 29/120), Phase 2 achieved **zero regressions on protected synthesis** and **3 net recoveries**:
  1. `syn_pfs_l1_005_mpls_bos_filter` (`packet_filtering_security`, `level_1`)
  2. `syn_pit_l2_004_vxlan_inner_l3_distribution` (`packet_inspection_telemetry`, `level_2`)
  3. `syn_pit_l3_005_gtpu_bearer_traffic_matrix` (`packet_inspection_telemetry`, `level_3`)
- **Statistical Assessment**: No statistically significant difference was detected ($p = 0.2500$).

---

### Protected Standalone Repair (120 Tasks, $T=0.0$)

| Metric | SFT v2 Baseline | Phase 1 (`000035`) | Checkpoint `000010` | Delta vs SFT v2 | Paired (F→P / P→F) | Exact McNemar $p$ |
|---|---:|---:|---:|---:|---:|---:|
| **Functional Pass@1** | **85/120 (70.8%)** | 85/120 (70.8%) | **84/120 (70.0%)** | **-1 task** | **0 / 1** | **1.0000** |
| Compilation Pass | 110/120 (91.7%) | 109/120 (90.8%) | 110/120 (91.7%) | 0 | — | — |
| Verifier Pass | 106/120 (88.3%) | 106/120 (88.3%) | 106/120 (88.3%) | 0 | — | — |
| Mean Reward | 0.8260 | 0.8255 | 0.8219 | -0.0041 | — | — |

- **Retention**: Retained 84 of 85 passing repair tasks (98.8% retention).
- **Regression**: `repair_ptr_l2_decap_gre_tunnel` (`protocol_transformation`, `level_2`).
- **Statistical Assessment**: No statistically significant difference was detected ($p = 1.0000$).

---

### Combined Protected Benchmark (276 Tasks, $T=0.0$)

| Metric | SFT v2 Baseline | Phase 1 (`000035`) | Checkpoint `000010` | Delta vs SFT v2 | Paired (F→P / P→F) | Exact McNemar $p$ |
|---|---:|---:|---:|---:|---:|---:|
| **Combined Functional Pass** | **137/276 (49.6%)** | 134/276 (48.6%) | **138/276 (50.0%)** | **+1 task (+0.36%)** | **3 / 2** | **1.0000** |
| Compilation Pass | 203/276 (73.6%) | 202/276 (73.2%) | 205/276 (74.3%) | +2 tasks | — | — |
| Verifier Pass | 182/276 (65.9%) | 181/276 (65.6%) | 183/276 (66.3%) | +1 task | — | — |

- **Contingency Matrix**:
  $$\begin{pmatrix} \text{Fail}\to\text{Fail}: 136 & \text{Fail}\to\text{Pass}: 3 \\ \text{Pass}\to\text{Fail}: 2 & \text{Pass}\to\text{Pass}: 135 \end{pmatrix}$$
- **Statistical Assessment**: No statistically significant difference was detected ($p = 1.0000$).

---

## 6. Comprehensive Gate Audit

| Gate | Category | Required Threshold | Observed Value | Result |
|---|---|---|---|:---:|
| **100% Empirical VPS Records** | Operational | 100% of candidate code executed on Linux VPS | 100.0% (972 rollouts, 0 mock) | **PASSED** |
| **Fail-Closed Infrastructure** | Operational | Zero infrastructure errors converted to numeric rewards | 0 errors encountered | **PASSED** |
| **Contamination Audit** | Operational | 100% disjoint from all protected benchmarks & RL v1 | 564/564 tasks disjoint (0 violations) | **PASSED** |
| **State Reproducibility** | Operational | Deterministic resume of RNG, sampler, & optimizer | Verified in unit tests & canary | **PASSED** |
| **Output Structural Compliance** | Efficacy | $\ge 99.0\%$ compliance across all candidate rollouts | 100.0% across all 972 rollouts | **PASSED** |
| **Protected Synthesis Exceeds SFT v2** | Efficacy | $> 31/120$ (i.e. $\ge 32/120$) | **34/120** (+3 net gain, 0 regressions) | **PASSED** |
| **Protected Calibration Retention** | Efficacy | $\ge 20/36$ tasks | **20/36** (55.6%) | **PASSED** |
| **Protected Repair Retention** | Efficacy | $\ge 83/120$ tasks | **84/120** (retained 84/85 passes) | **PASSED** |
| **Combined Protected Retention** | Efficacy | $\ge 137/276$ tasks | **138/276** (+1 net gain) | **PASSED** |
| **Zero Concentrated Regressions** | Efficacy | No category or difficulty stratum may lose $> 2$ tasks | Max category loss is 2; no stratum $> 1$ | **PASSED** |
| **Dev Checkpoint Selection Gate** | Efficacy | At least $+3/48$ tasks ($\ge 25/48$) over baseline | **$+1/48$ tasks** ($23/48$) | **FAILED** |
| **Locked Confirmation Gate** | Efficacy | At least $+3/60$ tasks ($\ge +5.0\%$, $\ge 36/60$) | **$+2/60$ tasks** ($35/60$, $+3.33\%$) | **FAILED** |
| **Confirmation Direction** | Efficacy | Fail$\to$pass count must exceed pass$\to$fail count | $2$ recoveries vs $0$ regressions | **PASSED** |

---

## 7. Comparative Analysis: Phase 1 vs Phase 2

```
========================================================================================
METRIC                             PHASE 1 (Step 35)               PHASE 2 (Step 10)
========================================================================================
Training Dataset                   96 tasks (unstratified)         144 tasks (12 cells x 12)
Sampling Strategy                  Deterministic Round-Robin       Seeded Priority Sampler
Dev Set Size                       24 tasks                        48 tasks
Confirmation Set                   None (unblinded)                60 tasks (locked, single eval)
Learning Rate                      5e-6 (constant)                 3e-6 (constant)
Post-KL Measurement                compute_post_kl: False          compute_post_kl: True
Early Stopping                     None (trained to step 50)       Online (early stopped at step 25)

--- EVALUATION OUTCOMES ---
Dev Functional Gain                +1/24 tasks (+4.17%)            +1/48 tasks (+2.08%)
Locked Confirmation Gain           N/A                             +2/60 tasks (+3.33%, 0 regr.)
Protected Synthesis Delta          -2 tasks (29/120, 5 regr.)      +3 tasks (34/120, 0 regr.)
Protected Repair Delta             0 tasks (85/120, 0 regr.)       -1 task (84/120, 1 regr.)
Protected Calibration Delta        -1 task (20/36, 3 regr.)        -1 task (20/36, 1 regr.)
Combined Protected Delta           -3 tasks (134/276, 8 regr.)     +1 task (138/276, 2 regr.)
========================================================================================
```

### Why Phase 2 Succeeded Technically
1. **Regressions Eliminated in Synthesis**: Phase 1 suffered from severe benchmark forgetting (5 synthesis regressions, dropping below baseline to 29/120). Phase 2 eliminated synthesis regressions entirely (0 regressions, 3 recoveries, reaching 34/120).
2. **Priority Sampler Mitigated Saturation**: Saturated tasks were actively downweighted once reaching $>90\%$ pass rates, redirecting gradient updates toward under-represented categories and higher difficulty strata.
3. **Controlled Optimization via Lower LR and Early Stopping**: Reducing learning rate from $5\times 10^{-6}$ to $3\times 10^{-6}$ and stopping at step 25 prevented the over-optimization collapse that characterized Phase 1 after step 35.

### Why Phase 2 Was Not Promoted
The $+5.0\%$ gate ($\ge +3/48$ on Dev, $\ge +3/60$ on Confirmation) was designed as a conservative safeguard against promoting stochastic fluctuations. Phase 2 achieved $+2.08\%$ on Dev ($+1/48$) and $+3.33\%$ on Confirmation ($+2/60$). Because statistical significance was not reached ($p = 0.5000$ on Confirmation, $p = 1.0000$ on Dev) and the point estimates missed the required $+3$-task minimum:
- SFT v2 remains the safer, frozen production anchor.
- Promoting Phase 2 would violate the pre-registered decision rule.

---

## 8. Recommendations for Phase 3 (Diagnostic-Guided Repair RL)

Per Section 733 of `docs/rl-phase2-handoff.md`, repair was intentionally excluded from Phase 2 to isolate synthesis generalization. The results demonstrate that pure synthesis RLVR reaches an empirical ceiling around 28–30% on complex XDP tasks when single-turn generation is used.

For Phase 3:
1. **Two-Step Diagnostic-Guided Repair Environment**:
   - Step 1: Model generates initial XDP implementation.
   - Harness executes empirical verifier/packet test on VPS.
   - Step 2: If failure occurs, environment provides standardized compiler/verifier diagnostic and requests repair.
2. **Dedicated Repair Training Pool**:
   - 120 independently generated faulty/diagnostic task pairs (strictly disjoint from protected repair).
3. **Dual Metric Evaluation**:
   - Track Pass@1 (initial generation) and Solve@2 (recovered generation) simultaneously.
   - Target the previous $0/15$ behavioral-failure recovery barrier identified in earlier analyses.
