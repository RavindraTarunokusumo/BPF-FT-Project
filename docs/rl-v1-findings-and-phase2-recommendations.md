# BPF-Guardian Qwen3-8B RLVR Phase 1: Findings & Recommended Phase 2

## Executive Summary

Phase 1 of Reinforcement Learning with Verifiable Rewards (RLVR) for `Qwen/Qwen3-8B` has concluded. Operating under strict empirical constraints, every candidate generated during canary sampling (48 rollouts), the 5-step canary (40 rollouts), the 50-step pilot (400 rollouts), dev checkpoint selection (168 rollouts), and frozen benchmark evaluations (276 rollouts) was compiled and verified live against the Linux 6.8 kernel on Hostinger Linux VPS `srv1534562` using real Clang 18, `bpftool prog load`, and packet testing with `BPF_PROG_TEST_RUN`.

### Core Advancement Gates Scorecard

| Advancement Gate | Required Threshold | Candidate `000035` Result | Outcome |
|---|:---:|:---:|:---:|
| **Gate 1: Dev Functional Pass@1 Gain** | $\ge +5.0\%$ ($\ge 19/24$ tasks) | **+4.17% (18/24 tasks)** | **FAIL (1 task short)** |
| **Gate 2: Output Structural Compliance** | $\ge 99.0\%$ | **100.0%** | **PASS** |
| **Gate 3: Protected Synthesis Regression** | $\le 3$ tasks lost from 31/120 ($\ge 28/120$) | **29/120 (-2 tasks)** | **PASS** |
| **Gate 4: Protected Repair Regression** | $\le 5$ tasks lost from 85/120 ($\ge 80/120$) | **85/120 (0 tasks lost)** | **PASS** |

### Promotion Decision
In strict adherence to the safety mandate of `RL_V1_Handoff.md`:
- **SFT v2 remains the production default checkpoint**:
  - `tinker://9461002d-2321-5858-8184-5604f9304283:train:0/sampler_weights/final`
- **RL Checkpoint `000035` is archived as an experimental pilot artifact**:
  - `tinker://a5e21df2-a4fe-54ce-9781-800ce6c75689:train:0/sampler_weights/000035`

---

## 1. Key Experimental Findings

### 1.1 Pilot Training Stability & Convergence (50 Steps)
- **Step Trajectory**: 50 optimizer steps completed (batch size 2 groups $\times$ group size 4 = 8 rollouts per step, 400 total training rollouts).
- **Constant Reward Rate**: **62.00%** (satisfies the $< 70.0\%$ constraint). 38% of groups contained mixed rewards, providing effective policy gradient updates.
- **Average Step Reward**: **0.7808** across the 50 steps.
- **KL Regularization**: The training run utilized a KL penalty coefficient $\beta = 0.05$ against the frozen SFT v2 reference policy (`compute_post_kl: false` was configured). The logged pre-update batch sampling metric `kl_policy_base` showed a mean of **0.001675** and maximum of **0.008570**. (Note: $\beta = 0.05$ is the loss objective coefficient, not a divergence threshold).
- **Compiler and Verifier Pass Rates**: Across the 400 training rollouts, compilation pass rate averaged 87.2%, kernel verifier pass rate averaged 85.8%, and functional pass rate averaged 64.2%.

### 1.2 Development Set Checkpoint Trajectory ($T=0.0$)
Periodic checkpoints saved during pilot training were evaluated on `data/rl/v1/dev` (24 tasks, strictly disjoint from benchmarks):

| Checkpoint | Pass@1 Count | Pass@1 Rate | Compile Rate | Verifier Rate | Compliance | Average Reward |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| **Baseline (SFT v2)** | 17 / 24 | 70.83% | 91.67% | 91.67% | 100.0% | 0.8431 |
| `000015` | 16 / 24 | 66.67% | 91.67% | 91.67% | 100.0% | 0.8264 |
| `000025` | 16 / 24 | 66.67% | 91.67% | 91.67% | 100.0% | 0.8264 |
| **`000035` (Peak)** | **18 / 24** | **75.00%** | **100.0%** | **100.0%** | **100.0%** | **0.9097** |
| `000045` | 17 / 24 | 70.83% | 95.83% | 95.83% | 100.0% | 0.8681 |
| `000050` | 16 / 24 | 66.67% | 91.67% | 91.67% | 100.0% | 0.8264 |
| `final` | 16 / 24 | 66.67% | 91.67% | 91.67% | 100.0% | 0.8264 |

**Observations**:
1. Checkpoint `000035` achieved peak performance: **18/24 (75.00%) functional pass rate**, with **100.0% compilation**, **100.0% verifier pass**, and an average reward of **0.9097**.
2. Note on Selection Bias: Checkpoint `000035` was selected after repeated post-hoc measurements across 6 candidate checkpoints on this small 24-task development set. Beyond step 35, performance dropped back to 16/24 at step 50.

### 1.3 Protected Benchmark Generalization & Paired McNemar Analysis
Selected checkpoint `000035` was evaluated on all 276 protected benchmark tasks at $T=0.0$:

| Benchmark Suite | Total Tasks | SFT v2 Pass@1 | RL `000035` Pass@1 | Retained (`P->P`) | Gained (`F->P`) | Regressed (`P->F`) | Unresolved (`F->F`) | Net Delta | McNemar $p$-value |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Calibration** | 36 | 21 (58.3%) | 20 (55.6%) | 18 | +2 | -3 | 13 | -1 | $1.0000$ |
| **Private Synthesis** | 120 | 31 (25.8%) | 29 (24.2%) | 26 | +3 | -5 | 86 | -2 | $0.7266$ |
| **Private Standalone Repair**| 120 | 85 (70.8%) | 85 (70.8%) | 85 | +0 | -0 | 35 | +0 | $1.0000$ |
| **Combined Benchmarks** | **276** | **137 (49.6%)** | **134 (48.6%)** | **129** | **+5** | **-8** | **134** | **-3** | **$0.5811$** |

**Statistical Significance & Caveats**:
- Under the exact two-sided McNemar test, **no statistically significant difference was detected** vs SFT v2 on Synthesis ($p = 0.7266$), Repair ($p = 1.0000$), or Combined ($p = 0.5811$).
- However, failure to reject the null does not imply absence of regression: observed point estimates declined by 2 tasks on protected synthesis (31 $\to$ 29) and 3 tasks overall (137 $\to$ 134).
- In Standalone Repair, all 85 previously passing repair tasks were retained in this deterministic evaluation (85/85), providing evidence of retention rather than universal preservation across unseen repair distributions.

---

## 2. Root Cause Analysis: Why Gate 1 Missed by 1 Task

The model achieved 18/24 on the Development set (+4.17% gain), exactly one task short of the 19/24 (+5.00%) advancement gate. Detailed inspection of candidate outputs reveals two primary factors:

1. **Level 1 Stateless Task Saturation**:
   - In the 96-task training set, Level 1 stateless tasks (simple UDP/TCP port drops, basic IP protocol filters) were solved with near 100% accuracy within the first 10 steps.
   - Consequently, 62% of training groups yielded uniform rewards, providing zero gradient update. The model spent a large fraction of training steps without policy updates on simple tasks.
2. **Failure Signature on Level 3 LPM Map Key Structs**:
   - The specific task that prevented qualification was `rl_dev_nrf_l3_01` (IPv6 longest-prefix matching using `BPF_MAP_TYPE_LPM_TRIE`).
   - The candidate correctly generated the complete C code, defined the LPM trie map, and verified cleanly. However, in the lookup key, it omitted the 4-byte `prefixlen` header required by `struct bpf_lpm_trie_key`, causing LPM lookups to mismatch the behavioral packet test fixtures.

---

## 3. Recommended Phase 2 Implementation Plan

To surpass the +5.0% dev threshold and achieve net positive generalization on the 120-task synthesis benchmark, Phase 2 should incorporate the following concrete enhancements:

### 3.1 Dynamic Difficulty Curriculum & Stratified Sampling
- **Current Limitation**: Uniform random task sampling causes Level 1 tasks to dominate early steps.
- **Phase 2 Solution**: Implement an adaptive priority sampler:
  - **Phase 2a (Steps 1–30)**: Warmup with 30% Level 1, 40% Level 2, 30% Level 3.
  - **Phase 2b (Steps 31–100)**: Transition to 10% Level 1, 45% Level 2, 45% Level 3.
  - Actively downsample tasks where the rolling pass rate exceeds 95%, keeping the mixed reward rate $> 50\%$.

### 3.2 Extended Step Budget with Cosine LR Decay
- **Current Limitation**: Peak performance was attained at step 35; with constant learning rate ($5\times 10^{-6}$), the model began overfitting training fixtures by step 50.
- **Phase 2 Solution**:
  - Increase the step budget from 50 to 100 steps.
  - Implement a cosine learning rate decay schedule: $5\times 10^{-6} \to 1\times 10^{-6}$, stabilizing the policy as it approaches peak generalization.

### 3.3 Intermediate Reward Shaping for Stateful BPF Maps
- **Current Limitation**: Tasks requiring BPF maps either receive full fixture credit or 0 fixture credit, creating high variance.
- **Phase 2 Solution**:
  - Add a granular structural map reward: $+0.05$ for correctly declaring and accessing BPF maps matching the task specification (e.g. `BPF_MAP_TYPE_ARRAY`, `HASH`, `LPM_TRIE`, `DEVMAP`) when the kernel verifier accepts the map operations.
  - Introduce a minor length efficiency penalty to discourage unnecessary boilerplate that triggers verifier complexity limits.

### 3.4 Hybrid Task Co-Training (Synthesis + Diagnostic Repair)
- **Current Limitation**: RL training was 100% synthesis. While repair capability was retained (85/85), it did not improve.
- **Phase 2 Solution**:
  - Mix in 15–20% diagnostic repair tasks into the training pool (`data/rl/v1/train/repair`), reinforcing both synthesis and code repair in a single unified RLVR loop.

---

## 4. Checkpoint & Artifact Registry

| Entity | Identifier / Path | Status |
|---|---|---|
| **Production Default Checkpoint (SFT v2)** | `tinker://9461002d-2321-5858-8184-5604f9304283:train:0/sampler_weights/final` | **ACTIVE PRODUCTION** |
| **RL Phase 1 Peak Checkpoint** | `tinker://a5e21df2-a4fe-54ce-9781-800ce6c75689:train:0/sampler_weights/000035` | **ARCHIVED PILOT** |
| **Pilot Training Session** | `a5e21df2-a4fe-54ce-9781-800ce6c75689` | Completed (50 Steps) |
| **VPS Runbook** | [`docs/rl-v1-vps-runbook.md`](file:///c:/Users/rvind/OneDrive/Desktop/Projects/BPF-FT-Project/docs/rl-v1-vps-runbook.md) | Complete (14 Sections) |
| **Pilot Verification Report** | [`runs/tinker/qwen3-8b-bpf-rl-v1/pilot_report.md`](file:///c:/Users/rvind/OneDrive/Desktop/Projects/BPF-FT-Project/runs/tinker/qwen3-8b-bpf-rl-v1/pilot_report.md) | Complete |
