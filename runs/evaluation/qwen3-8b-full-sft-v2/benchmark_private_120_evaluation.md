# Qwen3-8B SFT v2: Consolidated Empirical Linux Kernel Evaluation Report

**Evaluation Date**: 2026-09-02  
**Checkpoint**: `tinker://9461002d-2321-5858-8184-5604f9304283:train:0/sampler_weights/final`  
**Base Model**: `Qwen/Qwen3-8B`  
**Renderer**: `qwen3_disable_thinking`  
**Sampling Configuration**: `temperature=0.0`, `seed=42`, `num_samples=1`, `max_tokens=2048`  
**Verification Host**: Hostinger Linux VPS (`Linux srv1534562 6.8.0-106-generic x86_64`)  
**Toolchain**: Ubuntu Clang `18.1.3 (1ubuntu1)`, `bpftool v7.4.0`, `libbpf v1.4`  
**Behavioral Execution**: Linux Kernel `BPF_PROG_TEST_RUN` against multi-packet fixture suites  
**Total Evaluation Scope**: 276 Standardized Benchmark Tasks (36 Calibration + 120 Private Synthesis + 120 Private Repair) + 89 Controlled Synthesis Repair@1 Tasks

---

## 1. Master Empirical Comparison Matrix

All evaluations were executed live against the Linux 6.8 kernel verifier and actual packet test harness on the dedicated verification VPS:

| Evaluation Suite / Metric | Pre-SFT Baseline | SFT v1 Model | SFT v2 Model (Current) | Absolute Gain (v2 vs. v1) | Absolute Gain (v2 vs. Baseline) | Paired McNemar $p$-value |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| **Output Compliance Rate** | 22.2% (8/36) | 100.0% (276/276) | **100.0%** (276/276) | +0.0% | **+77.8%** | N/A |
| **Calibration Suite (Synthesis Pass@1)** | 8.3% (3/36) | 55.6% (20/36) | **58.3%** (21/36) | **+2.7%** | **+50.0%** | $p = 1.0000$ |
| **Private Synthesis Benchmark (120 Tasks)** | 0.0% (0/120) | 15.8% (19/120) | **25.8%** (31/120) | **+10.0%** | **+25.8%** | **$p = 0.0169$** |
| &bull; *Clang BPF Compilation* | 11.7% (14/120) | 40.8% (49/120) | **54.2%** (65/120) | **+13.4%** | **+42.5%** | $p = 0.0039$ |
| &bull; *Kernel Verifier Acceptance* | 4.2% (5/120) | 25.8% (31/120) | **38.3%** (46/120) | **+12.5%** | **+34.1%** | $p = 0.0077$ |
| **Private Repair Benchmark (120 Tasks)** | 9.1% (11/120) | 62.5% (75/120) | **70.8%** (85/120) | **+8.3%** | **+61.7%** | **$p = 0.0213$** |
| &bull; *Clang BPF Compilation* | 32.5% (39/120) | 84.2% (101/120) | **91.7%** (110/120) | **+7.5%** | **+59.2%** | $p = 0.0269$ |
| &bull; *Kernel Verifier Acceptance* | 25.0% (30/120) | 80.0% (96/120) | **88.3%** (106/120) | **+8.3%** | **+63.3%** | $p = 0.0159$ |
| **Global Functional Pass@1 (276 Tasks)** | **5.1%** (14/276) | **41.3%** (114/276) | **49.6%** (137/276) | **+8.3%** | **+44.5%** | **$p = 0.0014$** |

> [!NOTE]
> **Arithmetic Reconciliation**: The earlier preliminary draft recorded `138/276 = 50.0%` due to a manual summing error. Constituent empirical counts in raw records are `21` (calibration) + `31` (private synthesis) + `85` (private repair) = **`137` functional passes**. The exact global functional Pass@1 rate is **`137 / 276 = 49.6%`**, representing a **+8.3 percentage point improvement** (+23 solved tasks) over SFT v1 (`114 / 276 = 41.3%`).

---

## 2. 120-Task Private Synthesis Benchmark Breakdown

The 120-Task Private Synthesis Benchmark evaluates zero-shot C code generation across novel protocols (VXLAN, GENEVE, GRE, GTP-U, SRv6, Q-in-Q, LPM Tries, Token-bucket rate policers).

### 2.1 By Application Category (Pass@1)
| Application Category | Tasks | Output Compliant | Clang BPF Compile | Kernel Verifier | Behavioral Pass | Pass@1 (v2) | Pass@1 (v1) | Delta |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **`packet_inspection_telemetry`** | 30 | 30 (100.0%) | 15 (50.0%) | 13 (43.3%) | 13 | **43.3%** (13/30) | 26.7% (8/30) | **+16.6%** |
| **`network_routing_forwarding`** | 30 | 30 (100.0%) | 17 (56.7%) | 17 (56.7%) | 8 | **26.7%** (8/30) | 20.0% (6/30) | **+6.7%** |
| **`packet_filtering_security`** | 30 | 30 (100.0%) | 15 (50.0%) | 11 (36.7%) | 5 | **16.7%** (5/30) | 13.3% (4/30) | **+3.4%** |
| **`protocol_transformation`** | 30 | 30 (100.0%) | 18 (60.0%) | 5 (16.7%) | 5 | **16.7%** (5/30) | 3.3% (1/30) | **+13.4%** |
| **Total Synthesis** | **120** | **120 (100.0%)** | **65 (54.2%)** | **46 (38.3%)** | **31** | **25.8%** (31/120) | **15.8%** (19/120) | **+10.0%** |

### 2.2 By Difficulty Level (Pass@1)
| Difficulty Level | Tasks | Output Compliant | Clang Compile | Kernel Verifier | Fully Passed | Pass@1 (v2) | Pass@1 (v1) | Delta |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| `level_1` (Basic) | 40 | 40 (100.0%) | 21 (52.5%) | 18 (45.0%) | 13 | **32.5%** (13/40) | 25.0% (10/40) | **+7.5%** |
| `level_2` (Nested/Options) | 40 | 40 (100.0%) | 20 (50.0%) | 12 (30.0%) | 7 | **17.5%** (7/40) | 12.5% (5/40) | **+5.0%** |
| `level_3` (Stateful/Maps) | 40 | 40 (100.0%) | 24 (60.0%) | 16 (40.0%) | 11 | **27.5%** (11/40) | 10.0% (4/40) | **+17.5%** |

---

## 3. Controlled Synthesis Repair@1 and End-to-End Solve@2 Evaluation

All 89 synthesis candidates that failed initial execution received exactly one deterministic diagnostic-guided repair turn based on their initial failure mode:

- **Initial Synthesis Pass@1**: **31 / 120** (25.8%)
- **Eligible Synthesis Failures Repaired**: **89 tasks**
- **Repair@1 Recoveries**: **12 / 89** (13.5%)
- **End-to-End Solve@2**: **43 / 120** (**35.8%**)
- **Absolute Solve@2 Gain over Pass@1**: **+10.0%** (+12 solved tasks)

> [!NOTE]
> **Solve@2 vs. Pass@2**: `Solve@2` denotes an end-to-end multi-step workflow: exactly 1 synthesis generation attempt followed by at most 1 diagnostic-guided repair attempt for failing candidates. It is **not** sampling-based `Pass@2` ($k=2$ random draws).

### 3.1 Repair Recovery by Original Failure Stage
| Original Failure Stage | Eligible Tasks | Clang Compile | Verifier Acceptance | Recovered (Behavioral Pass) | Recovery Rate |
|---|:---:|:---:|:---:|:---:|:---:|
| `compilation` | 55 | 24 (43.6%) | 20 (36.4%) | **11** | **20.0%** (11/55) |
| `kernel_verifier` | 19 | 19 (100.0%) | 2 (10.5%) | **1** | **5.3%** (1/19) |
| `behavioral` | 15 | 15 (100.0%) | 15 (100.0%) | **0** | **0.0%** (0/15) |
| **Total** | **89** | **58 (65.2%)** | **37 (41.6%)** | **12** | **13.5%** (12/89) |

### 3.2 End-to-End Solve@2 by Application Category
| Application Category | Total Tasks | Initial Pass@1 | Repairs Eligible | Recovered | Solve@2 Solved | Solve@2 Rate | Absolute Gain |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| `packet_inspection_telemetry` | 30 | 13 (43.3%) | 17 | 5 | **18** | **60.0%** | **+16.7%** |
| `protocol_transformation` | 30 | 5 (16.7%) | 25 | 4 | **9** | **30.0%** | **+13.3%** |
| `packet_filtering_security` | 30 | 5 (16.7%) | 25 | 2 | **7** | **23.3%** | **+6.7%** |
| `network_routing_forwarding` | 30 | 8 (26.7%) | 22 | 1 | **9** | **30.0%** | **+3.3%** |
| **Total Solve@2** | **120** | **31 (25.8%)** | **89** | **12** | **43** | **35.8%** | **+10.0%** |

### 3.3 End-to-End Solve@2 by Difficulty Level
| Difficulty Level | Total Tasks | Initial Pass@1 | Repairs Eligible | Recovered | Solve@2 Solved | Solve@2 Rate | Absolute Gain |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| `level_1` (Basic) | 40 | 13 (32.5%) | 27 | 5 | **18** | **45.0%** | **+12.5%** |
| `level_2` (Nested/Options) | 40 | 7 (17.5%) | 33 | 3 | **10** | **25.0%** | **+7.5%** |
| `level_3` (Stateful/Maps) | 40 | 11 (27.5%) | 29 | 4 | **15** | **37.5%** | **+10.0%** |

---

## 4. 120-Task Private Standalone Repair Benchmark Breakdown

The 120-Task Standalone Repair Benchmark measures the model's ability to repair pre-constructed faulty XDP implementations given real compiler errors, verifier logs, or behavioral test failures.

### 4.1 By Application Category (Pass@1)
| Application Category | Total Tasks | Output Compliant | Clang Compile | Kernel Verifier | Behavioral Pass | Pass@1 (v2) | Pass@1 (v1) | Delta |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **`packet_inspection_telemetry`** | 30 | 30 (100.0%) | 30 (100.0%) | 29 (96.7%) | 24 | **80.0%** (24/30) | 80.0% (24/30) | +0.0% |
| **`packet_filtering_security`** | 30 | 30 (100.0%) | 28 (93.3%) | 28 (93.3%) | 23 | **76.7%** (23/30) | 70.0% (21/30) | **+6.7%** |
| **`protocol_transformation`** | 30 | 30 (100.0%) | 28 (93.3%) | 25 (83.3%) | 22 | **73.3%** (22/30) | 53.3% (16/30) | **+20.0%** |
| **`network_routing_forwarding`** | 30 | 30 (100.0%) | 24 (80.0%) | 24 (80.0%) | 16 | **53.3%** (16/30) | 46.7% (14/30) | **+6.6%** |
| **Total Standalone Repair** | **120** | **120 (100.0%)** | **110 (91.7%)** | **106 (88.3%)** | **85** | **70.8%** (85/120) | **62.5%** (75/120) | **+8.3%** |

### 4.2 By Difficulty Level (Pass@1)
| Difficulty Level | Total Tasks | Compliant | Clang Compile | Kernel Verifier | Fully Passed | Pass@1 (v2) | Pass@1 (v1) | Delta |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| `level_1` (Basic) | 40 | 40 (100.0%) | 39 (97.5%) | 37 (92.5%) | 26 | **65.0%** (26/40) | 57.5% (23/40) | **+7.5%** |
| `level_2` (Nested/Options) | 40 | 40 (100.0%) | 35 (87.5%) | 33 (82.5%) | 32 | **80.0%** (32/40) | 72.5% (29/40) | **+7.5%** |
| `level_3` (Stateful/Maps) | 40 | 40 (100.0%) | 36 (90.0%) | 36 (90.0%) | 27 | **67.5%** (27/40) | 57.5% (23/40) | **+10.0%** |

---

## 5. Paired SFT v1 &rarr; v2 Transition Analysis and McNemar Tests

Because SFT v1 and SFT v2 were evaluated on the exact same 276 tasks with identical sampling configurations, paired transition matrices and exact two-sided McNemar tests quantify genuine capability shifts versus random variance:

| Evaluation Suite | Tasks | Retained (`pass->pass`) | Recovered (`fail->pass`) | Regression (`pass->fail`) | Unresolved (`fail->fail`) | Discordant ($b, c$) | McNemar $p$-value | Statistically Significant? |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Private Synthesis (120 Tasks)** | 120 | 14 | **+17** | -5 | 84 | $b=5, c=17$ | **$p = 0.0169$** | **Yes ($p < 0.05$)** |
| **Private Repair (120 Tasks)** | 120 | 72 | **+13** | -3 | 32 | $b=3, c=13$ | **$p = 0.0213$** | **Yes ($p < 0.05$)** |
| **Calibration Suite (36 Tasks)** | 36 | 15 | **+6** | -5 | 10 | $b=5, c=6$ | **$p = 1.0000$** | No |
| **Global Total (All 276 Tasks)** | **276** | **101** | **+36** | **-13** | **126** | **$b=13, c=36$** | **$p = 0.0014$** | **Yes ($p < 0.01$)** |

### 5.1 Regressions Analysis (SFT v1 Pass &rarr; SFT v2 Fail)
Across all 276 tasks, 13 tasks regressed in SFT v2:
1. **Private Synthesis (5 tasks)**:
   - `syn_pfs_l1_006_coap_non_confirmable_drop` (compilation syntax regression)
   - `syn_pit_l1_004_gtpu_teid_zero_count` (verifier pointer alignment)
   - `syn_pit_l2_006_ntp_stratum_telemetry` (header offset bounds check)
   - `syn_pit_l3_005_gtpu_bearer_traffic_matrix` (map value struct layout mismatch)
   - `syn_ptr_l1_005_coap_port_remap` (checksum recalculation helper)
2. **Private Repair (3 tasks)**:
   - `repair_pfs_l2_subnet_blacklist` (CIDR mask bitwise operation)
   - `repair_pit_l2_protocol_matrix` (verifier array bounds index)
   - `repair_ptr_l3_nptv6_prefix_rewrite` (IPv6 address word swap)
3. **Calibration Suite (5 tasks)**:
   - `nrf_l1_icmp_reflector`, `pfs_l1_tcp23_drop`, `pfs_l1_udp53_drop`, `pit_l3_ipv4_flow_counter`, `pit_l3_tcp_flow_outcomes`

---

## 6. Synthesis and Repair Attrition Analysis

```
[120 Synthesis Tasks]
   │
   ├── Compliant Output: 120/120 (100.0%)
   │     │
   │     ├── Clang BPF Compilation: 65/120 (54.2%)  ──[Fail: 55]
   │     │     │
   │     │     ├── Verifier Accepted: 46/120 (38.3%)  ──[Fail: 19]
   │     │     │     │
   │     │     │     └── Behavioral Pass: 31/120 (25.8%)  ──[Fail: 15]
   │     │     │
   │     └── [89 Synthesis Failures Enter Controlled Repair@1]
   │           │
   │           ├── Clang BPF Compilation: 58/89 (65.2%)
   │           │     │
   │           │     ├── Verifier Accepted: 37/89 (41.6%)
   │           │     │     │
   │           │     │     └── Behavioral Pass (Recovered): 12/89 (13.5%)
   │           │
   │           └── End-to-End Solve@2: (31 + 12) = 43/120 (35.8%)
```

---

## 7. Limitations and Scope Constraints

1. **Benchmark Influence on Training Priority**:
   The 120-task private synthesis and repair benchmarks were constructed prior to the SFT v2 dataset redesign. While zero sample or task leakage exists between training splits and benchmarks (0% overlap in task IDs, hashes, and template definitions), the taxonomy of protocols and difficulty tiers informed the curriculum structure for SFT v2. As such, these benchmarks represent a stringent private test suite rather than a completely uninformed post-hoc lockbox.
2. **Output Formatting vs. Correctness**:
   100.0% output compliance indicates strict adherence to formatting constraints (zero Markdown prose, proper `#include`, `SEC()`, and license declarations), but does not guarantee semantic correctness or kernel safety.
3. **Production Readiness**:
   While SFT v2 achieves 70.8% Standalone Repair@1 and 35.8% End-to-End Solve@2, mission-critical Linux kernel deployments still require automated pre-commit verification pipelines with static analysis and live kernel testing.

---

## 8. Finalization Decision

> **SFT v2 is frozen as the final supervised-training checkpoint for this project. Further supervised fine-tuning (SFT) is not recommended. Any future extensions should focus on reinforcement learning (RL/GRPO) with execution verifier rewards or evaluation on a completely fresh blind lockbox.**
