# Qwen3-8B SFT v2: Controlled Synthesis Repair@1 & End-to-End Solve@2 Report

## 1. Executive Summary
- **Initial Private Synthesis Pass@1**: **31 / 120** (25.8%)
- **Eligible Synthesis Failures Repaired**: **89 tasks**
- **Repair@1 Recoveries**: **12 / 89** (13.5%)
- **End-to-End Solve@2**: **43 / 120** (**35.8%**)
- **Absolute Solve@2 Gain over Pass@1**: **+10.0%** (+12 tasks)

> [!NOTE]
> **Solve@2 Definition**: `Solve@2` represents a controlled multi-stage workflow: exactly one synthesis attempt followed by at most one diagnostic-guided repair attempt for failing candidates. It is **not** stochastic sampling-based `Pass@2`.

## 2. Recovery by Original Failure Stage
| Original Failure Stage | Eligible Tasks | Clang Compile | Verifier Pass | Recovered (Behavioral Pass) | Recovery Rate |
|---|:---:|:---:|:---:|:---:|:---:|
| `behavioral` | 15 | 15 (100.0%) | 15 (100.0%) | **0** | **0.0%** |
| `compilation` | 55 | 24 (43.6%) | 20 (36.4%) | **11** | **20.0%** |
| `kernel_verifier` | 19 | 19 (100.0%) | 2 (10.5%) | **1** | **5.3%** |

## 3. End-to-End Solve@2 by Application Category
| Category | Total Tasks | Initial Pass@1 | Repairs Eligible | Recovered | Solve@2 Solved | Solve@2 Rate | Solve@2 Gain |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| `network_routing_forwarding` | 30 | 8 (26.7%) | 22 | 1 | **9** | **30.0%** | **+3.3%** |
| `packet_filtering_security` | 30 | 5 (16.7%) | 25 | 2 | **7** | **23.3%** | **+6.7%** |
| `packet_inspection_telemetry` | 30 | 13 (43.3%) | 17 | 5 | **18** | **60.0%** | **+16.7%** |
| `protocol_transformation` | 30 | 5 (16.7%) | 25 | 4 | **9** | **30.0%** | **+13.3%** |

## 4. End-to-End Solve@2 by Difficulty Level
| Difficulty Level | Total Tasks | Initial Pass@1 | Repairs Eligible | Recovered | Solve@2 Solved | Solve@2 Rate | Solve@2 Gain |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| `level_1` | 40 | 13 (32.5%) | 27 | 5 | **18** | **45.0%** | **+12.5%** |
| `level_2` | 40 | 7 (17.5%) | 33 | 3 | **10** | **25.0%** | **+7.5%** |
| `level_3` | 40 | 11 (27.5%) | 29 | 4 | **15** | **37.5%** | **+10.0%** |
