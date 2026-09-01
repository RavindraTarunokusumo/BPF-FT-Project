# Paired SFT v1 &rarr; SFT v2 Transition and McNemar Statistical Analysis

## 1. Master Paired Transition Matrix
| Evaluation Suite | Tasks | v1 Pass@1 | v2 Pass@1 | Retained (`pass->pass`) | Recovered / Gain (`fail->pass`) | Regression (`pass->fail`) | Unresolved (`fail->fail`) | Discordant Pairs ($b+c$) | McNemar $p$-value | Significant? |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Private Synthesis Benchmark (120 Tasks)** | 120 | 19 (15.8%) | 31 (25.8%) | 14 | **+17** | -5 | 84 | $b=5, c=17$ | **p = 1.6901e-02** | **Yes (p < 0.05)** |
| **Private Standalone Repair Benchmark (120 Tasks)** | 120 | 75 (62.5%) | 85 (70.8%) | 72 | **+13** | -3 | 32 | $b=3, c=13$ | **p = 2.1271e-02** | **Yes (p < 0.05)** |
| **Calibration Synthesis Suite (36 Tasks)** | 36 | 20 (55.6%) | 21 (58.3%) | 15 | **+6** | -5 | 10 | $b=5, c=6$ | **p = 1.0000e+00** | No |
| **Global Total (All Suites)** | **276** | **114 (41.3%)** | **137 (49.6%)** | **101** | **+36** | **-13** | **126** | **$b=13, c=36$** | **p = 1.4027e-03** | **Yes (p < 0.01)** |

---

## 2. Detailed Breakdown by Suite
### Private Synthesis Benchmark (120 Tasks)
- **v1 Results File**: `runs/evaluation/qwen3-8b-full-sft-v1/benchmark-synthesis-120/verification/results.jsonl` (SHA-256: `064a2c63b33cde89f56e66bf552f302dcd4aac6724bf15e35af06a55f9d0e4cf`)
- **v2 Results File**: `runs/evaluation/qwen3-8b-full-sft-v2/benchmark-synthesis-120/verification/results.jsonl` (SHA-256: `50d4f39ef98f695bc21dceae9af359bf3da95489a5c8d2bc796929d6285892a6`)
- **McNemar Test**: $b=5$, $c=17$, exact $p = 0.01690$

#### Category Transitions
| Category | Tasks | Retained (`pass->pass`) | Recovered (`fail->pass`) | Regression (`pass->fail`) | Unresolved (`fail->fail`) |
|---|:---:|:---:|:---:|:---:|:---:|
| `network_routing_forwarding` | 30 | 6 | +2 | -0 | 22 |
| `packet_filtering_security` | 30 | 3 | +2 | -1 | 24 |
| `packet_inspection_telemetry` | 30 | 5 | +8 | -3 | 14 |
| `protocol_transformation` | 30 | 0 | +5 | -1 | 24 |

#### Difficulty Transitions
| Difficulty | Tasks | Retained (`pass->pass`) | Recovered (`fail->pass`) | Regression (`pass->fail`) | Unresolved (`fail->fail`) |
|---|:---:|:---:|:---:|:---:|:---:|
| `level_1` | 40 | 7 | +6 | -3 | 24 |
| `level_2` | 40 | 3 | +4 | -1 | 32 |
| `level_3` | 40 | 4 | +7 | -1 | 28 |

#### Regressed Tasks in Private Synthesis Benchmark (120 Tasks) (v1 Passed &rarr; v2 Failed):
- `syn_pfs_l1_006_coap_non_confirmable_drop`
- `syn_pit_l1_004_gtpu_teid_zero_count`
- `syn_pit_l2_006_ntp_stratum_telemetry`
- `syn_pit_l3_005_gtpu_bearer_traffic_matrix`
- `syn_ptr_l1_005_coap_port_remap`

### Private Standalone Repair Benchmark (120 Tasks)
- **v1 Results File**: `runs/evaluation/qwen3-8b-full-sft-v1/benchmark-repair-120/verification/results.jsonl` (SHA-256: `5501783f262ccba1b56a750ddb875f5122ce351134d0c265896e55ce53e037a9`)
- **v2 Results File**: `runs/evaluation/qwen3-8b-full-sft-v2/benchmark-repair-120/verification/results.jsonl` (SHA-256: `e93058df1f2d205784c579c519e77b1677caacde4351732bca020247fed42b7d`)
- **McNemar Test**: $b=3$, $c=13$, exact $p = 0.02127$

#### Category Transitions
| Category | Tasks | Retained (`pass->pass`) | Recovered (`fail->pass`) | Regression (`pass->fail`) | Unresolved (`fail->fail`) |
|---|:---:|:---:|:---:|:---:|:---:|
| `network_routing_forwarding` | 30 | 14 | +2 | -0 | 14 |
| `packet_filtering_security` | 30 | 20 | +3 | -1 | 6 |
| `packet_inspection_telemetry` | 30 | 23 | +1 | -1 | 5 |
| `protocol_transformation` | 30 | 15 | +7 | -1 | 7 |

#### Difficulty Transitions
| Difficulty | Tasks | Retained (`pass->pass`) | Recovered (`fail->pass`) | Regression (`pass->fail`) | Unresolved (`fail->fail`) |
|---|:---:|:---:|:---:|:---:|:---:|
| `level_1` | 40 | 23 | +3 | -0 | 14 |
| `level_2` | 40 | 27 | +5 | -2 | 6 |
| `level_3` | 40 | 22 | +5 | -1 | 12 |

#### Regressed Tasks in Private Standalone Repair Benchmark (120 Tasks) (v1 Passed &rarr; v2 Failed):
- `repair_pfs_l2_subnet_blacklist`
- `repair_pit_l2_protocol_matrix`
- `repair_ptr_l3_nptv6_prefix_rewrite`

### Calibration Synthesis Suite (36 Tasks)
- **v1 Results File**: `runs/evaluation/qwen3-8b-full-sft-v1/rollout-001/verification/results.jsonl` (SHA-256: `8674ac0d17631afb85b1a49a24d2e1524f4de176f2e455c188155161794013f0`)
- **v2 Results File**: `runs/evaluation/qwen3-8b-full-sft-v2/calibration-synthesis/verification/results.jsonl` (SHA-256: `208b642b23bef6740e95b24c3e5e45108a7a00e4a1b0fce857c0ad9d9f9edc0e`)
- **McNemar Test**: $b=5$, $c=6$, exact $p = 1.00000$

#### Category Transitions
| Category | Tasks | Retained (`pass->pass`) | Recovered (`fail->pass`) | Regression (`pass->fail`) | Unresolved (`fail->fail`) |
|---|:---:|:---:|:---:|:---:|:---:|
| `network_routing_forwarding` | 9 | 2 | +1 | -1 | 5 |
| `packet_filtering_security` | 9 | 2 | +1 | -2 | 4 |
| `packet_inspection_telemetry` | 9 | 6 | +0 | -2 | 1 |
| `protocol_transformation` | 9 | 5 | +4 | -0 | 0 |

#### Difficulty Transitions
| Difficulty | Tasks | Retained (`pass->pass`) | Recovered (`fail->pass`) | Regression (`pass->fail`) | Unresolved (`fail->fail`) |
|---|:---:|:---:|:---:|:---:|:---:|
| `level_1` | 12 | 6 | +2 | -3 | 1 |
| `level_2` | 12 | 8 | +1 | -0 | 3 |
| `level_3` | 12 | 1 | +3 | -2 | 6 |

#### Regressed Tasks in Calibration Synthesis Suite (36 Tasks) (v1 Passed &rarr; v2 Failed):
- `nrf_l1_icmp_reflector`
- `pfs_l1_tcp23_drop`
- `pfs_l1_udp53_drop`
- `pit_l3_ipv4_flow_counter`
- `pit_l3_tcp_flow_outcomes`

