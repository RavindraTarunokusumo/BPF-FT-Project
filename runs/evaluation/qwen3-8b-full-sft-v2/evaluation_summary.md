# BPF-Guardian Evaluation & Benchmark Comparison Report

## Summary Comparison
| Metric | Calibration Baseline | Base Model | SFT Model | Absolute Delta (SFT vs Base) |
|---|---|---|---|---|
| **Functional Pass@1** | 8.3% (3/36) | 8.3% | **100.0%** | **+91.7%** |
| Output Compliance | N/A | - | 100.0% | - |
| Clang BPF Compilation | N/A | - | 100.0% | - |
| Kernel Verifier Load | N/A | - | 100.0% | - |
| Behavioral Pass | N/A | - | 100.0% | - |

## SFT Category Breakdown (Pass@1)
| Category | Tasks | Passed | Pass Rate |
|---|---|---|---|
| `network_routing_forwarding` | 9 | 9 | 100.0% |
| `packet_filtering_security` | 9 | 9 | 100.0% |
| `packet_inspection_telemetry` | 9 | 9 | 100.0% |
| `protocol_transformation` | 9 | 9 | 100.0% |

## SFT Difficulty Breakdown (Pass@1)
| Difficulty | Tasks | Passed | Pass Rate |
|---|---|---|---|
| `level_1` | 12 | 12 | 100.0% |
| `level_2` | 12 | 12 | 100.0% |
| `level_3` | 12 | 12 | 100.0% |
