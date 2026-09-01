# BPF-Guardian Evaluation & Benchmark Comparison Report

## Summary Comparison
| Metric | Calibration Baseline | Base Model | SFT Model | Absolute Delta (SFT vs Base) |
|---|---|---|---|---|
| **Functional Pass@1** | 8.3% (3/36) | 8.3% | **58.3%** | **+50.0%** |
| Output Compliance | N/A | - | 100.0% | - |
| Clang BPF Compilation | N/A | - | 80.6% | - |
| Kernel Verifier Load | N/A | - | 75.0% | - |
| Behavioral Pass | N/A | - | 58.3% | - |

## SFT Category Breakdown (Pass@1)
| Category | Tasks | Passed | Pass Rate |
|---|---|---|---|
| `network_routing_forwarding` | 9 | 3 | 33.3% |
| `packet_filtering_security` | 9 | 3 | 33.3% |
| `packet_inspection_telemetry` | 9 | 6 | 66.7% |
| `protocol_transformation` | 9 | 9 | 100.0% |

## SFT Difficulty Breakdown (Pass@1)
| Difficulty | Tasks | Passed | Pass Rate |
|---|---|---|---|
| `level_1` | 12 | 8 | 66.7% |
| `level_2` | 12 | 9 | 75.0% |
| `level_3` | 12 | 4 | 33.3% |
