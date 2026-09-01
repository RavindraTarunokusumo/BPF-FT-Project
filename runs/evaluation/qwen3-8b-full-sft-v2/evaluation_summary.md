# BPF-Guardian Evaluation & Benchmark Comparison Report

## Summary Comparison
| Metric | Calibration Baseline | Base Model | SFT Model | Absolute Delta (SFT vs Base) |
|---|---|---|---|---|
| **Functional Pass@1** | 8.3% (3/36) | 8.3% | **25.8%** | **+17.5%** |
| Output Compliance | N/A | - | 100.0% | - |
| Clang BPF Compilation | N/A | - | 54.2% | - |
| Kernel Verifier Load | N/A | - | 38.3% | - |
| Behavioral Pass | N/A | - | 25.8% | - |
| Repair@1 Recovery | 9.1% (3/33) | - | 13.5% (12/89) | - |
| Post-Repair Total Pass | 16.7% (6/36) | - | **35.8%** (43/120) | **+19.2%** |

## SFT Category Breakdown (Pass@1)
| Category | Tasks | Passed | Pass Rate |
|---|---|---|---|
| `network_routing_forwarding` | 30 | 8 | 26.7% |
| `packet_filtering_security` | 30 | 5 | 16.7% |
| `packet_inspection_telemetry` | 30 | 13 | 43.3% |
| `protocol_transformation` | 30 | 5 | 16.7% |

## SFT Difficulty Breakdown (Pass@1)
| Difficulty | Tasks | Passed | Pass Rate |
|---|---|---|---|
| `level_1` | 40 | 13 | 32.5% |
| `level_2` | 40 | 7 | 17.5% |
| `level_3` | 40 | 11 | 27.5% |
