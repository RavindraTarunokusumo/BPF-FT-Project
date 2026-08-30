# BPF-Guardian Evaluation & Benchmark Comparison Report

## Summary Comparison
| Metric | Calibration Baseline | Base Model | SFT Model | Absolute Delta (SFT vs Base) |
|---|---|---|---|---|
| **Functional Pass@1** | 8.3% (3/36) | 8.3% | **55.6%** | **+47.2%** |
| Output Compliance | N/A | - | 0.0% | - |
| Clang BPF Compilation | N/A | - | 69.4% | - |
| Kernel Verifier Load | N/A | - | 61.1% | - |
| Behavioral Pass | N/A | - | 55.6% | - |

## SFT Category Breakdown (Pass@1)
| Category | Tasks | Passed | Pass Rate |
|---|---|---|---|
| `unknown` | 36 | 20 | 55.6% |

## SFT Difficulty Breakdown (Pass@1)
| Difficulty | Tasks | Passed | Pass Rate |
|---|---|---|---|
| `level_1` | 12 | 9 | 75.0% |
| `level_2` | 12 | 8 | 66.7% |
| `level_3` | 12 | 3 | 25.0% |
