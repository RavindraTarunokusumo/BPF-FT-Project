# BPF-Guardian Benchmark Verification Summary

## Aggregate Metrics
| Metric | Passed / Total | Rate |
|---|---|---|
| Output Compliance | 36 / 36 | 100.0% |
| Clang BPF Compilation | 29 / 36 | 80.6% |
| Kernel Verifier Load | 27 / 36 | 75.0% |
| Behavioral Packet Test | 21 / 36 | 58.3% |
| **Functional Pass@1** | **21 / 36** | **58.3%** |
| **Functional Pass@4** | N/A (1 sample/task) | N/A |

## Category Breakdown (Pass@1)
| Category | Tasks | Compliant | Compile | Verifier | Fully Passed | Pass@1 Rate |
|---|---|---|---|---|---|---|
| `network_routing_forwarding` | 9 | 9 | 6 | 6 | 3 | 33.3% |
| `packet_filtering_security` | 9 | 9 | 8 | 6 | 3 | 33.3% |
| `packet_inspection_telemetry` | 9 | 9 | 6 | 6 | 6 | 66.7% |
| `protocol_transformation` | 9 | 9 | 9 | 9 | 9 | 100.0% |

## Difficulty Breakdown (Pass@1)
| Difficulty | Tasks | Compliant | Compile | Verifier | Fully Passed | Pass@1 Rate |
|---|---|---|---|---|---|---|
| `level_1` | 12 | 12 | 12 | 11 | 8 | 66.7% |
| `level_2` | 12 | 12 | 12 | 12 | 9 | 75.0% |
| `level_3` | 12 | 12 | 5 | 4 | 4 | 33.3% |
