# BPF-Guardian Benchmark Verification Summary

## Aggregate Metrics
| Metric | Passed / Total | Rate |
|---|---|---|
| Output Compliance | 36 / 36 | 100.0% |
| Clang BPF Compilation | 25 / 36 | 69.4% |
| Kernel Verifier Load | 22 / 36 | 61.1% |
| Behavioral Packet Test | 20 / 36 | 55.6% |
| **Functional Pass@1** | **20 / 36** | **55.6%** |
| **Functional Pass@4** | **20 / 36** | **55.6%** |

## Category Breakdown (Pass@1)
| Category | Tasks | Compliant | Compile | Verifier | Fully Passed | Pass@1 Rate |
|---|---|---|---|---|---|---|
| `network_routing_forwarding` | 9 | 0 | 4 | 3 | 3 | 33.3% |
| `packet_filtering_security` | 9 | 0 | 8 | 6 | 4 | 44.4% |
| `packet_inspection_telemetry` | 9 | 0 | 8 | 8 | 8 | 88.9% |
| `protocol_transformation` | 9 | 0 | 5 | 5 | 5 | 55.6% |

## Difficulty Breakdown (Pass@1)
| Difficulty | Tasks | Compliant | Compile | Verifier | Fully Passed | Pass@1 Rate |
|---|---|---|---|---|---|---|
| `level_1` | 12 | 0 | 9 | 9 | 9 | 75.0% |
| `level_2` | 12 | 0 | 11 | 10 | 8 | 66.7% |
| `level_3` | 12 | 0 | 5 | 3 | 3 | 25.0% |
