# BPF-Guardian Benchmark Verification Summary

## Aggregate Metrics
| Metric | Passed / Total | Rate |
|---|---|---|
| Output Compliance | 36 / 36 | 100.0% |
| Clang BPF Compilation | 10 / 36 | 27.8% |
| Kernel Verifier Load | 8 / 36 | 22.2% |
| Behavioral Packet Test | 8 / 36 | 22.2% |
| **Functional Pass@1** | **8 / 36** | **22.2%** |
| **Functional Pass@4** | **8 / 36** | **22.2%** |

## Category Breakdown (Pass@1)
| Category | Tasks | Compliant | Compile | Verifier | Fully Passed | Pass@1 Rate |
|---|---|---|---|---|---|---|
| `network_routing_forwarding` | 9 | 0 | 1 | 0 | 0 | 0.0% |
| `packet_filtering_security` | 9 | 0 | 1 | 0 | 0 | 0.0% |
| `packet_inspection_telemetry` | 9 | 0 | 5 | 5 | 5 | 55.6% |
| `protocol_transformation` | 9 | 0 | 3 | 3 | 3 | 33.3% |

## Difficulty Breakdown (Pass@1)
| Difficulty | Tasks | Compliant | Compile | Verifier | Fully Passed | Pass@1 Rate |
|---|---|---|---|---|---|---|
| `level_1` | 12 | 0 | 5 | 4 | 4 | 33.3% |
| `level_2` | 12 | 0 | 2 | 2 | 2 | 16.7% |
| `level_3` | 12 | 0 | 3 | 2 | 2 | 16.7% |
