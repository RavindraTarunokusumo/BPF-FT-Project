# BPF-Guardian Benchmark Verification Summary

## Aggregate Metrics
| Metric | Passed / Total | Rate |
|---|---|---|
| Output Compliance | 36 / 36 | 100.0% |
| Clang BPF Compilation | 36 / 36 | 100.0% |
| Kernel Verifier Load | 36 / 36 | 100.0% |
| Behavioral Packet Test | 36 / 36 | 100.0% |
| **Functional Pass@1** | **36 / 36** | **100.0%** |
| **Functional Pass@4** | N/A (1 sample/task) | N/A |

## Category Breakdown (Pass@1)
| Category | Tasks | Compliant | Compile | Verifier | Fully Passed | Pass@1 Rate |
|---|---|---|---|---|---|---|
| `network_routing_forwarding` | 9 | 9 | 9 | 9 | 9 | 100.0% |
| `packet_filtering_security` | 9 | 9 | 9 | 9 | 9 | 100.0% |
| `packet_inspection_telemetry` | 9 | 9 | 9 | 9 | 9 | 100.0% |
| `protocol_transformation` | 9 | 9 | 9 | 9 | 9 | 100.0% |

## Difficulty Breakdown (Pass@1)
| Difficulty | Tasks | Compliant | Compile | Verifier | Fully Passed | Pass@1 Rate |
|---|---|---|---|---|---|---|
| `level_1` | 12 | 12 | 12 | 12 | 12 | 100.0% |
| `level_2` | 12 | 12 | 12 | 12 | 12 | 100.0% |
| `level_3` | 12 | 12 | 12 | 12 | 12 | 100.0% |
