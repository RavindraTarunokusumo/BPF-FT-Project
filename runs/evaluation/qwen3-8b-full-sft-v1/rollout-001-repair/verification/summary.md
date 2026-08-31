# BPF-Guardian Benchmark Verification Summary

## Aggregate Metrics
| Metric | Passed / Total | Rate |
|---|---|---|
| Output Compliance | 16 / 16 | 100.0% |
| Clang BPF Compilation | 16 / 16 | 100.0% |
| Kernel Verifier Load | 16 / 16 | 100.0% |
| Behavioral Packet Test | 16 / 16 | 100.0% |
| **Functional Pass@1** | **16 / 16** | **100.0%** |
| **Functional Pass@4** | N/A (1 sample/task) | N/A |

## Category Breakdown (Pass@1)
| Category | Tasks | Compliant | Compile | Verifier | Fully Passed | Pass@1 Rate |
|---|---|---|---|---|---|---|
| `network_routing_forwarding` | 6 | 6 | 6 | 6 | 6 | 100.0% |
| `packet_filtering_security` | 5 | 5 | 5 | 5 | 5 | 100.0% |
| `packet_inspection_telemetry` | 1 | 1 | 1 | 1 | 1 | 100.0% |
| `protocol_transformation` | 4 | 4 | 4 | 4 | 4 | 100.0% |

## Difficulty Breakdown (Pass@1)
| Difficulty | Tasks | Compliant | Compile | Verifier | Fully Passed | Pass@1 Rate |
|---|---|---|---|---|---|---|
| `level_1` | 3 | 3 | 3 | 3 | 3 | 100.0% |
| `level_2` | 4 | 4 | 4 | 4 | 4 | 100.0% |
| `level_3` | 9 | 9 | 9 | 9 | 9 | 100.0% |
