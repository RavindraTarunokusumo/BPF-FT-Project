# BPF-Guardian Benchmark Verification Summary

## Aggregate Metrics
| Metric | Passed / Total | Rate |
|---|---|---|
| Output Compliance | 120 / 120 | 100.0% |
| Clang BPF Compilation | 49 / 120 | 40.8% |
| Kernel Verifier Load | 31 / 120 | 25.8% |
| Behavioral Packet Test | 0 / 120 | 0.0% |
| **Functional Pass@1** | **0 / 120** | **0.0%** |
| **Functional Pass@4** | N/A (1 sample/task) | N/A |

## Category Breakdown (Pass@1)
| Category | Tasks | Compliant | Compile | Verifier | Fully Passed | Pass@1 Rate |
|---|---|---|---|---|---|---|
| `network_routing_forwarding` | 30 | 30 | 13 | 12 | 0 | 0.0% |
| `packet_filtering_security` | 30 | 30 | 15 | 10 | 0 | 0.0% |
| `packet_inspection_telemetry` | 30 | 30 | 13 | 8 | 0 | 0.0% |
| `protocol_transformation` | 30 | 30 | 8 | 1 | 0 | 0.0% |

## Difficulty Breakdown (Pass@1)
| Difficulty | Tasks | Compliant | Compile | Verifier | Fully Passed | Pass@1 Rate |
|---|---|---|---|---|---|---|
| `level_1` | 40 | 40 | 18 | 13 | 0 | 0.0% |
| `level_2` | 40 | 40 | 15 | 9 | 0 | 0.0% |
| `level_3` | 40 | 40 | 16 | 9 | 0 | 0.0% |
