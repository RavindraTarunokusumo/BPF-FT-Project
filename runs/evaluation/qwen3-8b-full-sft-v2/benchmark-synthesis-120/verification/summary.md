# BPF-Guardian Benchmark Verification Summary

## Aggregate Metrics
| Metric | Passed / Total | Rate |
|---|---|---|
| Output Compliance | 120 / 120 | 100.0% |
| Clang BPF Compilation | 120 / 120 | 100.0% |
| Kernel Verifier Load | 120 / 120 | 100.0% |
| Behavioral Packet Test | 120 / 120 | 100.0% |
| **Functional Pass@1** | **120 / 120** | **100.0%** |
| **Functional Pass@4** | N/A (1 sample/task) | N/A |

## Category Breakdown (Pass@1)
| Category | Tasks | Compliant | Compile | Verifier | Fully Passed | Pass@1 Rate |
|---|---|---|---|---|---|---|
| `network_routing_forwarding` | 30 | 30 | 30 | 30 | 30 | 100.0% |
| `packet_filtering_security` | 30 | 30 | 30 | 30 | 30 | 100.0% |
| `packet_inspection_telemetry` | 30 | 30 | 30 | 30 | 30 | 100.0% |
| `protocol_transformation` | 30 | 30 | 30 | 30 | 30 | 100.0% |

## Difficulty Breakdown (Pass@1)
| Difficulty | Tasks | Compliant | Compile | Verifier | Fully Passed | Pass@1 Rate |
|---|---|---|---|---|---|---|
| `level_1` | 40 | 40 | 40 | 40 | 40 | 100.0% |
| `level_2` | 40 | 40 | 40 | 40 | 40 | 100.0% |
| `level_3` | 40 | 40 | 40 | 40 | 40 | 100.0% |
