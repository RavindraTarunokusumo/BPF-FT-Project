# BPF-Guardian Benchmark Verification Summary

## Aggregate Metrics
| Metric | Passed / Total | Rate |
|---|---|---|
| Output Compliance | 120 / 120 | 100.0% |
| Clang BPF Compilation | 49 / 120 | 40.8% |
| Kernel Verifier Load | 31 / 120 | 25.8% |
| Behavioral Packet Test | 19 / 120 | 15.8% |
| **Functional Pass@1** | **19 / 120** | **15.8%** |
| **Functional Pass@4** | N/A (1 sample/task) | N/A |

## Category Breakdown (Pass@1)
| Category | Tasks | Compliant | Compile | Verifier | Fully Passed | Pass@1 Rate |
|---|---|---|---|---|---|---|
| `network_routing_forwarding` | 30 | 30 | 13 | 12 | 6 | 20.0% |
| `packet_filtering_security` | 30 | 30 | 15 | 10 | 4 | 13.3% |
| `packet_inspection_telemetry` | 30 | 30 | 13 | 8 | 8 | 26.7% |
| `protocol_transformation` | 30 | 30 | 8 | 1 | 1 | 3.3% |

## Difficulty Breakdown (Pass@1)
| Difficulty | Tasks | Compliant | Compile | Verifier | Fully Passed | Pass@1 Rate |
|---|---|---|---|---|---|---|
| `level_1` | 40 | 40 | 18 | 13 | 10 | 25.0% |
| `level_2` | 40 | 40 | 15 | 9 | 4 | 10.0% |
| `level_3` | 40 | 40 | 16 | 9 | 5 | 12.5% |
