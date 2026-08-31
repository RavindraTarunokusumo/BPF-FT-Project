# BPF-Guardian Benchmark Verification Summary

## Aggregate Metrics
| Metric | Passed / Total | Rate |
|---|---|---|
| Output Compliance | 120 / 120 | 100.0% |
| Clang BPF Compilation | 101 / 120 | 84.2% |
| Kernel Verifier Load | 96 / 120 | 80.0% |
| Behavioral Packet Test | 75 / 120 | 62.5% |
| **Functional Pass@1** | **75 / 120** | **62.5%** |
| **Functional Pass@4** | N/A (1 sample/task) | N/A |

## Category Breakdown (Pass@1)
| Category | Tasks | Compliant | Compile | Verifier | Fully Passed | Pass@1 Rate |
|---|---|---|---|---|---|---|
| `network_routing_forwarding` | 30 | 30 | 20 | 20 | 14 | 46.7% |
| `packet_filtering_security` | 30 | 30 | 29 | 28 | 21 | 70.0% |
| `packet_inspection_telemetry` | 30 | 30 | 30 | 29 | 24 | 80.0% |
| `protocol_transformation` | 30 | 30 | 22 | 19 | 16 | 53.3% |

## Difficulty Breakdown (Pass@1)
| Difficulty | Tasks | Compliant | Compile | Verifier | Fully Passed | Pass@1 Rate |
|---|---|---|---|---|---|---|
| `level_1` | 40 | 40 | 36 | 34 | 23 | 57.5% |
| `level_2` | 40 | 40 | 33 | 32 | 29 | 72.5% |
| `level_3` | 40 | 40 | 32 | 30 | 23 | 57.5% |
