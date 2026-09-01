# BPF-Guardian Benchmark Verification Summary

## Aggregate Metrics
| Metric | Passed / Total | Rate |
|---|---|---|
| Output Compliance | 120 / 120 | 100.0% |
| Clang BPF Compilation | 65 / 120 | 54.2% |
| Kernel Verifier Load | 46 / 120 | 38.3% |
| Behavioral Packet Test | 31 / 120 | 25.8% |
| **Functional Pass@1** | **31 / 120** | **25.8%** |
| **Functional Pass@4** | N/A (1 sample/task) | N/A |

## Category Breakdown (Pass@1)
| Category | Tasks | Compliant | Compile | Verifier | Fully Passed | Pass@1 Rate |
|---|---|---|---|---|---|---|
| `network_routing_forwarding` | 30 | 30 | 17 | 17 | 8 | 26.7% |
| `packet_filtering_security` | 30 | 30 | 15 | 11 | 5 | 16.7% |
| `packet_inspection_telemetry` | 30 | 30 | 15 | 13 | 13 | 43.3% |
| `protocol_transformation` | 30 | 30 | 18 | 5 | 5 | 16.7% |

## Difficulty Breakdown (Pass@1)
| Difficulty | Tasks | Compliant | Compile | Verifier | Fully Passed | Pass@1 Rate |
|---|---|---|---|---|---|---|
| `level_1` | 40 | 40 | 21 | 18 | 13 | 32.5% |
| `level_2` | 40 | 40 | 20 | 12 | 7 | 17.5% |
| `level_3` | 40 | 40 | 24 | 16 | 11 | 27.5% |
