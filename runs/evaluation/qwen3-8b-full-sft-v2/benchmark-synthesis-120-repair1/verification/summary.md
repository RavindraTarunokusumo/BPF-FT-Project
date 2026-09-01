# BPF-Guardian Benchmark Verification Summary

**Verification Mode**: `empirical` (Live Linux Kernel Verifier)
**Host Kernel**: `Linux 6.8.0-106-generic x86_64`
**Toolchain**: `Ubuntu clang version 18.1.3 (1ubuntu1)` | `bpftool v7.4.0` | `libbpf v1.4`
**Candidate Set Hash**: `39675572edeb442a7e836c113c5d8a0788d0c0b969c6b21dea1ff51566b13c86`
**Raw Results Hash**: `3596762b9fd661d5be29c1c889b2645f425667d959e6aab556c966531b1333bb`

## Aggregate Metrics
| Metric | Passed / Total | Rate |
|---|---|---|
| Output Compliance | 89 / 89 | 100.0% |
| Clang BPF Compilation | 58 / 89 | 65.2% |
| Kernel Verifier Load | 37 / 89 | 41.6% |
| Behavioral Packet Test | 12 / 89 | 13.5% |
| **Functional Pass@1** | **12 / 89** | **13.5%** |
| **Functional Pass@4** | N/A (1 sample/task) | N/A |

## Category Breakdown (Pass@1)
| Category | Tasks | Compliant | Compile | Verifier | Fully Passed | Pass@1 Rate |
|---|---|---|---|---|---|---|
| `network_routing_forwarding` | 22 | 22 | 16 | 16 | 1 | 4.5% |
| `packet_filtering_security` | 25 | 25 | 16 | 12 | 2 | 8.0% |
| `packet_inspection_telemetry` | 17 | 17 | 9 | 5 | 5 | 29.4% |
| `protocol_transformation` | 25 | 25 | 17 | 4 | 4 | 16.0% |

## Difficulty Breakdown (Pass@1)
| Difficulty | Tasks | Compliant | Compile | Verifier | Fully Passed | Pass@1 Rate |
|---|---|---|---|---|---|---|
| `level_1` | 27 | 27 | 17 | 12 | 5 | 18.5% |
| `level_2` | 33 | 33 | 20 | 10 | 3 | 9.1% |
| `level_3` | 29 | 29 | 21 | 15 | 4 | 13.8% |
