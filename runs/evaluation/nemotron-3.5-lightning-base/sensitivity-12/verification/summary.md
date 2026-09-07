# BPF-Guardian Benchmark Verification Summary

**Verification Mode**: `empirical` (Live Linux Kernel Verifier)
**Host Kernel**: `Linux 6.8.0-106-generic x86_64`
**Toolchain**: `Ubuntu clang version 18.1.3 (1ubuntu1)` | `bpftool v7.4.0` | `libbpf v1.4`
**Candidate Set Hash**: `8f34a4a717b51be19526b3434ba4b736dc73a2f64b4ea0aaa7af53e927d85e6e`
**Raw Results Hash**: `6bbe48ae6f104cb24384e3b2016e514f16789cb8dabd5d1bb8d98c37acc5c022`

## Aggregate Metrics
| Metric | Passed / Total | Rate |
|---|---|---|
| Output Compliance | 10 / 12 | 83.3% |
| Clang BPF Compilation | 0 / 12 | 0.0% |
| Kernel Verifier Load | 0 / 12 | 0.0% |
| Behavioral Packet Test | 0 / 12 | 0.0% |
| **Functional Pass@1** | **0 / 12** | **0.0%** |
| **Functional Pass@4** | N/A (1 sample/task) | N/A |

## Category Breakdown (Pass@1)
| Category | Tasks | Compliant | Compile | Verifier | Fully Passed | Pass@1 Rate |
|---|---|---|---|---|---|---|
| `network_routing_forwarding` | 3 | 3 | 0 | 0 | 0 | 0.0% |
| `packet_filtering_security` | 3 | 3 | 0 | 0 | 0 | 0.0% |
| `packet_inspection_telemetry` | 3 | 3 | 0 | 0 | 0 | 0.0% |
| `protocol_transformation` | 3 | 1 | 0 | 0 | 0 | 0.0% |

## Difficulty Breakdown (Pass@1)
| Difficulty | Tasks | Compliant | Compile | Verifier | Fully Passed | Pass@1 Rate |
|---|---|---|---|---|---|---|
| `level_1` | 4 | 4 | 0 | 0 | 0 | 0.0% |
| `level_2` | 4 | 3 | 0 | 0 | 0 | 0.0% |
| `level_3` | 4 | 3 | 0 | 0 | 0 | 0.0% |
