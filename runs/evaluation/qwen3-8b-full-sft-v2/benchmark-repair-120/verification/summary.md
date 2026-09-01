# BPF-Guardian Benchmark Verification Summary

**Verification Mode**: `empirical` (Live Linux Kernel Verifier)
**Host Kernel**: `Linux 6.8.0-106-generic x86_64`
**Toolchain**: `Ubuntu clang version 18.1.3 (1ubuntu1)` | `bpftool v7.4.0` | `libbpf v1.4`
**Candidate Set Hash**: `984a9187183a7ae5261a402f40f484117608d84692eed18f5b470a0f2ba3d2fd`
**Raw Results Hash**: `bc0ba5843517ca6d471359b477b0a5fe8db26d0ed26ddd0b62b7b2199094b94a`

## Aggregate Metrics
| Metric | Passed / Total | Rate |
|---|---|---|
| Output Compliance | 120 / 120 | 100.0% |
| Clang BPF Compilation | 110 / 120 | 91.7% |
| Kernel Verifier Load | 106 / 120 | 88.3% |
| Behavioral Packet Test | 85 / 120 | 70.8% |
| **Functional Pass@1** | **85 / 120** | **70.8%** |
| **Functional Pass@4** | N/A (1 sample/task) | N/A |

## Category Breakdown (Pass@1)
| Category | Tasks | Compliant | Compile | Verifier | Fully Passed | Pass@1 Rate |
|---|---|---|---|---|---|---|
| `network_routing_forwarding` | 30 | 30 | 24 | 24 | 16 | 53.3% |
| `packet_filtering_security` | 30 | 30 | 28 | 28 | 23 | 76.7% |
| `packet_inspection_telemetry` | 30 | 30 | 30 | 29 | 24 | 80.0% |
| `protocol_transformation` | 30 | 30 | 28 | 25 | 22 | 73.3% |

## Difficulty Breakdown (Pass@1)
| Difficulty | Tasks | Compliant | Compile | Verifier | Fully Passed | Pass@1 Rate |
|---|---|---|---|---|---|---|
| `level_1` | 40 | 40 | 39 | 37 | 26 | 65.0% |
| `level_2` | 40 | 40 | 35 | 33 | 32 | 80.0% |
| `level_3` | 40 | 40 | 36 | 36 | 27 | 67.5% |
