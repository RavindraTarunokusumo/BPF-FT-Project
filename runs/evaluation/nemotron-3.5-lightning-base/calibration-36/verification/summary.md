# BPF-Guardian Benchmark Verification Summary

**Verification Mode**: `empirical` (Live Linux Kernel Verifier)
**Host Kernel**: `Linux 6.8.0-106-generic x86_64`
**Toolchain**: `Ubuntu clang version 18.1.3 (1ubuntu1)` | `bpftool v7.4.0` | `libbpf v1.4`
**Candidate Set Hash**: `7bdef1af80bb3bc964c61f756085b4566d14396241fad6031f42e460a111b85d`
**Raw Results Hash**: `ae49b8bffe172653663c6b25a680968a1e2f2f9bb9217418b5afd9f7cd1c9fc0`

## Aggregate Metrics
| Metric | Passed / Total | Rate |
|---|---|---|
| Output Compliance | 36 / 36 | 100.0% |
| Clang BPF Compilation | 0 / 36 | 0.0% |
| Kernel Verifier Load | 0 / 36 | 0.0% |
| Behavioral Packet Test | 0 / 36 | 0.0% |
| **Functional Pass@1** | **0 / 36** | **0.0%** |
| **Functional Pass@4** | N/A (1 sample/task) | N/A |

## Category Breakdown (Pass@1)
| Category | Tasks | Compliant | Compile | Verifier | Fully Passed | Pass@1 Rate |
|---|---|---|---|---|---|---|
| `network_routing_forwarding` | 9 | 9 | 0 | 0 | 0 | 0.0% |
| `packet_filtering_security` | 9 | 9 | 0 | 0 | 0 | 0.0% |
| `packet_inspection_telemetry` | 9 | 9 | 0 | 0 | 0 | 0.0% |
| `protocol_transformation` | 9 | 9 | 0 | 0 | 0 | 0.0% |

## Difficulty Breakdown (Pass@1)
| Difficulty | Tasks | Compliant | Compile | Verifier | Fully Passed | Pass@1 Rate |
|---|---|---|---|---|---|---|
| `level_1` | 12 | 12 | 0 | 0 | 0 | 0.0% |
| `level_2` | 12 | 12 | 0 | 0 | 0 | 0.0% |
| `level_3` | 12 | 12 | 0 | 0 | 0 | 0.0% |
