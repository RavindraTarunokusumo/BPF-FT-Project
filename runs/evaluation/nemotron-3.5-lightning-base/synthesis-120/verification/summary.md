# BPF-Guardian Benchmark Verification Summary

**Verification Mode**: `empirical` (Live Linux Kernel Verifier)
**Host Kernel**: `Linux 6.8.0-106-generic x86_64`
**Toolchain**: `Ubuntu clang version 18.1.3 (1ubuntu1)` | `bpftool v7.4.0` | `libbpf v1.4`
**Candidate Set Hash**: `0ccd57e2969f5522837c808b05e10864cc723e66b1ffa17139c4c5f05e59dbe0`
**Raw Results Hash**: `ab4f684ecb907bf40c0d6fa746d362379a4afc2b2c334117763f0d345f6dc897`

## Aggregate Metrics
| Metric | Passed / Total | Rate |
|---|---|---|
| Output Compliance | 110 / 120 | 91.7% |
| Clang BPF Compilation | 1 / 120 | 0.8% |
| Kernel Verifier Load | 0 / 120 | 0.0% |
| Behavioral Packet Test | 0 / 120 | 0.0% |
| **Functional Pass@1** | **0 / 120** | **0.0%** |
| **Functional Pass@4** | N/A (1 sample/task) | N/A |

## Category Breakdown (Pass@1)
| Category | Tasks | Compliant | Compile | Verifier | Fully Passed | Pass@1 Rate |
|---|---|---|---|---|---|---|
| `network_routing_forwarding` | 30 | 28 | 1 | 0 | 0 | 0.0% |
| `packet_filtering_security` | 30 | 28 | 0 | 0 | 0 | 0.0% |
| `packet_inspection_telemetry` | 30 | 27 | 0 | 0 | 0 | 0.0% |
| `protocol_transformation` | 30 | 27 | 0 | 0 | 0 | 0.0% |

## Difficulty Breakdown (Pass@1)
| Difficulty | Tasks | Compliant | Compile | Verifier | Fully Passed | Pass@1 Rate |
|---|---|---|---|---|---|---|
| `level_1` | 40 | 38 | 1 | 0 | 0 | 0.0% |
| `level_2` | 40 | 38 | 0 | 0 | 0 | 0.0% |
| `level_3` | 40 | 34 | 0 | 0 | 0 | 0.0% |
