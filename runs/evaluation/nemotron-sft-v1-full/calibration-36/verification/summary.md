# BPF-Guardian Benchmark Verification Summary

**Verification Mode**: `empirical` (Live Linux Kernel Verifier)
**Host Kernel**: `Linux 6.8.0-106-generic x86_64`
**Toolchain**: `Ubuntu clang version 18.1.3 (1ubuntu1)` | `bpftool v7.4.0` | `libbpf v1.4`
**Candidate Set Hash**: `c9a7201b37eb04e8561e1062e13cc33dab0304c8aa06da0a7223068c19fc61a2`
**Raw Results Hash**: `5e0ea9e2d93948c5a8ff5633a14870caa7fd1f3e3f17d9c02e1eedbab210bb04`

## Aggregate Metrics
| Metric | Passed / Total | Rate |
|---|---|---|
| Output Compliance | 36 / 36 | 100.0% |
| Clang BPF Compilation | 29 / 36 | 80.6% |
| Kernel Verifier Load | 26 / 36 | 72.2% |
| Behavioral Packet Test | 23 / 36 | 63.9% |
| **Functional Pass@1** | **23 / 36** | **63.9%** |
| **Functional Pass@4** | N/A (1 sample/task) | N/A |

## Category Breakdown (Pass@1)
| Category | Tasks | Compliant | Compile | Verifier | Fully Passed | Pass@1 Rate |
|---|---|---|---|---|---|---|
| `network_routing_forwarding` | 9 | 9 | 7 | 6 | 4 | 44.4% |
| `packet_filtering_security` | 9 | 9 | 6 | 5 | 4 | 44.4% |
| `packet_inspection_telemetry` | 9 | 9 | 7 | 7 | 7 | 77.8% |
| `protocol_transformation` | 9 | 9 | 9 | 8 | 8 | 88.9% |

## Difficulty Breakdown (Pass@1)
| Difficulty | Tasks | Compliant | Compile | Verifier | Fully Passed | Pass@1 Rate |
|---|---|---|---|---|---|---|
| `level_1` | 12 | 12 | 12 | 12 | 11 | 91.7% |
| `level_2` | 12 | 12 | 11 | 10 | 8 | 66.7% |
| `level_3` | 12 | 12 | 6 | 4 | 4 | 33.3% |
