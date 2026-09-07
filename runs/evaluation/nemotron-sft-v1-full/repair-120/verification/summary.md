# BPF-Guardian Benchmark Verification Summary

**Verification Mode**: `empirical` (Live Linux Kernel Verifier)
**Host Kernel**: `Linux 6.8.0-106-generic x86_64`
**Toolchain**: `Ubuntu clang version 18.1.3 (1ubuntu1)` | `bpftool v7.4.0` | `libbpf v1.4`
**Candidate Set Hash**: `c5fee30ff61024dde41c528ba104999371e296fc38057a3a2c692f592530c646`
**Raw Results Hash**: `2083ca77d392263fedcbb9f1a1d8a8c21cb9f805626b4ec05db18e1268e5c81a`

## Aggregate Metrics
| Metric | Passed / Total | Rate |
|---|---|---|
| Output Compliance | 120 / 120 | 100.0% |
| Clang BPF Compilation | 111 / 120 | 92.5% |
| Kernel Verifier Load | 109 / 120 | 90.8% |
| Behavioral Packet Test | 91 / 120 | 75.8% |
| **Functional Pass@1** | **91 / 120** | **75.8%** |
| **Functional Pass@4** | N/A (1 sample/task) | N/A |

## Category Breakdown (Pass@1)
| Category | Tasks | Compliant | Compile | Verifier | Fully Passed | Pass@1 Rate |
|---|---|---|---|---|---|---|
| `network_routing_forwarding` | 30 | 30 | 24 | 24 | 17 | 56.7% |
| `packet_filtering_security` | 30 | 30 | 29 | 29 | 25 | 83.3% |
| `packet_inspection_telemetry` | 30 | 30 | 30 | 30 | 25 | 83.3% |
| `protocol_transformation` | 30 | 30 | 28 | 26 | 24 | 80.0% |

## Difficulty Breakdown (Pass@1)
| Difficulty | Tasks | Compliant | Compile | Verifier | Fully Passed | Pass@1 Rate |
|---|---|---|---|---|---|---|
| `level_1` | 40 | 40 | 39 | 38 | 29 | 72.5% |
| `level_2` | 40 | 40 | 38 | 37 | 34 | 85.0% |
| `level_3` | 40 | 40 | 34 | 34 | 28 | 70.0% |
