# BPF-Guardian Benchmark Verification Summary

**Verification Mode**: `empirical` (Live Linux Kernel Verifier)
**Host Kernel**: `Linux 6.8.0-106-generic x86_64`
**Toolchain**: `Ubuntu clang version 18.1.3 (1ubuntu1)` | `bpftool v7.4.0` | `libbpf v1.4`
**Candidate Set Hash**: `68f5822e6c893dd3ba74704a10159cdba55ccd01c7df9e52356675253bbe9d50`
**Raw Results Hash**: `b071d27546e358fd80c2914f07a5dace38ffd4aaf869f375ecd0762a8bd01d11`

## Aggregate Metrics
| Metric | Passed / Total | Rate |
|---|---|---|
| Output Compliance | 120 / 120 | 100.0% |
| Clang BPF Compilation | 99 / 120 | 82.5% |
| Kernel Verifier Load | 99 / 120 | 82.5% |
| Behavioral Packet Test | 79 / 120 | 65.8% |
| **Functional Pass@1** | **79 / 120** | **65.8%** |
| **Functional Pass@4** | N/A (1 sample/task) | N/A |

## Category Breakdown (Pass@1)
| Category | Tasks | Compliant | Compile | Verifier | Fully Passed | Pass@1 Rate |
|---|---|---|---|---|---|---|
| `network_routing_forwarding` | 30 | 30 | 23 | 23 | 16 | 53.3% |
| `packet_filtering_security` | 30 | 30 | 27 | 27 | 21 | 70.0% |
| `packet_inspection_telemetry` | 30 | 30 | 27 | 27 | 23 | 76.7% |
| `protocol_transformation` | 30 | 30 | 22 | 22 | 19 | 63.3% |

## Difficulty Breakdown (Pass@1)
| Difficulty | Tasks | Compliant | Compile | Verifier | Fully Passed | Pass@1 Rate |
|---|---|---|---|---|---|---|
| `level_1` | 40 | 40 | 34 | 34 | 24 | 60.0% |
| `level_2` | 40 | 40 | 35 | 35 | 31 | 77.5% |
| `level_3` | 40 | 40 | 30 | 30 | 24 | 60.0% |
