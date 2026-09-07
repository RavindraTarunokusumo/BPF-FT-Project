# BPF-Guardian Benchmark Verification Summary

**Verification Mode**: `empirical` (Live Linux Kernel Verifier)
**Host Kernel**: `Linux 6.8.0-106-generic x86_64`
**Toolchain**: `Ubuntu clang version 18.1.3 (1ubuntu1)` | `bpftool v7.4.0` | `libbpf v1.4`
**Candidate Set Hash**: `bf4e812063c6bb6557778d83d653aaca120901e410dcdc8840d335f60f9edee1`
**Raw Results Hash**: `4898c25d501db5094d353a5817aaed46b0ebf286be815efe99b29bf1c21ac4ca`

## Aggregate Metrics
| Metric | Passed / Total | Rate |
|---|---|---|
| Output Compliance | 120 / 120 | 100.0% |
| Clang BPF Compilation | 82 / 120 | 68.3% |
| Kernel Verifier Load | 68 / 120 | 56.7% |
| Behavioral Packet Test | 54 / 120 | 45.0% |
| **Functional Pass@1** | **54 / 120** | **45.0%** |
| **Functional Pass@4** | N/A (1 sample/task) | N/A |

## Category Breakdown (Pass@1)
| Category | Tasks | Compliant | Compile | Verifier | Fully Passed | Pass@1 Rate |
|---|---|---|---|---|---|---|
| `network_routing_forwarding` | 30 | 30 | 22 | 21 | 14 | 46.7% |
| `packet_filtering_security` | 30 | 30 | 18 | 16 | 9 | 30.0% |
| `packet_inspection_telemetry` | 30 | 30 | 20 | 17 | 17 | 56.7% |
| `protocol_transformation` | 30 | 30 | 22 | 14 | 14 | 46.7% |

## Difficulty Breakdown (Pass@1)
| Difficulty | Tasks | Compliant | Compile | Verifier | Fully Passed | Pass@1 Rate |
|---|---|---|---|---|---|---|
| `level_1` | 40 | 40 | 31 | 31 | 26 | 65.0% |
| `level_2` | 40 | 40 | 25 | 20 | 17 | 42.5% |
| `level_3` | 40 | 40 | 26 | 17 | 11 | 27.5% |
