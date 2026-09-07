# BPF-Guardian Benchmark Verification Summary

**Verification Mode**: `empirical` (Live Linux Kernel Verifier)
**Host Kernel**: `Linux 6.8.0-106-generic x86_64`
**Toolchain**: `Ubuntu clang version 18.1.3 (1ubuntu1)` | `bpftool v7.4.0` | `libbpf v1.4`
**Candidate Set Hash**: `2c3864ee71abdd22f1b34ebed7e56714476abd7c457cb07ad30ef745398cfd92`
**Raw Results Hash**: `a1bedc757c8ae155cb6e1161a95315d213bae253bb5d21aac24f6a71f3f995b3`

## Aggregate Metrics
| Metric | Passed / Total | Rate |
|---|---|---|
| Output Compliance | 48 / 48 | 100.0% |
| Clang BPF Compilation | 0 / 48 | 0.0% |
| Kernel Verifier Load | 0 / 48 | 0.0% |
| Behavioral Packet Test | 0 / 48 | 0.0% |
| **Functional Pass@1** | **0 / 48** | **0.0%** |
| **Functional Pass@4** | N/A (1 sample/task) | N/A |

## Category Breakdown (Pass@1)
| Category | Tasks | Compliant | Compile | Verifier | Fully Passed | Pass@1 Rate |
|---|---|---|---|---|---|---|
| `unknown` | 48 | 48 | 0 | 0 | 0 | 0.0% |

## Difficulty Breakdown (Pass@1)
| Difficulty | Tasks | Compliant | Compile | Verifier | Fully Passed | Pass@1 Rate |
|---|---|---|---|---|---|---|
| `unknown` | 48 | 48 | 0 | 0 | 0 | 0.0% |
