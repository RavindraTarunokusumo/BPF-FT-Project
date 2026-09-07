# BPF-Guardian Benchmark Verification Summary

**Verification Mode**: `empirical` (Live Linux Kernel Verifier)
**Host Kernel**: `Linux 6.8.0-106-generic x86_64`
**Toolchain**: `Ubuntu clang version 18.1.3 (1ubuntu1)` | `bpftool v7.4.0` | `libbpf v1.4`
**Candidate Set Hash**: `bc841f8632422a7cde195a546c1ecd5296c62eb71c36b0677077e374dbc4ebb7`
**Raw Results Hash**: `0b4fa2a97d7979ca149c549ae9913c180a894c3db02ff45dba1d4ba7008ca062`

## Aggregate Metrics
| Metric | Passed / Total | Rate |
|---|---|---|
| Output Compliance | 60 / 60 | 100.0% |
| Clang BPF Compilation | 0 / 60 | 0.0% |
| Kernel Verifier Load | 0 / 60 | 0.0% |
| Behavioral Packet Test | 0 / 60 | 0.0% |
| **Functional Pass@1** | **0 / 60** | **0.0%** |
| **Functional Pass@4** | N/A (1 sample/task) | N/A |

## Category Breakdown (Pass@1)
| Category | Tasks | Compliant | Compile | Verifier | Fully Passed | Pass@1 Rate |
|---|---|---|---|---|---|---|
| `unknown` | 60 | 60 | 0 | 0 | 0 | 0.0% |

## Difficulty Breakdown (Pass@1)
| Difficulty | Tasks | Compliant | Compile | Verifier | Fully Passed | Pass@1 Rate |
|---|---|---|---|---|---|---|
| `unknown` | 60 | 60 | 0 | 0 | 0 | 0.0% |
