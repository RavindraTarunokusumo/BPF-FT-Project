# BPF-Guardian Benchmark Verification Summary

**Verification Mode**: `empirical` (Live Linux Kernel Verifier)
**Host Kernel**: `Linux 6.8.0-106-generic x86_64`
**Toolchain**: `Ubuntu clang version 18.1.3 (1ubuntu1)` | `bpftool v7.4.0` | `libbpf v1.4`
**Candidate Set Hash**: `b3a18b198ebd12148937b249684451007d4d4f75355d76eb73ec513de210fbee`
**Raw Results Hash**: `28406fc5171068ec66224683dc7b1eadb45d0f522ffe68b5ae8cfb4151e3b30b`

## Aggregate Metrics
| Metric | Passed / Total | Rate |
|---|---|---|
| Output Compliance | 60 / 60 | 100.0% |
| Clang BPF Compilation | 48 / 60 | 80.0% |
| Kernel Verifier Load | 43 / 60 | 71.7% |
| Behavioral Packet Test | 42 / 60 | 70.0% |
| **Functional Pass@1** | **42 / 60** | **70.0%** |
| **Functional Pass@4** | N/A (1 sample/task) | N/A |

## Category Breakdown (Pass@1)
| Category | Tasks | Compliant | Compile | Verifier | Fully Passed | Pass@1 Rate |
|---|---|---|---|---|---|---|
| `unknown` | 60 | 60 | 48 | 43 | 42 | 70.0% |

## Difficulty Breakdown (Pass@1)
| Difficulty | Tasks | Compliant | Compile | Verifier | Fully Passed | Pass@1 Rate |
|---|---|---|---|---|---|---|
| `unknown` | 60 | 60 | 48 | 43 | 42 | 70.0% |
