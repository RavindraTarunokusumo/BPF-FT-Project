# BPF-Guardian Benchmark Verification Summary

**Verification Mode**: `empirical` (Live Linux Kernel Verifier)
**Host Kernel**: `Linux 6.8.0-106-generic x86_64`
**Toolchain**: `Ubuntu clang version 18.1.3 (1ubuntu1)` | `bpftool v7.4.0` | `libbpf v1.4`
**Candidate Set Hash**: `76313c572aef7287723307438edf62dc0e4072d0edd2447d9ffce7cdce634c88`
**Raw Results Hash**: `0ff66be9d0a6ba9b0d7cf7bca8dbd4eb36f0819dc2510f526f16fd4cb66bd0c1`

## Aggregate Metrics
| Metric | Passed / Total | Rate |
|---|---|---|
| Output Compliance | 48 / 48 | 100.0% |
| Clang BPF Compilation | 29 / 48 | 60.4% |
| Kernel Verifier Load | 25 / 48 | 52.1% |
| Behavioral Packet Test | 24 / 48 | 50.0% |
| **Functional Pass@1** | **24 / 48** | **50.0%** |
| **Functional Pass@4** | N/A (1 sample/task) | N/A |

## Category Breakdown (Pass@1)
| Category | Tasks | Compliant | Compile | Verifier | Fully Passed | Pass@1 Rate |
|---|---|---|---|---|---|---|
| `unknown` | 48 | 48 | 29 | 25 | 24 | 50.0% |

## Difficulty Breakdown (Pass@1)
| Difficulty | Tasks | Compliant | Compile | Verifier | Fully Passed | Pass@1 Rate |
|---|---|---|---|---|---|---|
| `unknown` | 48 | 48 | 29 | 25 | 24 | 50.0% |
