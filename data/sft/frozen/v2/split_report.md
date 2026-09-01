# BPF-Guardian SFT v2 Frozen Split Report

## Overview & Provenance
- **Dataset Version**: `v2`
- **Split Algorithm**: `bpf_guardian_3way_task_split_v2`
- **Configuration Fingerprint**: `ca29c2bdfe9eb512`
- **Source Git Commit**: `f2baf160bb1115a76122b675501db87ea0bbf4fc`
- **Split Random Seed**: `42`
- **Toolchain Baseline**: Linux Kernel 6.8 | Clang 18.1 (BPF) | bpftool v7.3 | libbpf v1.4
- **Excluded Benchmark Tasks**: 276 tasks (SHA256: `ed0221e45f0103ad...`)

## 3-Way Split Summary
| Split View | Tasks | Total Rows | Synthesis | Repair | New v2 | v1 Replay | Split SHA-256 |
|---|---|---|---|---|---|---|---|
| **Train** | 744 | 1297 (81.1%) | 744 | 553 | 937 | 360 | `4f412ba3db76ffd6...` |
| **Val (In-Domain)** | 92 | 159 (9.9%) | 92 | 67 | 119 | 40 | `f8b0f2679dd38d7b...` |
| **Val (Family-Heldout)** | 84 | 144 (9.0%) | 84 | 60 | 144 | 0 | `274896a738d3cd88...` |
| **Total** | **920** | **1600** (100.0%) | **920** | **680** | **1200** | **400** | - |

## Family-Heldout Validation View Analysis
The following 4 complete semantic template families (1 per category) are strictly held out from training and in-domain validation:

| Category | Held-Out Template Family | Tasks | Examples | Level 1 | Level 2 | Level 3 |
|---|---|---|---|---|---|---|
| `network_routing_forwarding` | `nrf_srv6_end_forwarder` | 21 | 36 | 12 | 12 | 12 |
| `packet_filtering_security` | `pfs_srv6_security_policy` | 21 | 36 | 12 | 12 | 12 |
| `packet_inspection_telemetry` | `pit_ipv6_ext_telemetry` | 21 | 36 | 12 | 12 | 12 |
| `protocol_transformation` | `ptr_ipv4_ipv6_translator` | 21 | 36 | 12 | 12 | 12 |

## Application Category Distribution
| Application Category | Train Tasks | In-Dom Val | Heldout Val | Train Rows | In-Dom Rows | Heldout Rows | Total Rows |
|---|---|---|---|---|---|---|---|
| `network_routing_forwarding` | 186 | 23 | 21 | 321 | 43 | 36 | 400 |
| `packet_filtering_security` | 186 | 23 | 21 | 322 | 42 | 36 | 400 |
| `packet_inspection_telemetry` | 186 | 23 | 21 | 326 | 38 | 36 | 400 |
| `protocol_transformation` | 186 | 23 | 21 | 328 | 36 | 36 | 400 |

## Difficulty Distribution
| Difficulty Level | Train Rows | In-Dom Val Rows | Heldout Val Rows | Total Rows | Share |
|---|---|---|---|---|---|
| `level_1` | 430 | 58 | 48 | 536 | 33.5% |
| `level_2` | 433 | 55 | 48 | 536 | 33.5% |
| `level_3` | 434 | 46 | 48 | 528 | 33.0% |

## Repair Fault Distribution
| Fault Class | Train | In-Dom Val | Heldout Val | Total Repairs |
|---|---|---|---|---|
| `behavioral` | 184 | 28 | 24 | 236 |
| `compiler` | 98 | 10 | 12 | 120 |
| `verifier` | 271 | 29 | 24 | 324 |

## V1 Replay Breakdown (400 Examples)
| Application Category | Level 1 (Tasks / Rows) | Level 2 (Tasks / Rows) | Level 3 (Tasks / Rows) | Total Replay Rows |
|---|---|---|---|---|
| `network_routing_forwarding` | 17 / 34 | 17 / 34 | 16 / 32 | 100 |
| `packet_filtering_security` | 17 / 34 | 17 / 34 | 16 / 32 | 100 |
| `packet_inspection_telemetry` | 17 / 34 | 17 / 34 | 16 / 32 | 100 |
| `protocol_transformation` | 17 / 34 | 17 / 34 | 16 / 32 | 100 |

## Integrity and Isolation Attestations
- [x] **Task Grouping**: 100% compliant — all synthesis and repair variants for each task ID are strictly co-located.
- [x] **Zero Split Overlap**: 0 overlapping task IDs and 0 overlapping example IDs between Train, In-Domain Validation, and Family-Heldout Validation.
- [x] **Benchmark Isolation**: 0 overlapping task IDs with all 276 protected calibration and benchmark tasks.
- [x] **Family-Heldout Purity**: Exactly 4 complete families (144 examples, 84 tasks) are 100% absent from training and in-domain validation.
- [x] **Replay Selection**: Exactly 400 balanced examples (200 synthesis, 200 repair, 100 per category) from frozen SFT v1.
- [x] **Deterministic Sorting & Formatting**: All splits sorted by `example_id` with Unix `\n` line endings.
