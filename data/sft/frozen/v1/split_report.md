# BPF-Guardian SFT Frozen Split Report (v1)

## Overview
- **Source Dataset**: `data\sft\sft_dataset_full.jsonl`
- **Source Git Commit**: `13d12eae02bcef595d8fa1e54afc292748f57780`
- **Source SHA-256**: `18d02d59cff20aa5d4553fb3e2eebc570b14a7eb10e99f07fb7b216b7c0dc876`
- **Split Seed**: `42`
- **Split Algorithm**: `bpf_guardian_stratified_task_split_v1`
- **Configuration Fingerprint**: `b3f1995712679b25`

## Split Summary
| Split | Tasks | Examples | Synthesis | Repair | SHA-256 |
|---|---|---|---|---|---|
| Train | 578 | 1014 | 578 | 436 | `71dd50816dfa7525...` |
| Validation | 62 | 106 | 62 | 44 | `2a61c686c0c862ca...` |
| **Total** | **640** | **1120** | **640** | **480** | - |

## Category Distribution
| Category | Train Tasks | Val Tasks | Train Examples | Val Examples |
|---|---|---|---|---|
| `network_routing_forwarding` | 145 | 15 | 256 | 24 |
| `packet_filtering_security` | 143 | 17 | 250 | 30 |
| `packet_inspection_telemetry` | 145 | 15 | 254 | 26 |
| `protocol_transformation` | 145 | 15 | 254 | 26 |

## Difficulty Distribution
| Difficulty | Train Tasks | Val Tasks | Train Examples | Val Examples |
|---|---|---|---|---|
| `level_1` | 230 | 26 | 404 | 44 |
| `level_2` | 232 | 24 | 406 | 42 |
| `level_3` | 116 | 12 | 204 | 20 |

## Integrity Verification
- [x] Grouping by `task_id`: 100% compliant (synthesis and repairs co-located)
- [x] Zero task overlap between train and validation: Verified
- [x] Zero overlap with 36 calibration benchmark tasks: Verified
- [x] Deterministic byte-reproducible ordering: Verified
