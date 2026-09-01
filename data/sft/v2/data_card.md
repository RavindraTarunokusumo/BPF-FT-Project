# Dataset Card: BPF-Guardian SFT v2 Dataset

## 1. Dataset Summary & Purpose

The **BPF-Guardian SFT v2 Dataset** is a high-assurance, verified dataset designed for supervised fine-tuning (SFT) of large language models—specifically **Qwen/Qwen3-8B**—to excel at out-of-distribution eBPF/XDP kernel program synthesis and diagnostic-guided repair.

### Primary Goals
- **Generalization to Novel Synthesis Families**: Substantially improves out-of-distribution eBPF/XDP synthesis across complex, unfamiliar network protocols, nested header encapsulations, stateful token-bucket rate limiting, dynamic routing (FIB, LPM trie, ECMP), QoS priority queues, and incremental checksum calculations.
- **Preservation of Diagnostic Repair Capabilities**: Maintains the strong recovery rates learned in SFT v1 by pairing synthesis tasks with multi-class fault injections (compilation errors, kernel verifier rejections, behavioral logic bugs).
- **Anti-Forgetting Replay**: Includes a deterministic, balanced 400-example replay partition from SFT v1 to ensure stability across foundational XDP operations.
- **Fail-Closed Quality Assurance**: 100% of gold completions pass Linux 6.8 kernel verification and behavioral packet test fixtures before entry into the dataset.

---

## 2. 36 Semantic Capability Families Taxonomy & Architecture

The v2 delta introduces **36 distinct semantic capability families** distributed evenly across 4 core application categories (9 families per category). No individual family exceeds **3.00%** of the v2 delta (ceiling quota: 5.00%).

### Taxonomy Matrix

| Application Category | Semantic Template Family | Description & Technical Capability |
|---|---|---|
| **Packet Filtering & Security** (`pfs`) | `pfs_tunnel_vxlan_filter` | VXLAN outer UDP 4789 decap, 24-bit VNI extraction, inner L3/L4 filtering |
| | `pfs_tunnel_geneve_gre_guard` | GENEVE variable options / GRE tunnel header parsing and protocol protection |
| | `pfs_ipv6_ext_header_acl` | IPv6 Hop-by-Hop, Routing, Fragment extension header traversal and ACL |
| | `pfs_srv6_security_policy` *(Held-Out)* | Segment Routing IPv6 (SRv6) Segment Routing Header (SRH) SID validation |
| | `pfs_vlan_qinq_firewall` | IEEE 802.1Q single and 802.1ad Q-in-Q double-tagged VLAN filtering |
| | `pfs_variable_ihl_tcp_guard` | Dynamic IPv4 IHL calculation, variable TCP data offset, and option parsing |
| | `pfs_lpm_prefix_blocklist` | Longest Prefix Match (`BPF_MAP_TYPE_LPM_TRIE`) CIDR blocklist enforcement |
| | `pfs_token_bucket_ratelimit` | Stateful token-bucket rate limiter with `BPF_MAP_TYPE_HASH` / per-CPU state |
| | `pfs_tcp_anomalous_flags` | TCP control flag anomaly detector (SYN-FIN, NULL, Xmas, invalid state) |
| **Network Routing & Forwarding** (`nrf`) | `nrf_vxlan_tunnel_router` | VXLAN tunnel routing, inner packet L2 MAC swapping, and XDP_TX / XDP_REDIRECT |
| | `nrf_gre_gtpu_demux` | GRE / GTP-U (TEID 0xFF) mobile core demultiplexer and forwarding |
| | `nrf_srv6_end_forwarder` *(Held-Out)* | SRv6 End / End.DX4 / End.DX6 segment endpoint forwarding and decapsulation |
| | `nrf_vlan_trunk_access_switch` | VLAN trunk-to-access port demux, tag popping, and interface routing |
| | `nrf_nested_ipip_forwarder` | IP-in-IP (outer/inner IPv4/IPv6) nested decapsulation and next-hop forwarding |
| | `nrf_fib_nexthop_router` | Forwarding Information Base (`bpf_fib_lookup`) next-hop selection and MTU check |
| | `nrf_ecmp_hash_loadbalancer` | Equal-Cost Multi-Path 5-tuple jhash load balancing across backend endpoints |
| | `nrf_lpm_trie_router` | LPM trie routing with longest-prefix match and fallback default route |
| | `nrf_dscp_qos_priority_router` | DiffServ Code Point (DSCP) traffic class inspection and priority interface queueing |
| **Packet Inspection & Telemetry** (`pit`) | `pit_vxlan_geneve_analyzer` | VXLAN/GENEVE inner/outer header telemetry extraction and packet metrics |
| | `pit_ipv6_ext_telemetry` *(Held-Out)* | IPv6 extension header chain analysis and telemetry recording |
| | `pit_vlan_qinq_flow_meter` | Dual-tag VLAN flow meter and bandwidth telemetry accounting |
| | `pit_tcp_options_extractor` | TCP MSS, Window Scale, Timestamps, and SACK option telemetry parser |
| | `pit_5tuple_canonical_hash` | Bidirectional canonical 5-tuple flow hashing and session accounting |
| | `pit_percpu_packet_histogram` | Multi-core per-CPU array (`BPF_MAP_TYPE_PERCPU_ARRAY`) packet size histogram |
| | `pit_lru_connection_tracker` | LRU connection state tracking (`BPF_MAP_TYPE_LRU_HASH`) and TCP lifecycle |
| | `pit_dns_metadata_extractor` | DNS query name and QTYPE parsing (RFC 1035 wire format) over UDP 53 |
| | `pit_qos_latency_telemetry` | Nanosecond timestamping (`bpf_ktime_get_ns`) and latency telemetry map |
| **Protocol Transformation** (`ptr`) | `ptr_vxlan_header_transform` | VXLAN encapsulation rewrite and inner payload mutation |
| | `ptr_gre_gtpu_transform` | GRE/GTP-U tunnel encapsulation and decapsulation rewriters |
| | `ptr_vlan_tag_push_pop` | Dynamic IEEE 802.1Q VLAN tag push / pop with `bpf_xdp_adjust_head` |
| | `ptr_ipv4_ipv6_translator` *(Held-Out)* | Stateless IP/ICMP Translation (SIIT / NAT64) header conversion |
| | `ptr_stateless_snat_dnat` | Stateless 1:1 IPv4 address translation and incremental 1's complement checksum |
| | `ptr_stateful_napt_rewriter` | Stateful NAPT with BPF hash connection tracking and TCP/UDP port mapping |
| | `ptr_l4_port_forwarder` | Layer 4 port redirection with L4 checksum delta updates (`bpf_csum_diff`) |
| | `ptr_icmp_echo_translator` | ICMP Echo Request to Echo Reply in-place packet translation and reflection |
| | `ptr_dscp_ttl_rewriter` | IPv4 TOS/DSCP reclassification and TTL decrement with RFC 1624 checksum update |

---

## 3. Dataset Composition

The cumulative dataset contains **1,600 examples** structured into two distinct layers:

```
+-------------------------------------------------------------------------+
|                  BPF-Guardian Cumulative Corpus (1,600)                 |
+------------------------------------+------------------------------------+
|         v2 Delta (1,200)           |          v1 Replay (400)           |
|  - 720 Synthesis Tasks             |  - 200 Synthesis Tasks             |
|  - 480 Diagnostic-Repair Examples  |  - 200 Diagnostic-Repair Examples  |
|  - 36 New Semantic Families        |  - Balanced across 4 categories    |
|  - 100% Verified in Linux 6.8      |  - 100% Non-benchmark tasks       |
+------------------------------------+------------------------------------+
```

### Cumulative Composition Metrics
- **Total Examples**: 1,600
- **Total Unique Synthesis Tasks**: 920 (720 new v2 + 200 v1 replay)
- **Total Synthesis Examples**: 920 (57.5%)
- **Total Diagnostic-Repair Examples**: 680 (42.5%)
- **Difficulty Stratification**:
  - `level_1`: 536 examples (33.5%)
  - `level_2`: 536 examples (33.5%)
  - `level_3`: 528 examples (33.0%)

---

## 4. 3-Way Split Structure & Evaluation Architecture

To measure both in-distribution retention and zero-shot out-of-distribution generalization, SFT v2 implements a **3-way task-disjoint split architecture**:

```
+------------------------------------------------------------------------------------+
|                                 3-Way Split Architecture                           |
+------------------------------+--------------------------+--------------------------+
|          Train               |    Val (In-Domain)       |  Val (Family-Heldout)    |
|         81.1%                |         9.9%             |          9.0%            |
|       1,297 rows             |       159 rows           |        144 rows          |
|       744 tasks              |       92 tasks           |        84 tasks          |
|  32 Semantic Families        |  32 Semantic Families    |   4 Held-Out Families    |
+------------------------------+--------------------------+--------------------------+
```

### Split Breakdown

| Split Partition | Tasks | Total Rows | Synthesis | Repair | New v2 | v1 Replay | Split Share |
|---|---|---|---|---|---|---|---|
| **Train** | 744 | 1,297 | 744 | 553 | 937 | 360 | 81.1% |
| **Validation (In-Domain)** | 92 | 159 | 92 | 67 | 119 | 40 | 9.9% |
| **Validation (Family-Heldout)** | 84 | 144 | 84 | 60 | 144 | 0 | 9.0% |
| **Total Cumulative** | **920** | **1,600** | **920** | **680** | **1,200** | **400** | **100.0%** |

### Family-Heldout Validation View
The following **4 complete semantic families** (1 per category, 84 tasks, 144 examples) are **100% excluded** from Training and In-Domain Validation:
1. `pfs_srv6_security_policy` (Packet Filtering & Security)
2. `nrf_srv6_end_forwarder` (Network Routing & Forwarding)
3. `pit_ipv6_ext_telemetry` (Packet Inspection & Telemetry)
4. `ptr_ipv4_ipv6_translator` (Protocol Transformation)

---

## 5. Fault Injection Taxonomy & Diagnostic Repair Contract

SFT v2 maintains realistic diagnostic-repair training pairs across 3 failure domains:

```
+----------------------------------------------------------------------------------+
|                            Repair Fault Taxonomy                                 |
+-------------------+-----------------+--------------------------------------------+
| Fault Class       | v2 Delta Count  | Target Failure Mechanisms                  |
+-------------------+-----------------+--------------------------------------------+
| **Compiler**      | 120 (25.0%)     | Header includes, struct typos, undeclared  |
|                   |                 | identifiers, syntax errors, missing bpf.h  |
+-------------------+-----------------+--------------------------------------------+
| **Verifier**      | 160 (33.3%)     | Out-of-bounds packet access, map value     |
|                   |                 | null-dereference, uninitialized stack reads|
|                   |                 | unbounded loops, illegal pointer math      |
+-------------------+-----------------+--------------------------------------------+
| **Behavioral**    | 200 (41.7%)     | Endianness inversion, incorrect action     |
|                   |                 | (PASS vs DROP/TX), bad CIDR subnet masks,  |
|                   |                 | unhandled protocols, stale checksum delta  |
+-------------------+-----------------+--------------------------------------------+
| **Total Repairs** | 480 (100.0%)    |                                            |
+-------------------+-----------------+--------------------------------------------+
```

### Conversational Repair Contract
1. **User Prompt**: Contains the task specification, technical requirements, previous faulty C implementation, and exact Clang/libbpf/verifier diagnostic log.
2. **Assistant Target**: Raw, corrected, complete C program that compiles cleanly with Clang 18, passes Linux 6.8 kernel verification, and satisfies all positive, negative, boundary, and truncated packet fixtures.

---

## 6. Contamination Controls & Benchmark Isolation Certification

### Isolation Scope
The dataset was audited against all **276 protected tasks**:
- **36 Development Calibration Tasks** (`data/calibration/index.jsonl`)
- **120 Private Synthesis Benchmark Tasks** (`data/benchmark/synthesis/index.jsonl`)
- **120 Private Repair Benchmark Tasks** (`data/benchmark/repair/index.jsonl`)

### Leakage Audit Results
- **Exact Task ID Overlap**: **0** (0.0%)
- **Exact Prompt Hash Overlap**: **0** (0.0%)
- **Exact C Code Hash Overlap**: **0** (0.0%)
- **Exact Duplicate Example IDs**: **0** (0.0%)
- **Exact Duplicate Message Hashes**: **0** (0.0%)
- **Max Prompt 3-gram Jaccard Similarity**: **0.1028** (~10.3%)
- **Max Code 3-gram Jaccard Similarity**: **0.5510** (common boilerplate `#include <linux/bpf.h>`)
- **Official Certification**: `CERTIFIED_100_PERCENT_ISOLATED`

---

## 7. Token Length Statistics & Format Specifications

Token lengths were evaluated with the **Qwen/Qwen3-8B** tokenizer using the **`qwen3_disable_thinking`** renderer. All sequences strictly conform to the 4,096 token limit.

| Dataset Partition | Total Examples | Min Tokens | Median Tokens | Mean Tokens | P95 Tokens | Max Tokens | Total Tokens |
|---|---|---|---|---|---|---|---|
| **v2 Delta** | 1,200 | 608 | 706 | 929.0 | 1,495 | 2,186 | 1,114,755 |
| **Train** | 1,297 | 381 | 740 | 1,026.9 | 2,127 | 3,682 | 1,331,860 |
| **Val (In-Domain)** | 159 | 381 | 706 | 993.5 | 2,103 | 3,672 | 157,963 |
| **Val (Family-Heldout)** | 144 | 610 | 706 | 919.3 | 1,484 | 1,500 | 132,382 |
| **Cumulative All** | 1,600 | 381 | 728 | 1,013.9 | 2,058 | 3,682 | 1,622,205 |

### Completion Format Constraints
- Raw C source code only.
- No markdown code fences (```).
- No explanatory preambles or postscripts.
- No `<think>` or `</think>` tags.
- Mandatory `#include`, `SEC("xdp")`, license declaration, and XDP action macros.
- Zero `FAULT`, `TODO`, `FIXME`, or placeholder markers in assistant targets.

---

## 8. Provenance Metadata Schema

Every example in SFT v2 includes comprehensive provenance fields outside `messages`:

```json
{
  "example_id": "v2_syn_v2_pfs_l1_001",
  "task_id": "v2_pfs_l1_001",
  "category": "packet_filtering_security",
  "difficulty": "level_1",
  "template_family": "pfs_tunnel_vxlan_filter",
  "semantic_family": "pfs_tunnel_vxlan_filter",
  "example_type": "synthesis",
  "dataset_version": "v2",
  "source_kind": "new_v2",
  "generator_id": "bpf_sft_v2_generator",
  "generation_attempt": 1,
  "gold_source_sha256": "bcb71e74cf4cbeb182da0869e63cb1e10cfed022ba51be89f7171ce3f11b2009",
  "task_spec_sha256": "479ba4fe47256eeb96a2bedc0224110ad2540334ab75083adf8c98ffd5b5ff10",
  "fixture_manifest_sha256": "2c51a69691ac7d121c08c512e2c43a56ddc4c0e9ab2c2e5e42402b429ea79e1c",
  "messages": [
    {"role": "system", "content": "..."},
    {"role": "user", "content": "..."},
    {"role": "assistant", "content": "..."}
  ]
}
```

For repair rows, the following additional fields are present:
- `fault_class`: `"compiler"` | `"verifier"` | `"behavioral"`
- `fault_injection_id`: Injection identifier (e.g., `"missing_endian_header"`)
- `diagnostic_sha256`: SHA-256 hash of the diagnostic error log
- `parent_synthesis_task_id`: Identifier of the matching synthesis task

---

## 9. Known Limitations & Out-of-Scope Items

1. **Kernel Target Scope**: Target environment is Linux Kernel 6.8+ (x86_64) with Clang 18.1. Programs utilizing newer 6.12+ helpers (e.g., custom kfuncs) are not part of this dataset.
2. **Hook Point**: All examples target `SEC("xdp")`. TC (traffic control), kprobe, tracepoint, and socket filter programs are out of scope for v2.
3. **Hardware Offload**: Programs assume standard native/driver or generic XDP execution. Hardware offload constraints (XDP_FLAGS_HW_MODE) are not modeled.
4. **Evaluation Benchmarks**: SFT v2 dataset explicitly excludes all 276 benchmark and calibration tasks to prevent data contamination.

---

## 10. Exact Reproduction Instructions

To reproduce the SFT v2 dataset and frozen splits from scratch:

```bash
# 1. Build the 1,200 new v2 delta examples and source bundles
python training/build_sft_v2.py --seed 42

# 2. Select v1 replay, build 3-way splits, and freeze the cumulative dataset
python training/prepare_sft_v2_splits.py --seed 42

# 3. Run master validation, benchmark leakage audit, and report generation
python training/validate_sft_v2.py

# 4. Run the full automated test suite
pytest tests/ -v
```
