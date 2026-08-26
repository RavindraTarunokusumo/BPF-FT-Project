# BPF-Guardian Calibration Task Specification

## 1. Assignment

Create a **calibration suite of 36 XDP synthesis tasks** for evaluating the
unmodified Qwen3 8B model before dataset generation or training.

The suite must contain:

- four application categories;
- three difficulty levels per category; and
- three independent tasks in every category/difficulty cell.

This produces `4 categories x 3 levels x 3 tasks = 36 tasks`.

Do not generate model answers, repairs, SFT records, preference pairs, or final
benchmark tasks in this assignment. Create only task contracts, executable test
contracts, deterministic packet fixtures, an assignment file, and supporting
documentation.

The four labels below are the BPF-Guardian project taxonomy. They are informed
by the XDP paper's packet parsing, metadata/map access, packet rewriting, verdict,
software-routing, DoS-mitigation, and load-balancing examples; do not describe
them as a formal taxonomy introduced by the paper.

## 2. Dataset Isolation

All calibration material must live under `data/calibration/`. It must never be
copied into SFT, RL, preference, validation, or final-evaluation splits.

Use this layout:

```text
data/calibration/
|-- README.md
|-- index.jsonl
|-- tasks/
|   `-- <task_id>/task.json
|-- tests/
|   `-- <task_id>/tests.json
|-- fixtures/
|   `-- <task_id>/*.bin
|-- candidates/
|   `-- <task_id>/<candidate_id>/
|       |-- program.c
|       `-- manifest.json
|-- results/
|   `-- raw/*.json
`-- assignments/
    `-- calibration_v1.yaml
```

Candidate and result directories may initially be empty, but their intended
layout must be documented in `README.md`.

## 3. Classification Rules

Every task in this suite has:

- `learning_mode: synthesis`
- exactly one `application_category`
- exactly one `difficulty`
- a stable `task_family`, `template_family`, and `semantic_signature`

Classify a task by its primary purpose, even if it uses a mechanism associated
with another category. For example, a router may rewrite MAC addresses, but its
primary category remains `network_routing_forwarding`.

### Categories

| JSON value | Human name | Primary purpose | Main validators |
|---|---|---|---|
| `packet_filtering_security` | Packet Filtering & Security | Accept or reject traffic according to packet fields or security policy | `packet_action`, optionally `map_state` |
| `network_routing_forwarding` | Network Routing & Forwarding | Select a packet path or egress and forward/redirect traffic | `live_forward`, optionally `packet_bytes` |
| `packet_inspection_telemetry` | Packet Inspection & Telemetry | Parse traffic and record deterministic observations in BPF maps | `map_state` |
| `protocol_transformation` | Protocol Transformation | Modify packet headers, payload layout, or encapsulation while preserving a valid packet | `packet_bytes` plus `packet_action` |

### Difficulty

Difficulty describes the original synthesis task, not whether a candidate later
fails compilation, verification, or behavioral tests.

| Level | Definition |
|---|---|
| `level_1` | Stateless; one main header or decision; no configuration lookup; one observable action or simple counter update |
| `level_2` | Multiple conditions or variable headers; one map/helper/configuration dependency; checksum or multi-field logic; moderate edge cases |
| `level_3` | Stateful or multi-stage parsing; multiple maps/helpers or live topology; encapsulation, policy routing, flow state, or coordinated packet and metadata changes |

A harder task must require a materially harder implementation and oracle. Do
not raise difficulty merely by making the prompt longer.

## 4. Required Task Inventory

The task IDs below are mandatory. Wording may be clarified, but behavior must
not be weakened.

### A. Packet Filtering & Security

#### Level 1

1. `pfs_l1_tcp23_drop` - Drop IPv4 TCP packets with destination port 23; pass
   all other and malformed packets; support variable IPv4 IHL.
2. `pfs_l1_udp53_drop` - Drop IPv4 UDP packets with destination port 53; pass
   TCP, other UDP ports, non-IPv4, and truncated packets.
3. `pfs_l1_icmp_echo_drop` - Drop IPv4 ICMP echo requests; pass other ICMP
   types, other protocols, non-IPv4, and malformed packets.

#### Level 2

1. `pfs_l2_syn_privileged_ports` - Drop initial IPv4 TCP SYN packets targeting
   destination ports 1-1023; do not drop ACK/RST traffic or higher ports; handle
   variable IHL.
2. `pfs_l2_source_subnet_exception` - Drop IPv4 traffic sourced from
   `198.51.100.0/24`, except UDP destination port 53; pass all other traffic.
3. `pfs_l2_vlan_tcp443` - Drop TCP destination port 443 inside either untagged
   IPv4 Ethernet or one 802.1Q VLAN header; pass other and malformed frames.

#### Level 3

1. `pfs_l3_source_packet_quota` - Maintain a per-source IPv4 packet count and
   pass the first five packets from each source, then drop later packets. The
   prompt must define the exact map ABI and behavior on failed map lookup/update.
2. `pfs_l3_configured_blocklist` - Consult an LPM-trie IPv4 blocklist and drop
   matching sources while incrementing an exact per-rule match counter; pass
   nonmatches and malformed packets. Define all map ABIs.
3. `pfs_l3_multivector_guard` - Implement one deterministic guard covering TCP
   SYN-to-privileged-port traffic, configured blocked UDP ports, and malformed
   IPv4 lengths, while keeping separate counters for each drop reason. Define
   map names, keys, values, and precedence when multiple rules match.

### B. Network Routing & Forwarding

#### Level 1

1. `nrf_l1_udp_reflector` - For valid IPv4 UDP packets, swap Ethernet source and
   destination addresses and return `XDP_TX`; pass every other packet unchanged.
2. `nrf_l1_subnet_reflector` - Reflect packets whose IPv4 destination is in
   `192.0.2.0/24` by swapping Ethernet addresses and returning `XDP_TX`; pass
   nonmatching and malformed packets.
3. `nrf_l1_icmp_reflector` - Reflect valid IPv4 ICMP packets at layer 2 by
   swapping Ethernet addresses and returning `XDP_TX`; pass other traffic.

#### Level 2

1. `nrf_l2_configured_redirect` - Redirect all valid Ethernet frames to the
   interface index stored at key zero in an array map named
   `forwarding_config`; return `XDP_ABORTED` when the entry is absent or zero.
2. `nrf_l2_protocol_redirect` - Redirect IPv4 TCP and UDP packets to two
   separately configured egress interfaces; pass other protocols. Define the
   exact configuration-map ABI and failure behavior.
3. `nrf_l2_prefix_redirect` - Select one of two configured egress interfaces by
   IPv4 destination prefix, with longest-prefix behavior and a defined no-route
   action. Validate both expected egress and absence on the wrong egress.

#### Level 3

1. `nrf_l3_fib_router` - Use `bpf_fib_lookup` to route IPv4 packets, decrement
   TTL, update the IPv4 checksum, apply returned source/destination MAC
   addresses, and redirect to the resolved egress. Define behavior for every
   relevant FIB return class.
2. `nrf_l3_policy_router` - Route packets to one of two egresses using source
   prefix, destination prefix, and IP protocol, with explicit precedence and a
   fallback path. Define configuration maps and validate live egress behavior.
3. `nrf_l3_flow_load_balancer` - Deterministically select one of two configured
   backends from the IPv4 five-tuple, keep all packets of a flow on the same
   backend, rewrite required layer-2 forwarding fields, and redirect through a
   devmap. Define the hashing and map contracts precisely enough for an exact
   oracle.

### C. Packet Inspection & Telemetry

#### Level 1

1. `pit_l1_total_packets` - Increment a 64-bit per-CPU total-packet counter once
   for every invocation and return `XDP_PASS`.
2. `pit_l1_total_bytes` - Add the observed packet length to a 64-bit per-CPU
   byte counter and return `XDP_PASS`, including for truncated packets.
3. `pit_l1_ipv4_split` - Increment exactly one of two per-CPU counters for IPv4
   and non-IPv4 frames, then return `XDP_PASS`.

#### Level 2

1. `pit_l2_protocol_counters` - Count IPv4 TCP, IPv4 UDP, other IPv4, and
   non-IPv4 packets in distinct per-CPU array slots.
2. `pit_l2_tcp_flag_counters` - Count valid IPv4 TCP packets by SYN, FIN, RST,
   and other; define precedence for packets carrying multiple flags.
3. `pit_l2_length_histogram` - Place every packet into one of four deterministic
   length buckets: `0-63`, `64-127`, `128-511`, and `512+` bytes.

#### Level 3

1. `pit_l3_ipv4_flow_counter` - Count valid IPv4 TCP/UDP packets in a hash map
   keyed by source address, destination address, source port, destination port,
   and protocol; support variable IPv4 IHL.
2. `pit_l3_vlan_dualstack_telemetry` - Count packets and bytes by Ethernet
   family for untagged, single-VLAN IPv4, single-VLAN IPv6, and other traffic,
   without double counting.
3. `pit_l3_tcp_flow_outcomes` - Maintain per-flow packet and byte totals plus
   SYN, FIN, and RST observations for IPv4 TCP traffic. Define the exact key and
   value structures, flag semantics, and malformed-packet behavior.

### D. Protocol Transformation

#### Level 1

1. `ptr_l1_swap_mac` - Swap Ethernet source and destination addresses and pass
   the packet; preserve every byte after the addresses.
2. `ptr_l1_set_destination_mac` - Replace the Ethernet destination address with
   `02:00:00:00:00:99`; preserve source, EtherType, payload, and packet length.
3. `ptr_l1_set_source_mac` - Replace the Ethernet source address with
   `02:00:00:00:00:42`; preserve destination, EtherType, payload, and length.

#### Level 2

1. `ptr_l2_decrement_ttl` - Decrement IPv4 TTL when greater than one and update
   the IPv4 checksum; define the action for TTL zero or one; preserve all other
   bytes.
2. `ptr_l2_rewrite_ipv4_destination` - Rewrite the IPv4 destination address to
   `203.0.113.9` and correctly update the IPv4 header checksum; pass non-IPv4
   packets unchanged.
3. `ptr_l2_rewrite_udp_port` - Rewrite the destination port of valid IPv4 UDP
   packets to 5353 and update a nonzero UDP checksum correctly; preserve a zero
   UDP checksum as zero.

#### Level 3

1. `ptr_l3_tcp_dnat` - Rewrite both the IPv4 destination address and TCP
   destination port to fixed specified values, updating IPv4 and TCP checksums
   correctly for variable-length IPv4 and TCP headers.
2. `ptr_l3_icmp_echo_reply` - Convert a valid IPv4 ICMP echo request into an
   echo reply by swapping Ethernet and IPv4 endpoints, changing ICMP type,
   updating checksums, and returning `XDP_TX`; pass other traffic unchanged.
3. `ptr_l3_vlan_pop` - Remove exactly one 802.1Q VLAN header using the supported
   XDP head-adjustment mechanism, restore the encapsulated EtherType, preserve
   the payload exactly, and pass untagged or malformed packets unchanged.

## 5. Task Contract Requirements

For every task:

1. Create a schema-valid `task.json` and `tests.json`.
2. Use the exact task ID listed above in both files.
3. Make the instruction self-contained. A model must not need access to the
   repository, tests, reference code, or hidden conventions to answer it.
4. State any required map name, map type, key/value size, key meaning, slot
   meaning, byte order, capacity, default behavior, and update-failure behavior.
5. Require complete C source, `SEC("xdp")`, necessary includes, safe bounds
   checks, and a GPL-compatible license.
6. Do not mention expected compiler/verifier failures, candidate failure stage,
   repairs, hidden tests, or gold implementations in the prompt.
7. Do not create a gold `program.c`; the final passing candidate produced after
   calibration repair will later be treated as the gold answer.

## 6. Executable Test Requirements

Each stated behavioral requirement must be exercised by an executable test.
Do not accept tasks using compilation or verifier acceptance alone.

Minimum cases:

- Level 1: at least 5 cases.
- Level 2: at least 7 cases.
- Level 3: at least 9 cases.

Every applicable task must include:

- a positive case;
- a negative/nonmatching case;
- a boundary case;
- a truncated or malformed packet case;
- an unchanged-packet assertion where the action should not modify data; and
- state reset/isolation checks for map-based tasks.

Use validators according to observable behavior:

- `packet_action` for `XDP_PASS`, `XDP_DROP`, `XDP_TX`, or `XDP_ABORTED`;
- `packet_bytes` for exact rewrites, output length, and unchanged ranges;
- `map_state` for exact map contents after deterministic packet sequences;
- `live_forward` when the selected egress or actual forwarding path matters.

Routing tests must assert that the packet appears on the expected egress and is
absent from every wrong egress. Transformation tests must use independently
constructed expected packet bytes and independently computed checksums. Do not
derive the expected output by executing a reference eBPF implementation.

All tests must be deterministic, fail closed, use repository-relative fixture
paths, clean up maps/programs/namespaces, and leave zero residual pins or
interfaces after success, failure, timeout, or interruption.

If the current harness cannot express an oracle required by one of these tasks,
do not weaken or silently skip the test. Mark the task blocked in `index.jsonl`
with a concrete reason and report it. Do not modify the harness in this
assignment unless explicitly authorized.

## 7. Validation and Acceptance

Before committing:

1. Validate every JSON file against the repository schemas.
2. Confirm all 36 task/test pairs exist and task IDs match.
3. Confirm there are exactly three tasks in each category/difficulty cell.
4. Generate every packet fixture reproducibly from a checked-in script.
5. Lint all tasks and tests.
6. Run the existing unprivileged unit/contract tests.
7. Run any privileged fixture/oracle checks supported by the harness.
8. Run the full harness acceptance suite and confirm cleanup remains clean.
9. Create `index.jsonl` containing task ID, category, difficulty, task family,
   required validators, readiness status, and any blocker.
10. Create `calibration_v1.yaml` listing all ready tasks but no candidates.

Commit and push the work to `main`. In the final report, provide:

- commit SHA;
- task counts by category and difficulty;
- validators and fixture counts;
- commands run and their outcomes;
- any blocked tasks and exact reasons; and
- confirmation that no candidates or gold answers were generated.

## 8. Later Calibration Protocol (Do Not Execute Yet)

The later Qwen3 8B run will generate exactly one first-attempt candidate per
task. Preserve it as `c00`, even if it fails. Record output compliance, compile,
verifier, behavior Pass@1, failure stage, and diagnostics. A failed candidate
may receive one diagnostic-guided repair attempt for `Repair@1`; preserve the
repair as `c00-r01`. Calibration tasks and outputs remain excluded from all
training and final evaluation data.
