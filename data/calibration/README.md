# BPF-Guardian Calibration Dataset

This directory contains the **36 calibration XDP synthesis tasks** strictly isolated under `data/calibration/`.
These tasks evaluate the unmodified baseline model before dataset generation or fine-tuning.

## Structure

```text
data/calibration/
|-- README.md
|-- index.jsonl
|-- assignments/
|   `-- calibration_v1.yaml
|-- packet_filtering_security/
|   |-- level_1/
|   |   |-- pfs_l1_tcp23_drop/
|   |   |-- pfs_l1_udp53_drop/
|   |   `-- pfs_l1_icmp_echo_drop/
|   |-- level_2/
|   |   |-- pfs_l2_syn_privileged_ports/
|   |   |-- pfs_l2_source_subnet_exception/
|   |   `-- pfs_l2_vlan_tcp443/
|   `-- level_3/
|       |-- pfs_l3_source_packet_quota/
|       |-- pfs_l3_configured_blocklist/
|       `-- pfs_l3_multivector_guard/
|-- network_routing_forwarding/
|   |-- level_1/
|   |   |-- nrf_l1_udp_reflector/
|   |   |-- nrf_l1_subnet_reflector/
|   |   `-- nrf_l1_icmp_reflector/
|   |-- level_2/
|   |   |-- nrf_l2_configured_redirect/
|   |   |-- nrf_l2_protocol_redirect/
|   |   `-- nrf_l2_prefix_redirect/
|   `-- level_3/
|       |-- nrf_l3_fib_router/
|       |-- nrf_l3_policy_router/
|       `-- nrf_l3_flow_load_balancer/
|-- packet_inspection_telemetry/
|   |-- level_1/
|   |   |-- pit_l1_total_packets/
|   |   |-- pit_l1_total_bytes/
|   |   `-- pit_l1_ipv4_split/
|   |-- level_2/
|   |   |-- pit_l2_protocol_counters/
|   |   |-- pit_l2_tcp_flag_counters/
|   |   `-- pit_l2_length_histogram/
|   `-- level_3/
|       |-- pit_l3_ipv4_flow_counter/
|       |-- pit_l3_vlan_dualstack_telemetry/
|       `-- pit_l3_tcp_flow_outcomes/
`-- protocol_transformation/
    |-- level_1/
    |   |-- ptr_l1_swap_mac/
    |   |-- ptr_l1_set_destination_mac/
    |   `-- ptr_l1_set_source_mac/
    |-- level_2/
    |   |-- ptr_l2_decrement_ttl/
    |   |-- ptr_l2_rewrite_ipv4_destination/
    |   `-- ptr_l2_rewrite_udp_port/
    `-- level_3/
        |-- ptr_l3_tcp_dnat/
        |-- ptr_l3_icmp_echo_reply/
        `-- ptr_l3_vlan_pop/
```

## Taxonomy Summary

| Category | Level 1 (>=5 tests) | Level 2 (>=7 tests) | Level 3 (>=9 tests) | Total |
|---|---|---|---|---|
| `packet_filtering_security` | 3 | 3 | 3 | 9 |
| `network_routing_forwarding` | 3 | 3 | 3 | 9 |
| `packet_inspection_telemetry` | 3 | 3 | 3 | 9 |
| `protocol_transformation` | 3 | 3 | 3 | 9 |
| **Total** | **12** | **12** | **12** | **36** |

## Invariants
* **Strict Dataset Isolation**: Never copied into SFT, RL, preference, or final benchmark splits.
* **No Gold Candidates**: No `c00.c` or reference answers generated in this phase.
* **Deterministic Fixtures**: All test vectors stored as reproducible `.bin` files and exact JSON contracts.
