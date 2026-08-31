"""
Task definitions for Category 2: Packet Inspection & Telemetry (30 Tasks)
Covers Level 1 (10 tasks), Level 2 (10 tasks), and Level 3 (10 tasks).
Includes metadata, self-contained instruction, strict requirements, verified C reference solution,
and deterministic test fixtures.
"""

from __future__ import annotations

import binascii
import struct
from typing import Any, Dict, List

from .packet_utils import (
    make_arp,
    make_coap,
    make_dhcp,
    make_dns,
    make_eth,
    make_geneve,
    make_gre,
    make_gtpu,
    make_icmp,
    make_icmpv6,
    make_ipv4,
    make_ipv6,
    make_mpls,
    make_ntp,
    make_quic,
    make_sctp,
    make_srv6,
    make_tcp,
    make_udp,
    make_vxlan,
    make_wireguard,
)


def get_packet_inspection_telemetry_tasks() -> List[Dict[str, Any]]:
    tasks: List[Dict[str, Any]] = []

    # =========================================================================
    # LEVEL 1 (10 Tasks) - Stateless observation, 1 metric/counter
    # =========================================================================

    # 31. syn_pit_l1_001_vxlan_vni_counter
    t31_tests = [
        {"name": "vxlan_packet_pass", "description": "VXLAN packet must increment counter and return XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=4789, payload=make_vxlan(vni=100, inner_frame=make_eth(payload=make_ipv4(proto=1, payload=make_icmp())))))).hex(), "expected_action": "XDP_PASS"},
        {"name": "vxlan_packet_2_pass", "description": "Second VXLAN packet with different VNI increments counter and passes", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=4789, payload=make_vxlan(vni=200, inner_frame=make_eth(payload=make_ipv4(proto=6, payload=make_tcp())))))).hex(), "expected_action": "XDP_PASS"},
        {"name": "non_vxlan_udp_pass", "description": "UDP packet on other port does not increment VXLAN counter and passes", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=53))).hex(), "expected_action": "XDP_PASS"},
        {"name": "tcp_pass", "description": "TCP packet passes", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "truncated_vxlan_pass", "description": "Truncated VXLAN packet passes safely", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=4789, payload=b"\x08\x00"))).hex(), "expected_action": "XDP_PASS"},
    ]
    t31_sol = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

struct vxlanhdr {
    __u32 vx_flags;
    __u32 vx_vni;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} vxlan_counter_map SEC(".maps");

SEC("xdp")
int xdp_vxlan_counter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    int ip_len = ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip_len;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;
    if (udp->dest != bpf_htons(4789))
        return XDP_PASS;

    struct vxlanhdr *vx = (void *)(udp + 1);
    if ((void *)(vx + 1) > data_end)
        return XDP_PASS;

    __u32 key = 0;
    __u64 *cnt = bpf_map_lookup_elem(&vxlan_counter_map, &key);
    if (cnt)
        *cnt += 1;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    tasks.append({
        "task_id": "syn_pit_l1_001_vxlan_vni_counter",
        "application_category": "packet_inspection_telemetry",
        "difficulty": "level_1",
        "task_family": "xdp_telemetry_tunnel",
        "template_family": "xdp_vxlan_counter",
        "semantic_signature": "vxlan_udp4789+percpu_packet_counter+pass",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that inspects VXLAN traffic (UDP port 4789) and counts valid VXLAN encapsulated frames in a per-CPU array map named 'vxlan_counter_map' (key 0, type BPF_MAP_TYPE_PERCPU_ARRAY, value __u64, max_entries 1). Increment the counter by 1 for every valid VXLAN frame. Always return XDP_PASS.",
        "requirements": [
            "Define per-CPU array map 'vxlan_counter_map' with key __u32, value __u64, max_entries 1",
            "Validate Ethernet, IPv4 (variable IHL), UDP, and VXLAN header bounds",
            "Verify UDP destination port is 4789",
            "Increment counter at key 0 for valid VXLAN frames",
            "Always return XDP_PASS",
            "SEC(\"xdp\") and GPL license declaration"
        ],
        "solution_c": t31_sol,
        "tests": t31_tests,
        "main_validator": "map_state"
    })

    # 32. syn_pit_l1_002_gre_protocol_split
    t32_tests = [
        {"name": "gre_ipv4_pass", "description": "GRE carrying IPv4 increments slot 0 and returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=47, payload=make_gre(proto=0x0800, inner_pkt=make_ipv4(proto=1, payload=make_icmp())))).hex(), "expected_action": "XDP_PASS"},
        {"name": "gre_ipv6_pass", "description": "GRE carrying IPv6 increments slot 1 and returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=47, payload=make_gre(proto=0x86DD, inner_pkt=make_ipv6(next_hdr=58, payload=make_icmpv6())))).hex(), "expected_action": "XDP_PASS"},
        {"name": "gre_other_pass", "description": "GRE carrying other protocol increments slot 2 and returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=47, payload=make_gre(proto=0x8847, inner_pkt=b"\x00"*10))).hex(), "expected_action": "XDP_PASS"},
        {"name": "non_gre_udp_pass", "description": "Non-GRE UDP packet passes without incrementing GRE map", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "truncated_gre_pass", "description": "Truncated GRE packet passes safely", "packet_hex": make_eth(payload=make_ipv4(proto=47, payload=b"\x00")).hex(), "expected_action": "XDP_PASS"},
    ]
    t32_sol = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

struct grehdr {
    __be16 flags;
    __be16 proto;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 3); // 0=IPv4, 1=IPv6, 2=Other
} gre_split_map SEC(".maps");

SEC("xdp")
int xdp_gre_split(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->protocol != 47) // IPPROTO_GRE
        return XDP_PASS;

    int ip_len = ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct grehdr *gre = (void *)ip + ip_len;
    if ((void *)(gre + 1) > data_end)
        return XDP_PASS;

    __u32 key = 2; // Other
    if (gre->proto == bpf_htons(ETH_P_IP))
        key = 0;
    else if (gre->proto == bpf_htons(ETH_P_IPV6))
        key = 1;

    __u64 *cnt = bpf_map_lookup_elem(&gre_split_map, &key);
    if (cnt)
        *cnt += 1;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    tasks.append({
        "task_id": "syn_pit_l1_002_gre_protocol_split",
        "application_category": "packet_inspection_telemetry",
        "difficulty": "level_1",
        "task_family": "xdp_telemetry_gre",
        "template_family": "xdp_gre_split_counter",
        "semantic_signature": "gre_proto47+inner_proto_split_counter+pass",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that inspects GRE tunnel traffic (IP protocol 47) and classifies encapsulated protocols into a per-CPU array map named 'gre_split_map' (max_entries 3). Use slot 0 for encapsulated IPv4 (0x0800), slot 1 for encapsulated IPv6 (0x86DD), and slot 2 for all other encapsulated protocols. Always return XDP_PASS.",
        "requirements": [
            "Define per-CPU array map 'gre_split_map' with max_entries 3",
            "Validate Ethernet, IPv4, and GRE header bounds",
            "Check ip->protocol == 47",
            "Increment slot 0 for IPv4, slot 1 for IPv6, slot 2 for other encapsulated protocols",
            "Always return XDP_PASS",
            "SEC(\"xdp\") and GPL license declaration"
        ],
        "solution_c": t32_sol,
        "tests": t32_tests,
        "main_validator": "map_state"
    })

    # 33. syn_pit_l1_003_mpls_depth_counter
    t33_tests = [
        {"name": "mpls_single_label_pass", "description": "Single-label MPLS frame increments slot 0 and returns XDP_PASS", "packet_hex": make_eth(eth_type=0x8847, payload=make_mpls([(100, 0, True, 64)], inner_pkt=make_ipv4(proto=1, payload=make_icmp()))).hex(), "expected_action": "XDP_PASS"},
        {"name": "mpls_multi_label_pass", "description": "Multi-label MPLS frame increments slot 1 and returns XDP_PASS", "packet_hex": make_eth(eth_type=0x8847, payload=make_mpls([(100, 0, False, 64), (200, 0, True, 64)], inner_pkt=make_ipv4(proto=1, payload=make_icmp()))).hex(), "expected_action": "XDP_PASS"},
        {"name": "non_mpls_ipv4_pass", "description": "Non-MPLS IPv4 packet passes without counting", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "arp_pass", "description": "ARP frame passes", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
        {"name": "truncated_mpls_pass", "description": "Truncated MPLS frame passes safely", "packet_hex": make_eth(eth_type=0x8847, payload=b"\x00\x01").hex(), "expected_action": "XDP_PASS"},
    ]
    t33_sol = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>

struct mpls_label {
    __u32 entry;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 2); // 0=single-label (BOS=1), 1=multi-label (BOS=0)
} mpls_depth_map SEC(".maps");

SEC("xdp")
int xdp_mpls_depth(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(0x8847))
        return XDP_PASS;

    struct mpls_label *mpls = (void *)(eth + 1);
    if ((void *)(mpls + 1) > data_end)
        return XDP_PASS;

    __u32 entry = bpf_ntohl(mpls->entry);
    __u32 key = (entry & 0x00000100) ? 0 : 1; // Bit 8 is BOS: 1 -> single label, 0 -> multi-label

    __u64 *cnt = bpf_map_lookup_elem(&mpls_depth_map, &key);
    if (cnt)
        *cnt += 1;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    tasks.append({
        "task_id": "syn_pit_l1_003_mpls_depth_counter",
        "application_category": "packet_inspection_telemetry",
        "difficulty": "level_1",
        "task_family": "xdp_telemetry_mpls",
        "template_family": "xdp_mpls_depth_counter",
        "semantic_signature": "mpls_0x8847+bos_bit_split_counter+pass",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that inspects MPLS unicast frames (EtherType 0x8847). Parse the first 4-byte MPLS label and inspect the Bottom-of-Stack (BOS / S-bit, bit 8). Count single-label frames (BOS == 1) in slot 0, and stacked multi-label frames (BOS == 0) in slot 1 of a per-CPU array map named 'mpls_depth_map' (max_entries 2). Always return XDP_PASS.",
        "requirements": [
            "Define per-CPU array map 'mpls_depth_map' with max_entries 2",
            "Validate Ethernet header bounds and check eth->h_proto == bpf_htons(0x8847)",
            "Validate 4-byte MPLS label header bounds",
            "Check BOS bit (entry & 0x00000100) and increment slot 0 (BOS=1) or slot 1 (BOS=0)",
            "Always return XDP_PASS",
            "SEC(\"xdp\") and GPL license declaration"
        ],
        "solution_c": t33_sol,
        "tests": t33_tests,
        "main_validator": "map_state"
    })

    # Tasks 34 to 40 (Level 1 PIT)
    # 34. syn_pit_l1_004_gtpu_teid_zero_count
    t34_tests = [
        {"name": "gtpu_control_teid0_pass", "description": "GTP-U with TEID 0 increments slot 0 and returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=2152, payload=make_gtpu(teid=0)))).hex(), "expected_action": "XDP_PASS"},
        {"name": "gtpu_data_teid_nonzero_pass", "description": "GTP-U with TEID != 0 increments slot 1 and returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=2152, payload=make_gtpu(teid=0x12345678, inner_pkt=make_ipv4(proto=1, payload=make_icmp()))))).hex(), "expected_action": "XDP_PASS"},
        {"name": "non_gtpu_udp_pass", "description": "UDP to port 2153 passes without counting", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=2153))).hex(), "expected_action": "XDP_PASS"},
        {"name": "tcp_pass", "description": "TCP packet passes", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "truncated_gtpu_pass", "description": "Truncated GTP-U packet passes safely", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=2152, payload=b"\x30"))).hex(), "expected_action": "XDP_PASS"},
    ]
    t34_sol = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

struct gtpuhdr {
    __u8 flags;
    __u8 msg_type;
    __be16 length;
    __be32 teid;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 2); // 0=TEID zero (control), 1=TEID non-zero (data)
} gtpu_teid_split_map SEC(".maps");

SEC("xdp")
int xdp_gtpu_teid_split(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    int ip_len = ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip_len;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;
    if (udp->dest != bpf_htons(2152))
        return XDP_PASS;

    struct gtpuhdr *gtp = (void *)(udp + 1);
    if ((void *)(gtp + 1) > data_end)
        return XDP_PASS;

    __u32 key = (gtp->teid == 0) ? 0 : 1;
    __u64 *cnt = bpf_map_lookup_elem(&gtpu_teid_split_map, &key);
    if (cnt)
        *cnt += 1;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    tasks.append({
        "task_id": "syn_pit_l1_004_gtpu_teid_zero_count",
        "application_category": "packet_inspection_telemetry",
        "difficulty": "level_1",
        "task_family": "xdp_telemetry_gtpu",
        "template_family": "xdp_gtpu_teid_counter",
        "semantic_signature": "gtpu_udp2152+teid_zero_vs_nonzero_counter+pass",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that inspects GTP-U traffic (UDP port 2152). Parse the 8-byte GTP-U header and inspect the 32-bit TEID field. Count control packets (teid == 0) in slot 0, and user data packets (teid != 0) in slot 1 of a per-CPU array map named 'gtpu_teid_split_map' (max_entries 2). Always return XDP_PASS.",
        "requirements": [
            "Define per-CPU array map 'gtpu_teid_split_map' with max_entries 2",
            "Validate Ethernet, IPv4 (variable IHL), UDP, and GTP-U header bounds",
            "Verify UDP destination port 2152",
            "Check gtp->teid == 0 (slot 0) vs gtp->teid != 0 (slot 1)",
            "Always return XDP_PASS",
            "SEC(\"xdp\") and GPL license declaration"
        ],
        "solution_c": t34_sol,
        "tests": t34_tests,
        "main_validator": "map_state"
    })

    # 35. syn_pit_l1_005_dns_query_response_split
    t35_tests = [
        {"name": "dns_query_pass", "description": "DNS Query (QR=0) increments slot 0 and returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=53, payload=make_dns(qr=0)))).hex(), "expected_action": "XDP_PASS"},
        {"name": "dns_response_pass", "description": "DNS Response (QR=1) increments slot 1 and returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(src_port=53, dst_port=12345, payload=make_dns(qr=1)))).hex(), "expected_action": "XDP_PASS"},
        {"name": "non_dns_udp_pass", "description": "UDP port 5353 passes without incrementing map", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=5353))).hex(), "expected_action": "XDP_PASS"},
        {"name": "tcp_pass", "description": "TCP packet passes", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "truncated_dns_pass", "description": "Truncated DNS packet passes safely", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=53, payload=b"\x12\x34"))).hex(), "expected_action": "XDP_PASS"},
    ]
    t35_sol = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 2); // 0=Query, 1=Response
} dns_qr_map SEC(".maps");

SEC("xdp")
int xdp_dns_qr_split(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    int ip_len = ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip_len;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;
    if (udp->dest != bpf_htons(53) && udp->source != bpf_htons(53))
        return XDP_PASS;

    void *dns_start = (void *)(udp + 1);
    if (dns_start + 4 > data_end)
        return XDP_PASS;

    __u16 flags = bpf_ntohs(*(__be16 *)(dns_start + 2));
    __u32 key = (flags & 0x8000) ? 1 : 0; // Bit 15: 0=Query, 1=Response

    __u64 *cnt = bpf_map_lookup_elem(&dns_qr_map, &key);
    if (cnt)
        *cnt += 1;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    tasks.append({
        "task_id": "syn_pit_l1_005_dns_query_response_split",
        "application_category": "packet_inspection_telemetry",
        "difficulty": "level_1",
        "task_family": "xdp_telemetry_dns",
        "template_family": "xdp_dns_qr_counter",
        "semantic_signature": "dns_udp53+qr_flag_split_counter+pass",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that inspects DNS traffic (UDP port 53 on source or destination). Parse the DNS header flags and inspect the QR bit (bit 15 / 0x8000). Count DNS Queries (QR == 0) in slot 0, and DNS Responses (QR == 1) in slot 1 of a per-CPU array map named 'dns_qr_map' (max_entries 2). Always return XDP_PASS.",
        "requirements": [
            "Define per-CPU array map 'dns_qr_map' with max_entries 2",
            "Validate Ethernet, IPv4, and UDP header bounds",
            "Check UDP port 53 on source or destination",
            "Inspect DNS flags word: bit 15 (0x8000) distinguishes query (0) from response (1)",
            "Always return XDP_PASS",
            "SEC(\"xdp\") and GPL license declaration"
        ],
        "solution_c": t35_sol,
        "tests": t35_tests,
        "main_validator": "map_state"
    })

    # Add tasks 36 to 40 (Level 1)
    # 36. syn_pit_l1_006_dhcp_message_type_counter
    t36_tests = [
        {"name": "dhcp_discover_pass", "description": "DHCP Discover (type 1) increments slot 0 and returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(src_ip="0.0.0.0", dst_ip="255.255.255.255", proto=17, payload=make_udp(src_port=68, dst_port=67, payload=make_dhcp(op=1, msg_type=1)))).hex(), "expected_action": "XDP_PASS"},
        {"name": "dhcp_offer_pass", "description": "DHCP Offer (type 2) increments slot 1 and returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.1", dst_ip="255.255.255.255", proto=17, payload=make_udp(src_port=67, dst_port=68, payload=make_dhcp(op=2, msg_type=2)))).hex(), "expected_action": "XDP_PASS"},
        {"name": "dhcp_request_pass", "description": "DHCP Request (type 3) increments slot 2 and returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(src_ip="0.0.0.0", dst_ip="255.255.255.255", proto=17, payload=make_udp(src_port=68, dst_port=67, payload=make_dhcp(op=1, msg_type=3)))).hex(), "expected_action": "XDP_PASS"},
        {"name": "dhcp_ack_pass", "description": "DHCP Ack (type 5) increments slot 3 and returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.1", dst_ip="192.168.1.50", proto=17, payload=make_udp(src_port=67, dst_port=68, payload=make_dhcp(op=2, msg_type=5)))).hex(), "expected_action": "XDP_PASS"},
        {"name": "non_dhcp_udp_pass", "description": "UDP port 69 passes without counting", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=69))).hex(), "expected_action": "XDP_PASS"},
        {"name": "truncated_dhcp_pass", "description": "Truncated DHCP packet passes safely", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(src_port=68, dst_port=67, payload=b"\x01\x01"))).hex(), "expected_action": "XDP_PASS"},
    ]
    t36_sol = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 4); // 0=Discover(1), 1=Offer(2), 2=Request(3), 3=Ack(5)
} dhcp_type_map SEC(".maps");

SEC("xdp")
int xdp_dhcp_type_counter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    int ip_len = ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip_len;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    if ((udp->source != bpf_htons(67) && udp->source != bpf_htons(68)) ||
        (udp->dest != bpf_htons(67) && udp->dest != bpf_htons(68)))
        return XDP_PASS;

    void *dhcp_start = (void *)(udp + 1);
    if (dhcp_start + 243 > data_end)
        return XDP_PASS;

    __be32 *magic = (void *)dhcp_start + 236;
    if (*magic != bpf_htonl(0x63825363))
        return XDP_PASS;

    __u8 *opt = (void *)dhcp_start + 240;
    if (*opt != 53 || *(opt + 1) != 1) // Option 53 (DHCP Message Type)
        return XDP_PASS;

    __u8 msg_type = *(opt + 2);
    __u32 key = 99;
    if (msg_type == 1) key = 0;      // Discover
    else if (msg_type == 2) key = 1; // Offer
    else if (msg_type == 3) key = 2; // Request
    else if (msg_type == 5) key = 3; // Ack

    if (key < 4) {
        __u64 *cnt = bpf_map_lookup_elem(&dhcp_type_map, &key);
        if (cnt)
            *cnt += 1;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    tasks.append({
        "task_id": "syn_pit_l1_006_dhcp_message_type_counter",
        "application_category": "packet_inspection_telemetry",
        "difficulty": "level_1",
        "task_family": "xdp_telemetry_dhcp",
        "template_family": "xdp_dhcp_type_counter",
        "semantic_signature": "dhcp_ports_67_68+option_53_split_counter+pass",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that inspects DHCP packets (UDP ports 67/68). Verify the 4-byte Magic Cookie 0x63825363 at offset 236. Parse DHCP Option 53 (Message Type) and count occurrences into a per-CPU array map named 'dhcp_type_map' (max_entries 4): slot 0 for Discover (1), slot 1 for Offer (2), slot 2 for Request (3), and slot 3 for Ack (5). Always return XDP_PASS.",
        "requirements": [
            "Define per-CPU array map 'dhcp_type_map' with max_entries 4",
            "Validate Ethernet, IPv4, UDP, and DHCP 243-byte offset bounds",
            "Verify Magic Cookie 0x63825363",
            "Extract Option 53 value and increment corresponding map slot",
            "Always return XDP_PASS",
            "SEC(\"xdp\") and GPL license declaration"
        ],
        "solution_c": t36_sol,
        "tests": t36_tests,
        "main_validator": "map_state"
    })

    # 37. syn_pit_l1_007_coap_method_telemetry
    t37_tests = [
        {"name": "coap_get_pass", "description": "CoAP GET (code 1) increments slot 0 and returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=5683, payload=make_coap(code=1)))).hex(), "expected_action": "XDP_PASS"},
        {"name": "coap_post_pass", "description": "CoAP POST (code 2) increments slot 1 and returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=5683, payload=make_coap(code=2)))).hex(), "expected_action": "XDP_PASS"},
        {"name": "coap_put_pass", "description": "CoAP PUT (code 3) increments slot 2 and returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=5683, payload=make_coap(code=3)))).hex(), "expected_action": "XDP_PASS"},
        {"name": "coap_delete_pass", "description": "CoAP DELETE (code 4) increments slot 3 and returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=5683, payload=make_coap(code=4)))).hex(), "expected_action": "XDP_PASS"},
        {"name": "non_coap_udp_pass", "description": "UDP to port 5684 passes without counting", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=5684))).hex(), "expected_action": "XDP_PASS"},
        {"name": "truncated_coap_pass", "description": "Truncated CoAP packet passes safely", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=5683, payload=b"\x40"))).hex(), "expected_action": "XDP_PASS"},
    ]
    t37_sol = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 4); // 0=GET(1), 1=POST(2), 2=PUT(3), 3=DELETE(4)
} coap_method_map SEC(".maps");

SEC("xdp")
int xdp_coap_method_telemetry(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    int ip_len = ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip_len;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;
    if (udp->dest != bpf_htons(5683))
        return XDP_PASS;

    __u8 *coap = (void *)(udp + 1);
    if (coap + 2 > data_end)
        return XDP_PASS;

    __u8 code = *(coap + 1); // Code field is second byte
    if (code >= 1 && code <= 4) {
        __u32 key = code - 1;
        __u64 *cnt = bpf_map_lookup_elem(&coap_method_map, &key);
        if (cnt)
            *cnt += 1;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    tasks.append({
        "task_id": "syn_pit_l1_007_coap_method_telemetry",
        "application_category": "packet_inspection_telemetry",
        "difficulty": "level_1",
        "task_family": "xdp_telemetry_coap",
        "template_family": "xdp_coap_method_counter",
        "semantic_signature": "coap_udp5683+method_code_split_counter+pass",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that inspects CoAP traffic (UDP port 5683). Parse the 4-byte CoAP header and inspect the 8-bit Code field (byte offset 1). Count request methods into a per-CPU array map named 'coap_method_map' (max_entries 4): slot 0 for GET (code 1), slot 1 for POST (code 2), slot 2 for PUT (code 3), and slot 3 for DELETE (code 4). Always return XDP_PASS.",
        "requirements": [
            "Define per-CPU array map 'coap_method_map' with max_entries 4",
            "Validate Ethernet, IPv4, UDP, and CoAP header bounds",
            "Verify UDP destination port is 5683",
            "Extract Code byte and increment slot (code - 1) for codes 1..4",
            "Always return XDP_PASS",
            "SEC(\"xdp\") and GPL license declaration"
        ],
        "solution_c": t37_sol,
        "tests": t37_tests,
        "main_validator": "map_state"
    })

    # 38. syn_pit_l1_008_arp_req_reply_counter
    t38_tests = [
        {"name": "arp_req_pass", "description": "ARP Request (opcode 1) increments slot 0 and returns XDP_PASS", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp(opcode=1)).hex(), "expected_action": "XDP_PASS"},
        {"name": "arp_reply_pass", "description": "ARP Reply (opcode 2) increments slot 1 and returns XDP_PASS", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp(opcode=2)).hex(), "expected_action": "XDP_PASS"},
        {"name": "ipv4_pass", "description": "IPv4 frame passes without incrementing ARP map", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "ipv6_pass", "description": "IPv6 frame passes", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(next_hdr=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "truncated_arp_pass", "description": "Truncated ARP frame passes safely", "packet_hex": make_eth(eth_type=0x0806, payload=b"\x00\x01\x08").hex(), "expected_action": "XDP_PASS"},
    ]
    t38_sol = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 2); // 0=Request(1), 1=Reply(2)
} arp_opcode_map SEC(".maps");

SEC("xdp")
int xdp_arp_opcode_counter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_ARP))
        return XDP_PASS;

    struct arphdr *arp = (void *)(eth + 1);
    if ((void *)(arp + 1) > data_end)
        return XDP_PASS;

    __u16 op = bpf_ntohs(arp->ar_op);
    if (op == ARPOP_REQUEST) {
        __u32 key = 0;
        __u64 *cnt = bpf_map_lookup_elem(&arp_opcode_map, &key);
        if (cnt)
            *cnt += 1;
    } else if (op == ARPOP_REPLY) {
        __u32 key = 1;
        __u64 *cnt = bpf_map_lookup_elem(&arp_opcode_map, &key);
        if (cnt)
            *cnt += 1;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    tasks.append({
        "task_id": "syn_pit_l1_008_arp_req_reply_counter",
        "application_category": "packet_inspection_telemetry",
        "difficulty": "level_1",
        "task_family": "xdp_telemetry_arp",
        "template_family": "xdp_arp_opcode_counter",
        "semantic_signature": "arp_0x0806+opcode_split_counter+pass",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that inspects ARP frames (EtherType 0x0806). Parse the standard struct arphdr and check the opcode (ar_op). Count ARP Requests (opcode 1) in slot 0, and ARP Replies (opcode 2) in slot 1 of a per-CPU array map named 'arp_opcode_map' (max_entries 2). Always return XDP_PASS.",
        "requirements": [
            "Define per-CPU array map 'arp_opcode_map' with max_entries 2",
            "Validate Ethernet and struct arphdr bounds",
            "Check eth->h_proto == bpf_htons(ETH_P_ARP)",
            "Increment slot 0 for ARPOP_REQUEST (1) and slot 1 for ARPOP_REPLY (2)",
            "Always return XDP_PASS",
            "SEC(\"xdp\") and GPL license declaration"
        ],
        "solution_c": t38_sol,
        "tests": t38_tests,
        "main_validator": "map_state"
    })

    # 39. syn_pit_l1_009_ipv6_next_header_split
    t39_tests = [
        {"name": "ipv6_tcp_pass", "description": "IPv6 TCP packet increments slot 0 and returns XDP_PASS", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(next_hdr=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "ipv6_udp_pass", "description": "IPv6 UDP packet increments slot 1 and returns XDP_PASS", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(next_hdr=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "ipv6_icmp6_pass", "description": "IPv6 ICMPv6 packet increments slot 2 and returns XDP_PASS", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(next_hdr=58, payload=make_icmpv6())).hex(), "expected_action": "XDP_PASS"},
        {"name": "ipv6_other_pass", "description": "IPv6 other next header (e.g. GRE 47) increments slot 3 and returns XDP_PASS", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(next_hdr=47, payload=b"\x00"*10)).hex(), "expected_action": "XDP_PASS"},
        {"name": "ipv4_pass", "description": "IPv4 packet passes without incrementing IPv6 map", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "truncated_ipv6_pass", "description": "Truncated IPv6 header passes safely", "packet_hex": make_eth(eth_type=0x86DD, payload=b"\x60\x00").hex(), "expected_action": "XDP_PASS"},
    ]
    t39_sol = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 4); // 0=TCP(6), 1=UDP(17), 2=ICMPv6(58), 3=Other
} ipv6_proto_map SEC(".maps");

SEC("xdp")
int xdp_ipv6_proto_split(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IPV6))
        return XDP_PASS;

    struct ipv6hdr *ip6 = (void *)(eth + 1);
    if ((void *)(ip6 + 1) > data_end)
        return XDP_PASS;

    __u32 key = 3; // Other
    if (ip6->nexthdr == IPPROTO_TCP)
        key = 0;
    else if (ip6->nexthdr == IPPROTO_UDP)
        key = 1;
    else if (ip6->nexthdr == IPPROTO_ICMPV6)
        key = 2;

    __u64 *cnt = bpf_map_lookup_elem(&ipv6_proto_map, &key);
    if (cnt)
        *cnt += 1;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    tasks.append({
        "task_id": "syn_pit_l1_009_ipv6_next_header_split",
        "application_category": "packet_inspection_telemetry",
        "difficulty": "level_1",
        "task_family": "xdp_telemetry_ipv6",
        "template_family": "xdp_ipv6_proto_counter",
        "semantic_signature": "ipv6_0x86dd+nexthdr_split_counter+pass",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that inspects IPv6 traffic (EtherType 0x86DD). Parse the 40-byte IPv6 header and inspect the nexthdr field. Count packets into a per-CPU array map named 'ipv6_proto_map' (max_entries 4): slot 0 for TCP (6), slot 1 for UDP (17), slot 2 for ICMPv6 (58), and slot 3 for all other Next Header types. Always return XDP_PASS.",
        "requirements": [
            "Define per-CPU array map 'ipv6_proto_map' with max_entries 4",
            "Validate Ethernet and struct ipv6hdr bounds",
            "Check eth->h_proto == bpf_htons(ETH_P_IPV6)",
            "Increment slot 0 for TCP, slot 1 for UDP, slot 2 for ICMPv6, slot 3 for other",
            "Always return XDP_PASS",
            "SEC(\"xdp\") and GPL license declaration"
        ],
        "solution_c": t39_sol,
        "tests": t39_tests,
        "main_validator": "map_state"
    })

    # 40. syn_pit_l1_010_quic_packet_type_counter
    t40_tests = [
        {"name": "quic_long_hdr_pass", "description": "QUIC Long Header packet increments slot 0 and returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=443, payload=make_quic(long_hdr=True, pkt_type=0)))).hex(), "expected_action": "XDP_PASS"},
        {"name": "quic_short_hdr_pass", "description": "QUIC Short Header packet increments slot 1 and returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=443, payload=make_quic(long_hdr=False)))).hex(), "expected_action": "XDP_PASS"},
        {"name": "non_quic_udp_pass", "description": "UDP to port 444 passes without counting", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=444))).hex(), "expected_action": "XDP_PASS"},
        {"name": "tcp_pass", "description": "TCP packet passes", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "truncated_quic_pass", "description": "Truncated QUIC packet passes safely", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=443, payload=b""))).hex(), "expected_action": "XDP_PASS"},
    ]
    t40_sol = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 2); // 0=Long Header (0x80), 1=Short Header (0x00)
} quic_hdr_type_map SEC(".maps");

SEC("xdp")
int xdp_quic_hdr_type_counter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    int ip_len = ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip_len;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;
    if (udp->dest != bpf_htons(443) && udp->source != bpf_htons(443))
        return XDP_PASS;

    __u8 *quic = (void *)(udp + 1);
    if (quic + 1 > data_end)
        return XDP_PASS;

    __u32 key = (*quic & 0x80) ? 0 : 1; // Bit 7: 1=Long Header, 0=Short Header
    __u64 *cnt = bpf_map_lookup_elem(&quic_hdr_type_map, &key);
    if (cnt)
        *cnt += 1;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    tasks.append({
        "task_id": "syn_pit_l1_010_quic_packet_type_counter",
        "application_category": "packet_inspection_telemetry",
        "difficulty": "level_1",
        "task_family": "xdp_telemetry_quic",
        "template_family": "xdp_quic_type_counter",
        "semantic_signature": "quic_udp443+long_vs_short_header_counter+pass",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that inspects QUIC traffic (UDP port 443). Check the first byte of the QUIC payload: bit 7 (0x80) indicates a Long Header packet (Initial, Handshake, 0-RTT), while bit 7 == 0 indicates a Short Header (1-RTT). Count Long Header packets in slot 0, and Short Header packets in slot 1 of a per-CPU array map named 'quic_hdr_type_map' (max_entries 2). Always return XDP_PASS.",
        "requirements": [
            "Define per-CPU array map 'quic_hdr_type_map' with max_entries 2",
            "Validate Ethernet, IPv4, UDP, and QUIC first-byte bounds",
            "Check UDP port 443 on source or destination",
            "Inspect first byte bit 7 and increment slot 0 (Long Header) or slot 1 (Short Header)",
            "Always return XDP_PASS",
            "SEC(\"xdp\") and GPL license declaration"
        ],
        "solution_c": t40_sol,
        "tests": t40_tests,
        "main_validator": "map_state"
    })

    # =========================================================================
    # LEVEL 2 (10 Tasks) - Multi-field, histograms, options telemetry
    # =========================================================================

    # 41. syn_pit_l2_001_tcp_options_telemetry
    opt_mss_ws = bytes([2, 4, 0x05, 0xB4, 3, 3, 7]) # MSS + Window Scale
    opt_sack_ts = bytes([4, 2, 8, 10, 1, 2, 3, 4, 5, 6, 7, 8]) # SACK Permitted + Timestamp
    t41_tests = [
        {"name": "tcp_opt_mss_ws_pass", "description": "TCP packet with MSS and WS options updates bitfield telemetry and passes", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(flags=0x02, options=opt_mss_ws))).hex(), "expected_action": "XDP_PASS"},
        {"name": "tcp_opt_sack_ts_pass", "description": "TCP packet with SACK and TS options updates bitfield and passes", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(flags=0x02, options=opt_sack_ts))).hex(), "expected_action": "XDP_PASS"},
        {"name": "tcp_no_options_pass", "description": "TCP packet without options passes", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(flags=0x02))).hex(), "expected_action": "XDP_PASS"},
        {"name": "tcp_ack_pass", "description": "TCP ACK passes", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(flags=0x10))).hex(), "expected_action": "XDP_PASS"},
        {"name": "udp_pass", "description": "UDP packet passes without telemetry", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "arp_pass", "description": "ARP frame passes", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
        {"name": "truncated_tcp_opt_pass", "description": "Truncated TCP options pass safely", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp()[:22])).hex(), "expected_action": "XDP_PASS"},
    ]
    t41_sol = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 4); // 0=MSS, 1=Window Scale, 2=SACK Permitted, 3=Timestamp
} tcp_options_freq_map SEC(".maps");

SEC("xdp")
int xdp_tcp_options_telemetry(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    int ip_len = ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip_len;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    int tcp_hdr_len = tcp->doff * 4;
    if (tcp_hdr_len <= sizeof(struct tcphdr) || (void *)tcp + tcp_hdr_len > data_end)
        return XDP_PASS;

    __u8 *opt = (void *)(tcp + 1);
    __u8 *opt_end = (void *)tcp + tcp_hdr_len;

    #pragma unroll
    for (int i = 0; i < 10; i++) {
        if (opt + 1 > opt_end || opt + 1 > data_end)
            break;

        __u8 kind = *opt;
        if (kind == 0) // End of options
            break;
        if (kind == 1) { // NOP
            opt += 1;
            continue;
        }

        if (opt + 2 > opt_end || opt + 2 > data_end)
            break;
        __u8 len = *(opt + 1);
        if (len < 2)
            break;

        __u32 key = 99;
        if (kind == 2) key = 0;      // MSS
        else if (kind == 3) key = 1; // Window Scale
        else if (kind == 4) key = 2; // SACK Permitted
        else if (kind == 8) key = 3; // Timestamp

        if (key < 4) {
            __u64 *cnt = bpf_map_lookup_elem(&tcp_options_freq_map, &key);
            if (cnt)
                *cnt += 1;
        }

        opt += len;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    tasks.append({
        "task_id": "syn_pit_l2_001_tcp_options_telemetry",
        "application_category": "packet_inspection_telemetry",
        "difficulty": "level_2",
        "task_family": "xdp_telemetry_tcp_options",
        "template_family": "xdp_tcp_options_parser",
        "semantic_signature": "tcp_options_parse+mss_ws_sack_ts_histogram+pass",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that parses variable-length TCP options and records option frequencies in a per-CPU array map named 'tcp_options_freq_map' (max_entries 4). Tally: slot 0 for MSS (Kind 2), slot 1 for Window Scale (Kind 3), slot 2 for SACK Permitted (Kind 4), and slot 3 for Timestamp (Kind 8). Safely iterate through options with explicit bounds checking on every dereference. Always return XDP_PASS.",
        "requirements": [
            "Define per-CPU array map 'tcp_options_freq_map' with max_entries 4",
            "Validate Ethernet, IPv4, TCP headers, and TCP options boundaries",
            "Safely walk TLV TCP options (Kind 0 EOL, Kind 1 NOP, Kind 2 MSS, Kind 3 WS, Kind 4 SACK, Kind 8 TS)",
            "Increment corresponding frequency counter slots without double-counting per option instance",
            "Always return XDP_PASS",
            "SEC(\"xdp\") and GPL license declaration"
        ],
        "solution_c": t41_sol,
        "tests": t41_tests,
        "main_validator": "map_state"
    })

    # Tasks 42 to 50 (Level 2 PIT)
    # 42. syn_pit_l2_002_geneve_opt_class_histogram
    opt_linux = bytes([0x01, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00]) # 0x0100 Linux
    opt_ovs = bytes([0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00])   # 0x0101 OVS
    opt_aws = bytes([0x01, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00])   # 0x0102 AWS
    t42_tests = [
        {"name": "geneve_linux_class_pass", "description": "GENEVE packet with Linux Option Class increments slot 0 and returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=6081, payload=make_geneve(options=opt_linux, inner_frame=make_eth(payload=make_ipv4(proto=1, payload=make_icmp())))))).hex(), "expected_action": "XDP_PASS"},
        {"name": "geneve_ovs_class_pass", "description": "GENEVE packet with OVS Option Class increments slot 1 and returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=6081, payload=make_geneve(options=opt_ovs, inner_frame=make_eth(payload=make_ipv4(proto=1, payload=make_icmp())))))).hex(), "expected_action": "XDP_PASS"},
        {"name": "geneve_aws_class_pass", "description": "GENEVE packet with AWS Option Class increments slot 2 and returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=6081, payload=make_geneve(options=opt_aws, inner_frame=make_eth(payload=make_ipv4(proto=1, payload=make_icmp())))))).hex(), "expected_action": "XDP_PASS"},
        {"name": "geneve_no_opt_pass", "description": "GENEVE packet without options passes without incrementing class map", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=6081, payload=make_geneve(inner_frame=make_eth(payload=make_ipv4(proto=1, payload=make_icmp())))))).hex(), "expected_action": "XDP_PASS"},
        {"name": "non_geneve_udp_pass", "description": "UDP port 6082 passes", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=6082))).hex(), "expected_action": "XDP_PASS"},
        {"name": "tcp_pass", "description": "TCP packet passes", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "truncated_geneve_pass", "description": "Truncated GENEVE packet passes safely", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=6081, payload=b"\x00\x00"))).hex(), "expected_action": "XDP_PASS"},
    ]
    t42_sol = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

struct genevehdr {
    __u8 opt_len:6;
    __u8 ver:2;
    __u8 rsvd1:6;
    __u8 critical:1;
    __u8 oam:1;
    __be16 proto_type;
    __u8 vni[3];
    __u8 reserved2;
};

struct geneve_opt {
    __be16 opt_class;
    __u8 type;
    __u8 flags_length;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 4); // 0=Linux(0x0100), 1=OVS(0x0101), 2=AWS(0x0102), 3=Other
} geneve_class_map SEC(".maps");

SEC("xdp")
int xdp_geneve_class_histogram(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    int ip_len = ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip_len;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;
    if (udp->dest != bpf_htons(6081))
        return XDP_PASS;

    struct genevehdr *gen = (void *)(udp + 1);
    if ((void *)(gen + 1) > data_end)
        return XDP_PASS;

    int opt_bytes = gen->opt_len * 4;
    if (opt_bytes == 0)
        return XDP_PASS;

    void *opts_start = (void *)(gen + 1);
    void *opts_end = opts_start + opt_bytes;
    if (opts_end > data_end)
        return XDP_PASS;

    __u8 *ptr = opts_start;

    #pragma unroll
    for (int i = 0; i < 5; i++) {
        if (ptr + sizeof(struct geneve_opt) > opts_end || ptr + sizeof(struct geneve_opt) > data_end)
            break;

        struct geneve_opt *opt = (void *)ptr;
        __u16 opt_class = bpf_ntohs(opt->opt_class);

        __u32 key = 3;
        if (opt_class == 0x0100) key = 0;
        else if (opt_class == 0x0101) key = 1;
        else if (opt_class == 0x0102) key = 2;

        __u64 *cnt = bpf_map_lookup_elem(&geneve_class_map, &key);
        if (cnt)
            *cnt += 1;

        int len = (opt->flags_length & 0x1F) * 4;
        ptr += sizeof(struct geneve_opt) + len;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    tasks.append({
        "task_id": "syn_pit_l2_002_geneve_opt_class_histogram",
        "application_category": "packet_inspection_telemetry",
        "difficulty": "level_2",
        "task_family": "xdp_telemetry_geneve",
        "template_family": "xdp_geneve_opt_histogram",
        "semantic_signature": "geneve_udp6081+option_class_histogram+pass",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that inspects GENEVE tunnel traffic (UDP port 6081) and tallies Option Class occurrences from TLV options into a per-CPU array map named 'geneve_class_map' (max_entries 4). Record: slot 0 for Linux (0x0100), slot 1 for Open vSwitch (0x0101), slot 2 for AWS (0x0102), and slot 3 for other classes. Safely iterate through options with strict bounds checking. Always return XDP_PASS.",
        "requirements": [
            "Define per-CPU array map 'geneve_class_map' with max_entries 4",
            "Validate Ethernet, IPv4, UDP, and GENEVE header bounds",
            "Safely iterate through GENEVE TLV options",
            "Tally option class frequencies into slots 0..3",
            "Always return XDP_PASS",
            "SEC(\"xdp\") and GPL license declaration"
        ],
        "solution_c": t42_sol,
        "tests": t42_tests,
        "main_validator": "map_state"
    })

    # 43. syn_pit_l2_003_dns_qtype_distribution
    t43_tests = [
        {"name": "dns_a_query_pass", "description": "DNS A query (QTYPE 1) increments slot 0 and returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=53, payload=make_dns(qname="a.com", qtype=1)))).hex(), "expected_action": "XDP_PASS"},
        {"name": "dns_aaaa_query_pass", "description": "DNS AAAA query (QTYPE 28) increments slot 1 and returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=53, payload=make_dns(qname="aaaa.com", qtype=28)))).hex(), "expected_action": "XDP_PASS"},
        {"name": "dns_cname_query_pass", "description": "DNS CNAME query (QTYPE 5) increments slot 2 and returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=53, payload=make_dns(qname="cname.com", qtype=5)))).hex(), "expected_action": "XDP_PASS"},
        {"name": "dns_mx_query_pass", "description": "DNS MX query (QTYPE 15) increments slot 3 and returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=53, payload=make_dns(qname="mx.com", qtype=15)))).hex(), "expected_action": "XDP_PASS"},
        {"name": "dns_txt_query_pass", "description": "DNS TXT query (QTYPE 16) increments slot 4 and returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=53, payload=make_dns(qname="txt.com", qtype=16)))).hex(), "expected_action": "XDP_PASS"},
        {"name": "dns_response_pass", "description": "DNS response passes without incrementing query distribution", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(src_port=53, dst_port=12345, payload=make_dns(qr=1)))).hex(), "expected_action": "XDP_PASS"},
        {"name": "truncated_dns_pass", "description": "Truncated DNS packet passes safely", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=53, payload=b"\x12\x34\x00"))).hex(), "expected_action": "XDP_PASS"},
    ]
    t43_sol = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

struct dnshdr {
    __be16 id;
    __be16 flags;
    __be16 qdcount;
    __be16 ancount;
    __be16 nscount;
    __be16 arcount;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 6); // 0=A(1), 1=AAAA(28), 2=CNAME(5), 3=MX(15), 4=TXT(16), 5=OTHER
} dns_qtype_dist_map SEC(".maps");

SEC("xdp")
int xdp_dns_qtype_dist(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    int ip_len = ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip_len;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;
    if (udp->dest != bpf_htons(53))
        return XDP_PASS;

    struct dnshdr *dns = (void *)(udp + 1);
    if ((void *)(dns + 1) > data_end)
        return XDP_PASS;

    __u16 flags = bpf_ntohs(dns->flags);
    if (flags & 0x8000) // Response -> skip
        return XDP_PASS;

    if (bpf_ntohs(dns->qdcount) < 1)
        return XDP_PASS;

    __u8 *ptr = (void *)(dns + 1);

    #pragma unroll
    for (int i = 0; i < 20; i++) {
        if (ptr + 1 > data_end)
            return XDP_PASS;
        __u8 len = *ptr;
        if (len == 0) {
            ptr += 1;
            break;
        }
        if (len > 63)
            return XDP_PASS;
        ptr += 1 + len;
    }

    if (ptr + 2 > data_end)
        return XDP_PASS;

    __u16 qtype = ((__u16)*ptr << 8) | (__u16)*(ptr + 1);
    __u32 key = 5; // OTHER
    if (qtype == 1) key = 0;       // A
    else if (qtype == 28) key = 1; // AAAA
    else if (qtype == 5) key = 2;  // CNAME
    else if (qtype == 15) key = 3; // MX
    else if (qtype == 16) key = 4; // TXT

    __u64 *cnt = bpf_map_lookup_elem(&dns_qtype_dist_map, &key);
    if (cnt)
        *cnt += 1;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    tasks.append({
        "task_id": "syn_pit_l2_003_dns_qtype_distribution",
        "application_category": "packet_inspection_telemetry",
        "difficulty": "level_2",
        "task_family": "xdp_telemetry_dns",
        "template_family": "xdp_dns_qtype_dist",
        "semantic_signature": "dns_queries_udp53+qtype_histogram+pass",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that inspects DNS query traffic (UDP port 53, QR == 0). Parse the DNS question section to extract the 16-bit QTYPE and record counts into a per-CPU array map named 'dns_qtype_dist_map' (max_entries 6): slot 0 for A (1), slot 1 for AAAA (28), slot 2 for CNAME (5), slot 3 for MX (15), slot 4 for TXT (16), and slot 5 for OTHER query types. Safely walk labels and bounds check. Always return XDP_PASS.",
        "requirements": [
            "Define per-CPU array map 'dns_qtype_dist_map' with max_entries 6",
            "Validate Ethernet, IPv4, UDP, and DNS header bounds",
            "Walk DNS QNAME labels safely and extract 16-bit QTYPE",
            "Increment corresponding slot in dns_qtype_dist_map",
            "Always return XDP_PASS",
            "SEC(\"xdp\") and GPL license declaration"
        ],
        "solution_c": t43_sol,
        "tests": t43_tests,
        "main_validator": "map_state"
    })

    # Add tasks 44 to 50
    # 44. syn_pit_l2_004_vxlan_inner_l3_distribution
    t44_tests = [
        {"name": "vxlan_inner_ipv4_pass", "description": "VXLAN carrying inner IPv4 increments slot 0 and returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=4789, payload=make_vxlan(inner_frame=make_eth(payload=make_ipv4(proto=1, payload=make_icmp())))))).hex(), "expected_action": "XDP_PASS"},
        {"name": "vxlan_inner_ipv6_pass", "description": "VXLAN carrying inner IPv6 increments slot 1 and returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=4789, payload=make_vxlan(inner_frame=make_eth(eth_type=0x86DD, payload=make_ipv6(next_hdr=58, payload=make_icmpv6())))))).hex(), "expected_action": "XDP_PASS"},
        {"name": "vxlan_inner_arp_pass", "description": "VXLAN carrying inner ARP increments slot 2 and returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=4789, payload=make_vxlan(inner_frame=make_eth(eth_type=0x0806, payload=make_arp()))))).hex(), "expected_action": "XDP_PASS"},
        {"name": "vxlan_inner_other_pass", "description": "VXLAN carrying other inner protocol increments slot 3 and returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=4789, payload=make_vxlan(inner_frame=make_eth(eth_type=0x8847, payload=b"\x00"*10))))).hex(), "expected_action": "XDP_PASS"},
        {"name": "non_vxlan_udp_pass", "description": "UDP to port 4790 passes without counting", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=4790))).hex(), "expected_action": "XDP_PASS"},
        {"name": "tcp_pass", "description": "TCP packet passes", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "truncated_vxlan_pass", "description": "Truncated VXLAN frame passes safely", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=4789, payload=b"\x08\x00\x00"))).hex(), "expected_action": "XDP_PASS"},
    ]
    t44_sol = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

struct vxlanhdr {
    __u32 vx_flags;
    __u32 vx_vni;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 4); // 0=IPv4, 1=IPv6, 2=ARP, 3=Other
} vxlan_inner_proto_map SEC(".maps");

SEC("xdp")
int xdp_vxlan_inner_dist(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    int ip_len = ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip_len;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;
    if (udp->dest != bpf_htons(4789))
        return XDP_PASS;

    struct vxlanhdr *vx = (void *)(udp + 1);
    if ((void *)(vx + 1) > data_end)
        return XDP_PASS;

    struct ethhdr *inner_eth = (void *)(vx + 1);
    if ((void *)(inner_eth + 1) > data_end)
        return XDP_PASS;

    __u32 key = 3; // Other
    if (inner_eth->h_proto == bpf_htons(ETH_P_IP))
        key = 0;
    else if (inner_eth->h_proto == bpf_htons(ETH_P_IPV6))
        key = 1;
    else if (inner_eth->h_proto == bpf_htons(ETH_P_ARP))
        key = 2;

    __u64 *cnt = bpf_map_lookup_elem(&vxlan_inner_proto_map, &key);
    if (cnt)
        *cnt += 1;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    tasks.append({
        "task_id": "syn_pit_l2_004_vxlan_inner_l3_distribution",
        "application_category": "packet_inspection_telemetry",
        "difficulty": "level_2",
        "task_family": "xdp_telemetry_vxlan",
        "template_family": "xdp_vxlan_inner_dist",
        "semantic_signature": "vxlan_udp4789+inner_l3_protocol_distribution+pass",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that inspects VXLAN tunnel traffic (UDP port 4789). Parse the outer headers, VXLAN header, and inner Ethernet header. Tally inner EtherType frequencies into a per-CPU array map named 'vxlan_inner_proto_map' (max_entries 4): slot 0 for inner IPv4 (0x0800), slot 1 for inner IPv6 (0x86DD), slot 2 for inner ARP (0x0806), and slot 3 for other protocols. Always return XDP_PASS.",
        "requirements": [
            "Define per-CPU array map 'vxlan_inner_proto_map' with max_entries 4",
            "Validate outer Ethernet, IPv4, UDP, VXLAN, and inner Ethernet header bounds",
            "Extract inner_eth->h_proto and increment slot 0 (IPv4), 1 (IPv6), 2 (ARP), or 3 (Other)",
            "Always return XDP_PASS",
            "SEC(\"xdp\") and GPL license declaration"
        ],
        "solution_c": t44_sol,
        "tests": t44_tests,
        "main_validator": "map_state"
    })

    # 45. syn_pit_l2_005_srv6_segment_left_histogram
    t45_tests = [
        {"name": "srv6_sl_0_pass", "description": "SRv6 packet with Segments Left 0 increments slot 0 and returns XDP_PASS", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(next_hdr=43, payload=make_srv6(segments_left=0, inner_pkt=make_ipv4(proto=1, payload=make_icmp())))).hex(), "expected_action": "XDP_PASS"},
        {"name": "srv6_sl_1_pass", "description": "SRv6 packet with Segments Left 1 increments slot 1 and returns XDP_PASS", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(next_hdr=43, payload=make_srv6(segments_left=1, inner_pkt=make_ipv4(proto=1, payload=make_icmp())))).hex(), "expected_action": "XDP_PASS"},
        {"name": "srv6_sl_2_pass", "description": "SRv6 packet with Segments Left 2 increments slot 2 and returns XDP_PASS", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(next_hdr=43, payload=make_srv6(segments_left=2, inner_pkt=make_ipv4(proto=1, payload=make_icmp())))).hex(), "expected_action": "XDP_PASS"},
        {"name": "srv6_sl_3_pass", "description": "SRv6 packet with Segments Left >= 3 increments slot 3 and returns XDP_PASS", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(next_hdr=43, payload=make_srv6(segments_left=3, inner_pkt=make_ipv4(proto=1, payload=make_icmp())))).hex(), "expected_action": "XDP_PASS"},
        {"name": "standard_ipv6_pass", "description": "Standard IPv6 TCP packet passes without SRv6 counting", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(next_hdr=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "ipv4_pass", "description": "IPv4 packet passes", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "truncated_srv6_pass", "description": "Truncated SRv6 packet passes safely", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(next_hdr=43, payload=b"\x04\x00")).hex(), "expected_action": "XDP_PASS"},
    ]
    t45_sol = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>

struct srv6_hdr {
    __u8 nexthdr;
    __u8 hdr_ext_len;
    __u8 routing_type;
    __u8 segments_left;
    __u8 last_entry;
    __u8 flags;
    __u16 tag;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 4); // 0=SL 0, 1=SL 1, 2=SL 2, 3=SL 3+
} srv6_sl_map SEC(".maps");

SEC("xdp")
int xdp_srv6_sl_histogram(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IPV6))
        return XDP_PASS;

    struct ipv6hdr *ip6 = (void *)(eth + 1);
    if ((void *)(ip6 + 1) > data_end)
        return XDP_PASS;

    // Next Header 43 indicates IPv6 Routing Header
    if (ip6->nexthdr != 43)
        return XDP_PASS;

    struct srv6_hdr *srh = (void *)(ip6 + 1);
    if ((void *)(srh + 1) > data_end)
        return XDP_PASS;

    if (srh->routing_type != 4) // Routing Type 4 = SRH (SRv6)
        return XDP_PASS;

    __u32 key = srh->segments_left;
    if (key > 3)
        key = 3;

    __u64 *cnt = bpf_map_lookup_elem(&srv6_sl_map, &key);
    if (cnt)
        *cnt += 1;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    tasks.append({
        "task_id": "syn_pit_l2_005_srv6_segment_left_histogram",
        "application_category": "packet_inspection_telemetry",
        "difficulty": "level_2",
        "task_family": "xdp_telemetry_srv6",
        "template_family": "xdp_srv6_sl_counter",
        "semantic_signature": "srv6_routing_type_4+segments_left_histogram+pass",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that inspects SRv6 traffic (IPv6 Next Header 43 / Routing Header with Routing Type 4). Parse the 8-byte SRH header and inspect the 8-bit Segments Left field. Record counts in a per-CPU array map named 'srv6_sl_map' (max_entries 4): slot 0 for Segments Left 0, slot 1 for 1, slot 2 for 2, and slot 3 for 3 or more. Always return XDP_PASS.",
        "requirements": [
            "Define per-CPU array map 'srv6_sl_map' with max_entries 4",
            "Validate Ethernet and IPv6 header bounds (eth->h_proto == 0x86DD)",
            "Verify ip6->nexthdr == 43 and srh->routing_type == 4",
            "Classify srh->segments_left into slots 0..3 (capping at slot 3)",
            "Always return XDP_PASS",
            "SEC(\"xdp\") and GPL license declaration"
        ],
        "solution_c": t45_sol,
        "tests": t45_tests,
        "main_validator": "map_state"
    })

    # Tasks 46 to 50 (Level 2 PIT)
    # 46. syn_pit_l2_006_ntp_stratum_telemetry
    t46_tests = [
        {"name": "ntp_stratum1_pass", "description": "NTP Stratum 1 packet increments slot 0 and returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=123, payload=make_ntp(stratum=1)))).hex(), "expected_action": "XDP_PASS"},
        {"name": "ntp_stratum2_pass", "description": "NTP Stratum 2 packet increments slot 1 and returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=123, payload=make_ntp(stratum=2)))).hex(), "expected_action": "XDP_PASS"},
        {"name": "ntp_stratum3_pass", "description": "NTP Stratum 3+ packet increments slot 2 and returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=123, payload=make_ntp(stratum=3)))).hex(), "expected_action": "XDP_PASS"},
        {"name": "ntp_unsynced_pass", "description": "NTP Unsynchronized (Stratum 0 or 16) increments slot 3 and returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=123, payload=make_ntp(stratum=0)))).hex(), "expected_action": "XDP_PASS"},
        {"name": "udp_other_pass", "description": "UDP to port 124 passes without counting", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=124))).hex(), "expected_action": "XDP_PASS"},
        {"name": "tcp_pass", "description": "TCP packet passes", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "truncated_ntp_pass", "description": "Truncated NTP packet passes safely", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=123, payload=b"\x17"))).hex(), "expected_action": "XDP_PASS"},
    ]
    t46_sol = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 4); // 0=Stratum 1, 1=Stratum 2, 2=Stratum 3-15, 3=Unsynchronized(0 or >=16)
} ntp_stratum_map SEC(".maps");

SEC("xdp")
int xdp_ntp_stratum_telemetry(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    int ip_len = ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip_len;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;
    if (udp->dest != bpf_htons(123) && udp->source != bpf_htons(123))
        return XDP_PASS;

    __u8 *ntp = (void *)(udp + 1);
    if (ntp + 2 > data_end)
        return XDP_PASS;

    __u8 stratum = *(ntp + 1);
    __u32 key = 3; // Unsynchronized (0 or >= 16)
    if (stratum == 1) key = 0;
    else if (stratum == 2) key = 1;
    else if (stratum >= 3 && stratum <= 15) key = 2;

    __u64 *cnt = bpf_map_lookup_elem(&ntp_stratum_map, &key);
    if (cnt)
        *cnt += 1;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    tasks.append({
        "task_id": "syn_pit_l2_006_ntp_stratum_telemetry",
        "application_category": "packet_inspection_telemetry",
        "difficulty": "level_2",
        "task_family": "xdp_telemetry_ntp",
        "template_family": "xdp_ntp_stratum_counter",
        "semantic_signature": "ntp_udp123+stratum_histogram+pass",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that inspects NTP traffic (UDP port 123) and classifies packet stratum into a per-CPU array map named 'ntp_stratum_map' (max_entries 4): slot 0 for Stratum 1 (Primary Reference), slot 1 for Stratum 2 (Secondary Reference), slot 2 for Stratum 3-15 (Downstream servers), and slot 3 for Unsynchronized / reserved (Stratum 0 or >= 16). Always return XDP_PASS.",
        "requirements": [
            "Define per-CPU array map 'ntp_stratum_map' with max_entries 4",
            "Validate Ethernet, IPv4, UDP, and NTP header bounds",
            "Inspect Stratum field at byte offset 1 of NTP payload",
            "Increment corresponding histogram slot",
            "Always return XDP_PASS",
            "SEC(\"xdp\") and GPL license declaration"
        ],
        "solution_c": t46_sol,
        "tests": t46_tests,
        "main_validator": "map_state"
    })

    # 47. syn_pit_l2_007_icmpv6_nd_telemetry
    t47_tests = [
        {"name": "icmp6_rs_pass", "description": "Router Solicitation (Type 133) increments slot 0 and returns XDP_PASS", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(next_hdr=58, payload=make_icmpv6(icmp_type=133))).hex(), "expected_action": "XDP_PASS"},
        {"name": "icmp6_ra_pass", "description": "Router Advertisement (Type 134) increments slot 1 and returns XDP_PASS", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(next_hdr=58, payload=make_icmpv6(icmp_type=134))).hex(), "expected_action": "XDP_PASS"},
        {"name": "icmp6_ns_pass", "description": "Neighbor Solicitation (Type 135) increments slot 2 and returns XDP_PASS", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(next_hdr=58, payload=make_icmpv6(icmp_type=135))).hex(), "expected_action": "XDP_PASS"},
        {"name": "icmp6_na_pass", "description": "Neighbor Advertisement (Type 136) increments slot 3 and returns XDP_PASS", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(next_hdr=58, payload=make_icmpv6(icmp_type=136))).hex(), "expected_action": "XDP_PASS"},
        {"name": "icmp6_echo_pass", "description": "ICMPv6 Echo Request (Type 128) passes without incrementing ND map", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(next_hdr=58, payload=make_icmpv6(icmp_type=128))).hex(), "expected_action": "XDP_PASS"},
        {"name": "ipv4_pass", "description": "IPv4 traffic passes", "packet_hex": make_eth(payload=make_ipv4(proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "truncated_icmp6_pass", "description": "Truncated ICMPv6 packet passes safely", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(next_hdr=58, payload=b"\x85")).hex(), "expected_action": "XDP_PASS"},
    ]
    t47_sol = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 4); // 0=RS(133), 1=RA(134), 2=NS(135), 3=NA(136)
} nd_telemetry_map SEC(".maps");

SEC("xdp")
int xdp_nd_telemetry(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IPV6))
        return XDP_PASS;

    struct ipv6hdr *ip6 = (void *)(eth + 1);
    if ((void *)(ip6 + 1) > data_end)
        return XDP_PASS;
    if (ip6->nexthdr != IPPROTO_ICMPV6)
        return XDP_PASS;

    struct icmp6hdr *icmp6 = (void *)(ip6 + 1);
    if ((void *)(icmp6 + 1) > data_end)
        return XDP_PASS;

    __u8 type = icmp6->icmp6_type;
    if (type >= 133 && type <= 136) {
        __u32 key = type - 133;
        __u64 *cnt = bpf_map_lookup_elem(&nd_telemetry_map, &key);
        if (cnt)
            *cnt += 1;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    tasks.append({
        "task_id": "syn_pit_l2_007_icmpv6_nd_telemetry",
        "application_category": "packet_inspection_telemetry",
        "difficulty": "level_2",
        "task_family": "xdp_telemetry_icmpv6",
        "template_family": "xdp_nd_message_counter",
        "semantic_signature": "icmpv6_nd_types_133_to_136+histogram+pass",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that inspects IPv6 ICMPv6 Neighbor Discovery traffic (Next Header 58). Parse struct icmp6hdr and record counts in a per-CPU array map named 'nd_telemetry_map' (max_entries 4): slot 0 for Router Solicitation (133), slot 1 for Router Advertisement (134), slot 2 for Neighbor Solicitation (135), and slot 3 for Neighbor Advertisement (136). Always return XDP_PASS.",
        "requirements": [
            "Define per-CPU array map 'nd_telemetry_map' with max_entries 4",
            "Validate Ethernet, IPv6, and struct icmp6hdr bounds",
            "Check icmp6_type in range 133..136 and increment slot (type - 133)",
            "Always return XDP_PASS",
            "SEC(\"xdp\") and GPL license declaration"
        ],
        "solution_c": t47_sol,
        "tests": t47_tests,
        "main_validator": "map_state"
    })

    # 48. syn_pit_l2_008_ip_in_ip_depth_telemetry
    t48_tests = [
        {"name": "single_ipinip_pass", "description": "Single IP-in-IP tunnel increments slot 0 and returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(src_ip="203.0.113.1", dst_ip="198.51.100.1", proto=4, payload=make_ipv4(proto=6, payload=make_tcp()))).hex(), "expected_action": "XDP_PASS"},
        {"name": "double_ipinip_pass", "description": "Double nested IP-in-IP tunnel increments slot 1 and returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(src_ip="203.0.113.1", dst_ip="198.51.100.1", proto=4, payload=make_ipv4(proto=4, payload=make_ipv4(proto=6, payload=make_tcp())))).hex(), "expected_action": "XDP_PASS"},
        {"name": "direct_ip_pass", "description": "Direct non-tunneled IP packet passes without counting", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "udp_pass", "description": "UDP packet passes", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "arp_pass", "description": "ARP frame passes", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
        {"name": "ipv6_pass", "description": "IPv6 frame passes", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(next_hdr=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "truncated_ipinip_pass", "description": "Truncated IP-in-IP packet passes safely", "packet_hex": make_eth(payload=make_ipv4(proto=4, payload=b"\x45\x00")).hex(), "expected_action": "XDP_PASS"},
    ]
    t48_sol = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 2); // 0=Single encapsulation, 1=Double nested encapsulation
} ipinip_depth_map SEC(".maps");

SEC("xdp")
int xdp_ipinip_depth_telemetry(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip1 = (void *)(eth + 1);
    if ((void *)(ip1 + 1) > data_end)
        return XDP_PASS;
    if (ip1->protocol != 4) // Not IP-in-IP
        return XDP_PASS;

    int ip1_len = ip1->ihl * 4;
    if (ip1_len < sizeof(struct iphdr) || (void *)ip1 + ip1_len > data_end)
        return XDP_PASS;

    struct iphdr *ip2 = (void *)ip1 + ip1_len;
    if ((void *)(ip2 + 1) > data_end)
        return XDP_PASS;

    __u32 key = 0; // Single encapsulation by default
    if (ip2->protocol == 4) { // Nested second encapsulation
        key = 1;
    }

    __u64 *cnt = bpf_map_lookup_elem(&ipinip_depth_map, &key);
    if (cnt)
        *cnt += 1;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    tasks.append({
        "task_id": "syn_pit_l2_008_ip_in_ip_depth_telemetry",
        "application_category": "packet_inspection_telemetry",
        "difficulty": "level_2",
        "task_family": "xdp_telemetry_ipinip",
        "template_family": "xdp_ipinip_depth_counter",
        "semantic_signature": "ipinip_proto4+nesting_depth_counter+pass",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that inspects IP-in-IP tunnel traffic (outer protocol 4). Parse the inner IPv4 header. If the inner IPv4 packet encapsulates another protocol (inner protocol != 4), increment slot 0 (Single encapsulation). If the inner IPv4 packet is itself another IP-in-IP tunnel (inner protocol == 4), increment slot 1 (Double nested encapsulation) in a per-CPU array map named 'ipinip_depth_map' (max_entries 2). Always return XDP_PASS.",
        "requirements": [
            "Define per-CPU array map 'ipinip_depth_map' with max_entries 2",
            "Validate Ethernet and outer IPv4 header bounds",
            "Validate inner IPv4 header bounds (accounting for variable outer IHL)",
            "Check inner protocol: slot 0 for single encap, slot 1 for double encap",
            "Always return XDP_PASS",
            "SEC(\"xdp\") and GPL license declaration"
        ],
        "solution_c": t48_sol,
        "tests": t48_tests,
        "main_validator": "map_state"
    })

    # 49. syn_pit_l2_009_tcp_mss_range_histogram
    t49_tests = [
        {"name": "mss_bucket0_pass", "description": "TCP SYN with MSS 1000 (<1200) increments slot 0 and returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(flags=0x02, options=bytes([2, 4, 0x03, 0xE8])))).hex(), "expected_action": "XDP_PASS"},
        {"name": "mss_bucket1_pass", "description": "TCP SYN with MSS 1300 (1200-1400) increments slot 1 and returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(flags=0x02, options=bytes([2, 4, 0x05, 0x14])))).hex(), "expected_action": "XDP_PASS"},
        {"name": "mss_bucket2_pass", "description": "TCP SYN with MSS 1460 (1401-1460) increments slot 2 and returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(flags=0x02, options=bytes([2, 4, 0x05, 0xB4])))).hex(), "expected_action": "XDP_PASS"},
        {"name": "mss_bucket3_pass", "description": "TCP SYN with MSS 1500 (>1460) increments slot 3 and returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(flags=0x02, options=bytes([2, 4, 0x05, 0xDC])))).hex(), "expected_action": "XDP_PASS"},
        {"name": "syn_no_mss_pass", "description": "TCP SYN without MSS option passes without counting", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(flags=0x02))).hex(), "expected_action": "XDP_PASS"},
        {"name": "ack_pass", "description": "TCP ACK passes", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(flags=0x10))).hex(), "expected_action": "XDP_PASS"},
        {"name": "truncated_tcp_pass", "description": "Truncated TCP packet passes safely", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=b"\x00\x50")).hex(), "expected_action": "XDP_PASS"},
    ]
    t49_sol = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 4); // 0: <1200, 1: 1200-1400, 2: 1401-1460, 3: >1460
} mss_histogram_map SEC(".maps");

SEC("xdp")
int xdp_tcp_mss_histogram(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    int ip_len = ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip_len;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    if (!tcp->syn)
        return XDP_PASS;

    int tcp_hdr_len = tcp->doff * 4;
    if (tcp_hdr_len <= sizeof(struct tcphdr) || (void *)tcp + tcp_hdr_len > data_end)
        return XDP_PASS;

    __u8 *opt = (void *)(tcp + 1);
    __u8 *opt_end = (void *)tcp + tcp_hdr_len;

    #pragma unroll
    for (int i = 0; i < 10; i++) {
        if (opt + 1 > opt_end || opt + 1 > data_end)
            break;

        __u8 kind = *opt;
        if (kind == 0) break;
        if (kind == 1) { opt += 1; continue; }

        if (opt + 2 > opt_end || opt + 2 > data_end)
            break;
        __u8 len = *(opt + 1);
        if (len < 2) break;

        if (kind == 2 && len == 4) { // MSS
            if (opt + 4 > opt_end || opt + 4 > data_end)
                break;
            __u16 mss = ((__u16)*(opt + 2) << 8) | (__u16)*(opt + 3);
            __u32 key = 0;
            if (mss < 1200) key = 0;
            else if (mss <= 1400) key = 1;
            else if (mss <= 1460) key = 2;
            else key = 3;

            __u64 *cnt = bpf_map_lookup_elem(&mss_histogram_map, &key);
            if (cnt)
                *cnt += 1;
            break;
        }

        opt += len;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    tasks.append({
        "task_id": "syn_pit_l2_009_tcp_mss_range_histogram",
        "application_category": "packet_inspection_telemetry",
        "difficulty": "level_2",
        "task_family": "xdp_telemetry_tcp",
        "template_family": "xdp_tcp_mss_histogram",
        "semantic_signature": "tcp_syn+mss_value_histogram_4_buckets+pass",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that inspects TCP SYN packets, parses the TCP options to locate the MSS option (Kind 2, Length 4), and places the MSS value into one of four deterministic histogram buckets in a per-CPU array map named 'mss_histogram_map' (max_entries 4): slot 0 for MSS < 1200, slot 1 for 1200 <= MSS <= 1400, slot 2 for 1401 <= MSS <= 1460, and slot 3 for MSS > 1460. Always return XDP_PASS.",
        "requirements": [
            "Define per-CPU array map 'mss_histogram_map' with max_entries 4",
            "Validate Ethernet, IPv4, TCP headers, and TCP options bounds",
            "Filter only TCP SYN packets (tcp->syn == 1)",
            "Parse MSS option and record count in range bucket",
            "Always return XDP_PASS",
            "SEC(\"xdp\") and GPL license declaration"
        ],
        "solution_c": t49_sol,
        "tests": t49_tests,
        "main_validator": "map_state"
    })

    # 50. syn_pit_l2_010_gre_flags_telemetry
    t50_tests = [
        {"name": "gre_key_flag_pass", "description": "GRE with Key flag increments slot 0 and returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=47, payload=make_gre(k_bit=True, key=100, inner_pkt=make_ipv4(proto=1, payload=make_icmp())))).hex(), "expected_action": "XDP_PASS"},
        {"name": "gre_seq_flag_pass", "description": "GRE with Seq flag increments slot 1 and returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=47, payload=make_gre(s_bit=True, seq=1, inner_pkt=make_ipv4(proto=1, payload=make_icmp())))).hex(), "expected_action": "XDP_PASS"},
        {"name": "gre_csum_flag_pass", "description": "GRE with Checksum flag increments slot 2 and returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=47, payload=make_gre(c_bit=True, inner_pkt=make_ipv4(proto=1, payload=make_icmp())))).hex(), "expected_action": "XDP_PASS"},
        {"name": "gre_no_flags_pass", "description": "GRE without optional flags passes without counting", "packet_hex": make_eth(payload=make_ipv4(proto=47, payload=make_gre(inner_pkt=make_ipv4(proto=1, payload=make_icmp())))).hex(), "expected_action": "XDP_PASS"},
        {"name": "udp_pass", "description": "UDP packet passes", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "tcp_pass", "description": "TCP packet passes", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "truncated_gre_pass", "description": "Truncated GRE packet passes safely", "packet_hex": make_eth(payload=make_ipv4(proto=47, payload=b"\x00")).hex(), "expected_action": "XDP_PASS"},
    ]
    t50_sol = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

struct grehdr {
    __be16 flags;
    __be16 proto;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 3); // 0=Key (0x2000), 1=Seq (0x1000), 2=Checksum (0x8000)
} gre_flags_freq_map SEC(".maps");

SEC("xdp")
int xdp_gre_flags_telemetry(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->protocol != 47) // IPPROTO_GRE
        return XDP_PASS;

    int ip_len = ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct grehdr *gre = (void *)ip + ip_len;
    if ((void *)(gre + 1) > data_end)
        return XDP_PASS;

    __u16 flags = bpf_ntohs(gre->flags);

    if (flags & 0x2000) { // Key present
        __u32 key = 0;
        __u64 *cnt = bpf_map_lookup_elem(&gre_flags_freq_map, &key);
        if (cnt) *cnt += 1;
    }
    if (flags & 0x1000) { // Sequence present
        __u32 key = 1;
        __u64 *cnt = bpf_map_lookup_elem(&gre_flags_freq_map, &key);
        if (cnt) *cnt += 1;
    }
    if (flags & 0x8000) { // Checksum present
        __u32 key = 2;
        __u64 *cnt = bpf_map_lookup_elem(&gre_flags_freq_map, &key);
        if (cnt) *cnt += 1;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    tasks.append({
        "task_id": "syn_pit_l2_010_gre_flags_telemetry",
        "application_category": "packet_inspection_telemetry",
        "difficulty": "level_2",
        "task_family": "xdp_telemetry_gre",
        "template_family": "xdp_gre_flags_counter",
        "semantic_signature": "gre_proto47+key_seq_csum_flags_telemetry+pass",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that inspects GRE packets (IP protocol 47) and tracks the presence of optional GRE header flags in a per-CPU array map named 'gre_flags_freq_map' (max_entries 3). Increment slot 0 if Key bit (0x2000) is set, slot 1 if Sequence bit (0x1000) is set, and slot 2 if Checksum bit (0x8000) is set. Always return XDP_PASS.",
        "requirements": [
            "Define per-CPU array map 'gre_flags_freq_map' with max_entries 3",
            "Validate Ethernet, IPv4, and struct grehdr bounds",
            "Inspect flags word and independently increment slots 0 (Key), 1 (Seq), and 2 (Checksum)",
            "Always return XDP_PASS",
            "SEC(\"xdp\") and GPL license declaration"
        ],
        "solution_c": t50_sol,
        "tests": t50_tests,
        "main_validator": "map_state"
    })

    # =========================================================================
    # LEVEL 3 (10 Tasks) - Stateful Sketches, Heavy Hitters, Latency Tracking
    # =========================================================================

    # 51. syn_pit_l3_001_count_min_sketch_heavy_hitters
    t51_tests = [
        {"name": "flow1_pkt1_pass", "description": "Flow 1 updates Count-Min Sketch matrix and passes", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.10", dst_ip="192.168.1.20", proto=6, payload=make_tcp(src_port=10001, dst_port=80))).hex(), "expected_action": "XDP_PASS"},
        {"name": "flow1_pkt2_pass", "description": "Flow 1 packet 2 updates sketch", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.10", dst_ip="192.168.1.20", proto=6, payload=make_tcp(src_port=10001, dst_port=80))).hex(), "expected_action": "XDP_PASS"},
        {"name": "flow2_pkt1_pass", "description": "Flow 2 updates sketch matrix", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.30", dst_ip="192.168.1.40", proto=6, payload=make_tcp(src_port=20002, dst_port=443))).hex(), "expected_action": "XDP_PASS"},
        {"name": "flow3_udp_pass", "description": "Flow 3 UDP updates sketch matrix", "packet_hex": make_eth(payload=make_ipv4(src_ip="10.0.0.1", dst_ip="10.0.0.2", proto=17, payload=make_udp(src_port=30003, dst_port=53))).hex(), "expected_action": "XDP_PASS"},
        {"name": "icmp_pass", "description": "ICMP packet passes without sketch update", "packet_hex": make_eth(payload=make_ipv4(proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "arp_pass", "description": "ARP frame passes", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
        {"name": "ipv6_pass", "description": "IPv6 frame passes", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(next_hdr=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "truncated_tcp_pass", "description": "Truncated TCP packet passes safely", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=b"\x00\x50")).hex(), "expected_action": "XDP_PASS"},
        {"name": "truncated_ip_pass", "description": "Truncated IPv4 packet passes safely", "packet_hex": make_eth(payload=b"\x45\x00").hex(), "expected_action": "XDP_PASS"},
    ]
    t51_sol = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#define CMS_ROWS 4
#define CMS_COLS 256
#define CMS_TOTAL (CMS_ROWS * CMS_COLS)

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, CMS_TOTAL);
} cms_sketch_map SEC(".maps");

static __always_inline __u32 hash_row(__u32 fhash, int row) {
    __u32 h = fhash ^ (row * 0x9e3779b9);
    h = ((h >> 16) ^ h) * 0x45d9f3b;
    h = ((h >> 16) ^ h) * 0x45d9f3b;
    h = (h >> 16) ^ h;
    return (row * CMS_COLS) + (h % CMS_COLS);
}

SEC("xdp")
int xdp_cms_heavy_hitters(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    int ip_len = ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    __u16 src_port = 0, dst_port = 0;
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + ip_len;
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        src_port = tcp->source;
        dst_port = tcp->dest;
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + ip_len;
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        src_port = udp->source;
        dst_port = udp->dest;
    } else {
        return XDP_PASS;
    }

    __u32 flow_hash = ip->saddr ^ ip->daddr ^ ((__u32)src_port << 16 | dst_port) ^ ip->protocol;

    #pragma unroll
    for (int r = 0; r < CMS_ROWS; r++) {
        __u32 idx = hash_row(flow_hash, r);
        __u64 *cnt = bpf_map_lookup_elem(&cms_sketch_map, &idx);
        if (cnt)
            *cnt += 1;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    tasks.append({
        "task_id": "syn_pit_l3_001_count_min_sketch_heavy_hitters",
        "application_category": "packet_inspection_telemetry",
        "difficulty": "level_3",
        "task_family": "xdp_telemetry_sketch",
        "template_family": "xdp_count_min_sketch",
        "semantic_signature": "ipv4_5tuple+count_min_sketch_4x256+pass",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that implements a 4-row by 256-column Count-Min Sketch (1024 cells total) in a per-CPU array map named 'cms_sketch_map' (max_entries 1024). For every IPv4 TCP or UDP packet, extract the 5-tuple and compute a flow hash. Using 4 distinct row hash functions, increment the corresponding cell in each row (row * 256 + hash_r % 256). Always return XDP_PASS.",
        "requirements": [
            "Define per-CPU array map 'cms_sketch_map' with max_entries 1024 (4 rows * 256 columns)",
            "Extract 5-tuple for TCP and UDP packets",
            "Compute 4 independent hash positions across sketch rows",
            "Increment sketch counter in each row",
            "Always return XDP_PASS",
            "SEC(\"xdp\") and GPL license declaration"
        ],
        "solution_c": t51_sol,
        "tests": t51_tests,
        "main_validator": "map_state"
    })

    # Tasks 52 to 60 (Level 3 PIT)
    # 52. syn_pit_l3_002_tcp_rtt_syn_ack_tracker
    t52_tests = [
        {"name": "syn_recorded_pass", "description": "SYN packet records initial timestamp and returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.10", dst_ip="192.168.1.20", proto=6, payload=make_tcp(src_port=10001, dst_port=80, flags=0x02))).hex(), "expected_action": "XDP_PASS"},
        {"name": "syn_ack_rtt_pass", "description": "Matching SYN-ACK computes RTT delta and returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.20", dst_ip="192.168.1.10", proto=6, payload=make_tcp(src_port=80, dst_port=10001, flags=0x12))).hex(), "expected_action": "XDP_PASS"},
        {"name": "ack_pass", "description": "Established ACK passes", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.10", dst_ip="192.168.1.20", proto=6, payload=make_tcp(src_port=10001, dst_port=80, flags=0x10))).hex(), "expected_action": "XDP_PASS"},
        {"name": "unmatched_syn_ack_pass", "description": "Unmatched SYN-ACK passes safely", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.99", dst_ip="192.168.1.10", proto=6, payload=make_tcp(src_port=80, dst_port=20002, flags=0x12))).hex(), "expected_action": "XDP_PASS"},
        {"name": "udp_pass", "description": "UDP packet passes", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "icmp_pass", "description": "ICMP packet passes", "packet_hex": make_eth(payload=make_ipv4(proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "arp_pass", "description": "ARP frame passes", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
        {"name": "ipv6_pass", "description": "IPv6 frame passes", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(next_hdr=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "truncated_tcp_pass", "description": "Truncated TCP packet passes safely", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=b"\x00\x50")).hex(), "expected_action": "XDP_PASS"},
    ]
    t52_sol = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

struct flow_key {
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct flow_key);
    __type(value, __u64); // timestamp ns
    __uint(max_entries, 1024);
} syn_ts_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 4); // 0: <1ms, 1: 1-10ms, 2: 10-100ms, 3: >100ms
} rtt_histogram_map SEC(".maps");

SEC("xdp")
int xdp_tcp_rtt_tracker(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    int ip_len = ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip_len;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    __u64 now = bpf_ktime_get_ns();

    if (tcp->syn && !tcp->ack) {
        struct flow_key fwd = {
            .src_ip = ip->saddr,
            .dst_ip = ip->daddr,
            .src_port = tcp->source,
            .dst_port = tcp->dest,
        };
        bpf_map_update_elem(&syn_ts_map, &fwd, &now, BPF_ANY);
        return XDP_PASS;
    }

    if (tcp->syn && tcp->ack) {
        struct flow_key rev = {
            .src_ip = ip->daddr,
            .dst_ip = ip->saddr,
            .src_port = tcp->dest,
            .dst_port = tcp->source,
        };
        __u64 *syn_time = bpf_map_lookup_elem(&syn_ts_map, &rev);
        if (syn_time) {
            __u64 rtt_ns = now > *syn_time ? (now - *syn_time) : 0;
            __u32 key = 0;
            if (rtt_ns < 1000000ULL) key = 0;         // < 1ms
            else if (rtt_ns < 10000000ULL) key = 1;   // 1-10ms
            else if (rtt_ns < 100000000ULL) key = 2;  // 10-100ms
            else key = 3;                             // > 100ms

            __u64 *cnt = bpf_map_lookup_elem(&rtt_histogram_map, &key);
            if (cnt)
                *cnt += 1;
            bpf_map_delete_elem(&syn_ts_map, &rev);
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    tasks.append({
        "task_id": "syn_pit_l3_002_tcp_rtt_syn_ack_tracker",
        "application_category": "packet_inspection_telemetry",
        "difficulty": "level_3",
        "task_family": "xdp_telemetry_rtt",
        "template_family": "xdp_tcp_rtt_histogram",
        "semantic_signature": "tcp_syn_ack_rtt+histogram_buckets+pass",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that measures TCP round-trip handshake latency (SYN to SYN-ACK RTT). On seeing a SYN packet, record the timestamp from bpf_ktime_get_ns() in a BPF hash map named 'syn_ts_map' (key struct flow_key, value __u64 timestamp, max_entries 1024). On seeing the corresponding SYN-ACK response, compute the RTT delta (now - syn_time) and record into a per-CPU array map named 'rtt_histogram_map' (max_entries 4): slot 0 for RTT < 1ms, slot 1 for 1-10ms, slot 2 for 10-100ms, and slot 3 for > 100ms. Delete the flow entry and return XDP_PASS.",
        "requirements": [
            "Define struct flow_key with 4-tuple endpoints",
            "Define hash map 'syn_ts_map' with max_entries 1024",
            "Define per-CPU array map 'rtt_histogram_map' with max_entries 4",
            "Record SYN timestamp and match against reverse SYN-ACK",
            "Bucket latency delta into microsecond/millisecond ranges",
            "Always return XDP_PASS",
            "SEC(\"xdp\") and GPL license declaration"
        ],
        "solution_c": t52_sol,
        "tests": t52_tests,
        "main_validator": "map_state"
    })

    # 53. syn_pit_l3_003_vxlan_flow_matrix
    t53_tests = [
        {"name": "vxlan_flow1_pass", "description": "VXLAN inner flow 1 recorded in flow matrix and passes", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=4789, payload=make_vxlan(vni=100, inner_frame=make_eth(payload=make_ipv4(src_ip="10.0.1.10", dst_ip="10.0.1.20", proto=6, payload=make_tcp(src_port=10001, dst_port=80))))))).hex(), "expected_action": "XDP_PASS"},
        {"name": "vxlan_flow1_pkt2_pass", "description": "Second packet of flow 1 increments packets/bytes", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=4789, payload=make_vxlan(vni=100, inner_frame=make_eth(payload=make_ipv4(src_ip="10.0.1.10", dst_ip="10.0.1.20", proto=6, payload=make_tcp(src_port=10001, dst_port=80))))))).hex(), "expected_action": "XDP_PASS"},
        {"name": "vxlan_flow2_vni200_pass", "description": "Flow with different VNI (200) creates distinct flow entry", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=4789, payload=make_vxlan(vni=200, inner_frame=make_eth(payload=make_ipv4(src_ip="10.0.1.10", dst_ip="10.0.1.20", proto=6, payload=make_tcp(src_port=10001, dst_port=80))))))).hex(), "expected_action": "XDP_PASS"},
        {"name": "vxlan_inner_udp_pass", "description": "VXLAN inner UDP flow recorded", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=4789, payload=make_vxlan(vni=100, inner_frame=make_eth(payload=make_ipv4(src_ip="10.0.2.1", dst_ip="10.0.2.2", proto=17, payload=make_udp(src_port=5000, dst_port=5000))))))).hex(), "expected_action": "XDP_PASS"},
        {"name": "non_vxlan_udp_pass", "description": "Non-VXLAN UDP passes", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=4790))).hex(), "expected_action": "XDP_PASS"},
        {"name": "direct_tcp_pass", "description": "Direct TCP passes", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "arp_pass", "description": "ARP frame passes", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
        {"name": "ipv6_pass", "description": "IPv6 frame passes", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(next_hdr=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "truncated_vxlan_pass", "description": "Truncated VXLAN frame passes safely", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=4789, payload=b"\x08\x00"))).hex(), "expected_action": "XDP_PASS"},
    ]
    t53_sol = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>

struct vxlan_flow_key {
    __u32 vni;
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    __u8 proto;
    __u8 pad[3];
};

struct flow_stats {
    __u64 pkts;
    __u64 bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct vxlan_flow_key);
    __type(value, struct flow_stats);
    __uint(max_entries, 2048);
} vxlan_matrix_map SEC(".maps");

SEC("xdp")
int xdp_vxlan_flow_matrix(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    int ip_len = ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip_len;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;
    if (udp->dest != bpf_htons(4789))
        return XDP_PASS;

    __u32 *vx = (void *)(udp + 1);
    if ((void *)(vx + 2) > data_end)
        return XDP_PASS;

    __u32 vni = bpf_ntohl(*(vx + 1)) >> 8;

    struct ethhdr *inner_eth = (void *)(vx + 2);
    if ((void *)(inner_eth + 1) > data_end)
        return XDP_PASS;
    if (inner_eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *inner_ip = (void *)(inner_eth + 1);
    if ((void *)(inner_ip + 1) > data_end)
        return XDP_PASS;

    int inner_ip_len = inner_ip->ihl * 4;
    if (inner_ip_len < sizeof(struct iphdr) || (void *)inner_ip + inner_ip_len > data_end)
        return XDP_PASS;

    __be16 sport = 0, dport = 0;
    if (inner_ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)inner_ip + inner_ip_len;
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        sport = tcp->source;
        dport = tcp->dest;
    } else if (inner_ip->protocol == IPPROTO_UDP) {
        struct udphdr *inner_udp = (void *)inner_ip + inner_ip_len;
        if ((void *)(inner_udp + 1) > data_end)
            return XDP_PASS;
        sport = inner_udp->source;
        dport = inner_udp->dest;
    } else {
        return XDP_PASS;
    }

    struct vxlan_flow_key key = {
        .vni = vni,
        .src_ip = inner_ip->saddr,
        .dst_ip = inner_ip->daddr,
        .src_port = sport,
        .dst_port = dport,
        .proto = inner_ip->protocol,
        .pad = {0, 0, 0},
    };

    __u64 pkt_len = (__u64)((void *)data_end - (void *)data);
    struct flow_stats *st = bpf_map_lookup_elem(&vxlan_matrix_map, &key);
    if (!st) {
        struct flow_stats new_st = { .pkts = 1, .bytes = pkt_len };
        bpf_map_update_elem(&vxlan_matrix_map, &key, &new_st, BPF_ANY);
    } else {
        st->pkts += 1;
        st->bytes += pkt_len;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    tasks.append({
        "task_id": "syn_pit_l3_003_vxlan_flow_matrix",
        "application_category": "packet_inspection_telemetry",
        "difficulty": "level_3",
        "task_family": "xdp_telemetry_vxlan_matrix",
        "template_family": "xdp_vxlan_flow_tracker",
        "semantic_signature": "vxlan_vni+inner_5tuple_flow_matrix+pass",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that maintains a multi-tenant flow statistics matrix for VXLAN traffic. Parse VXLAN encapsulated packets (UDP port 4789), extract the 24-bit VNI, and parse the inner IPv4 TCP/UDP 5-tuple. Maintain total packet and wire byte counts in a BPF hash map named 'vxlan_matrix_map' (key struct vxlan_flow_key { __u32 vni; __be32 src_ip, dst_ip; __be16 src_port, dst_port; __u8 proto; }, value struct flow_stats { __u64 pkts; __u64 bytes; }, max_entries 2048). Always return XDP_PASS.",
        "requirements": [
            "Define struct vxlan_flow_key and struct flow_stats",
            "Define hash map 'vxlan_matrix_map' with max_entries 2048",
            "Parse outer headers, VXLAN VNI, and inner Ethernet/IPv4/L4 headers",
            "Accumulate packets and byte volume per inner flow key",
            "Always return XDP_PASS",
            "SEC(\"xdp\") and GPL license declaration"
        ],
        "solution_c": t53_sol,
        "tests": t53_tests,
        "main_validator": "map_state"
    })

    # Tasks 54 to 60 (Level 3 PIT)
    # 54. syn_pit_l3_004_dns_domain_freq_tracker
    t54_tests = [
        {"name": "domain_a_pass", "description": "DNS query for domain a.com updates domain hash frequency and passes", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=53, payload=make_dns(qname="a.com")))).hex(), "expected_action": "XDP_PASS"},
        {"name": "domain_a_pkt2_pass", "description": "Second query for same domain increments count", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=53, payload=make_dns(qname="a.com")))).hex(), "expected_action": "XDP_PASS"},
        {"name": "domain_b_pass", "description": "Query for different domain b.com creates new entry", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=53, payload=make_dns(qname="b.com")))).hex(), "expected_action": "XDP_PASS"},
        {"name": "dns_response_pass", "description": "DNS response passes without tracking", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(src_port=53, dst_port=12345, payload=make_dns(qr=1)))).hex(), "expected_action": "XDP_PASS"},
        {"name": "non_dns_udp_pass", "description": "UDP to port 5353 passes", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=5353))).hex(), "expected_action": "XDP_PASS"},
        {"name": "tcp_pass", "description": "TCP packet passes", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "icmp_pass", "description": "ICMP packet passes", "packet_hex": make_eth(payload=make_ipv4(proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "arp_pass", "description": "ARP frame passes", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
        {"name": "truncated_dns_pass", "description": "Truncated DNS packet passes safely", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=53, payload=b"\x12\x34\x00"))).hex(), "expected_action": "XDP_PASS"},
    ]
    t54_sol = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

struct domain_stat {
    __u64 query_count;
    __u64 total_bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32); // Domain hash
    __type(value, struct domain_stat);
    __uint(max_entries, 1024);
} domain_freq_map SEC(".maps");

SEC("xdp")
int xdp_dns_domain_tracker(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    int ip_len = ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip_len;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;
    if (udp->dest != bpf_htons(53))
        return XDP_PASS;

    void *dns_start = (void *)(udp + 1);
    if (dns_start + 12 > data_end)
        return XDP_PASS;

    __u16 flags = bpf_ntohs(*(__be16 *)(dns_start + 2));
    if (flags & 0x8000) // Response
        return XDP_PASS;

    __u8 *ptr = dns_start + 12;
    __u32 domain_hash = 0x811c9dc5; // FNV-1a 32-bit offset basis

    #pragma unroll
    for (int i = 0; i < 20; i++) {
        if (ptr + 1 > data_end)
            return XDP_PASS;
        __u8 len = *ptr;
        if (len == 0)
            break;
        if (len > 63)
            return XDP_PASS;
        ptr += 1;
        if (ptr + 1 > data_end)
            return XDP_PASS;
        domain_hash = (domain_hash ^ (*ptr)) * 0x01000193;
        ptr += len;
    }

    __u64 pkt_len = (__u64)((void *)data_end - (void *)data);
    struct domain_stat *st = bpf_map_lookup_elem(&domain_freq_map, &domain_hash);
    if (!st) {
        struct domain_stat new_st = { .query_count = 1, .total_bytes = pkt_len };
        bpf_map_update_elem(&domain_freq_map, &domain_hash, &new_st, BPF_ANY);
    } else {
        st->query_count += 1;
        st->total_bytes += pkt_len;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    tasks.append({
        "task_id": "syn_pit_l3_004_dns_domain_freq_tracker",
        "application_category": "packet_inspection_telemetry",
        "difficulty": "level_3",
        "task_family": "xdp_telemetry_dns_domains",
        "template_family": "xdp_dns_domain_tracker",
        "semantic_signature": "dns_query+domain_hash_freq_and_bytes_map+pass",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that inspects DNS queries (UDP destination port 53, QR == 0). Parse the question QNAME labels, compute a 32-bit FNV-1a hash across the domain name bytes, and maintain query frequency and total wire byte volume in a BPF hash map named 'domain_freq_map' (key __u32 domain_hash, value struct domain_stat { __u64 query_count; __u64 total_bytes; }, max_entries 1024). Always return XDP_PASS.",
        "requirements": [
            "Define struct domain_stat with query_count and total_bytes",
            "Define hash map 'domain_freq_map' with key __u32 and max_entries 1024",
            "Walk DNS QNAME labels safely and compute 32-bit hash",
            "Accumulate query_count and total_bytes per domain hash",
            "Always return XDP_PASS",
            "SEC(\"xdp\") and GPL license declaration"
        ],
        "solution_c": t54_sol,
        "tests": t54_tests,
        "main_validator": "map_state"
    })

    # 55. syn_pit_l3_005_gtpu_bearer_traffic_matrix
    t55_tests = [
        {"name": "teid1_uplink_pass", "description": "TEID 1 uplink packet updates stats and passes", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.10", dst_ip="192.168.1.20", proto=17, payload=make_udp(dst_port=2152, payload=make_gtpu(teid=1, inner_pkt=make_ipv4(proto=1, payload=make_icmp()))))).hex(), "expected_action": "XDP_PASS"},
        {"name": "teid1_downlink_pass", "description": "TEID 1 downlink packet updates downlink stats and passes", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.20", dst_ip="192.168.1.10", proto=17, payload=make_udp(src_port=2152, dst_port=12345, payload=make_gtpu(teid=1, inner_pkt=make_ipv4(proto=1, payload=make_icmp()))))).hex(), "expected_action": "XDP_PASS"},
        {"name": "teid2_pass", "description": "TEID 2 packet updates separate table entry", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.10", dst_ip="192.168.1.20", proto=17, payload=make_udp(dst_port=2152, payload=make_gtpu(teid=2, inner_pkt=make_ipv4(proto=1, payload=make_icmp()))))).hex(), "expected_action": "XDP_PASS"},
        {"name": "echo_req_pass", "description": "Echo Request passes", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=2152, payload=make_gtpu(msg_type=1, teid=1)))).hex(), "expected_action": "XDP_PASS"},
        {"name": "non_gtpu_udp_pass", "description": "UDP port 2153 passes", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=2153))).hex(), "expected_action": "XDP_PASS"},
        {"name": "tcp_pass", "description": "TCP packet passes", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "icmp_pass", "description": "ICMP packet passes", "packet_hex": make_eth(payload=make_ipv4(proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "arp_pass", "description": "ARP frame passes", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
        {"name": "truncated_gtpu_pass", "description": "Truncated GTP-U packet passes safely", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=2152, payload=b"\x30\xFF"))).hex(), "expected_action": "XDP_PASS"},
    ]
    t55_sol = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

struct bearer_stats {
    __u64 uplink_bytes;
    __u64 downlink_bytes;
    __u64 total_pkts;
};

struct gtpuhdr {
    __u8 flags;
    __u8 msg_type;
    __be16 length;
    __be32 teid;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32); // TEID
    __type(value, struct bearer_stats);
    __uint(max_entries, 1024);
} bearer_matrix_map SEC(".maps");

SEC("xdp")
int xdp_gtpu_bearer_matrix(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    int ip_len = ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip_len;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    int is_uplink = (udp->dest == bpf_htons(2152));
    int is_downlink = (udp->source == bpf_htons(2152));
    if (!is_uplink && !is_downlink)
        return XDP_PASS;

    struct gtpuhdr *gtp = (void *)(udp + 1);
    if ((void *)(gtp + 1) > data_end)
        return XDP_PASS;

    __u32 teid = bpf_ntohl(gtp->teid);
    __u64 pkt_len = (__u64)((void *)data_end - (void *)data);

    struct bearer_stats *st = bpf_map_lookup_elem(&bearer_matrix_map, &teid);
    if (!st) {
        struct bearer_stats new_st = {
            .uplink_bytes = is_uplink ? pkt_len : 0,
            .downlink_bytes = is_downlink ? pkt_len : 0,
            .total_pkts = 1,
        };
        bpf_map_update_elem(&bearer_matrix_map, &teid, &new_st, BPF_ANY);
    } else {
        if (is_uplink)
            st->uplink_bytes += pkt_len;
        else
            st->downlink_bytes += pkt_len;
        st->total_pkts += 1;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    tasks.append({
        "task_id": "syn_pit_l3_005_gtpu_bearer_traffic_matrix",
        "application_category": "packet_inspection_telemetry",
        "difficulty": "level_3",
        "task_family": "xdp_telemetry_gtpu_bearer",
        "template_family": "xdp_gtpu_traffic_matrix",
        "semantic_signature": "gtpu_teid+uplink_downlink_traffic_matrix+pass",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that maintains a bearer traffic matrix for GTP-U cellular tunnels. Inspect GTP-U packets (UDP port 2152 on dest for uplink or source for downlink). Extract the 32-bit TEID and update per-TEID telemetry in a BPF hash map named 'bearer_matrix_map' (key __u32 teid, value struct bearer_stats { __u64 uplink_bytes; __u64 downlink_bytes; __u64 total_pkts; }, max_entries 1024). Accumulate uplink vs downlink bytes and total packets. Always return XDP_PASS.",
        "requirements": [
            "Define struct bearer_stats with uplink_bytes, downlink_bytes, and total_pkts",
            "Define hash map 'bearer_matrix_map' with key __u32 and max_entries 1024",
            "Distinguish uplink (dest port 2152) from downlink (source port 2152)",
            "Accumulate per-TEID direction bytes and packet counts",
            "Always return XDP_PASS",
            "SEC(\"xdp\") and GPL license declaration"
        ],
        "solution_c": t55_sol,
        "tests": t55_tests,
        "main_validator": "map_state"
    })

    # 56. syn_pit_l3_006_tcp_out_of_order_detector
    t56_tests = [
        {"name": "tcp_seq1_pass", "description": "First packet with SEQ 1000 and len 100 updates expected SEQ to 1100", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.10", dst_ip="192.168.1.20", proto=6, payload=make_tcp(src_port=10001, dst_port=80, seq=1000, payload=b"A"*100))).hex(), "expected_action": "XDP_PASS"},
        {"name": "tcp_seq2_in_order_pass", "description": "In-order packet with SEQ 1100 updates expected SEQ to 1200", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.10", dst_ip="192.168.1.20", proto=6, payload=make_tcp(src_port=10001, dst_port=80, seq=1100, payload=b"B"*100))).hex(), "expected_action": "XDP_PASS"},
        {"name": "tcp_seq_out_of_order_pass", "description": "Out-of-order packet (SEQ 1500 != 1200) increments out_of_order_count", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.10", dst_ip="192.168.1.20", proto=6, payload=make_tcp(src_port=10001, dst_port=80, seq=1500, payload=b"C"*100))).hex(), "expected_action": "XDP_PASS"},
        {"name": "other_flow_pass", "description": "Different flow is tracked in independent entry", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.30", dst_ip="192.168.1.40", proto=6, payload=make_tcp(src_port=20002, dst_port=443, seq=5000, payload=b"D"*50))).hex(), "expected_action": "XDP_PASS"},
        {"name": "udp_pass", "description": "UDP packet passes", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "icmp_pass", "description": "ICMP packet passes", "packet_hex": make_eth(payload=make_ipv4(proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "arp_pass", "description": "ARP frame passes", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
        {"name": "ipv6_pass", "description": "IPv6 frame passes", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(next_hdr=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "truncated_tcp_pass", "description": "Truncated TCP packet passes safely", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=b"\x00\x50")).hex(), "expected_action": "XDP_PASS"},
    ]
    t56_sol = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

struct flow_key {
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
};

struct seq_tracker {
    __u32 expected_seq;
    __u32 in_order_pkts;
    __u32 out_of_order_pkts;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct flow_key);
    __type(value, struct seq_tracker);
    __uint(max_entries, 1024);
} seq_tracker_map SEC(".maps");

SEC("xdp")
int xdp_tcp_ooo_detector(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    int ip_len = ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip_len;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    int tcp_hdr_len = tcp->doff * 4;
    if (tcp_hdr_len < sizeof(struct tcphdr) || (void *)tcp + tcp_hdr_len > data_end)
        return XDP_PASS;

    __u32 payload_len = (__u32)((void *)data_end - ((void *)tcp + tcp_hdr_len));
    if (payload_len == 0)
        return XDP_PASS; // Only track segments with payload

    struct flow_key key = {
        .src_ip = ip->saddr,
        .dst_ip = ip->daddr,
        .src_port = tcp->source,
        .dst_port = tcp->dest,
    };

    __u32 seq = bpf_ntohl(tcp->seq);
    struct seq_tracker *st = bpf_map_lookup_elem(&seq_tracker_map, &key);
    if (!st) {
        struct seq_tracker new_st = {
            .expected_seq = seq + payload_len,
            .in_order_pkts = 1,
            .out_of_order_pkts = 0,
        };
        bpf_map_update_elem(&seq_tracker_map, &key, &new_st, BPF_ANY);
        return XDP_PASS;
    }

    if (seq == st->expected_seq) {
        st->in_order_pkts += 1;
        st->expected_seq = seq + payload_len;
    } else {
        st->out_of_order_pkts += 1;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    tasks.append({
        "task_id": "syn_pit_l3_006_tcp_out_of_order_detector",
        "application_category": "packet_inspection_telemetry",
        "difficulty": "level_3",
        "task_family": "xdp_telemetry_tcp_ooo",
        "template_family": "xdp_tcp_seq_tracker",
        "semantic_signature": "tcp_seq_tracking+out_of_order_detector+pass",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that tracks TCP sequence continuity and detects out-of-order packets. Maintain per-flow state in a BPF hash map named 'seq_tracker_map' (key struct flow_key, value struct seq_tracker { __u32 expected_seq; __u32 in_order_pkts; __u32 out_of_order_pkts; }, max_entries 1024). For IPv4 TCP segments carrying payload, check if tcp->seq matches expected_seq. If it matches, advance expected_seq by payload length and increment in_order_pkts. If it deviates, increment out_of_order_pkts. Always return XDP_PASS.",
        "requirements": [
            "Define struct flow_key and struct seq_tracker",
            "Define hash map 'seq_tracker_map' with max_entries 1024",
            "Calculate TCP payload length and check sequence numbers",
            "Accumulate in_order vs out_of_order packet counts",
            "Always return XDP_PASS",
            "SEC(\"xdp\") and GPL license declaration"
        ],
        "solution_c": t56_sol,
        "tests": t56_tests,
        "main_validator": "map_state"
    })

    # 57. syn_pit_l3_007_wireguard_session_telemetry
    t57_tests = [
        {"name": "wg_data1_pass", "description": "WireGuard Data packet for Receiver Index 0x55667788 updates session and passes", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=51820, payload=make_wireguard(msg_type=4, receiver_idx=0x55667788, payload=b"DATA"*20)))).hex(), "expected_action": "XDP_PASS"},
        {"name": "wg_data1_pkt2_pass", "description": "Second data packet updates session byte volume", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=51820, payload=make_wireguard(msg_type=4, receiver_idx=0x55667788, payload=b"DATA"*30)))).hex(), "expected_action": "XDP_PASS"},
        {"name": "wg_other_session_pass", "description": "WireGuard Data for different Receiver Index creates separate session", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=51820, payload=make_wireguard(msg_type=4, receiver_idx=0x11223344, payload=b"DATA"*20)))).hex(), "expected_action": "XDP_PASS"},
        {"name": "wg_handshake_pass", "description": "WireGuard Handshake Initiation passes without data session update", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=51820, payload=make_wireguard(msg_type=1)))).hex(), "expected_action": "XDP_PASS"},
        {"name": "non_wg_udp_pass", "description": "UDP to port 51821 passes", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=51821))).hex(), "expected_action": "XDP_PASS"},
        {"name": "tcp_pass", "description": "TCP packet passes", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "icmp_pass", "description": "ICMP packet passes", "packet_hex": make_eth(payload=make_ipv4(proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "arp_pass", "description": "ARP frame passes", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
        {"name": "truncated_wg_pass", "description": "Truncated WireGuard packet passes safely", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=51820, payload=b"\x04\x00"))).hex(), "expected_action": "XDP_PASS"},
    ]
    t57_sol = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

struct wg_session_stat {
    __u64 last_seen_ns;
    __u64 total_packets;
    __u64 total_bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32); // Receiver Index
    __type(value, struct wg_session_stat);
    __uint(max_entries, 1024);
} wg_session_map SEC(".maps");

SEC("xdp")
int xdp_wg_session_telemetry(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    int ip_len = ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip_len;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;
    if (udp->dest != bpf_htons(51820) && udp->source != bpf_htons(51820))
        return XDP_PASS;

    __u8 *wg = (void *)(udp + 1);
    if (wg + 8 > data_end)
        return XDP_PASS;

    __u32 msg_type = *(__u32 *)wg;
    if ((msg_type & 0xFF) != 4) // Type 4: Data packet
        return XDP_PASS;

    __u32 receiver_idx = *(__u32 *)(wg + 4);
    __u64 now = bpf_ktime_get_ns();
    __u64 pkt_len = (__u64)((void *)data_end - (void *)data);

    struct wg_session_stat *st = bpf_map_lookup_elem(&wg_session_map, &receiver_idx);
    if (!st) {
        struct wg_session_stat new_st = {
            .last_seen_ns = now,
            .total_packets = 1,
            .total_bytes = pkt_len,
        };
        bpf_map_update_elem(&wg_session_map, &receiver_idx, &new_st, BPF_ANY);
    } else {
        st->last_seen_ns = now;
        st->total_packets += 1;
        st->total_bytes += pkt_len;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    tasks.append({
        "task_id": "syn_pit_l3_007_wireguard_session_telemetry",
        "application_category": "packet_inspection_telemetry",
        "difficulty": "level_3",
        "task_family": "xdp_telemetry_wireguard",
        "template_family": "xdp_wg_session_tracker",
        "semantic_signature": "wireguard_udp51820+receiver_idx_session_matrix+pass",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that maintains active WireGuard session telemetry (UDP port 51820). Parse WireGuard Type 4 data packets, extract the 32-bit Receiver Index, and update session statistics in a BPF hash map named 'wg_session_map' (key __u32 receiver_idx, value struct wg_session_stat { __u64 last_seen_ns; __u64 total_packets; __u64 total_bytes; }, max_entries 1024). Update timestamps with bpf_ktime_get_ns(). Always return XDP_PASS.",
        "requirements": [
            "Define struct wg_session_stat with last_seen_ns, total_packets, and total_bytes",
            "Define hash map 'wg_session_map' with key __u32 and max_entries 1024",
            "Filter WireGuard Type 4 data packets",
            "Accumulate packet count, wire byte volume, and last seen timestamp",
            "Always return XDP_PASS",
            "SEC(\"xdp\") and GPL license declaration"
        ],
        "solution_c": t57_sol,
        "tests": t57_tests,
        "main_validator": "map_state"
    })

    # 58. syn_pit_l3_008_mpls_vpn_flow_stats
    t58_tests = [
        {"name": "vpn_label_100_pass", "description": "MPLS frame with VPN Label 100 updates VPN stats and passes", "packet_hex": make_eth(eth_type=0x8847, payload=make_mpls([(100, 0, True, 64)], inner_pkt=make_ipv4(proto=6, payload=make_tcp()))).hex(), "expected_action": "XDP_PASS"},
        {"name": "vpn_label_100_pkt2_pass", "description": "Second packet on VPN Label 100 updates cumulative bytes", "packet_hex": make_eth(eth_type=0x8847, payload=make_mpls([(100, 0, True, 64)], inner_pkt=make_ipv4(proto=6, payload=make_tcp()))).hex(), "expected_action": "XDP_PASS"},
        {"name": "vpn_label_200_pass", "description": "MPLS frame with VPN Label 200 updates separate VPN entry", "packet_hex": make_eth(eth_type=0x8847, payload=make_mpls([(200, 0, True, 64)], inner_pkt=make_ipv4(proto=6, payload=make_tcp()))).hex(), "expected_action": "XDP_PASS"},
        {"name": "vpn_multi_label_pass", "description": "Stacked MPLS frame extracts bottom VPN label", "packet_hex": make_eth(eth_type=0x8847, payload=make_mpls([(1000, 0, False, 64), (100, 0, True, 64)], inner_pkt=make_ipv4(proto=6, payload=make_tcp()))).hex(), "expected_action": "XDP_PASS"},
        {"name": "non_mpls_ipv4_pass", "description": "Non-MPLS IPv4 passes", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "udp_pass", "description": "UDP packet passes", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "icmp_pass", "description": "ICMP packet passes", "packet_hex": make_eth(payload=make_ipv4(proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "arp_pass", "description": "ARP frame passes", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
        {"name": "truncated_mpls_pass", "description": "Truncated MPLS frame passes safely", "packet_hex": make_eth(eth_type=0x8847, payload=b"\x00\x01").hex(), "expected_action": "XDP_PASS"},
    ]
    t58_sol = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>

struct mpls_stats {
    __u64 pkts;
    __u64 bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32); // 20-bit VPN label
    __type(value, struct mpls_stats);
    __uint(max_entries, 1024);
} vpn_stats_map SEC(".maps");

SEC("xdp")
int xdp_mpls_vpn_telemetry(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(0x8847))
        return XDP_PASS;

    __u32 *ptr = (void *)(eth + 1);
    __u32 vpn_label = 0;
    int found = 0;

    #pragma unroll
    for (int i = 0; i < 4; i++) {
        if ((void *)(ptr + 1) > data_end)
            break;

        __u32 entry = bpf_ntohl(*ptr);
        __u32 label = entry >> 12;
        int bos = (entry & 0x00000100) != 0;

        if (bos) {
            vpn_label = label;
            found = 1;
            break;
        }
        ptr += 1;
    }

    if (found) {
        __u64 pkt_len = (__u64)((void *)data_end - (void *)data);
        struct mpls_stats *st = bpf_map_lookup_elem(&vpn_stats_map, &vpn_label);
        if (!st) {
            struct mpls_stats new_st = { .pkts = 1, .bytes = pkt_len };
            bpf_map_update_elem(&vpn_stats_map, &vpn_label, &new_st, BPF_ANY);
        } else {
            st->pkts += 1;
            st->bytes += pkt_len;
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    tasks.append({
        "task_id": "syn_pit_l3_008_mpls_vpn_flow_stats",
        "application_category": "packet_inspection_telemetry",
        "difficulty": "level_3",
        "task_family": "xdp_telemetry_mpls_vpn",
        "template_family": "xdp_mpls_vpn_tracker",
        "semantic_signature": "mpls_vpn_bos_label+traffic_stats_map+pass",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that inspects MPLS L3VPN traffic (EtherType 0x8847). Walk the MPLS label stack to locate the Bottom-of-Stack (BOS) VPN service label. Track cumulative packets and byte volume per VPN label in a BPF hash map named 'vpn_stats_map' (key __u32 vpn_label, value struct mpls_stats { __u64 pkts; __u64 bytes; }, max_entries 1024). Always return XDP_PASS.",
        "requirements": [
            "Define struct mpls_stats with pkts and bytes",
            "Define hash map 'vpn_stats_map' with key __u32 and max_entries 1024",
            "Walk MPLS label stack safely to extract the BOS service label",
            "Accumulate packets and wire bytes per VPN label",
            "Always return XDP_PASS",
            "SEC(\"xdp\") and GPL license declaration"
        ],
        "solution_c": t58_sol,
        "tests": t58_tests,
        "main_validator": "map_state"
    })

    # 59. syn_pit_l3_009_srv6_path_latency_telemetry
    t59_tests = [
        {"name": "srv6_path1_pass", "description": "SRv6 path updates SID path metrics and passes", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(next_hdr=43, payload=make_srv6(segments=["2001:db8::10", "2001:db8::20"], inner_pkt=make_ipv4(proto=1, payload=make_icmp())))).hex(), "expected_action": "XDP_PASS"},
        {"name": "srv6_path1_pkt2_pass", "description": "Second packet on same SRv6 path increments stats", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(next_hdr=43, payload=make_srv6(segments=["2001:db8::10", "2001:db8::20"], inner_pkt=make_ipv4(proto=1, payload=make_icmp())))).hex(), "expected_action": "XDP_PASS"},
        {"name": "srv6_path2_pass", "description": "Different SRv6 path creates distinct telemetry entry", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(next_hdr=43, payload=make_srv6(segments=["2001:db8::30", "2001:db8::40"], inner_pkt=make_ipv4(proto=1, payload=make_icmp())))).hex(), "expected_action": "XDP_PASS"},
        {"name": "standard_ipv6_pass", "description": "Standard IPv6 passes", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(next_hdr=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "ipv4_pass", "description": "IPv4 passes", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "udp_pass", "description": "UDP packet passes", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "icmp_pass", "description": "ICMP packet passes", "packet_hex": make_eth(payload=make_ipv4(proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "arp_pass", "description": "ARP frame passes", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
        {"name": "truncated_srv6_pass", "description": "Truncated SRv6 packet passes safely", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(next_hdr=43, payload=b"\x04\x00")).hex(), "expected_action": "XDP_PASS"},
    ]
    t59_sol = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>

struct srv6_hdr {
    __u8 nexthdr;
    __u8 hdr_ext_len;
    __u8 routing_type;
    __u8 segments_left;
    __u8 last_entry;
    __u8 flags;
    __u16 tag;
};

struct path_metrics {
    __u64 pkts;
    __u64 bytes;
    __u32 hops;
    __u32 pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32); // Path hash
    __type(value, struct path_metrics);
    __uint(max_entries, 1024);
} srv6_path_map SEC(".maps");

SEC("xdp")
int xdp_srv6_path_metrics(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IPV6))
        return XDP_PASS;

    struct ipv6hdr *ip6 = (void *)(eth + 1);
    if ((void *)(ip6 + 1) > data_end)
        return XDP_PASS;
    if (ip6->nexthdr != 43)
        return XDP_PASS;

    struct srv6_hdr *srh = (void *)(ip6 + 1);
    if ((void *)(srh + 1) > data_end)
        return XDP_PASS;
    if (srh->routing_type != 4)
        return XDP_PASS;

    __u32 path_hash = 0;
    __u32 *sid_ptr = (void *)(srh + 1);

    #pragma unroll
    for (int i = 0; i < 4; i++) {
        if ((void *)(sid_ptr + 4) > data_end)
            break;
        path_hash ^= *sid_ptr ^ *(sid_ptr + 1) ^ *(sid_ptr + 2) ^ *(sid_ptr + 3);
        sid_ptr += 4;
    }

    __u64 pkt_len = (__u64)((void *)data_end - (void *)data);
    struct path_metrics *st = bpf_map_lookup_elem(&srv6_path_map, &path_hash);
    if (!st) {
        struct path_metrics new_st = {
            .pkts = 1,
            .bytes = pkt_len,
            .hops = srh->last_entry + 1,
            .pad = 0,
        };
        bpf_map_update_elem(&srv6_path_map, &path_hash, &new_st, BPF_ANY);
    } else {
        st->pkts += 1;
        st->bytes += pkt_len;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    tasks.append({
        "task_id": "syn_pit_l3_009_srv6_path_latency_telemetry",
        "application_category": "packet_inspection_telemetry",
        "difficulty": "level_3",
        "task_family": "xdp_telemetry_srv6_path",
        "template_family": "xdp_srv6_path_tracker",
        "semantic_signature": "srv6_srh_path_hash+telemetry_metrics_map+pass",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that inspects SRv6 Segment Routing traffic (IPv6 Next Header 43, Routing Type 4). Compute a path hash across the active Segment List (128-bit IPv6 SIDs). Maintain telemetry metrics in a BPF hash map named 'srv6_path_map' (key __u32 path_hash, value struct path_metrics { __u64 pkts; __u64 bytes; __u32 hops; __u32 pad; }, max_entries 1024). Record total packet count, byte volume, and hops count (srh->last_entry + 1). Always return XDP_PASS.",
        "requirements": [
            "Define struct path_metrics with pkts, bytes, and hops",
            "Define hash map 'srv6_path_map' with key __u32 and max_entries 1024",
            "Parse SRv6 header and hash the Segment List SIDs",
            "Accumulate packets and byte volume per unique SRv6 path",
            "Always return XDP_PASS",
            "SEC(\"xdp\") and GPL license declaration"
        ],
        "solution_c": t59_sol,
        "tests": t59_tests,
        "main_validator": "map_state"
    })

    # 60. syn_pit_l3_010_connection_churn_monitor
    t60_tests = [
        {"name": "syn_churn_pass", "description": "SYN increments new connection counter and returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(flags=0x02))).hex(), "expected_action": "XDP_PASS"},
        {"name": "fin_churn_pass", "description": "FIN increments closed connection counter and returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(flags=0x11))).hex(), "expected_action": "XDP_PASS"},
        {"name": "rst_churn_pass", "description": "RST increments closed connection counter and returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(flags=0x14))).hex(), "expected_action": "XDP_PASS"},
        {"name": "ack_pass", "description": "Established ACK passes without churn count", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(flags=0x10))).hex(), "expected_action": "XDP_PASS"},
        {"name": "udp_pass", "description": "UDP packet passes", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "icmp_pass", "description": "ICMP packet passes", "packet_hex": make_eth(payload=make_ipv4(proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "arp_pass", "description": "ARP frame passes", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
        {"name": "ipv6_pass", "description": "IPv6 frame passes", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(next_hdr=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "truncated_tcp_pass", "description": "Truncated TCP packet passes safely", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=b"\x00\x50")).hex(), "expected_action": "XDP_PASS"},
    ]
    t60_sol = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 2); // 0=Created flows (SYN), 1=Teardown flows (FIN/RST)
} churn_monitor_map SEC(".maps");

SEC("xdp")
int xdp_connection_churn(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    int ip_len = ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip_len;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    if (tcp->syn && !tcp->ack) {
        __u32 key = 0; // Created
        __u64 *cnt = bpf_map_lookup_elem(&churn_monitor_map, &key);
        if (cnt)
            *cnt += 1;
    } else if (tcp->fin || tcp->rst) {
        __u32 key = 1; // Teardown
        __u64 *cnt = bpf_map_lookup_elem(&churn_monitor_map, &key);
        if (cnt)
            *cnt += 1;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    tasks.append({
        "task_id": "syn_pit_l3_010_connection_churn_monitor",
        "application_category": "packet_inspection_telemetry",
        "difficulty": "level_3",
        "task_family": "xdp_telemetry_churn",
        "template_family": "xdp_flow_churn_monitor",
        "semantic_signature": "tcp_syn_fin_rst+connection_churn_counter+pass",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that monitors TCP connection churn rate. Count newly initiated connections (TCP SYN with ACK=0) in slot 0, and terminated connections (TCP FIN or RST) in slot 1 of a per-CPU array map named 'churn_monitor_map' (max_entries 2). Always return XDP_PASS.",
        "requirements": [
            "Define per-CPU array map 'churn_monitor_map' with max_entries 2",
            "Validate Ethernet, IPv4, and TCP header bounds",
            "Increment slot 0 for SYN && !ACK",
            "Increment slot 1 for FIN || RST",
            "Always return XDP_PASS",
            "SEC(\"xdp\") and GPL license declaration"
        ],
        "solution_c": t60_sol,
        "tests": t60_tests,
        "main_validator": "map_state"
    })

    return tasks
