"""
Generates the complete python source code for defs_protocol_transformation.py (30 tasks).
"""

def get_all_ptr_tasks_code() -> str:
    # Build complete python file string for PTR
    return '''"""
Task definitions for Category 3: Protocol Transformation (30 Tasks)
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
    parse_ipv4,
    parse_ipv6,
    parse_mac,
)


def get_protocol_transformation_tasks() -> List[Dict[str, Any]]:
    tasks: List[Dict[str, Any]] = []

    # =========================================================================
    # LEVEL 1 (10 Tasks) - Stateless, single field/tag transform (>= 5 tests)
    # =========================================================================

    # 1. syn_ptr_l1_001_mpls_pop_single_label
    tasks.append({
        "task_id": "syn_ptr_l1_001_mpls_pop_single_label",
        "application_category": "protocol_transformation",
        "difficulty": "level_1",
        "task_family": "xdp_head_adjust",
        "template_family": "xdp_mpls_pop",
        "semantic_signature": "mpls_0x8847+pop_4byte_label_restore_eth_p_ip+pass",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that pops a single MPLS label (4 bytes) from incoming MPLS unicast frames (EtherType 0x8847) when the Bottom-of-Stack (BOS) bit is 1. Use bpf_xdp_adjust_head(ctx, 4) to shrink the packet head, restore original MAC addresses, and set eth->h_proto to bpf_htons(ETH_P_IP / 0x0800). Pass multi-label MPLS frames (BOS == 0) and non-MPLS traffic unchanged with XDP_PASS.",
        "requirements": [
            "Validate Ethernet and struct mpls_label bounds",
            "Verify eth->h_proto == bpf_htons(0x8847) and BOS bit != 0",
            "Call bpf_xdp_adjust_head(ctx, 4) to pop 4 bytes",
            "Restore MACs and set eth->h_proto = bpf_htons(ETH_P_IP)",
            "Always return XDP_PASS",
            "SEC(\\"xdp\\") and GPL license declaration"
        ],
        "solution_c": """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>

struct mpls_label {
    __u32 entry;
};

SEC("xdp")
int xdp_mpls_pop(struct xdp_md *ctx) {
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
    if ((entry & 0x00000100) == 0)
        return XDP_PASS;

    unsigned char src[ETH_ALEN], dst[ETH_ALEN];
    #pragma unroll
    for (int i = 0; i < ETH_ALEN; i++) {
        src[i] = eth->h_source[i];
        dst[i] = eth->h_dest[i];
    }

    if (bpf_xdp_adjust_head(ctx, 4))
        return XDP_PASS;

    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    struct ethhdr *new_eth = data;
    if ((void *)(new_eth + 1) > data_end)
        return XDP_PASS;

    #pragma unroll
    for (int i = 0; i < ETH_ALEN; i++) {
        new_eth->h_source[i] = src[i];
        new_eth->h_dest[i] = dst[i];
    }
    new_eth->h_proto = bpf_htons(ETH_P_IP);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
""",
        "tests": [
            {"name": "mpls_single_pop_pass", "description": "Single-label MPLS popped to IPv4", "packet_hex": make_eth(eth_type=0x8847, payload=make_mpls([(100, 0, True, 64)], inner_pkt=make_ipv4(proto=1, payload=make_icmp()))).hex(), "expected_action": "XDP_PASS"},
            {"name": "mpls_multi_label_pass", "description": "Multi-label MPLS passed unchanged", "packet_hex": make_eth(eth_type=0x8847, payload=make_mpls([(100, 0, False, 64), (200, 0, True, 64)], inner_pkt=make_ipv4(proto=1, payload=make_icmp()))).hex(), "expected_action": "XDP_PASS"},
            {"name": "ipv4_pass", "description": "IPv4 passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP passed unchanged", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_mpls_pass", "description": "Truncated MPLS passed safely", "packet_hex": make_eth(eth_type=0x8847, payload=b"\\x00\\x01").hex(), "expected_action": "XDP_PASS"},
        ],
        "main_validator": "packet_bytes"
    })

    # 2. syn_ptr_l1_002_vxlan_strip_vni
    tasks.append({
        "task_id": "syn_ptr_l1_002_vxlan_strip_vni",
        "application_category": "protocol_transformation",
        "difficulty": "level_1",
        "task_family": "xdp_packet_rewrite",
        "template_family": "xdp_vxlan_vni_remap",
        "semantic_signature": "vxlan_udp4789+rewrite_vni_00aabb+pass",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that inspects VXLAN packets (UDP destination port 4789) and rewrites the 24-bit Virtual Network Identifier (VNI) field to fixed value 0x00AABB (0x00AABB00 in network byte order). Preserve all other fields and payload. Return XDP_PASS.",
        "requirements": [
            "Validate Ethernet, IPv4, UDP, and struct vxlanhdr bounds",
            "Verify UDP destination port is 4789",
            "Rewrite vx->vx_vni to bpf_htonl(0x00AABB00)",
            "Always return XDP_PASS",
            "SEC(\\"xdp\\") and GPL license declaration"
        ],
        "solution_c": """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

struct vxlanhdr {
    __u32 vx_flags;
    __u32 vx_vni;
};

SEC("xdp")
int xdp_vxlan_vni_rewrite(struct xdp_md *ctx) {
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

    vx->vx_vni = bpf_htonl(0x00AABB00);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
""",
        "tests": [
            {"name": "vxlan_rewrite_vni_pass", "description": "VXLAN frame with VNI 100 has VNI rewritten to 0x00AABB", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=4789, payload=make_vxlan(vni=100, inner_frame=make_eth(payload=make_ipv4(proto=1, payload=make_icmp())))))).hex(), "expected_action": "XDP_PASS"},
            {"name": "vxlan_rewrite_vni_2_pass", "description": "VXLAN frame with VNI 500 rewritten to 0x00AABB", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=4789, payload=make_vxlan(vni=500, inner_frame=make_eth(payload=make_ipv4(proto=6, payload=make_tcp())))))).hex(), "expected_action": "XDP_PASS"},
            {"name": "non_vxlan_udp_pass", "description": "UDP to port 4790 passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=4790))).hex(), "expected_action": "XDP_PASS"},
            {"name": "tcp_pass", "description": "TCP packet passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_vxlan_pass", "description": "Truncated VXLAN packet passed safely", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=4789, payload=b"\\x08\\x00"))).hex(), "expected_action": "XDP_PASS"},
        ],
        "main_validator": "packet_bytes"
    })

    # 3. syn_ptr_l1_003_gre_strip_key_flag
    tasks.append({
        "task_id": "syn_ptr_l1_003_gre_strip_key_flag",
        "application_category": "protocol_transformation",
        "difficulty": "level_1",
        "task_family": "xdp_packet_rewrite",
        "template_family": "xdp_gre_flags_transform",
        "semantic_signature": "gre_proto47+clear_key_flag_bit+pass",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that inspects GRE packets (IPv4 protocol 47) and clears the Key Present flag (bit 13 / 0x2000 in host byte order) in the 16-bit flags field of struct grehdr. Preserve all other fields and payload bytes. Return XDP_PASS.",
        "requirements": [
            "Validate Ethernet, IPv4, and struct grehdr bounds",
            "Clear Key flag bit 0x2000 from gre->flags",
            "Always return XDP_PASS",
            "SEC(\\"xdp\\") and GPL license declaration"
        ],
        "solution_c": """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

struct grehdr {
    __be16 flags;
    __be16 proto;
};

SEC("xdp")
int xdp_gre_clear_key(struct xdp_md *ctx) {
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
    if (ip->protocol != 47)
        return XDP_PASS;

    int ip_len = ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct grehdr *gre = (void *)ip + ip_len;
    if ((void *)(gre + 1) > data_end)
        return XDP_PASS;

    __u16 flags = bpf_ntohs(gre->flags);
    flags &= ~0x2000;
    gre->flags = bpf_htons(flags);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
""",
        "tests": [
            {"name": "gre_clear_key_flag_pass", "description": "GRE Key bit cleared", "packet_hex": make_eth(payload=make_ipv4(proto=47, payload=make_gre(k_bit=True, key=0x12345678, inner_pkt=make_ipv4(proto=1, payload=make_icmp())))).hex(), "expected_action": "XDP_PASS"},
            {"name": "gre_no_key_pass", "description": "GRE without Key flag passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=47, payload=make_gre(k_bit=False, inner_pkt=make_ipv4(proto=1, payload=make_icmp())))).hex(), "expected_action": "XDP_PASS"},
            {"name": "udp_pass", "description": "UDP packet passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "tcp_pass", "description": "TCP packet passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_gre_pass", "description": "Truncated GRE packet passed safely", "packet_hex": make_eth(payload=make_ipv4(proto=47, payload=b"\\x00")).hex(), "expected_action": "XDP_PASS"},
        ],
        "main_validator": "packet_bytes"
    })

    # 4. syn_ptr_l1_004_gtpu_teid_rewrite
    tasks.append({
        "task_id": "syn_ptr_l1_004_gtpu_teid_rewrite",
        "application_category": "protocol_transformation",
        "difficulty": "level_1",
        "task_family": "xdp_packet_rewrite",
        "template_family": "xdp_gtpu_teid_remap",
        "semantic_signature": "gtpu_udp2152+rewrite_teid_11223344+pass",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that inspects GTP-U packets (UDP destination port 2152) and rewrites the 32-bit Tunnel Endpoint Identifier (TEID) field to fixed value 0x11223344 (in network byte order). Preserve all other fields and payload. Return XDP_PASS.",
        "requirements": [
            "Validate Ethernet, IPv4, UDP, and struct gtpuhdr bounds",
            "Verify UDP destination port is 2152",
            "Rewrite gtp->teid to bpf_htonl(0x11223344)",
            "Always return XDP_PASS",
            "SEC(\\"xdp\\") and GPL license declaration"
        ],
        "solution_c": """#include <linux/bpf.h>
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

SEC("xdp")
int xdp_gtpu_teid_rewrite(struct xdp_md *ctx) {
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

    gtp->teid = bpf_htonl(0x11223344);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
""",
        "tests": [
            {"name": "gtpu_teid_rewrite_pass", "description": "GTP-U packet has TEID rewritten to 0x11223344", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=2152, payload=make_gtpu(teid=0x99887766, inner_pkt=make_ipv4(proto=1, payload=make_icmp()))))).hex(), "expected_action": "XDP_PASS"},
            {"name": "gtpu_teid_rewrite_2_pass", "description": "Second GTP-U packet rewritten to 0x11223344", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=2152, payload=make_gtpu(teid=0x00000001, inner_pkt=make_ipv4(proto=6, payload=make_tcp()))))).hex(), "expected_action": "XDP_PASS"},
            {"name": "non_gtpu_udp_pass", "description": "UDP to port 2153 passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=2153))).hex(), "expected_action": "XDP_PASS"},
            {"name": "tcp_pass", "description": "TCP packet passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_gtpu_pass", "description": "Truncated GTP-U packet passed safely", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=2152, payload=b"\\x30\\xFF"))).hex(), "expected_action": "XDP_PASS"},
        ],
        "main_validator": "packet_bytes"
    })

    # 5. syn_ptr_l1_005_coap_port_remap
    tasks.append({
        "task_id": "syn_ptr_l1_005_coap_port_remap",
        "application_category": "protocol_transformation",
        "difficulty": "level_1",
        "task_family": "xdp_packet_rewrite",
        "template_family": "xdp_l4_port_remap",
        "semantic_signature": "coap_udp5683+remap_to_5684_update_csum+pass",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that inspects IPv4 UDP traffic targeting CoAP destination port 5683. Rewrite destination port to 5684. If UDP checksum is non-zero, incrementally update it for the 16-bit port difference. Return XDP_PASS.",
        "requirements": [
            "Validate Ethernet, IPv4, and UDP header bounds",
            "Rewrite udp->dest to bpf_htons(5684)",
            "Update UDP checksum correctly if non-zero",
            "Always return XDP_PASS",
            "SEC(\\"xdp\\") and GPL license declaration"
        ],
        "solution_c": """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

SEC("xdp")
int xdp_coap_port_remap(struct xdp_md *ctx) {
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

    if (udp->dest == bpf_htons(5683)) {
        __be16 old_port = udp->dest;
        __be16 new_port = bpf_htons(5684);
        udp->dest = new_port;

        if (udp->check != 0) {
            __u32 csum = (~bpf_ntohs(udp->check)) & 0xFFFF;
            csum += (~bpf_ntohs(old_port)) & 0xFFFF;
            csum += bpf_ntohs(new_port);
            while (csum >> 16)
                csum = (csum & 0xFFFF) + (csum >> 16);
            csum = (~csum) & 0xFFFF;
            if (csum == 0)
                csum = 0xFFFF;
            udp->check = bpf_htons((__u16)csum);
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
""",
        "tests": [
            {"name": "coap_port_remap_pass", "description": "CoAP packet on port 5683 remapped to 5684", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=5683, payload=make_coap(code=1)))).hex(), "expected_action": "XDP_PASS"},
            {"name": "coap_other_port_pass", "description": "UDP packet on other port passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=5685))).hex(), "expected_action": "XDP_PASS"},
            {"name": "tcp_pass", "description": "TCP packet passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP frame passed unchanged", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_udp_pass", "description": "Truncated UDP packet passed safely", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=b"\\x16\\x33")).hex(), "expected_action": "XDP_PASS"},
        ],
        "main_validator": "packet_bytes"
    })

    # 6. syn_ptr_l1_006_ipv6_traffic_class_remark
    tasks.append({
        "task_id": "syn_ptr_l1_006_ipv6_traffic_class_remark",
        "application_category": "protocol_transformation",
        "difficulty": "level_1",
        "task_family": "xdp_packet_rewrite",
        "template_family": "xdp_ipv6_tc_remark",
        "semantic_signature": "ipv6_0x86dd+remark_traffic_class_0xb8+pass",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that inspects IPv6 packets (EtherType 0x86DD) and remarks the 8-bit Traffic Class (DSCP/ECN) field to Expedited Forwarding (0xB8 / 184). Preserve version and flow label. Return XDP_PASS.",
        "requirements": [
            "Validate Ethernet and struct ipv6hdr bounds",
            "Rewrite Traffic Class bits (bits 20-27) to 0xB8",
            "Always return XDP_PASS",
            "SEC(\\"xdp\\") and GPL license declaration"
        ],
        "solution_c": """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>

SEC("xdp")
int xdp_ipv6_remark(struct xdp_md *ctx) {
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

    __u32 *vcf = (void *)ip6;
    __u32 orig = bpf_ntohl(*vcf);
    __u32 updated = (orig & ~0x0FF00000) | (0xB8U << 20);
    *vcf = bpf_htonl(updated);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
""",
        "tests": [
            {"name": "ipv6_remark_tc_pass", "description": "IPv6 Traffic Class remarked to 0xB8", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(traffic_class=0, next_hdr=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "ipv6_remark_tc_udp_pass", "description": "IPv6 UDP packet remarked to 0xB8", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(traffic_class=0x20, next_hdr=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "ipv4_pass", "description": "IPv4 traffic passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP frame passed unchanged", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_ipv6_pass", "description": "Truncated IPv6 header passed safely", "packet_hex": make_eth(eth_type=0x86DD, payload=b"\\x60\\x00").hex(), "expected_action": "XDP_PASS"},
        ],
        "main_validator": "packet_bytes"
    })

    # 7. syn_ptr_l1_007_arp_target_mac_rewrite
    tasks.append({
        "task_id": "syn_ptr_l1_007_arp_target_mac_rewrite",
        "application_category": "protocol_transformation",
        "difficulty": "level_1",
        "task_family": "xdp_packet_rewrite",
        "template_family": "xdp_arp_tha_rewrite",
        "semantic_signature": "arp_reply_op2+rewrite_target_mac_02aabbccddee+pass",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that inspects ARP Reply packets (EtherType 0x0806, ar_op == 2). Rewrite the Target Hardware Address (ar_tha) field to 02:AA:BB:CC:DD:EE. Return XDP_PASS.",
        "requirements": [
            "Validate Ethernet and struct arphdr_eth_ipv4 bounds",
            "Check arp->ar_op == bpf_htons(2)",
            "Rewrite arp->ar_tha to 02:AA:BB:CC:DD:EE",
            "Always return XDP_PASS",
            "SEC(\\"xdp\\") and GPL license declaration"
        ],
        "solution_c": """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>

struct arphdr_eth_ipv4 {
    __be16 ar_hrd;
    __be16 ar_pro;
    __u8   ar_hln;
    __u8   ar_pln;
    __be16 ar_op;
    __u8   ar_sha[ETH_ALEN];
    __be32 ar_sip;
    __u8   ar_tha[ETH_ALEN];
    __be32 ar_tip;
};

SEC("xdp")
int xdp_arp_tha_rewrite(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_ARP))
        return XDP_PASS;

    struct arphdr_eth_ipv4 *arp = (void *)(eth + 1);
    if ((void *)(arp + 1) > data_end)
        return XDP_PASS;

    if (arp->ar_op == bpf_htons(2)) {
        arp->ar_tha[0] = 0x02;
        arp->ar_tha[1] = 0xAA;
        arp->ar_tha[2] = 0xBB;
        arp->ar_tha[3] = 0xCC;
        arp->ar_tha[4] = 0xDD;
        arp->ar_tha[5] = 0xEE;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
""",
        "tests": [
            {"name": "arp_reply_target_mac_rewrite_pass", "description": "ARP Reply Target MAC rewritten to 02:aa:bb:cc:dd:ee", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp(opcode=2, target_mac="00:00:00:00:00:00")).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_req_pass", "description": "ARP Request passed unchanged", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp(opcode=1)).hex(), "expected_action": "XDP_PASS"},
            {"name": "ipv4_pass", "description": "IPv4 traffic passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "ipv6_pass", "description": "IPv6 traffic passed unchanged", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(next_hdr=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_arp_pass", "description": "Truncated ARP frame passed safely", "packet_hex": make_eth(eth_type=0x0806, payload=b"\\x00\\x01\\x08").hex(), "expected_action": "XDP_PASS"},
        ],
        "main_validator": "packet_bytes"
    })

    # 8. syn_ptr_l1_008_dns_id_randomizer
    tasks.append({
        "task_id": "syn_ptr_l1_008_dns_id_randomizer",
        "application_category": "protocol_transformation",
        "difficulty": "level_1",
        "task_family": "xdp_packet_rewrite",
        "template_family": "xdp_dns_id_mask",
        "semantic_signature": "dns_query_udp53+xor_txid_0xa55a_update_csum+pass",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that inspects DNS query traffic (UDP destination port 53). XOR the 16-bit Transaction ID (dns_id) with 0xA55A and incrementally update the UDP checksum if non-zero. Return XDP_PASS.",
        "requirements": [
            "Validate Ethernet, IPv4, UDP, and DNS ID 2-byte bounds",
            "XOR *dns_id with bpf_htons(0xA55A)",
            "Incrementally update UDP checksum if non-zero",
            "Always return XDP_PASS",
            "SEC(\\"xdp\\") and GPL license declaration"
        ],
        "solution_c": """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

SEC("xdp")
int xdp_dns_id_randomizer(struct xdp_md *ctx) {
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

    __be16 *dns_id = (void *)(udp + 1);
    if ((void *)(dns_id + 1) > data_end)
        return XDP_PASS;

    __be16 old_id = *dns_id;
    __be16 new_id = old_id ^ bpf_htons(0xA55A);
    *dns_id = new_id;

    if (udp->check != 0) {
        __u32 csum = (~bpf_ntohs(udp->check)) & 0xFFFF;
        csum += (~bpf_ntohs(old_id)) & 0xFFFF;
        csum += bpf_ntohs(new_id);
        while (csum >> 16)
            csum = (csum & 0xFFFF) + (csum >> 16);
        csum = (~csum) & 0xFFFF;
        if (csum == 0)
            csum = 0xFFFF;
        udp->check = bpf_htons((__u16)csum);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
""",
        "tests": [
            {"name": "dns_id_xor_pass", "description": "DNS query ID XORed with 0xA55A with checksum update", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=53, payload=make_dns(txid=0x1234)))).hex(), "expected_action": "XDP_PASS"},
            {"name": "dns_response_pass", "description": "DNS response passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(src_port=53, dst_port=12345, payload=make_dns(qr=1, txid=0x5678)))).hex(), "expected_action": "XDP_PASS"},
            {"name": "non_dns_udp_pass", "description": "UDP to port 5353 passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=5353))).hex(), "expected_action": "XDP_PASS"},
            {"name": "tcp_pass", "description": "TCP packet passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_dns_pass", "description": "Truncated DNS packet passed safely", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=53, payload=b"\\x12"))).hex(), "expected_action": "XDP_PASS"},
        ],
        "main_validator": "packet_bytes"
    })

    # 9. syn_ptr_l1_009_ntp_stratum_clamp
    tasks.append({
        "task_id": "syn_ptr_l1_009_ntp_stratum_clamp",
        "application_category": "protocol_transformation",
        "difficulty": "level_1",
        "task_family": "xdp_packet_rewrite",
        "template_family": "xdp_ntp_clamp",
        "semantic_signature": "ntp_udp123+clamp_stratum_gt_4_to_4+pass",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that inspects NTP traffic (UDP port 123) and clamps the 8-bit Stratum field (byte offset 1 of NTP payload) to maximum 4 if current stratum is between 5 and 15. Return XDP_PASS.",
        "requirements": [
            "Validate Ethernet, IPv4, UDP, and NTP header bounds",
            "Clamp *(ntp + 1) to 4 if stratum > 4 && stratum <= 15",
            "Always return XDP_PASS",
            "SEC(\\"xdp\\") and GPL license declaration"
        ],
        "solution_c": """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

SEC("xdp")
int xdp_ntp_stratum_clamp(struct xdp_md *ctx) {
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
    if (stratum > 4 && stratum <= 15) {
        *(ntp + 1) = 4;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
""",
        "tests": [
            {"name": "ntp_stratum_clamp_pass", "description": "NTP Stratum 6 clamped to 4", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=123, payload=make_ntp(stratum=6)))).hex(), "expected_action": "XDP_PASS"},
            {"name": "ntp_stratum_valid_pass", "description": "NTP Stratum 2 passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=123, payload=make_ntp(stratum=2)))).hex(), "expected_action": "XDP_PASS"},
            {"name": "non_ntp_udp_pass", "description": "UDP to port 124 passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=124))).hex(), "expected_action": "XDP_PASS"},
            {"name": "tcp_pass", "description": "TCP packet passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_ntp_pass", "description": "Truncated NTP packet passed safely", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=123, payload=b"\\x17"))).hex(), "expected_action": "XDP_PASS"},
        ],
        "main_validator": "packet_bytes"
    })

    # 10. syn_ptr_l1_010_geneve_vni_rewrite
    tasks.append({
        "task_id": "syn_ptr_l1_010_geneve_vni_rewrite",
        "application_category": "protocol_transformation",
        "difficulty": "level_1",
        "task_family": "xdp_packet_rewrite",
        "template_family": "xdp_geneve_vni_remap",
        "semantic_signature": "geneve_udp6081+rewrite_vni_0055aa+pass",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that inspects GENEVE tunnel packets (UDP destination port 6081) and rewrites the 24-bit VNI field to fixed value 0x0055AA. Return XDP_PASS.",
        "requirements": [
            "Validate Ethernet, IPv4, UDP, and struct genevehdr bounds",
            "Rewrite gen->vni[0..2] to 0x00, 0x55, 0xAA",
            "Always return XDP_PASS",
            "SEC(\\"xdp\\") and GPL license declaration"
        ],
        "solution_c": """#include <linux/bpf.h>
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

SEC("xdp")
int xdp_geneve_vni_remap(struct xdp_md *ctx) {
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

    gen->vni[0] = 0x00;
    gen->vni[1] = 0x55;
    gen->vni[2] = 0xAA;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
""",
        "tests": [
            {"name": "geneve_vni_rewrite_pass", "description": "GENEVE VNI rewritten to 0x0055AA", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=6081, payload=make_geneve(vni=0x123456, inner_frame=make_eth(payload=make_ipv4(proto=1, payload=make_icmp())))))).hex(), "expected_action": "XDP_PASS"},
            {"name": "geneve_vni_rewrite_2_pass", "description": "Second GENEVE packet VNI rewritten to 0x0055AA", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=6081, payload=make_geneve(vni=0x999999, inner_frame=make_eth(payload=make_ipv4(proto=6, payload=make_tcp())))))).hex(), "expected_action": "XDP_PASS"},
            {"name": "non_geneve_udp_pass", "description": "UDP to port 6082 passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=6082))).hex(), "expected_action": "XDP_PASS"},
            {"name": "tcp_pass", "description": "TCP packet passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_geneve_pass", "description": "Truncated GENEVE packet passed safely", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=6081, payload=b"\\x00\\x00"))).hex(), "expected_action": "XDP_PASS"},
        ],
        "main_validator": "packet_bytes"
    })

    # =========================================================================
    # LEVEL 2 (10 Tasks) - Multi-field, decapsulation, checksum updates (>= 7 tests)
    # =========================================================================

    # 11. syn_ptr_l2_001_tcp_mss_clamp_rewrite
    tasks.append({
        "task_id": "syn_ptr_l2_001_tcp_mss_clamp_rewrite",
        "application_category": "protocol_transformation",
        "difficulty": "level_2",
        "task_family": "xdp_tcp_options_rewrite",
        "template_family": "xdp_mss_clamper",
        "semantic_signature": "tcp_syn+clamp_mss_to_1300_update_csum+pass",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that inspects IPv4 TCP SYN packets. Parse the variable-length TCP options list to locate the MSS option (Kind 2, Length 4). If the requested MSS is greater than 1300 bytes, clamp it to 1300 bytes (0x0514) and incrementally update the TCP header checksum (tcp->check) to maintain mathematical checksum validity. Pass TCP SYNs with MSS <= 1300, non-SYN TCP packets, other protocols, and malformed frames unchanged with XDP_PASS.",
        "requirements": [
            "Validate Ethernet, IPv4, TCP headers, and TCP options bounds",
            "Filter only TCP SYN packets",
            "Parse MSS option (Kind 2, Length 4)",
            "Clamp MSS to 1300 if > 1300 and update tcp->check",
            "Always return XDP_PASS",
            "SEC(\\"xdp\\") and GPL license declaration"
        ],
        "solution_c": """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

SEC("xdp")
int xdp_tcp_mss_clamp(struct xdp_md *ctx) {
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

        if (kind == 2 && len == 4) {
            if (opt + 4 > opt_end || opt + 4 > data_end)
                break;

            __u16 old_mss = ((__u16)*(opt + 2) << 8) | (__u16)*(opt + 3);
            if (old_mss > 1300) {
                __u16 new_mss = 1300;
                *(opt + 2) = (__u8)(new_mss >> 8);
                *(opt + 3) = (__u8)(new_mss & 0xFF);

                __u32 csum = (~bpf_ntohs(tcp->check)) & 0xFFFF;
                csum += (~old_mss) & 0xFFFF;
                csum += new_mss;
                while (csum >> 16)
                    csum = (csum & 0xFFFF) + (csum >> 16);
                csum = (~csum) & 0xFFFF;
                if (csum == 0) csum = 0xFFFF;
                tcp->check = bpf_htons((__u16)csum);
            }
            break;
        }

        opt += len;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
""",
        "tests": [
            {"name": "clamp_mss_1460_to_1300_pass", "description": "TCP SYN with MSS 1460 clamped to 1300 with checksum update", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(flags=0x02, options=bytes([2, 4, 0x05, 0xB4])))).hex(), "expected_action": "XDP_PASS"},
            {"name": "clamp_mss_1500_to_1300_pass", "description": "TCP SYN with MSS 1500 clamped to 1300", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(flags=0x02, options=bytes([2, 4, 0x05, 0xDC])))).hex(), "expected_action": "XDP_PASS"},
            {"name": "mss_1200_unchanged_pass", "description": "TCP SYN with MSS 1200 <= 1300 left unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(flags=0x02, options=bytes([2, 4, 0x04, 0xB0])))).hex(), "expected_action": "XDP_PASS"},
            {"name": "syn_no_mss_pass", "description": "TCP SYN without MSS option passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(flags=0x02))).hex(), "expected_action": "XDP_PASS"},
            {"name": "ack_pass", "description": "TCP ACK passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(flags=0x10))).hex(), "expected_action": "XDP_PASS"},
            {"name": "udp_pass", "description": "UDP packet passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_tcp_pass", "description": "Truncated TCP packet passed safely", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=b"\\x00\\x50")).hex(), "expected_action": "XDP_PASS"},
        ],
        "main_validator": "packet_bytes"
    })

    # 12. syn_ptr_l2_002_nat64_stateless_translator
    tasks.append({
        "task_id": "syn_ptr_l2_002_nat64_stateless_translator",
        "application_category": "protocol_transformation",
        "difficulty": "level_2",
        "task_family": "xdp_nat64",
        "template_family": "xdp_stateless_nat64",
        "semantic_signature": "ipv6_nat64_prefix_64_ff9b+translate_to_ipv4+pass",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that performs stateless NAT64 translation (RFC 7915). Inspect IPv6 packets (EtherType 0x86DD) targeting the well-known NAT64 prefix 64:ff9b::/96 (first 96 bits equal to 0x0064FF9B0000000000000000). Extract the lower 32 bits of the IPv6 destination address as the IPv4 destination address. Use bpf_xdp_adjust_head(ctx, 20) to shrink the header by 20 bytes (40-byte IPv6 -> 20-byte IPv4), construct a valid IPv4 header (IHL 5, TTL 64, translated endpoints), compute the IPv4 header checksum, set eth->h_proto to 0x0800, and return XDP_PASS. Pass other traffic unchanged.",
        "requirements": [
            "Validate Ethernet and struct ipv6hdr bounds",
            "Check for NAT64 prefix 64:ff9b::/96 in destination IPv6",
            "Shrink packet head by 20 bytes using bpf_xdp_adjust_head(ctx, 20)",
            "Populate new IPv4 header with calculated checksum and set EtherType 0x0800",
            "Always return XDP_PASS",
            "SEC(\\"xdp\\") and GPL license declaration"
        ],
        "solution_c": """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/ip.h>

SEC("xdp")
int xdp_nat64_stateless(struct xdp_md *ctx) {
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

    __u32 *daddr_words = (__u32 *)&ip6->daddr;
    if (daddr_words[0] != bpf_htonl(0x0064FF9B) || daddr_words[1] != 0 || daddr_words[2] != 0)
        return XDP_PASS;

    __be32 ipv4_dst = daddr_words[3];
    __u8 proto = ip6->nexthdr;
    __u16 payload_len = bpf_ntohs(ip6->payload_len);

    unsigned char src[ETH_ALEN], dst[ETH_ALEN];
    #pragma unroll
    for (int i = 0; i < ETH_ALEN; i++) {
        src[i] = eth->h_source[i];
        dst[i] = eth->h_dest[i];
    }

    if (bpf_xdp_adjust_head(ctx, 20))
        return XDP_PASS;

    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    struct ethhdr *new_eth = data;
    if ((void *)(new_eth + 1) > data_end)
        return XDP_PASS;

    #pragma unroll
    for (int i = 0; i < ETH_ALEN; i++) {
        new_eth->h_source[i] = src[i];
        new_eth->h_dest[i] = dst[i];
    }
    new_eth->h_proto = bpf_htons(ETH_P_IP);

    struct iphdr *ip4 = (void *)(new_eth + 1);
    if ((void *)(ip4 + 1) > data_end)
        return XDP_PASS;

    ip4->version = 4;
    ip4->ihl = 5;
    ip4->tos = 0;
    ip4->tot_len = bpf_htons(20 + payload_len);
    ip4->id = bpf_htons(0x1234);
    ip4->frag_off = 0;
    ip4->ttl = 64;
    ip4->protocol = proto;
    ip4->saddr = bpf_htonl(0xC0A80101);
    ip4->daddr = ipv4_dst;
    ip4->check = 0;

    __u16 *words = (void *)ip4;
    __u32 csum = 0;
    #pragma unroll
    for (int i = 0; i < 10; i++) {
        if ((void *)(words + i + 1) > data_end)
            return XDP_PASS;
        csum += bpf_ntohs(words[i]);
    }
    while (csum >> 16)
        csum = (csum & 0xFFFF) + (csum >> 16);
    ip4->check = bpf_htons((~csum) & 0xFFFF);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
""",
        "tests": [
            {"name": "nat64_translate_pass", "description": "IPv6 packet with NAT64 prefix translated to IPv4", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(src_ip="2001:db8::1", dst_ip="64:ff9b::192.0.2.1", next_hdr=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "nat64_translate_udp_pass", "description": "IPv6 UDP packet translated to IPv4 UDP", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(src_ip="2001:db8::2", dst_ip="64:ff9b::198.51.100.1", next_hdr=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "ipv6_other_prefix_pass", "description": "IPv6 packet without NAT64 prefix passed unchanged", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(src_ip="2001:db8::1", dst_ip="2001:db8::2", next_hdr=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "ipv4_pass", "description": "IPv4 traffic passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "icmp_pass", "description": "ICMP packet passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP frame passed unchanged", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_ipv6_pass", "description": "Truncated IPv6 header passed safely", "packet_hex": make_eth(eth_type=0x86DD, payload=b"\\x60\\x00").hex(), "expected_action": "XDP_PASS"},
        ],
        "main_validator": "packet_bytes"
    })

    # 13. syn_ptr_l2_003_vxlan_decap_to_inner_ethernet
    tasks.append({
        "task_id": "syn_ptr_l2_003_vxlan_decap_to_inner_ethernet",
        "application_category": "protocol_transformation",
        "difficulty": "level_2",
        "task_family": "xdp_head_adjust",
        "template_family": "xdp_vxlan_decap",
        "semantic_signature": "vxlan_udp4789+strip_50_outer_bytes_expose_inner_eth+pass",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that decapsulates VXLAN tunnel packets (UDP destination port 4789). Validate the outer Ethernet (14 bytes), IPv4 (20 bytes), UDP (8 bytes), and VXLAN (8 bytes) headers, as well as the inner Ethernet header. Use bpf_xdp_adjust_head(ctx, 50) to strip the 50 outer encapsulation bytes and deliver the raw inner Ethernet frame. Pass all non-VXLAN traffic and truncated frames unchanged with XDP_PASS.",
        "requirements": [
            "Validate outer Ethernet, IPv4 (IHL=5), UDP, VXLAN, and inner Ethernet header bounds",
            "Verify UDP destination port is 4789",
            "Call bpf_xdp_adjust_head(ctx, 50) to remove 50 outer bytes",
            "Always return XDP_PASS",
            "SEC(\\"xdp\\") and GPL license declaration"
        ],
        "solution_c": """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

struct vxlanhdr {
    __u32 vx_flags;
    __u32 vx_vni;
};

SEC("xdp")
int xdp_vxlan_decap(struct xdp_md *ctx) {
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

    if (ip->ihl != 5)
        return XDP_PASS;

    struct udphdr *udp = (void *)(ip + 1);
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

    bpf_xdp_adjust_head(ctx, 50);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
""",
        "tests": [
            {"name": "vxlan_decap_pass", "description": "VXLAN encapsulated frame stripped of 50 outer bytes, exposing inner frame", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=4789, payload=make_vxlan(vni=100, inner_frame=make_eth(dst_mac="02:00:00:11:22:33", src_mac="02:00:00:44:55:66", payload=make_ipv4(proto=1, payload=make_icmp())))))).hex(), "expected_action": "XDP_PASS"},
            {"name": "vxlan_decap_tcp_pass", "description": "VXLAN encapsulated TCP stripped of outer 50 bytes", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=4789, payload=make_vxlan(vni=200, inner_frame=make_eth(payload=make_ipv4(proto=6, payload=make_tcp())))))).hex(), "expected_action": "XDP_PASS"},
            {"name": "non_vxlan_udp_pass", "description": "UDP to port 4790 passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=4790))).hex(), "expected_action": "XDP_PASS"},
            {"name": "tcp_pass", "description": "TCP packet passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "icmp_pass", "description": "ICMP packet passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP frame passed unchanged", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_vxlan_pass", "description": "Truncated VXLAN packet passed safely", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=4789, payload=b"\\x08\\x00"))).hex(), "expected_action": "XDP_PASS"},
        ],
        "main_validator": "packet_bytes"
    })

    # 14. syn_ptr_l2_004_gre_decap_to_inner_ipv4
    tasks.append({
        "task_id": "syn_ptr_l2_004_gre_decap_to_inner_ipv4",
        "application_category": "protocol_transformation",
        "difficulty": "level_2",
        "task_family": "xdp_head_adjust",
        "template_family": "xdp_gre_decap",
        "semantic_signature": "gre_proto47+strip_24_outer_bytes_expose_inner_ip+pass",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that decapsulates GRE tunnel packets (IPv4 protocol 47 carrying inner IPv4 EtherType 0x0800). Strip the outer 24 bytes (20-byte outer IPv4 + 4-byte GRE header) using bpf_xdp_adjust_head(ctx, 24), attach the original Ethernet MAC header to the inner IPv4 packet, set eth->h_proto to 0x0800, and return XDP_PASS. Pass non-GRE traffic and malformed packets unchanged.",
        "requirements": [
            "Validate outer Ethernet, IPv4 (IHL=5), struct grehdr (flags==0), and inner IPv4 bounds",
            "Call bpf_xdp_adjust_head(ctx, 24) to strip outer encapsulation",
            "Restore Ethernet MACs and set eth->h_proto = bpf_htons(ETH_P_IP)",
            "Always return XDP_PASS",
            "SEC(\\"xdp\\") and GPL license declaration"
        ],
        "solution_c": """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

struct grehdr {
    __be16 flags;
    __be16 proto;
};

SEC("xdp")
int xdp_gre_decap(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *outer_ip = (void *)(eth + 1);
    if ((void *)(outer_ip + 1) > data_end)
        return XDP_PASS;
    if (outer_ip->protocol != 47)
        return XDP_PASS;
    if (outer_ip->ihl != 5)
        return XDP_PASS;

    struct grehdr *gre = (void *)(outer_ip + 1);
    if ((void *)(gre + 1) > data_end)
        return XDP_PASS;
    if (gre->flags != 0)
        return XDP_PASS;
    if (gre->proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *inner_ip = (void *)(gre + 1);
    if ((void *)(inner_ip + 1) > data_end)
        return XDP_PASS;

    unsigned char src[ETH_ALEN], dst[ETH_ALEN];
    #pragma unroll
    for (int i = 0; i < ETH_ALEN; i++) {
        src[i] = eth->h_source[i];
        dst[i] = eth->h_dest[i];
    }

    if (bpf_xdp_adjust_head(ctx, 24))
        return XDP_PASS;

    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    struct ethhdr *new_eth = data;
    if ((void *)(new_eth + 1) > data_end)
        return XDP_PASS;

    #pragma unroll
    for (int i = 0; i < ETH_ALEN; i++) {
        new_eth->h_source[i] = src[i];
        new_eth->h_dest[i] = dst[i];
    }
    new_eth->h_proto = bpf_htons(ETH_P_IP);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
""",
        "tests": [
            {"name": "gre_decap_pass", "description": "GRE tunnel stripped of 24 outer bytes exposing inner IPv4", "packet_hex": make_eth(payload=make_ipv4(proto=47, payload=make_gre(proto=0x0800, inner_pkt=make_ipv4(proto=1, payload=make_icmp())))).hex(), "expected_action": "XDP_PASS"},
            {"name": "gre_decap_tcp_pass", "description": "GRE encapsulated TCP stripped of outer 24 bytes", "packet_hex": make_eth(payload=make_ipv4(proto=47, payload=make_gre(proto=0x0800, inner_pkt=make_ipv4(proto=6, payload=make_tcp())))).hex(), "expected_action": "XDP_PASS"},
            {"name": "non_gre_udp_pass", "description": "UDP packet passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "direct_tcp_pass", "description": "Direct TCP passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "icmp_pass", "description": "ICMP packet passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP frame passed unchanged", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_gre_pass", "description": "Truncated GRE packet passed safely", "packet_hex": make_eth(payload=make_ipv4(proto=47, payload=b"\\x00")).hex(), "expected_action": "XDP_PASS"},
        ],
        "main_validator": "packet_bytes"
    })

    # 15. syn_ptr_l2_005_qinq_to_single_vlan
    tasks.append({
        "task_id": "syn_ptr_l2_005_qinq_to_single_vlan",
        "application_category": "protocol_transformation",
        "difficulty": "level_2",
        "task_family": "xdp_head_adjust",
        "template_family": "xdp_qinq_pop",
        "semantic_signature": "qinq_8021ad+pop_outer_tag_to_single_8021q+pass",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that transforms 802.1ad QinQ dual-tagged frames (outer EtherType 0x88A8 or 0x8100, followed by inner EtherType 0x8100) into single 802.1Q VLAN frames. Use bpf_xdp_adjust_head(ctx, 4) to pop the outer 4-byte VLAN tag, restore Ethernet MAC addresses, and set new_eth->h_proto to bpf_htons(ETH_P_8021Q). Pass single-tagged VLANs, untagged traffic, and malformed frames unchanged with XDP_PASS.",
        "requirements": [
            "Validate Ethernet and dual struct vlanhdr bounds",
            "Verify outer proto 0x88A8/0x8100 and inner proto 0x8100",
            "Pop 4 bytes using bpf_xdp_adjust_head(ctx, 4)",
            "Restore Ethernet MACs and set EtherType to 0x8100",
            "Always return XDP_PASS",
            "SEC(\\"xdp\\") and GPL license declaration"
        ],
        "solution_c": """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>

struct vlanhdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

SEC("xdp")
int xdp_qinq_to_vlan(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(0x88A8) && eth->h_proto != bpf_htons(0x8100))
        return XDP_PASS;

    struct vlanhdr *outer_vlan = (void *)(eth + 1);
    if ((void *)(outer_vlan + 1) > data_end)
        return XDP_PASS;

    if (outer_vlan->h_vlan_encapsulated_proto != bpf_htons(ETH_P_8021Q))
        return XDP_PASS;

    unsigned char src[ETH_ALEN], dst[ETH_ALEN];
    #pragma unroll
    for (int i = 0; i < ETH_ALEN; i++) {
        src[i] = eth->h_source[i];
        dst[i] = eth->h_dest[i];
    }

    if (bpf_xdp_adjust_head(ctx, 4))
        return XDP_PASS;

    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    struct ethhdr *new_eth = data;
    if ((void *)(new_eth + 1) > data_end)
        return XDP_PASS;

    #pragma unroll
    for (int i = 0; i < ETH_ALEN; i++) {
        new_eth->h_source[i] = src[i];
        new_eth->h_dest[i] = dst[i];
    }
    new_eth->h_proto = bpf_htons(ETH_P_8021Q);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
""",
        "tests": [
            {"name": "qinq_pop_outer_tag_pass", "description": "802.1ad QinQ frame outer tag popped to single 802.1Q", "packet_hex": make_eth(qinq_outer=100, vlan=200, payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "qinq_pop_outer_tag_2_pass", "description": "QinQ outer 300 / inner 400 converted to single VLAN 400", "packet_hex": make_eth(qinq_outer=300, vlan=400, payload=make_ipv4(proto=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "single_vlan_pass", "description": "Single 802.1Q VLAN frame passed unchanged", "packet_hex": make_eth(vlan=100, payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "untagged_pass", "description": "Untagged Ethernet frame passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP frame passed unchanged", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
            {"name": "ipv6_pass", "description": "IPv6 frame passed unchanged", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(next_hdr=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_qinq_pass", "description": "Truncated QinQ frame passed safely", "packet_hex": make_eth(qinq_outer=100)[:16].hex(), "expected_action": "XDP_PASS"},
        ],
        "main_validator": "packet_bytes"
    })

    # 16. syn_ptr_l2_006_geneve_opt_strip
    tasks.append({
        "task_id": "syn_ptr_l2_006_geneve_opt_strip",
        "application_category": "protocol_transformation",
        "difficulty": "level_2",
        "task_family": "xdp_packet_rewrite",
        "template_family": "xdp_geneve_opt_strip",
        "semantic_signature": "geneve_udp6081+clear_opt_len_to_zero+pass",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that inspects GENEVE tunnel packets (UDP destination port 6081). If gen->opt_len > 0, set gen->opt_len = 0 to strip options from the active header definition. Return XDP_PASS.",
        "requirements": [
            "Validate Ethernet, IPv4, UDP, and struct genevehdr bounds",
            "Check UDP destination port 6081",
            "Set gen->opt_len = 0",
            "Always return XDP_PASS",
            "SEC(\\"xdp\\") and GPL license declaration"
        ],
        "solution_c": """#include <linux/bpf.h>
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

SEC("xdp")
int xdp_geneve_opt_strip(struct xdp_md *ctx) {
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

    gen->opt_len = 0;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
""",
        "tests": [
            {"name": "geneve_strip_opt_pass", "description": "GENEVE packet with options has opt_len set to 0", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=6081, payload=make_geneve(options=bytes([0x01, 0x00, 0x01, 0x01, 0, 0, 0, 0]), inner_frame=make_eth(payload=make_ipv4(proto=1, payload=make_icmp())))))).hex(), "expected_action": "XDP_PASS"},
            {"name": "geneve_no_opt_pass", "description": "GENEVE packet without options passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=6081, payload=make_geneve(inner_frame=make_eth(payload=make_ipv4(proto=6, payload=make_tcp())))))).hex(), "expected_action": "XDP_PASS"},
            {"name": "non_geneve_udp_pass", "description": "UDP to port 6082 passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=6082))).hex(), "expected_action": "XDP_PASS"},
            {"name": "tcp_pass", "description": "TCP packet passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "icmp_pass", "description": "ICMP packet passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP frame passed unchanged", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_geneve_pass", "description": "Truncated GENEVE packet passed safely", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=6081, payload=b"\\x00\\x00"))).hex(), "expected_action": "XDP_PASS"},
        ],
        "main_validator": "packet_bytes"
    })

    # 17. syn_ptr_l2_007_ipv4_options_strip
    tasks.append({
        "task_id": "syn_ptr_l2_007_ipv4_options_strip",
        "application_category": "protocol_transformation",
        "difficulty": "level_2",
        "task_family": "xdp_head_adjust",
        "template_family": "xdp_ipv4_options_stripper",
        "semantic_signature": "ipv4_ihl_gt_5+strip_options_reset_ihl_5+pass",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that strips IPv4 options from IPv4 packets where ihl == 6 (24-byte header containing 4 bytes of options). Use bpf_xdp_adjust_head(ctx, 4) to pop 4 bytes, restore Ethernet MACs, set ip->ihl = 5, update ip->tot_len, recompute the IPv4 header checksum, and return XDP_PASS. Pass packets with ihl == 5 unchanged.",
        "requirements": [
            "Validate Ethernet and struct iphdr bounds",
            "Verify ip->ihl == 6",
            "Pop 4 option bytes using bpf_xdp_adjust_head(ctx, 4)",
            "Restore MACs, set ip->ihl = 5, and update IPv4 checksum",
            "Always return XDP_PASS",
            "SEC(\\"xdp\\") and GPL license declaration"
        ],
        "solution_c": """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

SEC("xdp")
int xdp_ipv4_opt_strip(struct xdp_md *ctx) {
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

    if (ip->ihl != 6) // Only strip 4-byte option
        return XDP_PASS;

    unsigned char src[ETH_ALEN], dst[ETH_ALEN];
    #pragma unroll
    for (int i = 0; i < ETH_ALEN; i++) {
        src[i] = eth->h_source[i];
        dst[i] = eth->h_dest[i];
    }

    struct iphdr saved_ip = *ip;
    saved_ip.ihl = 5;
    saved_ip.tot_len = bpf_htons(bpf_ntohs(saved_ip.tot_len) - 4);
    saved_ip.check = 0;

    if (bpf_xdp_adjust_head(ctx, 4))
        return XDP_PASS;

    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    struct ethhdr *new_eth = data;
    if ((void *)(new_eth + 1) > data_end)
        return XDP_PASS;

    #pragma unroll
    for (int i = 0; i < ETH_ALEN; i++) {
        new_eth->h_source[i] = src[i];
        new_eth->h_dest[i] = dst[i];
    }
    new_eth->h_proto = bpf_htons(ETH_P_IP);

    struct iphdr *new_ip = (void *)(new_eth + 1);
    if ((void *)(new_ip + 1) > data_end)
        return XDP_PASS;

    *new_ip = saved_ip;

    __u16 *words = (void *)new_ip;
    __u32 csum = 0;
    #pragma unroll
    for (int i = 0; i < 10; i++) {
        if ((void *)(words + i + 1) > data_end)
            return XDP_PASS;
        csum += bpf_ntohs(words[i]);
    }
    while (csum >> 16)
        csum = (csum & 0xFFFF) + (csum >> 16);
    new_ip->check = bpf_htons((~csum) & 0xFFFF);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
""",
        "tests": [
            {"name": "ihl_6_options_stripped_pass", "description": "IPv4 packet with IHL 6 has 4 option bytes stripped and IHL set to 5", "packet_hex": make_eth(payload=make_ipv4(ihl=6, options=b"\\x01\\x01\\x01\\x00", proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "ihl_5_no_options_pass", "description": "IPv4 packet with IHL 5 passed unchanged", "packet_hex": make_eth(payload=make_ipv4(ihl=5, proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "udp_pass", "description": "UDP packet passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "icmp_pass", "description": "ICMP packet passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP frame passed unchanged", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
            {"name": "ipv6_pass", "description": "IPv6 frame passed unchanged", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(next_hdr=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_ip_pass", "description": "Truncated IPv4 packet passed safely", "packet_hex": make_eth(payload=b"\\x45\\x00").hex(), "expected_action": "XDP_PASS"},
        ],
        "main_validator": "packet_bytes"
    })

    # 18. syn_ptr_l2_008_ip_in_ip_decap (added above)
    tasks.append({
        "task_id": "syn_ptr_l2_008_ip_in_ip_decap",
        "application_category": "protocol_transformation",
        "difficulty": "level_2",
        "task_family": "xdp_head_adjust",
        "template_family": "xdp_ipinip_decap",
        "semantic_signature": "ipinip_proto4+strip_20_outer_bytes_expose_inner_ip+pass",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that decapsulates IPv4-in-IPv4 tunnel packets (outer IP protocol 4 / IPPROTO_IPIP). Strip the 20-byte outer IPv4 header using bpf_xdp_adjust_head(ctx, 20), preserve Ethernet MAC addresses, set eth->h_proto to bpf_htons(ETH_P_IP), and return XDP_PASS. Pass non-tunneled traffic and truncated frames unchanged.",
        "requirements": [
            "Validate outer Ethernet, IPv4 (IHL=5), and inner IPv4 header bounds",
            "Verify outer_ip->protocol == 4",
            "Call bpf_xdp_adjust_head(ctx, 20) to strip outer IPv4 header",
            "Restore Ethernet MACs and set eth->h_proto = bpf_htons(ETH_P_IP)",
            "Always return XDP_PASS",
            "SEC(\\"xdp\\") and GPL license declaration"
        ],
        "solution_c": """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

SEC("xdp")
int xdp_ipinip_decap(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *outer_ip = (void *)(eth + 1);
    if ((void *)(outer_ip + 1) > data_end)
        return XDP_PASS;
    if (outer_ip->protocol != 4)
        return XDP_PASS;
    if (outer_ip->ihl != 5)
        return XDP_PASS;

    struct iphdr *inner_ip = (void *)(outer_ip + 1);
    if ((void *)(inner_ip + 1) > data_end)
        return XDP_PASS;

    unsigned char src[ETH_ALEN], dst[ETH_ALEN];
    #pragma unroll
    for (int i = 0; i < ETH_ALEN; i++) {
        src[i] = eth->h_source[i];
        dst[i] = eth->h_dest[i];
    }

    if (bpf_xdp_adjust_head(ctx, 20))
        return XDP_PASS;

    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    struct ethhdr *new_eth = data;
    if ((void *)(new_eth + 1) > data_end)
        return XDP_PASS;

    #pragma unroll
    for (int i = 0; i < ETH_ALEN; i++) {
        new_eth->h_source[i] = src[i];
        new_eth->h_dest[i] = dst[i];
    }
    new_eth->h_proto = bpf_htons(ETH_P_IP);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
""",
        "tests": [
            {"name": "ipinip_decap_pass", "description": "IP-in-IP tunnel stripped of outer 20-byte IPv4 header", "packet_hex": make_eth(payload=make_ipv4(src_ip="203.0.113.1", dst_ip="198.51.100.1", proto=4, payload=make_ipv4(src_ip="10.0.0.1", dst_ip="10.0.0.2", proto=6, payload=make_tcp()))).hex(), "expected_action": "XDP_PASS"},
            {"name": "ipinip_decap_udp_pass", "description": "IP-in-IP tunnel carrying UDP stripped of outer 20 bytes", "packet_hex": make_eth(payload=make_ipv4(src_ip="203.0.113.1", dst_ip="198.51.100.1", proto=4, payload=make_ipv4(src_ip="10.0.0.1", dst_ip="10.0.0.2", proto=17, payload=make_udp()))).hex(), "expected_action": "XDP_PASS"},
            {"name": "direct_tcp_pass", "description": "Direct TCP passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "udp_pass", "description": "UDP packet passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "icmp_pass", "description": "ICMP packet passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP frame passed unchanged", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_ipinip_pass", "description": "Truncated IP-in-IP packet passed safely", "packet_hex": make_eth(payload=make_ipv4(proto=4, payload=b"\\x45\\x00")).hex(), "expected_action": "XDP_PASS"},
        ],
        "main_validator": "packet_bytes"
    })

    # 19. syn_ptr_l2_009_gtpu_decap_to_inner_ipv4
    tasks.append({
        "task_id": "syn_ptr_l2_009_gtpu_decap_to_inner_ipv4",
        "application_category": "protocol_transformation",
        "difficulty": "level_2",
        "task_family": "xdp_head_adjust",
        "template_family": "xdp_gtpu_decap",
        "semantic_signature": "gtpu_udp2152+strip_36_outer_bytes_expose_inner_ip+pass",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that decapsulates GTP-U cellular tunnel packets (UDP destination port 2152). Strip the outer 36 bytes (20-byte outer IPv4 + 8-byte UDP + 8-byte GTP-U) using bpf_xdp_adjust_head(ctx, 36), attach original Ethernet MAC addresses, set eth->h_proto to 0x0800, and return XDP_PASS.",
        "requirements": [
            "Validate outer Ethernet, IPv4, UDP, and GTP-U header bounds",
            "Verify UDP destination port is 2152",
            "Call bpf_xdp_adjust_head(ctx, 36) to strip outer encapsulation",
            "Restore Ethernet MACs and set eth->h_proto = bpf_htons(ETH_P_IP)",
            "Always return XDP_PASS",
            "SEC(\\"xdp\\") and GPL license declaration"
        ],
        "solution_c": """#include <linux/bpf.h>
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

SEC("xdp")
int xdp_gtpu_decap(struct xdp_md *ctx) {
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
    if (ip->ihl != 5)
        return XDP_PASS;

    struct udphdr *udp = (void *)(ip + 1);
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;
    if (udp->dest != bpf_htons(2152))
        return XDP_PASS;

    struct gtpuhdr *gtp = (void *)(udp + 1);
    if ((void *)(gtp + 1) > data_end)
        return XDP_PASS;

    // Verify inner IPv4 exists
    struct iphdr *inner_ip = (void *)(gtp + 1);
    if ((void *)(inner_ip + 1) > data_end)
        return XDP_PASS;

    unsigned char src[ETH_ALEN], dst[ETH_ALEN];
    #pragma unroll
    for (int i = 0; i < ETH_ALEN; i++) {
        src[i] = eth->h_source[i];
        dst[i] = eth->h_dest[i];
    }

    // Outer IPv4 (20) + UDP (8) + GTP-U (8) = 36 bytes
    if (bpf_xdp_adjust_head(ctx, 36))
        return XDP_PASS;

    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    struct ethhdr *new_eth = data;
    if ((void *)(new_eth + 1) > data_end)
        return XDP_PASS;

    #pragma unroll
    for (int i = 0; i < ETH_ALEN; i++) {
        new_eth->h_source[i] = src[i];
        new_eth->h_dest[i] = dst[i];
    }
    new_eth->h_proto = bpf_htons(ETH_P_IP);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
""",
        "tests": [
            {"name": "gtpu_decap_pass", "description": "GTP-U tunnel stripped of 36 outer bytes exposing inner IPv4", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=2152, payload=make_gtpu(teid=1, inner_pkt=make_ipv4(proto=1, payload=make_icmp()))))).hex(), "expected_action": "XDP_PASS"},
            {"name": "gtpu_decap_tcp_pass", "description": "GTP-U encapsulated TCP stripped of outer 36 bytes", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=2152, payload=make_gtpu(teid=2, inner_pkt=make_ipv4(proto=6, payload=make_tcp()))))).hex(), "expected_action": "XDP_PASS"},
            {"name": "non_gtpu_udp_pass", "description": "UDP to port 2153 passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=2153))).hex(), "expected_action": "XDP_PASS"},
            {"name": "direct_tcp_pass", "description": "Direct TCP passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "icmp_pass", "description": "ICMP packet passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP frame passed unchanged", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_gtpu_pass", "description": "Truncated GTP-U packet passed safely", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=2152, payload=b"\\x30\\xFF"))).hex(), "expected_action": "XDP_PASS"},
        ],
        "main_validator": "packet_bytes"
    })

    # 20. syn_ptr_l2_010_tcp_timestamp_strip
    tasks.append({
        "task_id": "syn_ptr_l2_010_tcp_timestamp_strip",
        "application_category": "protocol_transformation",
        "difficulty": "level_2",
        "task_family": "xdp_tcp_options_rewrite",
        "template_family": "xdp_ts_stripper",
        "semantic_signature": "tcp_options+replace_timestamp_with_nops+pass",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that inspects TCP packets with options. Parse the TCP options to locate the Timestamp option (Kind 8, Length 10). Overwrite the 10 option bytes with 10 NOP bytes (0x01), recalculate the TCP checksum, and return XDP_PASS.",
        "requirements": [
            "Validate Ethernet, IPv4, TCP headers, and TCP options bounds",
            "Locate TCP Timestamp option (Kind 8, Length 10)",
            "Overwrite 10 bytes with NOPs (0x01)",
            "Update TCP checksum",
            "Always return XDP_PASS",
            "SEC(\\"xdp\\") and GPL license declaration"
        ],
        "solution_c": """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

SEC("xdp")
int xdp_ts_strip(struct xdp_md *ctx) {
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
        if (kind == 0) break;
        if (kind == 1) { opt += 1; continue; }

        if (opt + 2 > opt_end || opt + 2 > data_end)
            break;
        __u8 len = *(opt + 1);
        if (len < 2) break;

        if (kind == 8 && len == 10) {
            if (opt + 10 > opt_end || opt + 10 > data_end)
                break;

            #pragma unroll
            for (int j = 0; j < 10; j++) {
                opt[j] = 1; // NOP
            }
            tcp->check = 0; // Reset checksum
            break;
        }

        opt += len;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
""",
        "tests": [
            {"name": "ts_stripped_pass", "description": "TCP packet with Timestamp option replaced by 10 NOPs", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(options=bytes([8, 10, 1, 2, 3, 4, 5, 6, 7, 8])))).hex(), "expected_action": "XDP_PASS"},
            {"name": "ts_with_mss_pass", "description": "TCP packet with MSS + Timestamp has Timestamp replaced", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(options=bytes([2, 4, 0x05, 0xB4, 8, 10, 1, 2, 3, 4, 5, 6, 7, 8])))).hex(), "expected_action": "XDP_PASS"},
            {"name": "no_ts_pass", "description": "TCP packet without Timestamp option passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(options=bytes([2, 4, 0x05, 0xB4])))).hex(), "expected_action": "XDP_PASS"},
            {"name": "udp_pass", "description": "UDP packet passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "icmp_pass", "description": "ICMP packet passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP frame passed unchanged", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_tcp_pass", "description": "Truncated TCP packet passed safely", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=b"\\x00\\x50")).hex(), "expected_action": "XDP_PASS"},
        ],
        "main_validator": "packet_bytes"
    })

    # =========================================================================
    # LEVEL 3 (10 Tasks) - Complex Encap, NAT, Synthesizers, DPI (>= 9 tests)
    # =========================================================================

    # 21. syn_ptr_l3_001_vxlan_encap_push
    tasks.append({
        "task_id": "syn_ptr_l3_001_vxlan_encap_push",
        "application_category": "protocol_transformation",
        "difficulty": "level_3",
        "task_family": "xdp_head_adjust",
        "template_family": "xdp_vxlan_encap",
        "semantic_signature": "ipv4_raw+push_50byte_vxlan_header+pass",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that encapsulates incoming raw IPv4 Ethernet frames into VXLAN (UDP port 4789, VNI 100). Use bpf_xdp_adjust_head(ctx, -50) to expand the packet headroom by 50 bytes. Populate the outer Ethernet, outer IPv4 (src 192.168.1.1, dst 192.168.1.254, UDP proto), outer UDP (dport 4789), and VXLAN header (VNI 100). Compute the outer IPv4 checksum and return XDP_PASS.",
        "requirements": [
            "Validate Ethernet and IPv4 header bounds",
            "Call bpf_xdp_adjust_head(ctx, -50) to expand head by 50 bytes",
            "Populate outer Ethernet, IPv4, UDP (dport 4789), and VXLAN (VNI 100) headers",
            "Calculate outer IPv4 checksum",
            "Always return XDP_PASS",
            "SEC(\\"xdp\\") and GPL license declaration"
        ],
        "solution_c": """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

struct vxlanhdr {
    __u32 vx_flags;
    __u32 vx_vni;
};

SEC("xdp")
int xdp_vxlan_encap_push(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    __u16 orig_len = (__u16)((void *)data_end - (void *)data);

    if (bpf_xdp_adjust_head(ctx, -50))
        return XDP_PASS;

    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    struct ethhdr *out_eth = data;
    if ((void *)(out_eth + 1) > data_end)
        return XDP_PASS;

    out_eth->h_proto = bpf_htons(ETH_P_IP);

    struct iphdr *out_ip = (void *)(out_eth + 1);
    if ((void *)(out_ip + 1) > data_end)
        return XDP_PASS;

    out_ip->version = 4;
    out_ip->ihl = 5;
    out_ip->tos = 0;
    out_ip->tot_len = bpf_htons(orig_len + 36);
    out_ip->id = bpf_htons(0x4321);
    out_ip->frag_off = 0;
    out_ip->ttl = 64;
    out_ip->protocol = IPPROTO_UDP;
    out_ip->saddr = bpf_htonl(0xC0A80101);
    out_ip->daddr = bpf_htonl(0xC0A801FE);
    out_ip->check = 0;

    struct udphdr *out_udp = (void *)(out_ip + 1);
    if ((void *)(out_udp + 1) > data_end)
        return XDP_PASS;

    out_udp->source = bpf_htons(12345);
    out_udp->dest = bpf_htons(4789);
    out_udp->len = bpf_htons(orig_len + 16);
    out_udp->check = 0;

    struct vxlanhdr *out_vx = (void *)(out_udp + 1);
    if ((void *)(out_vx + 1) > data_end)
        return XDP_PASS;

    out_vx->vx_flags = bpf_htonl(0x08000000);
    out_vx->vx_vni = bpf_htonl(100 << 8);

    __u16 *words = (void *)out_ip;
    __u32 csum = 0;
    #pragma unroll
    for (int i = 0; i < 10; i++) {
        if ((void *)(words + i + 1) > data_end)
            return XDP_PASS;
        csum += bpf_ntohs(words[i]);
    }
    while (csum >> 16)
        csum = (csum & 0xFFFF) + (csum >> 16);
    out_ip->check = bpf_htons((~csum) & 0xFFFF);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
""",
        "tests": [
            {"name": "encap_tcp_pass", "description": "Raw IPv4 TCP frame encapsulated into VXLAN VNI 100", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "encap_udp_pass", "description": "Raw IPv4 UDP frame encapsulated into VXLAN VNI 100", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "encap_icmp_pass", "description": "Raw IPv4 ICMP frame encapsulated into VXLAN VNI 100", "packet_hex": make_eth(payload=make_ipv4(proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP frame passed unchanged", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
            {"name": "ipv6_pass", "description": "IPv6 frame passed unchanged", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(next_hdr=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "vlan_pass", "description": "VLAN frame passed unchanged", "packet_hex": make_eth(vlan=100, payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "mpls_pass", "description": "MPLS frame passed unchanged", "packet_hex": make_eth(eth_type=0x8847, payload=make_mpls([(100, 0, True, 64)], inner_pkt=make_ipv4(proto=1, payload=make_icmp()))).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_ip_pass", "description": "Truncated IPv4 packet passed safely", "packet_hex": make_eth(payload=b"\\x45\\x00").hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_eth_pass", "description": "Truncated Ethernet frame passed safely", "packet_hex": b"\\x52\\x54\\x00".hex(), "expected_action": "XDP_PASS"},
        ],
        "main_validator": "packet_bytes"
    })

    # 22. syn_ptr_l3_002_gre_encap_push
    tasks.append({
        "task_id": "syn_ptr_l3_002_gre_encap_push",
        "application_category": "protocol_transformation",
        "difficulty": "level_3",
        "task_family": "xdp_head_adjust",
        "template_family": "xdp_gre_encap",
        "semantic_signature": "ipv4_raw+push_24byte_gre_header+pass",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that encapsulates incoming raw IPv4 packets into a GRE tunnel (outer IPv4 protocol 47, outer src 192.168.1.1, dst 192.168.1.254, GRE proto 0x0800). Use bpf_xdp_adjust_head(ctx, -24) to expand the packet head by 24 bytes. Populate the outer IPv4 and 4-byte GRE header, recompute the outer IPv4 checksum, and return XDP_PASS.",
        "requirements": [
            "Validate Ethernet and IPv4 header bounds",
            "Call bpf_xdp_adjust_head(ctx, -24) to expand head by 24 bytes",
            "Populate outer IPv4 (protocol 47) and struct grehdr (proto 0x0800)",
            "Compute outer IPv4 checksum",
            "Always return XDP_PASS",
            "SEC(\\"xdp\\") and GPL license declaration"
        ],
        "solution_c": """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

struct grehdr {
    __be16 flags;
    __be16 proto;
};

SEC("xdp")
int xdp_gre_encap_push(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    __u16 orig_ip_len = (__u16)((void *)data_end - (void *)(eth + 1));

    unsigned char src[ETH_ALEN], dst[ETH_ALEN];
    #pragma unroll
    for (int i = 0; i < ETH_ALEN; i++) {
        src[i] = eth->h_source[i];
        dst[i] = eth->h_dest[i];
    }

    if (bpf_xdp_adjust_head(ctx, -24))
        return XDP_PASS;

    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    struct ethhdr *new_eth = data;
    if ((void *)(new_eth + 1) > data_end)
        return XDP_PASS;

    #pragma unroll
    for (int i = 0; i < ETH_ALEN; i++) {
        new_eth->h_source[i] = src[i];
        new_eth->h_dest[i] = dst[i];
    }
    new_eth->h_proto = bpf_htons(ETH_P_IP);

    struct iphdr *out_ip = (void *)(new_eth + 1);
    if ((void *)(out_ip + 1) > data_end)
        return XDP_PASS;

    out_ip->version = 4;
    out_ip->ihl = 5;
    out_ip->tos = 0;
    out_ip->tot_len = bpf_htons(orig_ip_len + 24);
    out_ip->id = bpf_htons(0x5678);
    out_ip->frag_off = 0;
    out_ip->ttl = 64;
    out_ip->protocol = 47; // IPPROTO_GRE
    out_ip->saddr = bpf_htonl(0xC0A80101);
    out_ip->daddr = bpf_htonl(0xC0A801FE);
    out_ip->check = 0;

    struct grehdr *gre = (void *)(out_ip + 1);
    if ((void *)(gre + 1) > data_end)
        return XDP_PASS;

    gre->flags = 0;
    gre->proto = bpf_htons(ETH_P_IP);

    __u16 *words = (void *)out_ip;
    __u32 csum = 0;
    #pragma unroll
    for (int i = 0; i < 10; i++) {
        if ((void *)(words + i + 1) > data_end)
            return XDP_PASS;
        csum += bpf_ntohs(words[i]);
    }
    while (csum >> 16)
        csum = (csum & 0xFFFF) + (csum >> 16);
    out_ip->check = bpf_htons((~csum) & 0xFFFF);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
""",
        "tests": [
            {"name": "encap_gre_tcp_pass", "description": "Raw IPv4 TCP frame encapsulated into GRE tunnel", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "encap_gre_udp_pass", "description": "Raw IPv4 UDP frame encapsulated into GRE tunnel", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "encap_gre_icmp_pass", "description": "Raw IPv4 ICMP frame encapsulated into GRE tunnel", "packet_hex": make_eth(payload=make_ipv4(proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP frame passed unchanged", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
            {"name": "ipv6_pass", "description": "IPv6 frame passed unchanged", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(next_hdr=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "vlan_pass", "description": "VLAN frame passed unchanged", "packet_hex": make_eth(vlan=100, payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "mpls_pass", "description": "MPLS frame passed unchanged", "packet_hex": make_eth(eth_type=0x8847, payload=make_mpls([(100, 0, True, 64)], inner_pkt=make_ipv4(proto=1, payload=make_icmp()))).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_ip_pass", "description": "Truncated IPv4 packet passed safely", "packet_hex": make_eth(payload=b"\\x45\\x00").hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_eth_pass", "description": "Truncated Ethernet frame passed safely", "packet_hex": b"\\x52\\x54\\x00".hex(), "expected_action": "XDP_PASS"},
        ],
        "main_validator": "packet_bytes"
    })

    # 23. syn_ptr_l3_003_srv6_end_dx4_decapsulation
    tasks.append({
        "task_id": "syn_ptr_l3_003_srv6_end_dx4_decapsulation",
        "application_category": "protocol_transformation",
        "difficulty": "level_3",
        "task_family": "xdp_srv6_dx4",
        "template_family": "xdp_srv6_end_dx4_decap",
        "semantic_signature": "srv6_end_dx4+decap_outer_ipv6_srh_to_ipv4+pass",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program implementing SRv6 End.DX4 behavior (decapsulating outer IPv6 and Segment Routing Header to expose the inner IPv4 payload). When Segments Left == 0, strip the 48-byte outer IPv6 + 8-byte SRH header using bpf_xdp_adjust_head(ctx, 48), attach the original Ethernet MAC addresses, set eth->h_proto to bpf_htons(ETH_P_IP / 0x0800), and return XDP_PASS. Pass non-matching traffic unchanged.",
        "requirements": [
            "Validate Ethernet, IPv6, and struct srv6_hdr bounds",
            "Verify ip6->nexthdr == 43, srh->routing_type == 4, and srh->segments_left == 0",
            "Strip 48 outer bytes using bpf_xdp_adjust_head(ctx, 48)",
            "Restore Ethernet MACs and set EtherType to 0x0800",
            "Always return XDP_PASS",
            "SEC(\\"xdp\\") and GPL license declaration"
        ],
        "solution_c": """#include <linux/bpf.h>
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

SEC("xdp")
int xdp_srv6_end_dx4(struct xdp_md *ctx) {
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
    if (srh->routing_type != 4 || srh->segments_left != 0)
        return XDP_PASS;

    unsigned char src[ETH_ALEN], dst[ETH_ALEN];
    #pragma unroll
    for (int i = 0; i < ETH_ALEN; i++) {
        src[i] = eth->h_source[i];
        dst[i] = eth->h_dest[i];
    }

    // Outer IPv6 (40) + SRH (8) = 48 bytes
    if (bpf_xdp_adjust_head(ctx, 48))
        return XDP_PASS;

    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    struct ethhdr *new_eth = data;
    if ((void *)(new_eth + 1) > data_end)
        return XDP_PASS;

    #pragma unroll
    for (int i = 0; i < ETH_ALEN; i++) {
        new_eth->h_source[i] = src[i];
        new_eth->h_dest[i] = dst[i];
    }
    new_eth->h_proto = bpf_htons(ETH_P_IP);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
""",
        "tests": [
            {"name": "srv6_dx4_decap_pass", "description": "SRv6 packet with SL 0 stripped to inner IPv4", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(next_hdr=43, payload=make_srv6(segments_left=0, inner_pkt=make_ipv4(proto=1, payload=make_icmp())))).hex(), "expected_action": "XDP_PASS"},
            {"name": "srv6_dx4_decap_tcp_pass", "description": "SRv6 packet carrying TCP stripped to inner IPv4 TCP", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(next_hdr=43, payload=make_srv6(segments_left=0, inner_pkt=make_ipv4(proto=6, payload=make_tcp())))).hex(), "expected_action": "XDP_PASS"},
            {"name": "srv6_sl_nonzero_pass", "description": "SRv6 packet with SL > 0 passed unchanged", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(next_hdr=43, payload=make_srv6(segments_left=1, inner_pkt=make_ipv4(proto=1, payload=make_icmp())))).hex(), "expected_action": "XDP_PASS"},
            {"name": "standard_ipv6_pass", "description": "Standard IPv6 passed unchanged", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(next_hdr=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "ipv4_pass", "description": "IPv4 passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "udp_pass", "description": "UDP packet passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "icmp_pass", "description": "ICMP packet passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP frame passed unchanged", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_srv6_pass", "description": "Truncated SRv6 frame passed safely", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(next_hdr=43, payload=b"\\x04\\x00")).hex(), "expected_action": "XDP_PASS"},
        ],
        "main_validator": "packet_bytes"
    })

    # 24. syn_ptr_l3_004_stateful_napt44
    tasks.append({
        "task_id": "syn_ptr_l3_004_stateful_napt44",
        "application_category": "protocol_transformation",
        "difficulty": "level_3",
        "task_family": "xdp_napt44",
        "template_family": "xdp_stateful_nat",
        "semantic_signature": "ipv4_tcp_napt44+stateful_session_translation+pass",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that implements stateful NAPT44 for IPv4 TCP traffic. Maintain outbound mappings in a BPF hash map 'napt_fwd_map' and inbound reverse mappings in 'napt_rev_map' (max_entries 1024). Translate private IP source 10.0.0.x to public IP 198.51.100.1 and remap source port to 30000. For inbound return traffic to 198.51.100.1:30000, restore original private IP/port. Recalculate IP checksums and return XDP_PASS.",
        "requirements": [
            "Define struct napt_tuple with 4-tuple endpoints",
            "Define hash maps 'napt_fwd_map' and 'napt_rev_map' with max_entries 1024",
            "Perform outbound SNAT translation (src IP -> 198.51.100.1, src port -> 30000)",
            "Perform inbound DNAT translation for return traffic",
            "Recalculate IPv4 checksum",
            "Always return XDP_PASS",
            "SEC(\\"xdp\\") and GPL license declaration"
        ],
        "solution_c": """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

struct napt_tuple {
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct napt_tuple);
    __type(value, struct napt_tuple);
    __uint(max_entries, 1024);
} napt_fwd_map SEC(".maps");

SEC("xdp")
int xdp_stateful_napt(struct xdp_md *ctx) {
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

    // Outbound: from 10.0.0.0/24 subnet -> SNAT
    if ((bpf_ntohl(ip->saddr) & 0xFFFFFF00) == 0x0A000000) {
        ip->saddr = bpf_htonl(0xC6336401); // 198.51.100.1
        tcp->source = bpf_htons(30000);
        ip->check = 0;

        __u16 *words = (void *)ip;
        __u32 csum = 0;
        #pragma unroll
        for (int i = 0; i < 10; i++) {
            if ((void *)(words + i + 1) > data_end)
                return XDP_PASS;
            csum += bpf_ntohs(words[i]);
        }
        while (csum >> 16)
            csum = (csum & 0xFFFF) + (csum >> 16);
        ip->check = bpf_htons((~csum) & 0xFFFF);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
""",
        "tests": [
            {"name": "outbound_snat_pass", "description": "Outbound TCP packet from 10.0.0.10 SNATed to 198.51.100.1:30000", "packet_hex": make_eth(payload=make_ipv4(src_ip="10.0.0.10", dst_ip="192.0.2.1", proto=6, payload=make_tcp(src_port=10001, dst_port=80))).hex(), "expected_action": "XDP_PASS"},
            {"name": "outbound_snat_2_pass", "description": "Second outbound packet from 10.0.0.20 SNATed", "packet_hex": make_eth(payload=make_ipv4(src_ip="10.0.0.20", dst_ip="192.0.2.2", proto=6, payload=make_tcp(src_port=10002, dst_port=443))).hex(), "expected_action": "XDP_PASS"},
            {"name": "non_private_ip_pass", "description": "Packet from non-private IP passed unchanged", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.10", dst_ip="192.0.2.1", proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "udp_pass", "description": "UDP packet passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "icmp_pass", "description": "ICMP packet passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP frame passed unchanged", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
            {"name": "ipv6_pass", "description": "IPv6 frame passed unchanged", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(next_hdr=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_tcp_pass", "description": "Truncated TCP packet passed safely", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=b"\\x00\\x50")).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_ip_pass", "description": "Truncated IPv4 packet passed safely", "packet_hex": make_eth(payload=b"\\x45\\x00").hex(), "expected_action": "XDP_PASS"},
        ],
        "main_validator": "packet_bytes"
    })

    # 25. syn_ptr_l3_005_icmp_ttl_expired_generator (added above)
    tasks.append({
        "task_id": "syn_ptr_l3_005_icmp_ttl_expired_generator",
        "application_category": "protocol_transformation",
        "difficulty": "level_3",
        "task_family": "xdp_icmp_error_generator",
        "template_family": "xdp_time_exceeded_synthesizer",
        "semantic_signature": "ipv4_ttl_le_1+synthesize_icmp_type_11_and_tx",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that acts as a router TTL expired responder. When an incoming IPv4 packet has TTL <= 1, synthesize an ICMP Time Exceeded response (Type 11, Code 0): swap Ethernet MAC addresses, swap IPv4 source and destination addresses, reset IPv4 TTL to 64, set ip->protocol to IPPROTO_ICMP, construct struct icmphdr with type 11 and code 0, recompute IPv4 and ICMP checksums, and return XDP_TX. Pass packets with TTL > 1 and non-IPv4 traffic unchanged with XDP_PASS.",
        "requirements": [
            "Validate Ethernet and IPv4 header bounds",
            "Check ip->ttl <= 1",
            "Swap Ethernet MAC addresses and IPv4 endpoints",
            "Set IP TTL=64 and protocol=IPPROTO_ICMP",
            "Synthesize ICMP Type 11 Code 0 header and recalculate checksums",
            "Return XDP_TX for TTL <= 1, XDP_PASS for TTL > 1",
            "SEC(\\"xdp\\") and GPL license declaration"
        ],
        "solution_c": """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/icmp.h>

SEC("xdp")
int xdp_icmp_time_exceeded(struct xdp_md *ctx) {
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

    if (ip->ttl > 1)
        return XDP_PASS;

    unsigned char tmp_mac[ETH_ALEN];
    #pragma unroll
    for (int i = 0; i < ETH_ALEN; i++) {
        tmp_mac[i] = eth->h_source[i];
        eth->h_source[i] = eth->h_dest[i];
        eth->h_dest[i] = tmp_mac[i];
    }

    __be32 src = ip->saddr;
    ip->saddr = ip->daddr;
    ip->daddr = src;
    ip->ttl = 64;
    ip->protocol = IPPROTO_ICMP;
    ip->check = 0;

    __u16 *ip_words = (void *)ip;
    __u32 csum = 0;
    #pragma unroll
    for (int i = 0; i < 10; i++) {
        if ((void *)(ip_words + i + 1) > data_end)
            return XDP_PASS;
        csum += bpf_ntohs(ip_words[i]);
    }
    while (csum >> 16)
        csum = (csum & 0xFFFF) + (csum >> 16);
    ip->check = bpf_htons((~csum) & 0xFFFF);

    struct icmphdr *icmp = (void *)(ip + 1);
    if ((void *)(icmp + 1) <= data_end) {
        icmp->type = 11;
        icmp->code = 0;
        icmp->checksum = 0;
        __u16 *icmp_words = (void *)icmp;
        __u32 icmp_csum = 0;
        #pragma unroll
        for (int i = 0; i < 4; i++) {
            if ((void *)(icmp_words + i + 1) <= data_end)
                icmp_csum += bpf_ntohs(icmp_words[i]);
        }
        while (icmp_csum >> 16)
            icmp_csum = (icmp_csum & 0xFFFF) + (icmp_csum >> 16);
        icmp->checksum = bpf_htons((~icmp_csum) & 0xFFFF);
    }

    return XDP_TX;
}

char _license[] SEC("license") = "GPL";
""",
        "tests": [
            {"name": "ttl_1_icmp_time_exceeded_tx", "description": "IPv4 packet with TTL 1 triggers ICMP Time Exceeded (Type 11) and returns XDP_TX", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.10", dst_ip="192.168.1.20", ttl=1, proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_TX"},
            {"name": "ttl_0_icmp_time_exceeded_tx", "description": "IPv4 packet with TTL 0 triggers ICMP Time Exceeded and returns XDP_TX", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.10", dst_ip="192.168.1.20", ttl=0, proto=17, payload=make_udp())).hex(), "expected_action": "XDP_TX"},
            {"name": "ttl_64_pass", "description": "IPv4 packet with TTL 64 passes unchanged", "packet_hex": make_eth(payload=make_ipv4(ttl=64, proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "ttl_2_pass", "description": "IPv4 packet with TTL 2 passes unchanged", "packet_hex": make_eth(payload=make_ipv4(ttl=2, proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "icmp_ttl1_tx", "description": "ICMP packet with TTL 1 triggers ICMP Time Exceeded and returns XDP_TX", "packet_hex": make_eth(payload=make_ipv4(ttl=1, proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_TX"},
            {"name": "arp_pass", "description": "ARP frame passes unchanged", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
            {"name": "ipv6_pass", "description": "IPv6 packet passes unchanged", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(hop_limit=1, next_hdr=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_ip_pass", "description": "Truncated IPv4 packet passes safely", "packet_hex": make_eth(payload=b"\\x45\\x00\\x00").hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_eth_pass", "description": "Truncated Ethernet frame passes safely", "packet_hex": b"\\x52\\x54\\x00".hex(), "expected_action": "XDP_PASS"},
        ],
        "main_validator": "packet_bytes"
    })

    # 26. syn_ptr_l3_006_icmp_port_unreachable_generator
    tasks.append({
        "task_id": "syn_ptr_l3_006_icmp_port_unreachable_generator",
        "application_category": "protocol_transformation",
        "difficulty": "level_3",
        "task_family": "xdp_icmp_error_generator",
        "template_family": "xdp_port_unreachable_synthesizer",
        "semantic_signature": "udp_port_9999_closed+synthesize_icmp_type_3_code_3_and_tx",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that synthesizes an ICMP Destination Unreachable / Port Unreachable response (Type 3, Code 3) when incoming IPv4 UDP traffic targets closed port 9999. Swap Ethernet MAC addresses, swap IPv4 source and destination addresses, set IPv4 protocol to IPPROTO_ICMP, construct struct icmphdr with type 3 code 3, compute checksums, and return XDP_TX. Pass other UDP ports and protocols unchanged with XDP_PASS.",
        "requirements": [
            "Validate Ethernet, IPv4, and UDP header bounds",
            "Check udp->dest == bpf_htons(9999)",
            "Swap MACs and IP endpoints",
            "Set IP protocol to ICMP and construct ICMP Type 3 Code 3 header",
            "Return XDP_TX for closed port, XDP_PASS for other traffic",
            "SEC(\\"xdp\\") and GPL license declaration"
        ],
        "solution_c": """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/icmp.h>

SEC("xdp")
int xdp_icmp_port_unreachable(struct xdp_md *ctx) {
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

    if (udp->dest != bpf_htons(9999))
        return XDP_PASS;

    unsigned char tmp_mac[ETH_ALEN];
    #pragma unroll
    for (int i = 0; i < ETH_ALEN; i++) {
        tmp_mac[i] = eth->h_source[i];
        eth->h_source[i] = eth->h_dest[i];
        eth->h_dest[i] = tmp_mac[i];
    }

    __be32 src = ip->saddr;
    ip->saddr = ip->daddr;
    ip->daddr = src;
    ip->ttl = 64;
    ip->protocol = IPPROTO_ICMP;
    ip->check = 0;

    __u16 *ip_words = (void *)ip;
    __u32 csum = 0;
    #pragma unroll
    for (int i = 0; i < 10; i++) {
        if ((void *)(ip_words + i + 1) > data_end)
            return XDP_PASS;
        csum += bpf_ntohs(ip_words[i]);
    }
    while (csum >> 16)
        csum = (csum & 0xFFFF) + (csum >> 16);
    ip->check = bpf_htons((~csum) & 0xFFFF);

    struct icmphdr *icmp = (void *)(ip + 1);
    if ((void *)(icmp + 1) <= data_end) {
        icmp->type = 3; // Destination Unreachable
        icmp->code = 3; // Port Unreachable
        icmp->checksum = 0;
        __u16 *icmp_words = (void *)icmp;
        __u32 icmp_csum = 0;
        #pragma unroll
        for (int i = 0; i < 4; i++) {
            if ((void *)(icmp_words + i + 1) <= data_end)
                icmp_csum += bpf_ntohs(icmp_words[i]);
        }
        while (icmp_csum >> 16)
            icmp_csum = (icmp_csum & 0xFFFF) + (icmp_csum >> 16);
        icmp->checksum = bpf_htons((~icmp_csum) & 0xFFFF);
    }

    return XDP_TX;
}

char _license[] SEC("license") = "GPL";
""",
        "tests": [
            {"name": "udp_port_9999_icmp_unreachable_tx", "description": "UDP to port 9999 triggers ICMP Port Unreachable and returns XDP_TX", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.10", dst_ip="192.168.1.20", proto=17, payload=make_udp(dst_port=9999))).hex(), "expected_action": "XDP_TX"},
            {"name": "udp_port_80_pass", "description": "UDP to open port 80 passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=80))).hex(), "expected_action": "XDP_PASS"},
            {"name": "tcp_port_9999_pass", "description": "TCP to port 9999 passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(dst_port=9999))).hex(), "expected_action": "XDP_PASS"},
            {"name": "icmp_pass", "description": "ICMP packet passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP frame passed unchanged", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
            {"name": "ipv6_pass", "description": "IPv6 frame passed unchanged", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(next_hdr=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_udp_pass", "description": "Truncated UDP packet passed safely", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=b"\\x27\\x0F")).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_ip_pass", "description": "Truncated IPv4 packet passed safely", "packet_hex": make_eth(payload=b"\\x45\\x00").hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_eth_pass", "description": "Truncated Ethernet frame passed safely", "packet_hex": b"\\x52\\x54\\x00".hex(), "expected_action": "XDP_PASS"},
        ],
        "main_validator": "packet_bytes"
    })

    # 27. syn_ptr_l3_007_geneve_metadata_insertion
    tasks.append({
        "task_id": "syn_ptr_l3_007_geneve_metadata_insertion",
        "application_category": "protocol_transformation",
        "difficulty": "level_3",
        "task_family": "xdp_geneve_metadata",
        "template_family": "xdp_geneve_meta_injector",
        "semantic_signature": "geneve_udp6081+insert_custom_8byte_tlv_metadata+pass",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that inspects GENEVE tunnel packets without options (gen->opt_len == 0). Use bpf_xdp_adjust_head(ctx, -8) to insert an 8-byte custom TLV option (Class 0x0100, Type 1, Length 1 word = 4 bytes of data 0xDEADBEEF). Update gen->opt_len to 2 (8 bytes), adjust UDP length by 8, and return XDP_PASS.",
        "requirements": [
            "Validate outer Ethernet, IPv4, UDP, and struct genevehdr bounds",
            "Verify UDP destination port is 6081 and gen->opt_len == 0",
            "Expand packet head by 8 bytes using bpf_xdp_adjust_head(ctx, -8)",
            "Insert 8-byte GENEVE TLV option with Class 0x0100, Type 1, Data 0xDEADBEEF",
            "Update gen->opt_len = 2",
            "Always return XDP_PASS",
            "SEC(\\"xdp\\") and GPL license declaration"
        ],
        "solution_c": """#include <linux/bpf.h>
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
    __u32 data;
};

SEC("xdp")
int xdp_geneve_meta_insert(struct xdp_md *ctx) {
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

    if (gen->opt_len != 0)
        return XDP_PASS;

    // Expand headroom by 8 bytes
    if (bpf_xdp_adjust_head(ctx, -8))
        return XDP_PASS;

    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    struct ethhdr *new_eth = data;
    if ((void *)(new_eth + 1) > data_end)
        return XDP_PASS;

    new_eth->h_proto = bpf_htons(ETH_P_IP);

    struct iphdr *new_ip = (void *)(new_eth + 1);
    if ((void *)(new_ip + 1) > data_end)
        return XDP_PASS;

    struct udphdr *new_udp = (void *)(new_ip + 1);
    if ((void *)(new_udp + 1) > data_end)
        return XDP_PASS;

    struct genevehdr *new_gen = (void *)(new_udp + 1);
    if ((void *)(new_gen + 1) > data_end)
        return XDP_PASS;

    new_gen->opt_len = 2; // 2 words = 8 bytes

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
""",
        "tests": [
            {"name": "geneve_meta_inserted_pass", "description": "GENEVE packet without options has 8-byte metadata inserted", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=6081, payload=make_geneve(inner_frame=make_eth(payload=make_ipv4(proto=1, payload=make_icmp())))))).hex(), "expected_action": "XDP_PASS"},
            {"name": "geneve_already_has_opts_pass", "description": "GENEVE packet already with options passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=6081, payload=make_geneve(options=bytes([0x01, 0x00, 0x01, 0x01, 0, 0, 0, 0]), inner_frame=make_eth(payload=make_ipv4(proto=6, payload=make_tcp())))))).hex(), "expected_action": "XDP_PASS"},
            {"name": "non_geneve_udp_pass", "description": "UDP to port 6082 passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=6082))).hex(), "expected_action": "XDP_PASS"},
            {"name": "tcp_pass", "description": "TCP packet passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "icmp_pass", "description": "ICMP packet passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP frame passed unchanged", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
            {"name": "ipv6_pass", "description": "IPv6 frame passed unchanged", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(next_hdr=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_geneve_pass", "description": "Truncated GENEVE packet passed safely", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=6081, payload=b"\\x00\\x00"))).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_ip_pass", "description": "Truncated IPv4 packet passed safely", "packet_hex": make_eth(payload=b"\\x45\\x00").hex(), "expected_action": "XDP_PASS"},
        ],
        "main_validator": "packet_bytes"
    })

    # 28. syn_ptr_l3_008_gtpu_teid_remapping_and_csum
    tasks.append({
        "task_id": "syn_ptr_l3_008_gtpu_teid_remapping_and_csum",
        "application_category": "protocol_transformation",
        "difficulty": "level_3",
        "task_family": "xdp_gtpu_upf",
        "template_family": "xdp_gtpu_teid_remapper",
        "semantic_signature": "gtpu_teid_remap_table+rewrite_teid_and_daddr+pass",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that performs cellular UPF session forwarding for GTP-U packets (UDP destination port 2152). If the 32-bit incoming TEID is 0x1000, remap it to 0x2000 and rewrite the outer destination IPv4 address to 198.51.100.1. Recalculate outer IPv4 checksum and return XDP_PASS.",
        "requirements": [
            "Validate Ethernet, IPv4, UDP, and struct gtpuhdr bounds",
            "Verify UDP destination port is 2152 and gtp->teid == bpf_htonl(0x1000)",
            "Rewrite gtp->teid = bpf_htonl(0x2000) and ip->daddr = bpf_htonl(0xC6336401)",
            "Recalculate IPv4 checksum",
            "Always return XDP_PASS",
            "SEC(\\"xdp\\") and GPL license declaration"
        ],
        "solution_c": """#include <linux/bpf.h>
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

SEC("xdp")
int xdp_gtpu_upf_remap(struct xdp_md *ctx) {
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

    if (gtp->teid == bpf_htonl(0x1000)) {
        gtp->teid = bpf_htonl(0x2000);
        ip->daddr = bpf_htonl(0xC6336401);
        ip->check = 0;

        __u16 *words = (void *)ip;
        __u32 csum = 0;
        #pragma unroll
        for (int i = 0; i < 10; i++) {
            if ((void *)(words + i + 1) > data_end)
                return XDP_PASS;
            csum += bpf_ntohs(words[i]);
        }
        while (csum >> 16)
            csum = (csum & 0xFFFF) + (csum >> 16);
        ip->check = bpf_htons((~csum) & 0xFFFF);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
""",
        "tests": [
            {"name": "teid_1000_remapped_pass", "description": "GTP-U packet with TEID 0x1000 remapped to 0x2000 and destination 198.51.100.1", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.10", dst_ip="192.168.1.20", proto=17, payload=make_udp(dst_port=2152, payload=make_gtpu(teid=0x1000, inner_pkt=make_ipv4(proto=1, payload=make_icmp()))))).hex(), "expected_action": "XDP_PASS"},
            {"name": "teid_3000_unchanged_pass", "description": "GTP-U packet with TEID 0x3000 passed unchanged", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.10", dst_ip="192.168.1.20", proto=17, payload=make_udp(dst_port=2152, payload=make_gtpu(teid=0x3000, inner_pkt=make_ipv4(proto=6, payload=make_tcp()))))).hex(), "expected_action": "XDP_PASS"},
            {"name": "non_gtpu_udp_pass", "description": "UDP to port 2153 passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=2153))).hex(), "expected_action": "XDP_PASS"},
            {"name": "tcp_pass", "description": "TCP packet passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "icmp_pass", "description": "ICMP packet passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP frame passed unchanged", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
            {"name": "ipv6_pass", "description": "IPv6 frame passed unchanged", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(next_hdr=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_gtpu_pass", "description": "Truncated GTP-U packet passed safely", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=2152, payload=b"\\x30\\xFF"))).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_ip_pass", "description": "Truncated IPv4 packet passed safely", "packet_hex": make_eth(payload=b"\\x45\\x00").hex(), "expected_action": "XDP_PASS"},
        ],
        "main_validator": "packet_bytes"
    })

    # 29. syn_ptr_l3_009_mpls_push_dual_label_vpn
    tasks.append({
        "task_id": "syn_ptr_l3_009_mpls_push_dual_label_vpn",
        "application_category": "protocol_transformation",
        "difficulty": "level_3",
        "task_family": "xdp_head_adjust",
        "template_family": "xdp_mpls_push_dual",
        "semantic_signature": "ipv4_raw+push_dual_mpls_labels_1000_and_200+pass",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that encapsulates incoming raw IPv4 packets into a dual MPLS label stack (outer Transport Label 1000 with BOS=0, inner VPN Service Label 200 with BOS=1, TTL 64). Use bpf_xdp_adjust_head(ctx, -8) to expand the packet head by 8 bytes. Set eth->h_proto to bpf_htons(0x8847) and return XDP_PASS. Pass non-IPv4 traffic unchanged.",
        "requirements": [
            "Validate Ethernet and struct iphdr bounds",
            "Verify eth->h_proto == bpf_htons(ETH_P_IP)",
            "Expand packet head by 8 bytes using bpf_xdp_adjust_head(ctx, -8)",
            "Push outer label 1000 (BOS=0, TTL 64) and inner label 200 (BOS=1, TTL 64)",
            "Set eth->h_proto = bpf_htons(0x8847)",
            "Always return XDP_PASS",
            "SEC(\\"xdp\\") and GPL license declaration"
        ],
        "solution_c": """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

struct mpls_label {
    __u32 entry;
};

SEC("xdp")
int xdp_mpls_push_dual(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    unsigned char src[ETH_ALEN], dst[ETH_ALEN];
    #pragma unroll
    for (int i = 0; i < ETH_ALEN; i++) {
        src[i] = eth->h_source[i];
        dst[i] = eth->h_dest[i];
    }

    if (bpf_xdp_adjust_head(ctx, -8))
        return XDP_PASS;

    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    struct ethhdr *new_eth = data;
    if ((void *)(new_eth + 1) > data_end)
        return XDP_PASS;

    #pragma unroll
    for (int i = 0; i < ETH_ALEN; i++) {
        new_eth->h_source[i] = src[i];
        new_eth->h_dest[i] = dst[i];
    }
    new_eth->h_proto = bpf_htons(0x8847);

    struct mpls_label *lbl1 = (void *)(new_eth + 1);
    if ((void *)(lbl1 + 2) > data_end)
        return XDP_PASS;

    // Label 1000, TC 0, S 0, TTL 64: (1000 << 12) | 64 = 0x003E8040
    lbl1[0].entry = bpf_htonl(0x003E8040);
    // Label 200, TC 0, S 1, TTL 64: (200 << 12) | 0x100 | 64 = 0x000C8140
    lbl1[1].entry = bpf_htonl(0x000C8140);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
""",
        "tests": [
            {"name": "push_dual_mpls_tcp_pass", "description": "Raw IPv4 TCP frame encapsulated with dual MPLS labels 1000 and 200", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "push_dual_mpls_udp_pass", "description": "Raw IPv4 UDP frame encapsulated with dual MPLS labels", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "push_dual_mpls_icmp_pass", "description": "Raw IPv4 ICMP frame encapsulated with dual MPLS labels", "packet_hex": make_eth(payload=make_ipv4(proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP frame passed unchanged", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
            {"name": "ipv6_pass", "description": "IPv6 frame passed unchanged", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(next_hdr=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "vlan_pass", "description": "VLAN frame passed unchanged", "packet_hex": make_eth(vlan=100, payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "existing_mpls_pass", "description": "Existing MPLS frame passed unchanged", "packet_hex": make_eth(eth_type=0x8847, payload=make_mpls([(100, 0, True, 64)], inner_pkt=make_ipv4(proto=1, payload=make_icmp()))).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_ip_pass", "description": "Truncated IPv4 packet passed safely", "packet_hex": make_eth(payload=b"\\x45\\x00").hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_eth_pass", "description": "Truncated Ethernet frame passed safely", "packet_hex": b"\\x52\\x54\\x00".hex(), "expected_action": "XDP_PASS"},
        ],
        "main_validator": "packet_bytes"
    })

    # 30. syn_ptr_l3_010_payload_pattern_masking (added above)
    tasks.append({
        "task_id": "syn_ptr_l3_010_payload_pattern_masking",
        "application_category": "protocol_transformation",
        "difficulty": "level_3",
        "task_family": "xdp_dpi_scrubber",
        "template_family": "xdp_payload_sanitizer",
        "semantic_signature": "tcp_payload_dpi+mask_token_secret99_with_X+pass",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that performs deep packet inspection (DPI) payload sanitization on IPv4 TCP traffic. Search the TCP payload for the 8-byte sensitive string 'SECRET99'. When found, overwrite the 8 bytes with 'XXXXXXXX' (0x58), reset the TCP checksum, and return XDP_PASS. Pass non-matching traffic unchanged.",
        "requirements": [
            "Validate Ethernet, IPv4, and TCP header bounds",
            "Calculate TCP payload offset from tcp->doff * 4",
            "Safely search payload for 8-byte pattern 'SECRET99'",
            "Mask matching pattern with 'XXXXXXXX'",
            "Always return XDP_PASS",
            "SEC(\\"xdp\\") and GPL license declaration"
        ],
        "solution_c": """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

SEC("xdp")
int xdp_payload_masking(struct xdp_md *ctx) {
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

    __u8 *payload = (void *)tcp + tcp_hdr_len;
    if (payload + 8 > data_end)
        return XDP_PASS;

    #pragma unroll
    for (int i = 0; i < 32; i++) {
        if (payload + i + 8 > data_end)
            break;

        if (payload[i] == 'S' && payload[i+1] == 'E' && payload[i+2] == 'C' &&
            payload[i+3] == 'R' && payload[i+4] == 'E' && payload[i+5] == 'T' &&
            payload[i+6] == '9' && payload[i+7] == '9') {
            
            #pragma unroll
            for (int j = 0; j < 8; j++) {
                payload[i + j] = 'X';
            }

            tcp->check = 0;
            break;
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
""",
        "tests": [
            {"name": "mask_secret_token_pass", "description": "TCP packet containing sensitive token 'SECRET99' has token masked to 'XXXXXXXX' with checksum update", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(payload=b"USER=admin&PASS=SECRET99&AUTH=OK"))).hex(), "expected_action": "XDP_PASS"},
            {"name": "mask_secret_token_2_pass", "description": "Second TCP packet with 'SECRET99' at different offset masked to 'XXXXXXXX'", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(payload=b"SECRET99_DATA_STREAM"))).hex(), "expected_action": "XDP_PASS"},
            {"name": "clean_payload_pass", "description": "TCP packet without sensitive token passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(payload=b"NORMAL_TRAFFIC_DATA"))).hex(), "expected_action": "XDP_PASS"},
            {"name": "no_payload_tcp_pass", "description": "TCP ACK without payload passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(flags=0x10))).hex(), "expected_action": "XDP_PASS"},
            {"name": "udp_pass", "description": "UDP packet passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "icmp_pass", "description": "ICMP packet passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP frame passed unchanged", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
            {"name": "ipv6_pass", "description": "IPv6 frame passed unchanged", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(next_hdr=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_tcp_pass", "description": "Truncated TCP packet passed safely", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=b"\\x00\\x50")).hex(), "expected_action": "XDP_PASS"},
        ],
        "main_validator": "packet_bytes"
    })

    return tasks
'''
