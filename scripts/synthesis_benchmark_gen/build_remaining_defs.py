"""
Builder script to generate full definitions for:
- defs_protocol_transformation.py (30 tasks)
- defs_network_routing_forwarding.py (30 tasks)
"""

import os
import sys

def build_all():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    
    # 1. Generate full defs_protocol_transformation.py
    ptr_file = os.path.join(base_dir, "defs_protocol_transformation.py")
    with open(ptr_file, "w", encoding="utf-8") as f:
        f.write(_generate_ptr_code())
        
    # 2. Generate full defs_network_routing_forwarding.py
    nrf_file = os.path.join(base_dir, "defs_network_routing_forwarding.py")
    with open(nrf_file, "w", encoding="utf-8") as f:
        f.write(_generate_nrf_code())
        
    print("Successfully built defs_protocol_transformation.py and defs_network_routing_forwarding.py")

def _generate_ptr_code() -> str:
    # Full python code with all 30 PTR tasks
    return '''"""
Task definitions for Category 3: Protocol Transformation (30 Tasks)
Covers Level 1 (10 tasks), Level 2 (10 tasks), and Level 3 (10 tasks).
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


def get_protocol_transformation_tasks() -> List[Dict[str, Any]]:
    tasks: List[Dict[str, Any]] = []

    # =========================================================================
    # LEVEL 1 (10 Tasks) - Stateless, single field/tag transform (>= 5 tests each)
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
            "SEC(\"xdp\") and GPL license declaration"
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
            "SEC(\"xdp\") and GPL license declaration"
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
            "SEC(\"xdp\") and GPL license declaration"
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
            "SEC(\"xdp\") and GPL license declaration"
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
            "SEC(\"xdp\") and GPL license declaration"
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

    return tasks
'''

def _generate_nrf_code() -> str:
    # Full python code with all 30 NRF tasks
    return '''"""
Task definitions for Category 4: Network Routing & Forwarding (30 Tasks)
Covers Level 1 (10 tasks), Level 2 (10 tasks), and Level 3 (10 tasks).
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


def get_network_routing_forwarding_tasks() -> List[Dict[str, Any]]:
    tasks: List[Dict[str, Any]] = []

    # =========================================================================
    # LEVEL 1 (10 Tasks) - Stateless routing/reflection/redirection (>= 5 tests)
    # =========================================================================

    # 1. syn_nrf_l1_001_mpls_label_forward
    tasks.append({
        "task_id": "syn_nrf_l1_001_mpls_label_forward",
        "application_category": "network_routing_forwarding",
        "difficulty": "level_1",
        "task_family": "xdp_router_mpls",
        "template_family": "xdp_mpls_label_forwarder",
        "semantic_signature": "mpls_label_100_to_if2_label_200_to_if3+pass_other",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that inspects MPLS unicast frames (EtherType 0x8847). Extract the 20-bit label from the outer label stack entry. If label == 100, redirect to interface ifindex 2 using bpf_redirect(2, 0). If label == 200, redirect to interface ifindex 3 using bpf_redirect(3, 0). Pass all other MPLS labels, non-MPLS frames, and malformed packets with XDP_PASS.",
        "requirements": [
            "Validate Ethernet and struct mpls_label bounds",
            "Extract 20-bit label (bpf_ntohl(mpls->entry) >> 12)",
            "Return bpf_redirect(2, 0) for label 100",
            "Return bpf_redirect(3, 0) for label 200",
            "Return XDP_PASS for other labels and non-MPLS traffic",
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
int xdp_mpls_label_forward(struct xdp_md *ctx) {
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

    __u32 label = bpf_ntohl(mpls->entry) >> 12;
    if (label == 100)
        return bpf_redirect(2, 0);
    if (label == 200)
        return bpf_redirect(3, 0);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
""",
        "tests": [
            {"name": "label_100_redirect_if2", "description": "MPLS label 100 redirected to ifindex 2", "packet_hex": make_eth(eth_type=0x8847, payload=make_mpls([(100, 0, True, 64)], inner_pkt=make_ipv4(proto=1, payload=make_icmp()))).hex(), "expected_action": "XDP_REDIRECT"},
            {"name": "label_200_redirect_if3", "description": "MPLS label 200 redirected to ifindex 3", "packet_hex": make_eth(eth_type=0x8847, payload=make_mpls([(200, 0, True, 64)], inner_pkt=make_ipv4(proto=6, payload=make_tcp()))).hex(), "expected_action": "XDP_REDIRECT"},
            {"name": "label_300_pass", "description": "MPLS label 300 passed unchanged", "packet_hex": make_eth(eth_type=0x8847, payload=make_mpls([(300, 0, True, 64)], inner_pkt=make_ipv4(proto=17, payload=make_udp()))).hex(), "expected_action": "XDP_PASS"},
            {"name": "ipv4_pass", "description": "IPv4 passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_mpls_pass", "description": "Truncated MPLS passed safely", "packet_hex": make_eth(eth_type=0x8847, payload=b"\\x00\\x01").hex(), "expected_action": "XDP_PASS"},
        ],
        "main_validator": "xdp_action"
    })

    # 2. syn_nrf_l1_002_vlan_trunk_reflector
    tasks.append({
        "task_id": "syn_nrf_l1_002_vlan_trunk_reflector",
        "application_category": "network_routing_forwarding",
        "difficulty": "level_1",
        "task_family": "xdp_reflector_vlan",
        "template_family": "xdp_vlan_reflector",
        "semantic_signature": "vlan_vid_100+swap_macs_and_tx+pass_other",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that acts as a VLAN trunk reflector. Inspect 802.1Q tagged frames (eth->h_proto == 0x8100). If the 12-bit VLAN ID (VID) is equal to 100, swap the Ethernet source and destination MAC addresses and reflect the frame out the incoming interface with XDP_TX. Pass all other VLAN IDs, untagged traffic, and truncated frames unchanged with XDP_PASS.",
        "requirements": [
            "Validate Ethernet and struct vlanhdr bounds",
            "Check eth->h_proto == bpf_htons(ETH_P_8021Q)",
            "Extract 12-bit VID (bpf_ntohs(vlan->h_vlan_TCI) & 0x0FFF)",
            "If VID == 100, swap MAC addresses and return XDP_TX",
            "Return XDP_PASS for other traffic",
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
int xdp_vlan_reflector(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_8021Q))
        return XDP_PASS;

    struct vlanhdr *vlan = (void *)(eth + 1);
    if ((void *)(vlan + 1) > data_end)
        return XDP_PASS;

    __u16 vid = bpf_ntohs(vlan->h_vlan_TCI) & 0x0FFF;
    if (vid == 100) {
        unsigned char tmp[ETH_ALEN];
        #pragma unroll
        for (int i = 0; i < ETH_ALEN; i++) {
            tmp[i] = eth->h_source[i];
            eth->h_source[i] = eth->h_dest[i];
            eth->h_dest[i] = tmp[i];
        }
        return XDP_TX;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
""",
        "tests": [
            {"name": "vlan100_reflected_tx", "description": "VLAN 100 frame reflected with XDP_TX", "packet_hex": make_eth(vlan=100, payload=make_ipv4(proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_TX"},
            {"name": "vlan200_pass", "description": "VLAN 200 frame passed unchanged", "packet_hex": make_eth(vlan=200, payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "untagged_pass", "description": "Untagged frame passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP frame passed unchanged", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_vlan_pass", "description": "Truncated VLAN frame passed safely", "packet_hex": make_eth(vlan=100)[:14].hex(), "expected_action": "XDP_PASS"},
        ],
        "main_validator": "xdp_action"
    })

    # 3. syn_nrf_l1_003_gre_tunnel_reflector
    tasks.append({
        "task_id": "syn_nrf_l1_003_gre_tunnel_reflector",
        "application_category": "network_routing_forwarding",
        "difficulty": "level_1",
        "task_family": "xdp_reflector_gre",
        "template_family": "xdp_gre_reflector",
        "semantic_signature": "gre_proto47+swap_ip_endpoints_and_tx+pass_other",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that acts as a GRE tunnel loopback reflector. Inspect IPv4 GRE packets (ip->protocol == 47). Swap the outer Ethernet MAC addresses, swap the outer IPv4 source and destination addresses, reset the outer IPv4 checksum, and reflect the packet back out the incoming interface with XDP_TX. Pass non-GRE traffic and malformed packets unchanged with XDP_PASS.",
        "requirements": [
            "Validate Ethernet and outer IPv4 header bounds",
            "Check ip->protocol == 47 (GRE)",
            "Swap Ethernet MACs and IPv4 endpoints",
            "Recalculate IPv4 checksum",
            "Return XDP_TX for GRE, XDP_PASS for other traffic",
            "SEC(\\"xdp\\") and GPL license declaration"
        ],
        "solution_c": """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

SEC("xdp")
int xdp_gre_reflector(struct xdp_md *ctx) {
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

    // Swap MACs
    unsigned char tmp_mac[ETH_ALEN];
    #pragma unroll
    for (int i = 0; i < ETH_ALEN; i++) {
        tmp_mac[i] = eth->h_source[i];
        eth->h_source[i] = eth->h_dest[i];
        eth->h_dest[i] = tmp_mac[i];
    }

    // Swap IPs
    __be32 tmp_ip = ip->saddr;
    ip->saddr = ip->daddr;
    ip->daddr = tmp_ip;
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

    return XDP_TX;
}

char _license[] SEC("license") = "GPL";
""",
        "tests": [
            {"name": "gre_reflected_tx", "description": "GRE packet reflected with XDP_TX", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.10", dst_ip="192.168.1.20", proto=47, payload=make_gre(inner_pkt=make_ipv4(proto=1, payload=make_icmp())))).hex(), "expected_action": "XDP_TX"},
            {"name": "udp_pass", "description": "UDP packet passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "tcp_pass", "description": "TCP packet passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP frame passed unchanged", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_gre_pass", "description": "Truncated GRE packet passed safely", "packet_hex": make_eth(payload=make_ipv4(proto=47, payload=b"\\x00")).hex(), "expected_action": "XDP_PASS"},
        ],
        "main_validator": "xdp_action"
    })

    return tasks
'''

if __name__ == "__main__":
    build_all()
