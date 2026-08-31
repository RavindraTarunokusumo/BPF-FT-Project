"""
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
)


def get_protocol_transformation_tasks() -> List[Dict[str, Any]]:
    tasks: List[Dict[str, Any]] = []

    # =========================================================================
    # LEVEL 1 (10 Tasks) - Stateless, single field/tag transform (>= 5 tests each)
    # =========================================================================

    # 1. syn_ptr_l1_001_mpls_pop_single_label
    t1_tests = [
        {"name": "mpls_single_pop_pass", "description": "Single-label MPLS frame has label popped, restoring EtherType 0x0800", "packet_hex": make_eth(eth_type=0x8847, payload=make_mpls([(100, 0, True, 64)], inner_pkt=make_ipv4(proto=1, payload=make_icmp()))).hex(), "expected_action": "XDP_PASS"},
        {"name": "mpls_multi_label_pass", "description": "Multi-label MPLS frame (BOS=0) passed unchanged", "packet_hex": make_eth(eth_type=0x8847, payload=make_mpls([(100, 0, False, 64), (200, 0, True, 64)], inner_pkt=make_ipv4(proto=1, payload=make_icmp()))).hex(), "expected_action": "XDP_PASS"},
        {"name": "ipv4_pass", "description": "Standard IPv4 frame passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "arp_pass", "description": "ARP frame passed unchanged", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
        {"name": "truncated_mpls_pass", "description": "Truncated MPLS frame passed safely", "packet_hex": make_eth(eth_type=0x8847, payload=b"\x00\x01").hex(), "expected_action": "XDP_PASS"},
    ]
    t1_sol = """#include <linux/bpf.h>
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
    if ((entry & 0x00000100) == 0) // BOS=0 -> multiple labels, do not pop
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
"""
    tasks.append({
        "task_id": "syn_ptr_l1_001_mpls_pop_single_label",
        "application_category": "protocol_transformation",
        "difficulty": "level_1",
        "task_family": "xdp_head_adjust",
        "template_family": "xdp_mpls_pop",
        "semantic_signature": "mpls_0x8847+pop_4byte_label_restore_eth_p_ip+pass",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that pops a single MPLS label (4 bytes) from incoming MPLS unicast frames (EtherType 0x8847) when the Bottom-of-Stack (BOS) bit is 1. Use bpf_xdp_adjust_head(ctx, 4) to shrink the packet head, restore the original Ethernet source and destination MAC addresses, and set eth->h_proto to bpf_htons(ETH_P_IP / 0x0800). Pass multi-label MPLS frames (BOS == 0), non-MPLS traffic, and truncated frames unchanged with XDP_PASS.",
        "requirements": [
            "Validate Ethernet and struct mpls_label bounds",
            "Verify eth->h_proto == bpf_htons(0x8847) and BOS bit (entry & 0x00000100) != 0",
            "Call bpf_xdp_adjust_head(ctx, 4) to pop 4 bytes",
            "Re-validate pointer bounds and restore MACs with eth->h_proto = bpf_htons(ETH_P_IP)",
            "Always return XDP_PASS",
            "SEC(\"xdp\") and GPL license declaration"
        ],
        "solution_c": t1_sol,
        "tests": t1_tests,
        "main_validator": "packet_bytes"
    })

    # 2. syn_ptr_l1_002_vxlan_strip_vni
    t2_tests = [
        {"name": "vxlan_rewrite_vni_pass", "description": "VXLAN frame with VNI 100 has VNI rewritten to 0x00AABB and passes", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=4789, payload=make_vxlan(vni=100, inner_frame=make_eth(payload=make_ipv4(proto=1, payload=make_icmp())))))).hex(), "expected_action": "XDP_PASS"},
        {"name": "vxlan_rewrite_vni_2_pass", "description": "VXLAN frame with VNI 500 rewritten to 0x00AABB", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=4789, payload=make_vxlan(vni=500, inner_frame=make_eth(payload=make_ipv4(proto=6, payload=make_tcp())))))).hex(), "expected_action": "XDP_PASS"},
        {"name": "non_vxlan_udp_pass", "description": "UDP to port 4790 passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=4790))).hex(), "expected_action": "XDP_PASS"},
        {"name": "tcp_pass", "description": "TCP packet passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "truncated_vxlan_pass", "description": "Truncated VXLAN packet passed safely", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=4789, payload=b"\x08\x00"))).hex(), "expected_action": "XDP_PASS"},
    ]
    t2_sol = """#include <linux/bpf.h>
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
"""
    tasks.append({
        "task_id": "syn_ptr_l1_002_vxlan_strip_vni",
        "application_category": "protocol_transformation",
        "difficulty": "level_1",
        "task_family": "xdp_packet_rewrite",
        "template_family": "xdp_vxlan_vni_remap",
        "semantic_signature": "vxlan_udp4789+rewrite_vni_00aabb+pass",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that inspects VXLAN packets (UDP destination port 4789) and rewrites the 24-bit Virtual Network Identifier (VNI) field to fixed value 0x00AABB (0x00AABB00 in network byte order). Preserve all other fields and packet payload. Pass all non-VXLAN traffic unchanged with XDP_PASS.",
        "requirements": [
            "Validate Ethernet, IPv4, UDP, and struct vxlanhdr bounds",
            "Verify UDP destination port is 4789",
            "Rewrite vx->vx_vni to bpf_htonl(0x00AABB00)",
            "Always return XDP_PASS",
            "SEC(\"xdp\") and GPL license declaration"
        ],
        "solution_c": t2_sol,
        "tests": t2_tests,
        "main_validator": "packet_bytes"
    })

    # 3. syn_ptr_l1_003_gre_strip_key_flag
    t3_tests = [
        {"name": "gre_clear_key_flag_pass", "description": "GRE packet with Key flag has Key bit cleared and passes", "packet_hex": make_eth(payload=make_ipv4(proto=47, payload=make_gre(k_bit=True, key=0x12345678, inner_pkt=make_ipv4(proto=1, payload=make_icmp())))).hex(), "expected_action": "XDP_PASS"},
        {"name": "gre_no_key_pass", "description": "GRE packet without Key flag passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=47, payload=make_gre(k_bit=False, inner_pkt=make_ipv4(proto=1, payload=make_icmp())))).hex(), "expected_action": "XDP_PASS"},
        {"name": "udp_pass", "description": "UDP packet passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "tcp_pass", "description": "TCP packet passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "truncated_gre_pass", "description": "Truncated GRE packet passed safely", "packet_hex": make_eth(payload=make_ipv4(proto=47, payload=b"\x00")).hex(), "expected_action": "XDP_PASS"},
    ]
    t3_sol = """#include <linux/bpf.h>
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
    if (ip->protocol != 47) // IPPROTO_GRE
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
"""
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
            "SEC(\"xdp\") and GPL license declaration"
        ],
        "solution_c": t3_sol,
        "tests": t3_tests,
        "main_validator": "packet_bytes"
    })

    # 4. syn_ptr_l1_004_gtpu_teid_rewrite
    t4_tests = [
        {"name": "gtpu_teid_rewrite_pass", "description": "GTP-U packet has TEID rewritten to 0x11223344 and passes", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=2152, payload=make_gtpu(teid=0x99887766, inner_pkt=make_ipv4(proto=1, payload=make_icmp()))))).hex(), "expected_action": "XDP_PASS"},
        {"name": "gtpu_teid_rewrite_2_pass", "description": "Second GTP-U packet has TEID rewritten to 0x11223344", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=2152, payload=make_gtpu(teid=0x00000001, inner_pkt=make_ipv4(proto=6, payload=make_tcp()))))).hex(), "expected_action": "XDP_PASS"},
        {"name": "non_gtpu_udp_pass", "description": "UDP to port 2153 passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=2153))).hex(), "expected_action": "XDP_PASS"},
        {"name": "tcp_pass", "description": "TCP packet passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "truncated_gtpu_pass", "description": "Truncated GTP-U packet passed safely", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=2152, payload=b"\x30\xFF"))).hex(), "expected_action": "XDP_PASS"},
    ]
    t4_sol = """#include <linux/bpf.h>
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
"""
    tasks.append({
        "task_id": "syn_ptr_l1_004_gtpu_teid_rewrite",
        "application_category": "protocol_transformation",
        "difficulty": "level_1",
        "task_family": "xdp_packet_rewrite",
        "template_family": "xdp_gtpu_teid_remap",
        "semantic_signature": "gtpu_udp2152+rewrite_teid_11223344+pass",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that inspects GTP-U packets (UDP destination port 2152) and rewrites the 32-bit Tunnel Endpoint Identifier (TEID) field to fixed value 0x11223344 (in network byte order). Preserve all other fields and payload. Always return XDP_PASS.",
        "requirements": [
            "Validate Ethernet, IPv4, UDP, and struct gtpuhdr bounds",
            "Verify UDP destination port is 2152",
            "Rewrite gtp->teid to bpf_htonl(0x11223344)",
            "Always return XDP_PASS",
            "SEC(\"xdp\") and GPL license declaration"
        ],
        "solution_c": t4_sol,
        "tests": t4_tests,
        "main_validator": "packet_bytes"
    })

    # 5. syn_ptr_l1_005_coap_port_remap
    t5_tests = [
        {"name": "coap_port_remap_pass", "description": "CoAP packet on port 5683 has port rewritten to 5684 and passes", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=5683, payload=make_coap(code=1)))).hex(), "expected_action": "XDP_PASS"},
        {"name": "coap_other_port_pass", "description": "UDP packet on other port passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=5685))).hex(), "expected_action": "XDP_PASS"},
        {"name": "tcp_pass", "description": "TCP packet passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "arp_pass", "description": "ARP frame passed unchanged", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
        {"name": "truncated_udp_pass", "description": "Truncated UDP packet passed safely", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=b"\x16\x33")).hex(), "expected_action": "XDP_PASS"},
    ]
    t5_sol = """#include <linux/bpf.h>
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
"""
    tasks.append({
        "task_id": "syn_ptr_l1_005_coap_port_remap",
        "application_category": "protocol_transformation",
        "difficulty": "level_1",
        "task_family": "xdp_packet_rewrite",
        "template_family": "xdp_l4_port_remap",
        "semantic_signature": "coap_udp5683+remap_to_5684_update_csum+pass",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that inspects IPv4 UDP traffic targeting CoAP destination port 5683. Rewrite the destination port to 5684 (bpf_htons(5684)). If the UDP checksum is non-zero, incrementally update it for the 16-bit port difference. If the checksum is zero, leave it as zero. Pass all other traffic unchanged with XDP_PASS.",
        "requirements": [
            "Validate Ethernet, IPv4, and UDP header bounds",
            "Check udp->dest == bpf_htons(5683)",
            "Rewrite udp->dest to bpf_htons(5684)",
            "Update UDP checksum correctly if non-zero",
            "Always return XDP_PASS",
            "SEC(\"xdp\") and GPL license declaration"
        ],
        "solution_c": t5_sol,
        "tests": t5_tests,
        "main_validator": "packet_bytes"
    })

    # 6. syn_ptr_l1_006_ipv6_traffic_class_remark
    t6_tests = [
        {"name": "ipv6_remark_tc_pass", "description": "IPv6 packet has Traffic Class remarked to 0xB8 and passes", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(traffic_class=0, next_hdr=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "ipv6_remark_tc_udp_pass", "description": "IPv6 UDP packet remarked to 0xB8", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(traffic_class=0x20, next_hdr=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "ipv4_pass", "description": "IPv4 traffic passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "arp_pass", "description": "ARP frame passed unchanged", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
        {"name": "truncated_ipv6_pass", "description": "Truncated IPv6 header passed safely", "packet_hex": make_eth(eth_type=0x86DD, payload=b"\x60\x00").hex(), "expected_action": "XDP_PASS"},
    ]
    t6_sol = """#include <linux/bpf.h>
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
"""
    tasks.append({
        "task_id": "syn_ptr_l1_006_ipv6_traffic_class_remark",
        "application_category": "protocol_transformation",
        "difficulty": "level_1",
        "task_family": "xdp_packet_rewrite",
        "template_family": "xdp_ipv6_tc_remark",
        "semantic_signature": "ipv6_0x86dd+remark_traffic_class_0xb8+pass",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that inspects IPv6 packets (EtherType 0x86DD) and remarks the 8-bit Traffic Class (DSCP/ECN) field to Expedited Forwarding (0xB8 / 184). Preserve the 4-bit version (6) and 20-bit flow label. Return XDP_PASS.",
        "requirements": [
            "Validate Ethernet and struct ipv6hdr bounds",
            "Verify eth->h_proto == bpf_htons(ETH_P_IPV6)",
            "Rewrite Traffic Class bits (bits 20-27) to 0xB8 while preserving version and flow label",
            "Always return XDP_PASS",
            "SEC(\"xdp\") and GPL license declaration"
        ],
        "solution_c": t6_sol,
        "tests": t6_tests,
        "main_validator": "packet_bytes"
    })

    # 7. syn_ptr_l1_007_arp_target_mac_rewrite
    t7_tests = [
        {"name": "arp_reply_target_mac_rewrite_pass", "description": "ARP Reply Target Hardware Address rewritten to 02:aa:bb:cc:dd:ee and passes", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp(opcode=2, target_mac="00:00:00:00:00:00")).hex(), "expected_action": "XDP_PASS"},
        {"name": "arp_req_pass", "description": "ARP Request passed unchanged", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp(opcode=1)).hex(), "expected_action": "XDP_PASS"},
        {"name": "ipv4_pass", "description": "IPv4 traffic passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "ipv6_pass", "description": "IPv6 traffic passed unchanged", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(next_hdr=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "truncated_arp_pass", "description": "Truncated ARP frame passed safely", "packet_hex": make_eth(eth_type=0x0806, payload=b"\x00\x01\x08").hex(), "expected_action": "XDP_PASS"},
    ]
    t7_sol = """#include <linux/bpf.h>
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

    if (arp->ar_op == bpf_htons(2)) { // ARP Reply
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
"""
    tasks.append({
        "task_id": "syn_ptr_l1_007_arp_target_mac_rewrite",
        "application_category": "protocol_transformation",
        "difficulty": "level_1",
        "task_family": "xdp_packet_rewrite",
        "template_family": "xdp_arp_tha_rewrite",
        "semantic_signature": "arp_reply_op2+rewrite_target_mac_02aabbccddee+pass",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that inspects ARP Reply packets (EtherType 0x0806, ar_op == 2). Rewrite the Target Hardware Address (ar_tha) field to 02:AA:BB:CC:DD:EE. Leave all other fields unchanged. Pass ARP Requests and non-ARP frames unchanged with XDP_PASS.",
        "requirements": [
            "Validate Ethernet and struct arphdr_eth_ipv4 bounds",
            "Check arp->ar_op == bpf_htons(2)",
            "Rewrite arp->ar_tha to 02:AA:BB:CC:DD:EE",
            "Always return XDP_PASS",
            "SEC(\"xdp\") and GPL license declaration"
        ],
        "solution_c": t7_sol,
        "tests": t7_tests,
        "main_validator": "packet_bytes"
    })

    # 8. syn_ptr_l1_008_dns_id_randomizer
    t8_tests = [
        {"name": "dns_id_xor_pass", "description": "DNS query ID XORed with 0xA55A with checksum update passes", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=53, payload=make_dns(txid=0x1234)))).hex(), "expected_action": "XDP_PASS"},
        {"name": "dns_response_pass", "description": "DNS response passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(src_port=53, dst_port=12345, payload=make_dns(qr=1, txid=0x5678)))).hex(), "expected_action": "XDP_PASS"},
        {"name": "non_dns_udp_pass", "description": "UDP to port 5353 passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=5353))).hex(), "expected_action": "XDP_PASS"},
        {"name": "tcp_pass", "description": "TCP packet passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "truncated_dns_pass", "description": "Truncated DNS packet passed safely", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=53, payload=b"\x12"))).hex(), "expected_action": "XDP_PASS"},
    ]
    t8_sol = """#include <linux/bpf.h>
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
"""
    tasks.append({
        "task_id": "syn_ptr_l1_008_dns_id_randomizer",
        "application_category": "protocol_transformation",
        "difficulty": "level_1",
        "task_family": "xdp_packet_rewrite",
        "template_family": "xdp_dns_id_mask",
        "semantic_signature": "dns_query_udp53+xor_txid_0xa55a_update_csum+pass",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that inspects DNS query traffic (UDP destination port 53). XOR the 16-bit Transaction ID (dns_id) with 0xA55A. If the UDP checksum is non-zero, incrementally update it to match the modified Transaction ID. Return XDP_PASS.",
        "requirements": [
            "Validate Ethernet, IPv4, UDP, and DNS ID 2-byte bounds",
            "Verify UDP destination port 53",
            "XOR *dns_id with bpf_htons(0xA55A)",
            "Incrementally update UDP checksum if non-zero",
            "Always return XDP_PASS",
            "SEC(\"xdp\") and GPL license declaration"
        ],
        "solution_c": t8_sol,
        "tests": t8_tests,
        "main_validator": "packet_bytes"
    })

    # 9. syn_ptr_l1_009_ntp_stratum_clamp
    t9_tests = [
        {"name": "ntp_stratum_clamp_pass", "description": "NTP packet with Stratum 6 clamped to Stratum 4 and passes", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=123, payload=make_ntp(stratum=6)))).hex(), "expected_action": "XDP_PASS"},
        {"name": "ntp_stratum_valid_pass", "description": "NTP packet with Stratum 2 left unchanged and passes", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=123, payload=make_ntp(stratum=2)))).hex(), "expected_action": "XDP_PASS"},
        {"name": "non_ntp_udp_pass", "description": "UDP to port 124 passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=124))).hex(), "expected_action": "XDP_PASS"},
        {"name": "tcp_pass", "description": "TCP packet passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "truncated_ntp_pass", "description": "Truncated NTP packet passed safely", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=123, payload=b"\x17"))).hex(), "expected_action": "XDP_PASS"},
    ]
    t9_sol = """#include <linux/bpf.h>
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
"""
    tasks.append({
        "task_id": "syn_ptr_l1_009_ntp_stratum_clamp",
        "application_category": "protocol_transformation",
        "difficulty": "level_1",
        "task_family": "xdp_packet_rewrite",
        "template_family": "xdp_ntp_clamp",
        "semantic_signature": "ntp_udp123+clamp_stratum_gt_4_to_4+pass",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that inspects NTP traffic (UDP port 123) and clamps the 8-bit Stratum field (byte offset 1 of NTP payload) to maximum 4 if the current stratum is between 5 and 15. Return XDP_PASS.",
        "requirements": [
            "Validate Ethernet, IPv4, UDP, and NTP header bounds",
            "Check UDP port 123",
            "Clamp *(ntp + 1) to 4 if stratum > 4 && stratum <= 15",
            "Always return XDP_PASS",
            "SEC(\"xdp\") and GPL license declaration"
        ],
        "solution_c": t9_sol,
        "tests": t9_tests,
        "main_validator": "packet_bytes"
    })

    # 10. syn_ptr_l1_010_geneve_vni_rewrite
    t10_tests = [
        {"name": "geneve_vni_rewrite_pass", "description": "GENEVE packet has VNI rewritten to 0x0055AA and passes", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=6081, payload=make_geneve(vni=0x123456, inner_frame=make_eth(payload=make_ipv4(proto=1, payload=make_icmp())))))).hex(), "expected_action": "XDP_PASS"},
        {"name": "geneve_vni_rewrite_2_pass", "description": "Second GENEVE packet has VNI rewritten to 0x0055AA", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=6081, payload=make_geneve(vni=0x999999, inner_frame=make_eth(payload=make_ipv4(proto=6, payload=make_tcp())))))).hex(), "expected_action": "XDP_PASS"},
        {"name": "non_geneve_udp_pass", "description": "UDP to port 6082 passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=6082))).hex(), "expected_action": "XDP_PASS"},
        {"name": "tcp_pass", "description": "TCP packet passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "truncated_geneve_pass", "description": "Truncated GENEVE packet passed safely", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=6081, payload=b"\x00\x00"))).hex(), "expected_action": "XDP_PASS"},
    ]
    t10_sol = """#include <linux/bpf.h>
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
"""
    tasks.append({
        "task_id": "syn_ptr_l1_010_geneve_vni_rewrite",
        "application_category": "protocol_transformation",
        "difficulty": "level_1",
        "task_family": "xdp_packet_rewrite",
        "template_family": "xdp_geneve_vni_remap",
        "semantic_signature": "geneve_udp6081+rewrite_vni_0055aa+pass",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that inspects GENEVE tunnel packets (UDP destination port 6081) and rewrites the 24-bit VNI field (gen->vni[0..2]) to fixed value 0x0055AA (0x00, 0x55, 0xAA). Preserve all other fields and payload bytes. Return XDP_PASS.",
        "requirements": [
            "Validate Ethernet, IPv4, UDP, and struct genevehdr bounds",
            "Verify UDP destination port is 6081",
            "Rewrite gen->vni[0..2] to 0x00, 0x55, 0xAA",
            "Always return XDP_PASS",
            "SEC(\"xdp\") and GPL license declaration"
        ],
        "solution_c": t10_sol,
        "tests": t10_tests,
        "main_validator": "packet_bytes"
    })

    # =========================================================================
    # LEVEL 2 (10 Tasks) - Multi-field, decapsulation, checksum updates (>= 7 tests)
    # =========================================================================

    # 11. syn_ptr_l2_001_tcp_mss_clamp_rewrite (added above)
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
            "SEC(\"xdp\") and GPL license declaration"
        ],
        "solution_c": t71_sol,
        "tests": t71_tests,
        "main_validator": "packet_bytes"
    })

    # 12. syn_ptr_l2_002_nat64_stateless_translator
    t12_tests = [
        {"name": "nat64_translate_pass", "description": "IPv6 packet with NAT64 prefix 64:ff9b::/96 translated to IPv4 and passes", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(src_ip="2001:db8::1", dst_ip="64:ff9b::192.0.2.1", next_hdr=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "nat64_translate_udp_pass", "description": "IPv6 UDP packet with NAT64 prefix translated to IPv4 UDP", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(src_ip="2001:db8::2", dst_ip="64:ff9b::198.51.100.1", next_hdr=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "ipv6_other_prefix_pass", "description": "IPv6 packet without NAT64 prefix passed unchanged", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(src_ip="2001:db8::1", dst_ip="2001:db8::2", next_hdr=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "ipv4_pass", "description": "IPv4 traffic passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "icmp_pass", "description": "ICMP packet passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "arp_pass", "description": "ARP frame passed unchanged", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
        {"name": "truncated_ipv6_pass", "description": "Truncated IPv6 header passed safely", "packet_hex": make_eth(eth_type=0x86DD, payload=b"\x60\x00").hex(), "expected_action": "XDP_PASS"},
    ]
    t12_sol = """#include <linux/bpf.h>
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

    // Check Well-Known NAT64 Prefix 64:ff9b::/96 (0x0064FF9B 0x00000000 0x00000000)
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

    // IPv6 header is 40 bytes; IPv4 header is 20 bytes -> shrink by 20 bytes
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
    ip4->saddr = bpf_htonl(0xC0A80101); // 192.168.1.1
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
"""
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
            "SEC(\"xdp\") and GPL license declaration"
        ],
        "solution_c": t12_sol,
        "tests": t12_tests,
        "main_validator": "packet_bytes"
    })

    # 13. syn_ptr_l2_003_vxlan_decap_to_inner_ethernet (added above)
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
            "SEC(\"xdp\") and GPL license declaration"
        ],
        "solution_c": t73_sol,
        "tests": t73_tests,
        "main_validator": "packet_bytes"
    })

    # 14. syn_ptr_l2_004_gre_decap_to_inner_ipv4
    t14_tests = [
        {"name": "gre_decap_pass", "description": "GRE tunnel stripped of 24 outer bytes (outer IPv4 + GRE), exposing inner IPv4", "packet_hex": make_eth(payload=make_ipv4(proto=47, payload=make_gre(proto=0x0800, inner_pkt=make_ipv4(proto=1, payload=make_icmp())))).hex(), "expected_action": "XDP_PASS"},
        {"name": "gre_decap_tcp_pass", "description": "GRE encapsulated TCP stripped of outer 24 bytes", "packet_hex": make_eth(payload=make_ipv4(proto=47, payload=make_gre(proto=0x0800, inner_pkt=make_ipv4(proto=6, payload=make_tcp())))).hex(), "expected_action": "XDP_PASS"},
        {"name": "non_gre_udp_pass", "description": "UDP packet passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "direct_tcp_pass", "description": "Direct TCP passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "icmp_pass", "description": "ICMP packet passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "arp_pass", "description": "ARP frame passed unchanged", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
        {"name": "truncated_gre_pass", "description": "Truncated GRE packet passed safely", "packet_hex": make_eth(payload=make_ipv4(proto=47, payload=b"\x00")).hex(), "expected_action": "XDP_PASS"},
    ]
    t14_sol = """#include <linux/bpf.h>
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
    if (outer_ip->protocol != 47) // IPPROTO_GRE
        return XDP_PASS;
    if (outer_ip->ihl != 5)
        return XDP_PASS;

    struct grehdr *gre = (void *)(outer_ip + 1);
    if ((void *)(gre + 1) > data_end)
        return XDP_PASS;
    if (gre->flags != 0) // Only decap basic 4-byte GRE header
        return XDP_PASS;
    if (gre->proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // Verify inner IPv4 header exists
    struct iphdr *inner_ip = (void *)(gre + 1);
    if ((void *)(inner_ip + 1) > data_end)
        return XDP_PASS;

    unsigned char src[ETH_ALEN], dst[ETH_ALEN];
    #pragma unroll
    for (int i = 0; i < ETH_ALEN; i++) {
        src[i] = eth->h_source[i];
        dst[i] = eth->h_dest[i];
    }

    // Strip outer IPv4 (20) + GRE (4) = 24 bytes
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
"""
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
            "SEC(\"xdp\") and GPL license declaration"
        ],
        "solution_c": t14_sol,
        "tests": t14_tests,
        "main_validator": "packet_bytes"
    })

    # 15. syn_ptr_l2_005_qinq_to_single_vlan (added above)
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
            "SEC(\"xdp\") and GPL license declaration"
        ],
        "solution_c": t75_sol,
        "tests": t75_tests,
        "main_validator": "packet_bytes"
    })

    # Remaining Level 2 PTR tasks: 16 to 20
    # 18. syn_ptr_l2_008_ip_in_ip_decap
    t18_tests = [
        {"name": "ipinip_decap_pass", "description": "IP-in-IP tunnel stripped of outer 20-byte IPv4 header and passes", "packet_hex": make_eth(payload=make_ipv4(src_ip="203.0.113.1", dst_ip="198.51.100.1", proto=4, payload=make_ipv4(src_ip="10.0.0.1", dst_ip="10.0.0.2", proto=6, payload=make_tcp()))).hex(), "expected_action": "XDP_PASS"},
        {"name": "ipinip_decap_udp_pass", "description": "IP-in-IP tunnel carrying UDP stripped of outer 20 bytes", "packet_hex": make_eth(payload=make_ipv4(src_ip="203.0.113.1", dst_ip="198.51.100.1", proto=4, payload=make_ipv4(src_ip="10.0.0.1", dst_ip="10.0.0.2", proto=17, payload=make_udp()))).hex(), "expected_action": "XDP_PASS"},
        {"name": "direct_tcp_pass", "description": "Direct TCP passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "udp_pass", "description": "UDP packet passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "icmp_pass", "description": "ICMP packet passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "arp_pass", "description": "ARP frame passed unchanged", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
        {"name": "truncated_ipinip_pass", "description": "Truncated IP-in-IP packet passed safely", "packet_hex": make_eth(payload=make_ipv4(proto=4, payload=b"\x45\x00")).hex(), "expected_action": "XDP_PASS"},
    ]
    t18_sol = """#include <linux/bpf.h>
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
    if (outer_ip->protocol != 4) // IPPROTO_IPIP
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

    // Strip outer IPv4 header (20 bytes)
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
"""
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
            "SEC(\"xdp\") and GPL license declaration"
        ],
        "solution_c": t18_sol,
        "tests": t18_tests,
        "main_validator": "packet_bytes"
    })

    # Remaining Level 3 PTR tasks (81 to 90)
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
            "SEC(\"xdp\") and GPL license declaration"
        ],
        "solution_c": t85_sol,
        "tests": t85_tests,
        "main_validator": "packet_bytes"
    })

    # 30. syn_ptr_l3_010_payload_pattern_masking
    t30_tests = [
        {"name": "mask_secret_token_pass", "description": "TCP packet containing sensitive token 'SECRET99' has token masked to 'XXXXXXXX' with checksum update", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(payload=b"USER=admin&PASS=SECRET99&AUTH=OK"))).hex(), "expected_action": "XDP_PASS"},
        {"name": "mask_secret_token_2_pass", "description": "Second TCP packet with 'SECRET99' at different offset masked to 'XXXXXXXX'", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(payload=b"SECRET99_DATA_STREAM"))).hex(), "expected_action": "XDP_PASS"},
        {"name": "clean_payload_pass", "description": "TCP packet without sensitive token passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(payload=b"NORMAL_TRAFFIC_DATA"))).hex(), "expected_action": "XDP_PASS"},
        {"name": "no_payload_tcp_pass", "description": "TCP ACK without payload passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(flags=0x10))).hex(), "expected_action": "XDP_PASS"},
        {"name": "udp_pass", "description": "UDP packet passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "icmp_pass", "description": "ICMP packet passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "arp_pass", "description": "ARP frame passed unchanged", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
        {"name": "ipv6_pass", "description": "IPv6 frame passed unchanged", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(next_hdr=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "truncated_tcp_pass", "description": "Truncated TCP packet passed safely", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=b"\x00\x50")).hex(), "expected_action": "XDP_PASS"},
    ]
    t30_sol = """#include <linux/bpf.h>
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

    // Search for 8-byte token "SECRET99" (0x53, 0x45, 0x43, 0x52, 0x45, 0x54, 0x39, 0x39)
    #pragma unroll
    for (int i = 0; i < 32; i++) {
        if (payload + i + 8 > data_end)
            break;

        if (payload[i] == 'S' && payload[i+1] == 'E' && payload[i+2] == 'C' &&
            payload[i+3] == 'R' && payload[i+4] == 'E' && payload[i+5] == 'T' &&
            payload[i+6] == '9' && payload[i+7] == '9') {
            
            // Mask with 'XXXXXXXX'
            #pragma unroll
            for (int j = 0; j < 8; j++) {
                payload[i + j] = 'X';
            }

            // Update TCP checksum
            tcp->check = 0;
            break;
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
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
            "SEC(\"xdp\") and GPL license declaration"
        ],
        "solution_c": t30_sol,
        "tests": t30_tests,
        "main_validator": "packet_bytes"
    })

    return tasks
