"""
Task definitions for Category 1: Packet Filtering & Security (30 Tasks)
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


def get_packet_filtering_security_tasks() -> List[Dict[str, Any]]:
    tasks: List[Dict[str, Any]] = []

    # =========================================================================
    # LEVEL 1 (10 Tasks) - Stateless, single header check / action
    # =========================================================================

    # 1. syn_pfs_l1_001_geneve_vni_filter
    t1_tests = [
        {"name": "geneve_match_drop", "description": "GENEVE packet with VNI 0x001234 must be dropped", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=6081, payload=make_geneve(vni=0x001234, inner_frame=make_eth(payload=make_ipv4(proto=1, payload=make_icmp())))))).hex(), "expected_action": "XDP_DROP"},
        {"name": "geneve_other_vni_pass", "description": "GENEVE packet with VNI 0x005678 must pass", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=6081, payload=make_geneve(vni=0x005678, inner_frame=make_eth(payload=make_ipv4(proto=1, payload=make_icmp())))))).hex(), "expected_action": "XDP_PASS"},
        {"name": "geneve_wrong_port_pass", "description": "UDP packet to port 6080 must pass", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=6080, payload=b"NOT_GENEVE"))).hex(), "expected_action": "XDP_PASS"},
        {"name": "tcp_pass", "description": "TCP packet must pass", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "truncated_geneve_pass", "description": "Truncated GENEVE packet must pass safely", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=6081, payload=b"\x00\x00"))).hex(), "expected_action": "XDP_PASS"},
    ]
    t1_sol = """#include <linux/bpf.h>
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
int xdp_geneve_filter(struct xdp_md *ctx) {
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

    __u32 vni = ((__u32)gen->vni[0] << 16) | ((__u32)gen->vni[1] << 8) | (__u32)gen->vni[2];
    if (vni == 0x001234)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    tasks.append({
        "task_id": "syn_pfs_l1_001_geneve_vni_filter",
        "application_category": "packet_filtering_security",
        "difficulty": "level_1",
        "task_family": "xdp_tunnel_filter",
        "template_family": "xdp_geneve_vni_filter",
        "semantic_signature": "geneve_udp6081+vni_001234+drop",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that inspects UDP packets on destination port 6081 (GENEVE encapsulation). Parse the GENEVE tunnel header and drop packets where the 24-bit Virtual Network Identifier (VNI) is exactly 0x001234. Pass all other GENEVE VNIs, non-GENEVE UDP packets, TCP/ICMP/other protocols, non-IPv4 frames, and malformed/truncated packets with XDP_PASS.",
        "requirements": [
            "Validate Ethernet header bounds and check eth->h_proto == bpf_htons(ETH_P_IP)",
            "Validate IPv4 header bounds (supporting variable IHL) and check ip->protocol == IPPROTO_UDP",
            "Validate UDP header bounds and check udp->dest == bpf_htons(6081)",
            "Validate GENEVE header bounds (struct genevehdr)",
            "Extract 24-bit VNI from gen->vni[0..2] and drop if equal to 0x001234",
            "Return XDP_PASS for non-matching or malformed packets",
            "Include SEC(\"xdp\") and GPL license declaration"
        ],
        "solution_c": t1_sol,
        "tests": t1_tests,
        "main_validator": "packet_action"
    })

    # 2. syn_pfs_l1_002_vxlan_flags_filter
    t2_tests = [
        {"name": "vxlan_bad_flags_drop", "description": "VXLAN packet with non-zero reserved flags must be dropped", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=4789, payload=make_vxlan(vni=100, flags=0x09, inner_frame=make_eth(payload=make_ipv4(proto=1, payload=make_icmp())))))).hex(), "expected_action": "XDP_DROP"},
        {"name": "vxlan_valid_pass", "description": "VXLAN packet with standard flags 0x08 must pass", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=4789, payload=make_vxlan(vni=100, flags=0x08, inner_frame=make_eth(payload=make_ipv4(proto=1, payload=make_icmp())))))).hex(), "expected_action": "XDP_PASS"},
        {"name": "vxlan_other_port_pass", "description": "UDP packet on other port must pass", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=4788, payload=b"NOT_VXLAN"))).hex(), "expected_action": "XDP_PASS"},
        {"name": "tcp_pass", "description": "TCP packet must pass", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "truncated_vxlan_pass", "description": "Truncated VXLAN header must pass safely", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=4789, payload=b"\x08\x00"))).hex(), "expected_action": "XDP_PASS"},
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
int xdp_vxlan_flags_filter(struct xdp_md *ctx) {
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

    __u32 flags = bpf_ntohl(vx->vx_flags);
    // Standard VXLAN flag has bit 27 set (0x08000000). Any other bits in flags are reserved.
    if ((flags & 0xF7FFFFFF) != 0)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    tasks.append({
        "task_id": "syn_pfs_l1_002_vxlan_flags_filter",
        "application_category": "packet_filtering_security",
        "difficulty": "level_1",
        "task_family": "xdp_tunnel_filter",
        "template_family": "xdp_vxlan_flags_filter",
        "semantic_signature": "vxlan_udp4789+reserved_flags_nonzero+drop",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that inspects VXLAN traffic on UDP destination port 4789. Parse the 8-byte VXLAN header and check the 32-bit flags field. The only valid flag in RFC 7348 is the I-bit (0x08000000 in network order / bit 27). If any reserved flag bits are non-zero (i.e. flags & ~0x08000000 != 0), drop the packet with XDP_DROP. Pass all valid VXLAN frames, non-VXLAN traffic, and malformed packets with XDP_PASS.",
        "requirements": [
            "Validate Ethernet and IPv4 header bounds (accounting for variable IHL)",
            "Verify UDP destination port is 4789",
            "Validate VXLAN header bounds (8 bytes)",
            "Check flags field: drop if reserved bits are set",
            "Pass all other and truncated packets safely",
            "SEC(\"xdp\") and GPL license declaration"
        ],
        "solution_c": t2_sol,
        "tests": t2_tests,
        "main_validator": "packet_action"
    })

    # 3. syn_pfs_l1_003_gre_checksum_drop
    t3_tests = [
        {"name": "gre_csum_present_drop", "description": "GRE packet with Checksum Present bit set must be dropped", "packet_hex": make_eth(payload=make_ipv4(proto=47, payload=make_gre(c_bit=True, inner_pkt=make_ipv4(proto=1, payload=make_icmp())))).hex(), "expected_action": "XDP_DROP"},
        {"name": "gre_no_csum_pass", "description": "GRE packet without Checksum Present bit must pass", "packet_hex": make_eth(payload=make_ipv4(proto=47, payload=make_gre(c_bit=False, inner_pkt=make_ipv4(proto=1, payload=make_icmp())))).hex(), "expected_action": "XDP_PASS"},
        {"name": "udp_pass", "description": "UDP packet must pass", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "tcp_pass", "description": "TCP packet must pass", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "truncated_gre_pass", "description": "Truncated GRE packet must pass safely", "packet_hex": make_eth(payload=make_ipv4(proto=47, payload=b"\x80")).hex(), "expected_action": "XDP_PASS"},
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
int xdp_gre_csum_filter(struct xdp_md *ctx) {
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
    // Bit 15 (0x8000) indicates Checksum Present
    if (flags & 0x8000)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    tasks.append({
        "task_id": "syn_pfs_l1_003_gre_checksum_drop",
        "application_category": "packet_filtering_security",
        "difficulty": "level_1",
        "task_family": "xdp_gre_filter",
        "template_family": "xdp_gre_csum_filter",
        "semantic_signature": "gre_proto47+csum_present_bit+drop",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that inspects GRE packets (IPv4 protocol 47). Parse the GRE fixed header and check the Checksum Present flag (bit 15 / 0x8000 in host byte order). If the Checksum Present bit is set, drop the packet with XDP_DROP. Pass GRE packets without the checksum bit, non-GRE traffic, and malformed frames with XDP_PASS.",
        "requirements": [
            "Validate Ethernet and IPv4 header bounds",
            "Verify ip->protocol == 47 (GRE)",
            "Validate GRE header bounds (struct grehdr)",
            "Extract 16-bit flags and drop if bit 0x8000 is set",
            "Pass all other traffic and truncated packets",
            "SEC(\"xdp\") and GPL license declaration"
        ],
        "solution_c": t3_sol,
        "tests": t3_tests,
        "main_validator": "packet_action"
    })

    # 4. syn_pfs_l1_004_gtpu_echo_req_drop
    t4_tests = [
        {"name": "gtpu_echo_req_drop", "description": "GTP-U packet with Message Type 1 (Echo Request) must be dropped", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=2152, payload=make_gtpu(msg_type=1)))).hex(), "expected_action": "XDP_DROP"},
        {"name": "gtpu_gpdu_pass", "description": "GTP-U packet with Message Type 255 (G-PDU user data) must pass", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=2152, payload=make_gtpu(msg_type=255, inner_pkt=make_ipv4(proto=1, payload=make_icmp()))))).hex(), "expected_action": "XDP_PASS"},
        {"name": "gtpu_echo_reply_pass", "description": "GTP-U packet with Message Type 2 (Echo Reply) must pass", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=2152, payload=make_gtpu(msg_type=2)))).hex(), "expected_action": "XDP_PASS"},
        {"name": "udp_other_port_pass", "description": "UDP packet on port 2153 must pass", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=2153, payload=b"\x30\x01\x00\x00"))).hex(), "expected_action": "XDP_PASS"},
        {"name": "truncated_gtpu_pass", "description": "Truncated GTP-U packet must pass safely", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=2152, payload=b"\x30\x01"))).hex(), "expected_action": "XDP_PASS"},
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
int xdp_gtpu_echo_filter(struct xdp_md *ctx) {
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

    if (gtp->msg_type == 1) // Echo Request
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    tasks.append({
        "task_id": "syn_pfs_l1_004_gtpu_echo_req_drop",
        "application_category": "packet_filtering_security",
        "difficulty": "level_1",
        "task_family": "xdp_gtpu_filter",
        "template_family": "xdp_gtpu_msgtype_filter",
        "semantic_signature": "gtpu_udp2152+msgtype_1_echo_req+drop",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that inspects GTP-U tunnel traffic on UDP destination port 2152. Parse the 8-byte GTP-U header and check the Message Type field. If the Message Type is 1 (Echo Request), drop the packet with XDP_DROP. Pass other GTP-U message types (e.g. 255 G-PDU, 2 Echo Reply), non-GTP-U UDP packets, and malformed frames with XDP_PASS.",
        "requirements": [
            "Validate Ethernet, IPv4, and UDP header bounds",
            "Check UDP destination port is 2152",
            "Validate GTP-U header bounds (struct gtpuhdr)",
            "Drop packet if gtp->msg_type == 1",
            "Pass all non-matching and truncated packets",
            "SEC(\"xdp\") and GPL license declaration"
        ],
        "solution_c": t4_sol,
        "tests": t4_tests,
        "main_validator": "packet_action"
    })

    # 5. syn_pfs_l1_005_mpls_bos_filter
    t5_tests = [
        {"name": "mpls_nobos_drop", "description": "MPLS unicast frame where top label has BOS=0 (stacked) must be dropped", "packet_hex": make_eth(eth_type=0x8847, payload=make_mpls([(100, 0, False, 64), (200, 0, True, 64)], inner_pkt=make_ipv4(proto=1, payload=make_icmp()))).hex(), "expected_action": "XDP_DROP"},
        {"name": "mpls_bos_pass", "description": "MPLS unicast frame where top label has BOS=1 must pass", "packet_hex": make_eth(eth_type=0x8847, payload=make_mpls([(100, 0, True, 64)], inner_pkt=make_ipv4(proto=1, payload=make_icmp()))).hex(), "expected_action": "XDP_PASS"},
        {"name": "ipv4_pass", "description": "Standard IPv4 frame must pass", "packet_hex": make_eth(payload=make_ipv4(proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "arp_pass", "description": "ARP frame must pass", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
        {"name": "truncated_mpls_pass", "description": "Truncated MPLS frame must pass safely", "packet_hex": make_eth(eth_type=0x8847, payload=b"\x00\x01").hex(), "expected_action": "XDP_PASS"},
    ]
    t5_sol = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>

struct mpls_label {
    __u32 entry;
};

SEC("xdp")
int xdp_mpls_bos_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(0x8847)) // ETH_P_MPLS_UC
        return XDP_PASS;

    struct mpls_label *mpls = (void *)(eth + 1);
    if ((void *)(mpls + 1) > data_end)
        return XDP_PASS;

    __u32 entry = bpf_ntohl(mpls->entry);
    // Bit 8 is Bottom-of-Stack (S-bit)
    if ((entry & 0x00000100) == 0)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    tasks.append({
        "task_id": "syn_pfs_l1_005_mpls_bos_filter",
        "application_category": "packet_filtering_security",
        "difficulty": "level_1",
        "task_family": "xdp_mpls_filter",
        "template_family": "xdp_mpls_bos_filter",
        "semantic_signature": "mpls_0x8847+top_label_bos_zero+drop",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that inspects MPLS unicast frames (EtherType 0x8847). Parse the first 4-byte MPLS shim header and check the Bottom-of-Stack (BOS / S-bit, bit 8 in 32-bit big-endian representation). If the BOS bit is 0 (meaning more labels follow in the stack), drop the packet with XDP_DROP. Pass MPLS packets with BOS=1, non-MPLS traffic, and truncated frames with XDP_PASS.",
        "requirements": [
            "Validate Ethernet header bounds and check eth->h_proto == bpf_htons(0x8847)",
            "Validate 4-byte MPLS label header bounds",
            "Extract 32-bit label entry and check bit 8 (0x00000100)",
            "Drop packet if BOS bit is 0",
            "Pass single-label MPLS and non-MPLS packets safely",
            "SEC(\"xdp\") and GPL license declaration"
        ],
        "solution_c": t5_sol,
        "tests": t5_tests,
        "main_validator": "packet_action"
    })

    # 6. syn_pfs_l1_006_coap_non_confirmable_drop
    t6_tests = [
        {"name": "coap_non_drop", "description": "CoAP packet with Type 1 (Non-confirmable) must be dropped", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=5683, payload=make_coap(type_=1, code=1)))).hex(), "expected_action": "XDP_DROP"},
        {"name": "coap_con_pass", "description": "CoAP packet with Type 0 (Confirmable) must pass", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=5683, payload=make_coap(type_=0, code=1)))).hex(), "expected_action": "XDP_PASS"},
        {"name": "coap_ack_pass", "description": "CoAP packet with Type 2 (Acknowledgement) must pass", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=5683, payload=make_coap(type_=2, code=69)))).hex(), "expected_action": "XDP_PASS"},
        {"name": "udp_other_port_pass", "description": "UDP packet on port 5684 must pass", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=5684, payload=make_coap(type_=1)))).hex(), "expected_action": "XDP_PASS"},
        {"name": "truncated_coap_pass", "description": "Truncated CoAP packet must pass safely", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=5683, payload=b"\x50"))).hex(), "expected_action": "XDP_PASS"},
    ]
    t6_sol = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

struct coaphdr {
    __u8 ver_t_tkl;
    __u8 code;
    __be16 msg_id;
};

SEC("xdp")
int xdp_coap_filter(struct xdp_md *ctx) {
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

    struct coaphdr *coap = (void *)(udp + 1);
    if ((void *)(coap + 1) > data_end)
        return XDP_PASS;

    // Type field is bits 4-5 of the first byte: (ver_t_tkl >> 4) & 0x03
    __u8 type = (coap->ver_t_tkl >> 4) & 0x03;
    if (type == 1) // 1 = NON (Non-confirmable)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    tasks.append({
        "task_id": "syn_pfs_l1_006_coap_non_confirmable_drop",
        "application_category": "packet_filtering_security",
        "difficulty": "level_1",
        "task_family": "xdp_coap_filter",
        "template_family": "xdp_coap_type_filter",
        "semantic_signature": "coap_udp5683+type_1_non_confirmable+drop",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that inspects CoAP traffic (RFC 7252) on UDP destination port 5683. Parse the 4-byte CoAP fixed header and extract the 2-bit Type field from bits 4-5 of the first byte ((byte >> 4) & 0x03). If the message type is 1 (Non-confirmable / NON), drop the packet with XDP_DROP. Pass Confirmable (0), ACK (2), Reset (3), non-CoAP UDP packets, and malformed frames with XDP_PASS.",
        "requirements": [
            "Validate Ethernet, IPv4 (variable IHL), and UDP headers",
            "Verify UDP destination port is 5683",
            "Validate 4-byte CoAP header bounds",
            "Extract 2-bit Type field and drop if type == 1",
            "Pass all other traffic safely",
            "SEC(\"xdp\") and GPL license declaration"
        ],
        "solution_c": t6_sol,
        "tests": t6_tests,
        "main_validator": "packet_action"
    })

    # 7. syn_pfs_l1_007_wireguard_init_filter
    t7_tests = [
        {"name": "wg_init_drop", "description": "WireGuard Handshake Initiation packet (Type 1) must be dropped", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=51820, payload=make_wireguard(msg_type=1)))).hex(), "expected_action": "XDP_DROP"},
        {"name": "wg_data_pass", "description": "WireGuard Data packet (Type 4) must pass", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=51820, payload=make_wireguard(msg_type=4)))).hex(), "expected_action": "XDP_PASS"},
        {"name": "wg_resp_pass", "description": "WireGuard Handshake Response (Type 2) must pass", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=51820, payload=make_wireguard(msg_type=2)))).hex(), "expected_action": "XDP_PASS"},
        {"name": "udp_other_pass", "description": "UDP packet on other port must pass", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=51821, payload=b"\x01\x00\x00\x00"))).hex(), "expected_action": "XDP_PASS"},
        {"name": "truncated_wg_pass", "description": "Truncated WireGuard packet must pass safely", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=51820, payload=b"\x01"))).hex(), "expected_action": "XDP_PASS"},
    ]
    t7_sol = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

struct wg_hdr {
    __u8 msg_type;
    __u8 reserved[3];
};

SEC("xdp")
int xdp_wireguard_filter(struct xdp_md *ctx) {
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
    if (udp->dest != bpf_htons(51820))
        return XDP_PASS;

    struct wg_hdr *wg = (void *)(udp + 1);
    if ((void *)(wg + 1) > data_end)
        return XDP_PASS;

    if (wg->msg_type == 1) // Type 1: Handshake Initiation
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    tasks.append({
        "task_id": "syn_pfs_l1_007_wireguard_init_filter",
        "application_category": "packet_filtering_security",
        "difficulty": "level_1",
        "task_family": "xdp_wireguard_filter",
        "template_family": "xdp_wireguard_msgtype_filter",
        "semantic_signature": "wireguard_udp51820+msgtype_1_init+drop",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that inspects WireGuard VPN traffic on UDP destination port 51820. Parse the first 4 bytes of the WireGuard header and check the Message Type (first byte). If the message type is 1 (Handshake Initiation), drop the packet with XDP_DROP. Pass other WireGuard messages (Type 2 Response, Type 4 Data), non-WireGuard traffic, and malformed frames with XDP_PASS.",
        "requirements": [
            "Validate Ethernet, IPv4, and UDP header bounds",
            "Verify UDP destination port is 51820",
            "Validate 4-byte WireGuard header bounds",
            "Drop packet if msg_type == 1",
            "Pass all other traffic safely",
            "SEC(\"xdp\") and GPL license declaration"
        ],
        "solution_c": t7_sol,
        "tests": t7_tests,
        "main_validator": "packet_action"
    })

    # 8. syn_pfs_l1_008_arp_gratuitous_drop
    t8_tests = [
        {"name": "gratuitous_arp_drop", "description": "Gratuitous ARP frame (Sender IP == Target IP) must be dropped", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp(opcode=1, sender_ip="192.168.1.50", target_ip="192.168.1.50")).hex(), "expected_action": "XDP_DROP"},
        {"name": "standard_arp_req_pass", "description": "Standard ARP Request (Sender IP != Target IP) must pass", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp(opcode=1, sender_ip="192.168.1.50", target_ip="192.168.1.1")).hex(), "expected_action": "XDP_PASS"},
        {"name": "standard_arp_reply_pass", "description": "Standard ARP Reply (Sender IP != Target IP) must pass", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp(opcode=2, sender_ip="192.168.1.1", target_ip="192.168.1.50")).hex(), "expected_action": "XDP_PASS"},
        {"name": "ipv4_pass", "description": "IPv4 traffic must pass", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "truncated_arp_pass", "description": "Truncated ARP frame must pass safely", "packet_hex": make_eth(eth_type=0x0806, payload=b"\x00\x01\x08\x00\x06\x04").hex(), "expected_action": "XDP_PASS"},
    ]
    t8_sol = """#include <linux/bpf.h>
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
int xdp_garp_filter(struct xdp_md *ctx) {
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

    if (arp->ar_hrd != bpf_htons(1) || arp->ar_pro != bpf_htons(ETH_P_IP) ||
        arp->ar_hln != ETH_ALEN || arp->ar_pln != 4)
        return XDP_PASS;

    // Gratuitous ARP has sender IP equal to target IP
    if (arp->ar_sip == arp->ar_tip)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    tasks.append({
        "task_id": "syn_pfs_l1_008_arp_gratuitous_drop",
        "application_category": "packet_filtering_security",
        "difficulty": "level_1",
        "task_family": "xdp_arp_filter",
        "template_family": "xdp_garp_filter",
        "semantic_signature": "arp_0x0806+sender_ip_eq_target_ip+drop",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that inspects ARP frames (EtherType 0x0806). Parse the 28-byte Ethernet/IPv4 ARP structure and check if the Sender IP (ar_sip) is identical to the Target IP (ar_tip), which identifies Gratuitous ARP / ARP announcements. If ar_sip == ar_tip, drop the packet with XDP_DROP. Pass standard ARP requests and replies, non-ARP traffic, and malformed frames with XDP_PASS.",
        "requirements": [
            "Validate Ethernet header bounds and check eth->h_proto == bpf_htons(ETH_P_ARP)",
            "Validate 28-byte struct arphdr_eth_ipv4 bounds",
            "Verify hardware format (1), protocol (0x0800), hlen (6), and plen (4)",
            "Drop packet if arp->ar_sip == arp->ar_tip",
            "Pass non-matching and truncated packets safely",
            "SEC(\"xdp\") and GPL license declaration"
        ],
        "solution_c": t8_sol,
        "tests": t8_tests,
        "main_validator": "packet_action"
    })

    # 9. syn_pfs_l1_009_sctp_abort_drop
    t9_tests = [
        {"name": "sctp_abort_drop", "description": "SCTP packet containing an ABORT chunk (Type 6) must be dropped", "packet_hex": make_eth(payload=make_ipv4(proto=132, payload=make_sctp(chunk_type=6))).hex(), "expected_action": "XDP_DROP"},
        {"name": "sctp_data_pass", "description": "SCTP packet containing DATA chunk (Type 0) must pass", "packet_hex": make_eth(payload=make_ipv4(proto=132, payload=make_sctp(chunk_type=0))).hex(), "expected_action": "XDP_PASS"},
        {"name": "sctp_init_pass", "description": "SCTP packet containing INIT chunk (Type 1) must pass", "packet_hex": make_eth(payload=make_ipv4(proto=132, payload=make_sctp(chunk_type=1))).hex(), "expected_action": "XDP_PASS"},
        {"name": "tcp_pass", "description": "TCP packet must pass", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "truncated_sctp_pass", "description": "Truncated SCTP packet must pass safely", "packet_hex": make_eth(payload=make_ipv4(proto=132, payload=b"\x13\x88\x13\x88")).hex(), "expected_action": "XDP_PASS"},
    ]
    t9_sol = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

struct sctphdr {
    __be16 src_port;
    __be16 dst_port;
    __be32 vtag;
    __be32 checksum;
};

struct sctp_chunkhdr {
    __u8 chunk_type;
    __u8 chunk_flags;
    __be16 chunk_length;
};

SEC("xdp")
int xdp_sctp_abort_filter(struct xdp_md *ctx) {
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
    if (ip->protocol != 132) // IPPROTO_SCTP
        return XDP_PASS;

    int ip_len = ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct sctphdr *sctp = (void *)ip + ip_len;
    if ((void *)(sctp + 1) > data_end)
        return XDP_PASS;

    struct sctp_chunkhdr *chunk = (void *)(sctp + 1);
    if ((void *)(chunk + 1) > data_end)
        return XDP_PASS;

    if (chunk->chunk_type == 6) // ABORT Chunk
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    tasks.append({
        "task_id": "syn_pfs_l1_009_sctp_abort_drop",
        "application_category": "packet_filtering_security",
        "difficulty": "level_1",
        "task_family": "xdp_sctp_filter",
        "template_family": "xdp_sctp_chunk_filter",
        "semantic_signature": "sctp_proto132+chunk_type_6_abort+drop",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that inspects SCTP traffic (IP protocol 132). Parse the 12-byte SCTP common header and the first SCTP chunk header (struct sctp_chunkhdr). If the chunk type is 6 (ABORT chunk), drop the packet with XDP_DROP. Pass other SCTP chunks (DATA 0, INIT 1, SACK 3), non-SCTP traffic, and malformed frames with XDP_PASS.",
        "requirements": [
            "Validate Ethernet and IPv4 header bounds (accounting for variable IHL)",
            "Verify ip->protocol == 132 (SCTP)",
            "Validate 12-byte struct sctphdr bounds",
            "Validate 4-byte struct sctp_chunkhdr bounds",
            "Drop packet if chunk->chunk_type == 6",
            "Pass all other traffic safely",
            "SEC(\"xdp\") and GPL license declaration"
        ],
        "solution_c": t9_sol,
        "tests": t9_tests,
        "main_validator": "packet_action"
    })

    # 10. syn_pfs_l1_010_ipv6_hop_by_hop_drop
    t10_tests = [
        {"name": "ipv6_hbh_drop", "description": "IPv6 packet with Next Header 0 (Hop-by-Hop) must be dropped", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(next_hdr=0, payload=b"\x06\x00\x00\x00\x00\x00\x00\x00" + make_tcp())).hex(), "expected_action": "XDP_DROP"},
        {"name": "ipv6_tcp_pass", "description": "IPv6 packet with Next Header 6 (TCP) must pass", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(next_hdr=6, payload=make_tcp(src_ip="2001:db8::1", dst_ip="2001:db8::2"))).hex(), "expected_action": "XDP_PASS"},
        {"name": "ipv6_udp_pass", "description": "IPv6 packet with Next Header 17 (UDP) must pass", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(next_hdr=17, payload=make_udp(src_ip="2001:db8::1", dst_ip="2001:db8::2"))).hex(), "expected_action": "XDP_PASS"},
        {"name": "ipv4_pass", "description": "IPv4 traffic must pass", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "truncated_ipv6_pass", "description": "Truncated IPv6 header must pass safely", "packet_hex": make_eth(eth_type=0x86DD, payload=b"\x60\x00\x00").hex(), "expected_action": "XDP_PASS"},
    ]
    t10_sol = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>

SEC("xdp")
int xdp_ipv6_hbh_filter(struct xdp_md *ctx) {
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

    // Next Header 0 indicates Hop-by-Hop Options
    if (ip6->nexthdr == 0)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    tasks.append({
        "task_id": "syn_pfs_l1_010_ipv6_hop_by_hop_drop",
        "application_category": "packet_filtering_security",
        "difficulty": "level_1",
        "task_family": "xdp_ipv6_filter",
        "template_family": "xdp_ipv6_nexthdr_filter",
        "semantic_signature": "ipv6_0x86dd+nexthdr_0_hop_by_hop+drop",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that inspects IPv6 packets (EtherType 0x86DD). Parse the 40-byte IPv6 header and check the nexthdr field. If the next header is 0 (IPPROTO_HOPOPTS / Hop-by-Hop Options), drop the packet with XDP_DROP. Pass standard IPv6 traffic (TCP, UDP, ICMPv6), IPv4 traffic, and malformed frames with XDP_PASS.",
        "requirements": [
            "Validate Ethernet header bounds and check eth->h_proto == bpf_htons(ETH_P_IPV6)",
            "Validate 40-byte struct ipv6hdr bounds",
            "Check ip6->nexthdr == 0 and drop if true",
            "Pass all other traffic safely",
            "SEC(\"xdp\") and GPL license declaration"
        ],
        "solution_c": t10_sol,
        "tests": t10_tests,
        "main_validator": "packet_action"
    })

    # =========================================================================
    # LEVEL 2 (10 Tasks) - Multi-field, variable headers, options, maps
    # =========================================================================

    # 11. syn_pfs_l2_001_tcp_mss_clamp_filter
    mss_opt_too_large = bytes([2, 4, 0x05, 0xE0])  # MSS = 1504 > 1460
    mss_opt_valid = bytes([2, 4, 0x05, 0xB4])      # MSS = 1460
    mss_opt_small = bytes([2, 4, 0x04, 0xB0])      # MSS = 1200
    t11_tests = [
        {"name": "syn_large_mss_drop", "description": "TCP SYN with MSS 1504 (>1460) must be dropped", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(flags=0x02, options=mss_opt_too_large))).hex(), "expected_action": "XDP_DROP"},
        {"name": "syn_valid_mss_pass", "description": "TCP SYN with MSS 1460 must pass", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(flags=0x02, options=mss_opt_valid))).hex(), "expected_action": "XDP_PASS"},
        {"name": "syn_small_mss_pass", "description": "TCP SYN with MSS 1200 must pass", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(flags=0x02, options=mss_opt_small))).hex(), "expected_action": "XDP_PASS"},
        {"name": "syn_no_options_pass", "description": "TCP SYN without options must pass", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(flags=0x02))).hex(), "expected_action": "XDP_PASS"},
        {"name": "ack_large_mss_pass", "description": "Non-SYN TCP packet with large MSS option must pass (only SYNs checked)", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(flags=0x10, options=mss_opt_too_large))).hex(), "expected_action": "XDP_PASS"},
        {"name": "udp_pass", "description": "UDP packet must pass", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "truncated_tcp_opt_pass", "description": "Truncated TCP options must pass safely", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(flags=0x02)[:22])).hex(), "expected_action": "XDP_PASS"},
    ]
    t11_sol = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

SEC("xdp")
int xdp_tcp_mss_filter(struct xdp_md *ctx) {
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

    // Only inspect SYN packets
    if (!tcp->syn)
        return XDP_PASS;

    int tcp_hdr_len = tcp->doff * 4;
    if (tcp_hdr_len < sizeof(struct tcphdr) || (void *)tcp + tcp_hdr_len > data_end)
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

        if (kind == 2 && len == 4) { // MSS option
            if (opt + 4 > opt_end || opt + 4 > data_end)
                break;
            __u16 mss = ((__u16)*(opt + 2) << 8) | (__u16)*(opt + 3);
            if (mss > 1460)
                return XDP_DROP;
            break;
        }

        opt += len;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    tasks.append({
        "task_id": "syn_pfs_l2_001_tcp_mss_clamp_filter",
        "application_category": "packet_filtering_security",
        "difficulty": "level_2",
        "task_family": "xdp_tcp_options_filter",
        "template_family": "xdp_mss_option_filter",
        "semantic_signature": "ipv4_tcp_syn+parse_mss_opt_gt_1460+drop",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that inspects IPv4 TCP SYN packets. Parse the variable-length TCP options list to locate the Maximum Segment Size (MSS) option (Kind 2, Length 4). If the requested MSS is strictly greater than 1460 bytes, drop the packet with XDP_DROP. Pass TCP SYN packets with valid MSS <= 1460 or without MSS option, non-SYN TCP packets, other protocols, and malformed frames with XDP_PASS.",
        "requirements": [
            "Validate Ethernet and IPv4 headers (supporting variable IHL)",
            "Validate TCP header and check tcp->syn is set",
            "Calculate TCP header length from tcp->doff * 4 and bounds-check options region",
            "Iterate through TCP options with safe bounds checking on every step",
            "Parse MSS option (Kind 2, Length 4) and drop if MSS > 1460",
            "SEC(\"xdp\") and GPL license declaration"
        ],
        "solution_c": t11_sol,
        "tests": t11_tests,
        "main_validator": "packet_action"
    })

    # 12. syn_pfs_l2_002_dns_null_txt_drop
    t12_tests = [
        {"name": "dns_null_drop", "description": "DNS query with QTYPE=NULL (10) must be dropped", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=53, payload=make_dns(qname="test.tunnel.com", qtype=10)))).hex(), "expected_action": "XDP_DROP"},
        {"name": "dns_txt_drop", "description": "DNS query with QTYPE=TXT (16) must be dropped", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=53, payload=make_dns(qname="exfil.tunnel.com", qtype=16)))).hex(), "expected_action": "XDP_DROP"},
        {"name": "dns_a_pass", "description": "DNS query with QTYPE=A (1) must pass", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=53, payload=make_dns(qname="example.com", qtype=1)))).hex(), "expected_action": "XDP_PASS"},
        {"name": "dns_aaaa_pass", "description": "DNS query with QTYPE=AAAA (28) must pass", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=53, payload=make_dns(qname="example.com", qtype=28)))).hex(), "expected_action": "XDP_PASS"},
        {"name": "dns_response_pass", "description": "DNS response packet (QR=1) must pass", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(src_port=53, dst_port=12345, payload=make_dns(qr=1, qtype=16)))).hex(), "expected_action": "XDP_PASS"},
        {"name": "udp_other_port_pass", "description": "UDP packet on other port must pass", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=5353, payload=make_dns(qtype=10)))).hex(), "expected_action": "XDP_PASS"},
        {"name": "truncated_dns_pass", "description": "Truncated DNS packet must pass safely", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=53, payload=b"\x12\x34\x01\x00"))).hex(), "expected_action": "XDP_PASS"},
    ]
    t12_sol = """#include <linux/bpf.h>
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

SEC("xdp")
int xdp_dns_null_txt_filter(struct xdp_md *ctx) {
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
    // Bit 15 indicates QR (0 = Query, 1 = Response)
    if (flags & 0x8000)
        return XDP_PASS; // Only filter Queries

    if (bpf_ntohs(dns->qdcount) < 1)
        return XDP_PASS;

    __u8 *ptr = (void *)(dns + 1);

    // Skip QNAME labels (bounded loop)
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
            return XDP_PASS; // Pointer compression not allowed in standard query QNAME
        ptr += 1 + len;
    }

    // Now ptr points to QTYPE (2 bytes) + QCLASS (2 bytes)
    if (ptr + 4 > data_end)
        return XDP_PASS;

    __u16 qtype = ((__u16)*ptr << 8) | (__u16)*(ptr + 1);
    if (qtype == 10 || qtype == 16) // 10 = NULL, 16 = TXT
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    tasks.append({
        "task_id": "syn_pfs_l2_002_dns_null_txt_drop",
        "application_category": "packet_filtering_security",
        "difficulty": "level_2",
        "task_family": "xdp_dns_filter",
        "template_family": "xdp_dns_qtype_filter",
        "semantic_signature": "dns_udp53+query_qtype_null_or_txt+drop",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that inspects DNS query traffic on UDP destination port 53. Parse the DNS 12-byte header, verify it is a DNS Query (QR flag bit == 0) with qdcount >= 1. Walk the variable-length DNS QNAME wire format until the terminating null byte, and inspect the 16-bit QTYPE. If the query type is NULL (10) or TXT (16), drop the packet with XDP_DROP to prevent DNS tunneling exfiltration. Pass standard query types (A 1, AAAA 28, MX 15), DNS responses, non-DNS traffic, and malformed frames with XDP_PASS.",
        "requirements": [
            "Validate Ethernet, IPv4, UDP, and DNS header bounds",
            "Verify UDP destination port is 53 and DNS QR bit == 0",
            "Safely iterate through DNS label lengths with bounds checks",
            "Extract 16-bit QTYPE and drop if qtype == 10 or qtype == 16",
            "Pass all other queries and responses safely",
            "SEC(\"xdp\") and GPL license declaration"
        ],
        "solution_c": t12_sol,
        "tests": t12_tests,
        "main_validator": "packet_action"
    })

    # 13. syn_pfs_l2_003_dhcp_rogue_server_filter
    t13_tests = [
        {"name": "dhcp_rogue_offer_drop", "description": "DHCP Offer from unauthorized server IP 192.168.1.100 must be dropped", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.100", dst_ip="255.255.255.255", proto=17, payload=make_udp(src_port=67, dst_port=68, payload=make_dhcp(op=2, msg_type=2, server_ip="192.168.1.100")))).hex(), "expected_action": "XDP_DROP"},
        {"name": "dhcp_auth_offer_pass", "description": "DHCP Offer from authorized server IP 192.168.1.1 must pass", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.1", dst_ip="255.255.255.255", proto=17, payload=make_udp(src_port=67, dst_port=68, payload=make_dhcp(op=2, msg_type=2, server_ip="192.168.1.1")))).hex(), "expected_action": "XDP_PASS"},
        {"name": "dhcp_auth_ack_pass", "description": "DHCP Ack from authorized server IP 192.168.1.1 must pass", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.1", dst_ip="192.168.1.50", proto=17, payload=make_udp(src_port=67, dst_port=68, payload=make_dhcp(op=2, msg_type=5, server_ip="192.168.1.1")))).hex(), "expected_action": "XDP_PASS"},
        {"name": "dhcp_client_discover_pass", "description": "DHCP Discover from client (src port 68, dst port 67) must pass", "packet_hex": make_eth(payload=make_ipv4(src_ip="0.0.0.0", dst_ip="255.255.255.255", proto=17, payload=make_udp(src_port=68, dst_port=67, payload=make_dhcp(op=1, msg_type=1)))).hex(), "expected_action": "XDP_PASS"},
        {"name": "dhcp_bad_cookie_pass", "description": "BOOTP packet with invalid magic cookie must pass", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.100", proto=17, payload=make_udp(src_port=67, dst_port=68, payload=b"\x02\x01\x06\x00" + b"\x00"*232 + b"\x11\x22\x33\x44"))).hex(), "expected_action": "XDP_PASS"},
        {"name": "tcp_pass", "description": "TCP packet must pass", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "truncated_dhcp_pass", "description": "Truncated DHCP packet must pass safely", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(src_port=67, dst_port=68, payload=b"\x02\x01"))).hex(), "expected_action": "XDP_PASS"},
    ]
    t13_sol = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __be32);
    __uint(max_entries, 1);
} auth_dhcp_server SEC(".maps");

SEC("xdp")
int xdp_dhcp_rogue_filter(struct xdp_md *ctx) {
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

    // DHCP server responses originate from port 67 targeting client port 68
    if (udp->source != bpf_htons(67) || udp->dest != bpf_htons(68))
        return XDP_PASS;

    // Fixed DHCP body is 236 bytes followed by 4-byte magic cookie
    void *dhcp_start = (void *)(udp + 1);
    if (dhcp_start + 240 > data_end)
        return XDP_PASS;

    __u8 op = *(__u8 *)dhcp_start;
    if (op != 2) // 2 = BOOTREPLY / DHCP server response
        return XDP_PASS;

    __be32 *magic = (void *)dhcp_start + 236;
    if (*magic != bpf_htonl(0x63825363))
        return XDP_PASS;

    __u32 key = 0;
    __be32 *auth_ip = bpf_map_lookup_elem(&auth_dhcp_server, &key);
    __be32 expected_ip = auth_ip ? *auth_ip : bpf_htonl(0xC0A80101); // Default 192.168.1.1

    if (ip->saddr != expected_ip)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    tasks.append({
        "task_id": "syn_pfs_l2_003_dhcp_rogue_server_filter",
        "application_category": "packet_filtering_security",
        "difficulty": "level_2",
        "task_family": "xdp_dhcp_filter",
        "template_family": "xdp_dhcp_rogue_filter",
        "semantic_signature": "dhcp_resp_src67_dst68+unauthorized_server_ip+drop",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that blocks rogue DHCP servers. Inspect UDP traffic from source port 67 to destination port 68. Verify the BOOTREPLY op code (op == 2) and the 4-byte DHCP Magic Cookie (0x63825363 at offset 236). Look up the authorized DHCP server IPv4 address in an array map named 'auth_dhcp_server' (key 0, type BPF_MAP_TYPE_ARRAY, max_entries 1, default fallback 192.168.1.1 / 0xC0A80101). If the packet source IP (ip->saddr) does not match the authorized server IP, drop the packet with XDP_DROP. Pass authorized DHCP responses, client requests, non-DHCP traffic, and malformed frames with XDP_PASS.",
        "requirements": [
            "Define array map 'auth_dhcp_server' with key __u32, value __be32, max_entries 1",
            "Validate Ethernet, IPv4, UDP, and DHCP 240-byte header bounds",
            "Verify UDP src == 67, dst == 68, op == 2, and magic cookie == 0x63825363",
            "Lookup authorized server IP in map (fallback to 192.168.1.1 if unconfigured)",
            "Drop packet if ip->saddr != authorized_ip",
            "SEC(\"xdp\") and GPL license declaration"
        ],
        "solution_c": t13_sol,
        "tests": t13_tests,
        "main_validator": "packet_action"
    })

    # 14. syn_pfs_l2_004_qinq_double_vlan_drop
    t14_tests = [
        {"name": "qinq_100_200_drop", "description": "802.1ad QinQ frame with outer VID 100 and inner VID 200 must be dropped", "packet_hex": make_eth(qinq_outer=100, vlan=200, payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_DROP"},
        {"name": "qinq_100_300_pass", "description": "QinQ frame with outer VID 100 and inner VID 300 must pass", "packet_hex": make_eth(qinq_outer=100, vlan=300, payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "qinq_200_100_pass", "description": "QinQ frame with outer VID 200 and inner VID 100 must pass", "packet_hex": make_eth(qinq_outer=200, vlan=100, payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "single_vlan_100_pass", "description": "Single 802.1Q VLAN tagged frame (VID 100) must pass", "packet_hex": make_eth(vlan=100, payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "untagged_pass", "description": "Untagged Ethernet frame must pass", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "arp_pass", "description": "ARP frame must pass", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
        {"name": "truncated_qinq_pass", "description": "Truncated QinQ frame must pass safely", "packet_hex": make_eth(qinq_outer=100)[:16].hex(), "expected_action": "XDP_PASS"},
    ]
    t14_sol = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>

struct vlanhdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

SEC("xdp")
int xdp_qinq_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Check for 802.1ad (0x88A8) or stacked 802.1Q (0x8100) outer tag
    if (eth->h_proto != bpf_htons(0x88A8) && eth->h_proto != bpf_htons(0x8100))
        return XDP_PASS;

    struct vlanhdr *outer_vlan = (void *)(eth + 1);
    if ((void *)(outer_vlan + 1) > data_end)
        return XDP_PASS;

    __u16 outer_vid = bpf_ntohs(outer_vlan->h_vlan_TCI) & 0x0FFF;

    // Inner tag must be 0x8100
    if (outer_vlan->h_vlan_encapsulated_proto != bpf_htons(ETH_P_8021Q))
        return XDP_PASS;

    struct vlanhdr *inner_vlan = (void *)(outer_vlan + 1);
    if ((void *)(inner_vlan + 1) > data_end)
        return XDP_PASS;

    __u16 inner_vid = bpf_ntohs(inner_vlan->h_vlan_TCI) & 0x0FFF;

    if (outer_vid == 100 && inner_vid == 200)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    tasks.append({
        "task_id": "syn_pfs_l2_004_qinq_double_vlan_drop",
        "application_category": "packet_filtering_security",
        "difficulty": "level_2",
        "task_family": "xdp_qinq_filter",
        "template_family": "xdp_qinq_vid_filter",
        "semantic_signature": "qinq_8021ad+outer_vid_100_inner_vid_200+drop",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that inspects 802.1ad QinQ dual-VLAN tagged frames (outer EtherType 0x88A8 or 0x8100, followed by inner EtherType 0x8100). Parse both outer and inner VLAN headers and extract the 12-bit VLAN IDs (TCI & 0x0FFF). If outer VID is 100 AND inner VID is 200, drop the frame with XDP_DROP. Pass other QinQ combinations, single-tagged VLANs, untagged traffic, and truncated frames with XDP_PASS.",
        "requirements": [
            "Validate Ethernet header and check for outer tag 0x88A8 or 0x8100",
            "Validate outer struct vlanhdr and verify inner proto is 0x8100",
            "Validate inner struct vlanhdr bounds",
            "Extract outer VID and inner VID from h_vlan_TCI & 0x0FFF",
            "Drop packet if outer_vid == 100 && inner_vid == 200",
            "SEC(\"xdp\") and GPL license declaration"
        ],
        "solution_c": t14_sol,
        "tests": t14_tests,
        "main_validator": "packet_action"
    })

    # 15. syn_pfs_l2_005_ntp_monlist_guard
    t15_tests = [
        {"name": "ntp_mode7_monlist_drop", "description": "NTP packet with Mode 7 (Private / monlist) must be dropped", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=123, payload=make_ntp(mode=7)))).hex(), "expected_action": "XDP_DROP"},
        {"name": "ntp_mode6_control_drop", "description": "NTP packet with Mode 6 (Control message) must be dropped", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=123, payload=make_ntp(mode=6)))).hex(), "expected_action": "XDP_DROP"},
        {"name": "ntp_mode3_client_pass", "description": "NTP Client query (Mode 3) must pass", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=123, payload=make_ntp(mode=3)))).hex(), "expected_action": "XDP_PASS"},
        {"name": "ntp_mode4_server_pass", "description": "NTP Server response (Mode 4) must pass", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(src_port=123, dst_port=12345, payload=make_ntp(mode=4)))).hex(), "expected_action": "XDP_PASS"},
        {"name": "udp_other_port_pass", "description": "UDP packet to port 124 must pass", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=124, payload=make_ntp(mode=7)))).hex(), "expected_action": "XDP_PASS"},
        {"name": "tcp_pass", "description": "TCP packet must pass", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "truncated_ntp_pass", "description": "Truncated NTP packet must pass safely", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=123, payload=b"\x17"))).hex(), "expected_action": "XDP_PASS"},
    ]
    t15_sol = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

struct ntphdr {
    __u8 li_vn_mode;
    __u8 stratum;
    __u8 poll;
    __u8 precision;
    __u32 root_delay;
    __u32 root_dispersion;
    __u32 ref_id;
    __u64 ref_ts;
    __u64 orig_ts;
    __u64 recv_ts;
    __u64 trans_ts;
};

SEC("xdp")
int xdp_ntp_guard(struct xdp_md *ctx) {
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

    // Check NTP port 123 (either source or destination)
    if (udp->dest != bpf_htons(123) && udp->source != bpf_htons(123))
        return XDP_PASS;

    struct ntphdr *ntp = (void *)(udp + 1);
    if ((void *)(ntp + 1) > data_end)
        return XDP_PASS;

    // Mode is bottom 3 bits: (li_vn_mode & 0x07)
    __u8 mode = ntp->li_vn_mode & 0x07;
    if (mode == 6 || mode == 7) // Mode 6 (Control) or Mode 7 (Private/Monlist)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    tasks.append({
        "task_id": "syn_pfs_l2_005_ntp_monlist_guard",
        "application_category": "packet_filtering_security",
        "difficulty": "level_2",
        "task_family": "xdp_ntp_filter",
        "template_family": "xdp_ntp_mode_guard",
        "semantic_signature": "ntp_udp123+mode_6_or_7+drop",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that inspects NTP traffic (UDP port 123). Parse the 48-byte NTP fixed header (struct ntphdr) and extract the 3-bit Mode field (li_vn_mode & 0x07). To prevent NTP amplification attacks, drop packets where mode is 6 (Control Message) or 7 (Private / monlist command) with XDP_DROP. Pass standard NTP Client (3), Server (4), Broadcast (5), non-NTP traffic, and malformed frames with XDP_PASS.",
        "requirements": [
            "Validate Ethernet, IPv4, and UDP headers",
            "Verify UDP port 123 on source or destination",
            "Validate 48-byte struct ntphdr bounds",
            "Extract 3-bit mode field and drop if mode == 6 || mode == 7",
            "Pass all other NTP modes and protocols safely",
            "SEC(\"xdp\") and GPL license declaration"
        ],
        "solution_c": t15_sol,
        "tests": t15_tests,
        "main_validator": "packet_action"
    })

    # 16. syn_pfs_l2_006_geneve_opt_critical_drop
    opt_crit = bytes([0x01, 0x00, 0x81, 0x01, 0x00, 0x00, 0x00, 0x00])  # Class 0x0100, Type 1 with Critical bit (0x80)
    opt_norm = bytes([0x01, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00])  # Class 0x0100, Type 1 without Critical bit
    t16_tests = [
        {"name": "geneve_crit_opt_drop", "description": "GENEVE packet containing a Critical Option (C-bit set) must be dropped", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=6081, payload=make_geneve(vni=100, critical=True, options=opt_crit, inner_frame=make_eth(payload=make_ipv4(proto=1, payload=make_icmp())))))).hex(), "expected_action": "XDP_DROP"},
        {"name": "geneve_normal_opt_pass", "description": "GENEVE packet with non-critical options must pass", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=6081, payload=make_geneve(vni=100, critical=False, options=opt_norm, inner_frame=make_eth(payload=make_ipv4(proto=1, payload=make_icmp())))))).hex(), "expected_action": "XDP_PASS"},
        {"name": "geneve_no_opt_pass", "description": "GENEVE packet without options must pass", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=6081, payload=make_geneve(vni=100, inner_frame=make_eth(payload=make_ipv4(proto=1, payload=make_icmp())))))).hex(), "expected_action": "XDP_PASS"},
        {"name": "udp_other_pass", "description": "UDP packet on other port must pass", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=6082, payload=b"TEST"))).hex(), "expected_action": "XDP_PASS"},
        {"name": "tcp_pass", "description": "TCP packet must pass", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "arp_pass", "description": "ARP frame must pass", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
        {"name": "truncated_geneve_pass", "description": "Truncated GENEVE packet must pass safely", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=6081, payload=b"\x00\x00\x08\x00"))).hex(), "expected_action": "XDP_PASS"},
    ]
    t16_sol = """#include <linux/bpf.h>
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
    __u8 flags_length; // rsvd:3, length:5 (in 4-byte multiples)
};

SEC("xdp")
int xdp_geneve_crit_filter(struct xdp_md *ctx) {
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

    if (gen->critical) // Global critical flag in base header
        return XDP_DROP;

    int opt_len_bytes = gen->opt_len * 4;
    if (opt_len_bytes == 0)
        return XDP_PASS;

    void *opts_start = (void *)(gen + 1);
    void *opts_end = opts_start + opt_len_bytes;
    if (opts_end > data_end)
        return XDP_PASS;

    __u8 *ptr = opts_start;

    #pragma unroll
    for (int i = 0; i < 5; i++) {
        if (ptr + sizeof(struct geneve_opt) > opts_end || ptr + sizeof(struct geneve_opt) > data_end)
            break;

        struct geneve_opt *opt = (void *)ptr;
        // High bit of type (bit 7 / 0x80) indicates Critical Option
        if (opt->type & 0x80)
            return XDP_DROP;

        int len = (opt->flags_length & 0x1F) * 4;
        ptr += sizeof(struct geneve_opt) + len;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    tasks.append({
        "task_id": "syn_pfs_l2_006_geneve_opt_critical_drop",
        "application_category": "packet_filtering_security",
        "difficulty": "level_2",
        "task_family": "xdp_geneve_filter",
        "template_family": "xdp_geneve_opt_filter",
        "semantic_signature": "geneve_udp6081+critical_opt_bit+drop",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that inspects GENEVE tunnel traffic (UDP port 6081). Parse the 8-byte GENEVE header and any variable-length TLV options (length specified by gen->opt_len * 4). If either the global Critical flag in the base header (gen->critical) is set OR any TLV option has the Critical bit set (bit 7 / 0x80 of option type field), drop the packet with XDP_DROP. Pass GENEVE packets with non-critical options or no options, non-GENEVE traffic, and malformed frames with XDP_PASS.",
        "requirements": [
            "Validate Ethernet, IPv4, UDP, and GENEVE header bounds",
            "Verify UDP destination port is 6081",
            "Check base header gen->critical flag",
            "Iterate through GENEVE TLV options with strict bounds checking",
            "Check option type bit 0x80 and drop if critical",
            "SEC(\"xdp\") and GPL license declaration"
        ],
        "solution_c": t16_sol,
        "tests": t16_tests,
        "main_validator": "packet_action"
    })

    # 17. syn_pfs_l2_007_ipv6_nd_spoof_guard
    t17_tests = [
        {"name": "unsolicited_router_na_drop", "description": "Unsolicited ICMPv6 NA (S=0, R=1) claiming router status must be dropped", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(next_hdr=58, payload=make_icmpv6(icmp_type=136, icmp_code=0, payload=b"\x80\x00\x00\x00" + parse_ipv6("2001:db8::1") + b"\x02\x01\x52\x54\x00\x12\x34\x56"))).hex(), "expected_action": "XDP_DROP"},
        {"name": "solicited_router_na_pass", "description": "Solicited ICMPv6 NA (S=1, R=1) must pass", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(next_hdr=58, payload=make_icmpv6(icmp_type=136, icmp_code=0, payload=b"\xC0\x00\x00\x00" + parse_ipv6("2001:db8::1") + b"\x02\x01\x52\x54\x00\x12\x34\x56"))).hex(), "expected_action": "XDP_PASS"},
        {"name": "unsolicited_host_na_pass", "description": "Unsolicited ICMPv6 NA for normal host (S=0, R=0) must pass", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(next_hdr=58, payload=make_icmpv6(icmp_type=136, icmp_code=0, payload=b"\x00\x00\x00\x00" + parse_ipv6("2001:db8::50") + b"\x02\x01\x52\x54\x00\x12\x34\x56"))).hex(), "expected_action": "XDP_PASS"},
        {"name": "ns_pass", "description": "Neighbor Solicitation (Type 135) must pass", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(next_hdr=58, payload=make_icmpv6(icmp_type=135, icmp_code=0, payload=b"\x00\x00\x00\x00" + parse_ipv6("2001:db8::1")))).hex(), "expected_action": "XDP_PASS"},
        {"name": "ipv6_tcp_pass", "description": "IPv6 TCP packet must pass", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(next_hdr=6, payload=make_tcp(src_ip="2001:db8::1", dst_ip="2001:db8::2"))).hex(), "expected_action": "XDP_PASS"},
        {"name": "ipv4_pass", "description": "IPv4 traffic must pass", "packet_hex": make_eth(payload=make_ipv4(proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "truncated_na_pass", "description": "Truncated ICMPv6 NA must pass safely", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(next_hdr=58, payload=b"\x88\x00\x00\x00")).hex(), "expected_action": "XDP_PASS"},
    ]
    t17_sol = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>

struct icmp6_na_hdr {
    struct icmp6hdr icmp6;
    __u32 flags_reserved; // R (bit 31), S (bit 30), O (bit 29)
    struct in6_addr target_addr;
};

SEC("xdp")
int xdp_nd_spoof_guard(struct xdp_md *ctx) {
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

    struct icmp6_na_hdr *na = (void *)(ip6 + 1);
    if ((void *)(na + 1) > data_end)
        return XDP_PASS;

    if (na->icmp6.icmp6_type != 136) // 136 = Neighbor Advertisement
        return XDP_PASS;

    __u32 flags = bpf_ntohl(na->flags_reserved);
    int r_bit = (flags & 0x80000000) != 0; // Router flag
    int s_bit = (flags & 0x40000000) != 0; // Solicited flag

    // Drop unsolicited Neighbor Advertisements claiming to be a Router (R=1, S=0)
    if (r_bit && !s_bit)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    tasks.append({
        "task_id": "syn_pfs_l2_007_ipv6_nd_spoof_guard",
        "application_category": "packet_filtering_security",
        "difficulty": "level_2",
        "task_family": "xdp_icmpv6_filter",
        "template_family": "xdp_nd_spoof_filter",
        "semantic_signature": "icmpv6_na_136+router_flag_and_unsolicited+drop",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that protects against rogue IPv6 router advertisement attacks via ICMPv6 Neighbor Advertisement (Type 136). Parse the IPv6 header and ICMPv6 NA structure. Extract the Router flag (R-bit, bit 31) and Solicited flag (S-bit, bit 30). If a packet is an unsolicited NA claiming router status (R == 1 and S == 0), drop the packet with XDP_DROP. Pass solicited router NAs, host NAs, other ICMPv6 messages, non-IPv6 traffic, and malformed frames with XDP_PASS.",
        "requirements": [
            "Validate Ethernet and IPv6 header bounds",
            "Verify ip6->nexthdr == IPPROTO_ICMPV6",
            "Validate struct icmp6_na_hdr bounds (24 bytes)",
            "Verify icmp6_type == 136",
            "Extract R and S flags: drop if (flags & 0x80000000) != 0 && (flags & 0x40000000) == 0",
            "SEC(\"xdp\") and GPL license declaration"
        ],
        "solution_c": t17_sol,
        "tests": t17_tests,
        "main_validator": "packet_action"
    })

    # 18. syn_pfs_l2_008_quic_initial_short_token_drop
    t18_tests = [
        {"name": "quic_empty_token_drop", "description": "QUIC Initial packet with Token Length == 0 must be dropped", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=443, payload=make_quic(long_hdr=True, pkt_type=0, token=b"")))).hex(), "expected_action": "XDP_DROP"},
        {"name": "quic_valid_token_pass", "description": "QUIC Initial packet with non-empty token must pass", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=443, payload=make_quic(long_hdr=True, pkt_type=0, token=b"\x01\x02\x03\x04")))).hex(), "expected_action": "XDP_PASS"},
        {"name": "quic_short_hdr_pass", "description": "QUIC Short Header (1-RTT) packet must pass", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=443, payload=make_quic(long_hdr=False)))).hex(), "expected_action": "XDP_PASS"},
        {"name": "quic_handshake_pass", "description": "QUIC Long Header Handshake packet (pkt_type 2) must pass", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=443, payload=make_quic(long_hdr=True, pkt_type=2)))).hex(), "expected_action": "XDP_PASS"},
        {"name": "udp_other_port_pass", "description": "UDP packet to port 444 must pass", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=444, payload=make_quic(long_hdr=True, pkt_type=0, token=b"")))).hex(), "expected_action": "XDP_PASS"},
        {"name": "tcp_pass", "description": "TCP packet must pass", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "truncated_quic_pass", "description": "Truncated QUIC header must pass safely", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=443, payload=b"\xC0\x00\x00\x01"))).hex(), "expected_action": "XDP_PASS"},
    ]
    t18_sol = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

SEC("xdp")
int xdp_quic_token_filter(struct xdp_md *ctx) {
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
    if (udp->dest != bpf_htons(443))
        return XDP_PASS;

    __u8 *quic = (void *)(udp + 1);
    if (quic + 5 > data_end)
        return XDP_PASS;

    __u8 first_byte = *quic;
    // Long Header has bit 7 set (0x80)
    if ((first_byte & 0x80) == 0)
        return XDP_PASS;

    // Packet Type is bits 4-5: (first_byte >> 4) & 0x03. Type 0 = Initial
    __u8 pkt_type = (first_byte >> 4) & 0x03;
    if (pkt_type != 0)
        return XDP_PASS;

    // Skip Version (4 bytes): offset 5
    __u8 *ptr = quic + 5;
    if (ptr + 1 > data_end)
        return XDP_PASS;

    __u8 dcid_len = *ptr;
    ptr += 1 + dcid_len;
    if (ptr + 1 > data_end)
        return XDP_PASS;

    __u8 scid_len = *ptr;
    ptr += 1 + scid_len;
    if (ptr + 1 > data_end)
        return XDP_PASS;

    // In QUIC Initial, next is Token Length (varint; 1 byte if < 64)
    __u8 token_len = *ptr;
    if (token_len == 0)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    tasks.append({
        "task_id": "syn_pfs_l2_008_quic_initial_short_token_drop",
        "application_category": "packet_filtering_security",
        "difficulty": "level_2",
        "task_family": "xdp_quic_filter",
        "template_family": "xdp_quic_token_filter",
        "semantic_signature": "quic_udp443+initial_token_len_zero+drop",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that inspects QUIC traffic (RFC 9000) on UDP destination port 443. Check for Long Header (bit 7 set) and Initial Packet Type (bits 4-5 == 0). Parse past Version (4 bytes), Destination Connection ID (variable length), and Source Connection ID (variable length) to reach the Token Length field. If Token Length is 0, drop the packet with XDP_DROP to prevent unauthenticated client amplification. Pass QUIC packets with non-zero tokens, other packet types (Handshake, 1-RTT), other UDP ports, and malformed frames with XDP_PASS.",
        "requirements": [
            "Validate Ethernet, IPv4, UDP, and QUIC initial byte bounds",
            "Verify UDP destination port 443",
            "Verify Long Header (first_byte & 0x80) and Initial Type ((first_byte >> 4) & 0x03 == 0)",
            "Parse variable DCID and SCID lengths safely",
            "Drop packet if Token Length byte == 0",
            "SEC(\"xdp\") and GPL license declaration"
        ],
        "solution_c": t18_sol,
        "tests": t18_tests,
        "main_validator": "packet_action"
    })

    # 19. syn_pfs_l2_009_ip_in_ip_nested_loopback_drop
    t19_tests = [
        {"name": "ipinip_loopback_dest_drop", "description": "IP-in-IP tunnel with inner destination 127.0.0.1 must be dropped", "packet_hex": make_eth(payload=make_ipv4(src_ip="203.0.113.1", dst_ip="198.51.100.1", proto=4, payload=make_ipv4(src_ip="10.0.0.1", dst_ip="127.0.0.1", proto=6, payload=make_tcp()))).hex(), "expected_action": "XDP_DROP"},
        {"name": "ipinip_valid_dest_pass", "description": "IP-in-IP tunnel with inner destination 10.0.0.2 must pass", "packet_hex": make_eth(payload=make_ipv4(src_ip="203.0.113.1", dst_ip="198.51.100.1", proto=4, payload=make_ipv4(src_ip="10.0.0.1", dst_ip="10.0.0.2", proto=6, payload=make_tcp()))).hex(), "expected_action": "XDP_PASS"},
        {"name": "ipinip_inner_icmp_pass", "description": "IP-in-IP tunnel with inner ICMP must pass", "packet_hex": make_eth(payload=make_ipv4(src_ip="203.0.113.1", dst_ip="198.51.100.1", proto=4, payload=make_ipv4(src_ip="10.0.0.1", dst_ip="192.168.1.1", proto=1, payload=make_icmp()))).hex(), "expected_action": "XDP_PASS"},
        {"name": "direct_tcp_pass", "description": "Direct TCP packet must pass", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "udp_pass", "description": "UDP packet must pass", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "arp_pass", "description": "ARP frame must pass", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
        {"name": "truncated_ipinip_pass", "description": "Truncated IP-in-IP inner header must pass safely", "packet_hex": make_eth(payload=make_ipv4(proto=4, payload=b"\x45\x00\x00")).hex(), "expected_action": "XDP_PASS"},
    ]
    t19_sol = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

SEC("xdp")
int xdp_ipinip_loopback_filter(struct xdp_md *ctx) {
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

    if (outer_ip->protocol != 4) // IPPROTO_IPIP (IPv4-in-IPv4)
        return XDP_PASS;

    int outer_len = outer_ip->ihl * 4;
    if (outer_len < sizeof(struct iphdr) || (void *)outer_ip + outer_len > data_end)
        return XDP_PASS;

    struct iphdr *inner_ip = (void *)outer_ip + outer_len;
    if ((void *)(inner_ip + 1) > data_end)
        return XDP_PASS;

    // Check if inner destination IP is in 127.0.0.0/8 (0x7F000000 / 0xFF000000)
    __u32 inner_dst = bpf_ntohl(inner_ip->daddr);
    if ((inner_dst & 0xFF000000) == 0x7F000000)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    tasks.append({
        "task_id": "syn_pfs_l2_009_ip_in_ip_nested_loopback_drop",
        "application_category": "packet_filtering_security",
        "difficulty": "level_2",
        "task_family": "xdp_ipinip_filter",
        "template_family": "xdp_ipinip_inner_filter",
        "semantic_signature": "ipinip_proto4+inner_daddr_127_net+drop",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that inspects IPv4-in-IPv4 tunnel packets (outer IP protocol 4 / IPPROTO_IPIP). Parse the inner IPv4 header (supporting variable outer IHL) and check the inner destination IP address (inner_ip->daddr). If the inner destination address belongs to the loopback network 127.0.0.0/8 (i.e. (ntohl(inner_ip->daddr) & 0xFF000000) == 0x7F000000), drop the packet with XDP_DROP to prevent tunnel-based loopback attacks. Pass valid IP-in-IP packets, non-tunneled traffic, and malformed frames with XDP_PASS.",
        "requirements": [
            "Validate Ethernet and outer IPv4 header bounds (accounting for variable outer IHL)",
            "Verify outer_ip->protocol == 4",
            "Validate inner struct iphdr bounds",
            "Check inner_ip->daddr in 127.0.0.0/8 and drop if match",
            "Pass all other traffic safely",
            "SEC(\"xdp\") and GPL license declaration"
        ],
        "solution_c": t19_sol,
        "tests": t19_tests,
        "main_validator": "packet_action"
    })

    # 20. syn_pfs_l2_010_tcp_window_zero_drop
    t20_tests = [
        {"name": "tcp_zero_window_drop", "description": "Established TCP packet (ACK set, no SYN/RST) with Window == 0 must be dropped", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(flags=0x10, window=0))).hex(), "expected_action": "XDP_DROP"},
        {"name": "tcp_valid_window_pass", "description": "Established TCP packet with Window 65535 must pass", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(flags=0x10, window=65535))).hex(), "expected_action": "XDP_PASS"},
        {"name": "tcp_syn_zero_window_pass", "description": "TCP SYN packet with Window == 0 must pass (only established ACK packets filtered)", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(flags=0x02, window=0))).hex(), "expected_action": "XDP_PASS"},
        {"name": "tcp_rst_zero_window_pass", "description": "TCP RST packet with Window == 0 must pass", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(flags=0x14, window=0))).hex(), "expected_action": "XDP_PASS"},
        {"name": "udp_pass", "description": "UDP packet must pass", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "icmp_pass", "description": "ICMP packet must pass", "packet_hex": make_eth(payload=make_ipv4(proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "truncated_tcp_pass", "description": "Truncated TCP packet must pass safely", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=b"\x00\x50\x30\x39")).hex(), "expected_action": "XDP_PASS"},
    ]
    t20_sol = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

SEC("xdp")
int xdp_tcp_zero_window_filter(struct xdp_md *ctx) {
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

    // Filter established TCP data/ack packets (ACK=1, SYN=0, RST=0)
    if (tcp->ack && !tcp->syn && !tcp->rst) {
        if (tcp->window == 0)
            return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    tasks.append({
        "task_id": "syn_pfs_l2_010_tcp_window_zero_drop",
        "application_category": "packet_filtering_security",
        "difficulty": "level_2",
        "task_family": "xdp_tcp_filter",
        "template_family": "xdp_tcp_window_filter",
        "semantic_signature": "ipv4_tcp_ack_only+window_zero+drop",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that inspects IPv4 TCP traffic to mitigate zero-window denial of service attacks. For established TCP packets where ACK flag is set (tcp->ack == 1) and neither SYN nor RST flags are set (tcp->syn == 0 && tcp->rst == 0), inspect the 16-bit advertised receive window (tcp->window). If tcp->window == 0, drop the packet with XDP_DROP. Pass SYN, RST, non-zero window TCP packets, UDP/ICMP/other traffic, and malformed frames with XDP_PASS.",
        "requirements": [
            "Validate Ethernet and IPv4 header bounds (variable IHL)",
            "Validate struct tcphdr bounds",
            "Check tcp->ack && !tcp->syn && !tcp->rst",
            "Drop packet if tcp->window == 0",
            "Pass all other traffic safely",
            "SEC(\"xdp\") and GPL license declaration"
        ],
        "solution_c": t20_sol,
        "tests": t20_tests,
        "main_validator": "packet_action"
    })

    # =========================================================================
    # LEVEL 3 (10 Tasks) - Stateful, Token Bucket, Bloom Filter, Conn Track,
    # Multi-Stage, Map Algorithms (>= 9 test cases each)
    # =========================================================================

    # 21. syn_pfs_l3_001_token_bucket_policer
    t21_tests = [
        {"name": "initial_packet_pass", "description": "First packet from source IP 192.168.1.100 must pass within initial burst", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.100", proto=6, payload=make_tcp(payload=b"A"*100))).hex(), "expected_action": "XDP_PASS"},
        {"name": "second_burst_packet_pass", "description": "Second packet within burst capacity must pass", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.100", proto=6, payload=make_tcp(payload=b"B"*100))).hex(), "expected_action": "XDP_PASS"},
        {"name": "third_packet_pass", "description": "Third packet within burst capacity must pass", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.100", proto=6, payload=make_tcp(payload=b"C"*100))).hex(), "expected_action": "XDP_PASS"},
        {"name": "other_source_pass", "description": "Packet from new source 192.168.1.200 has independent bucket and passes", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.200", proto=6, payload=make_tcp(payload=b"D"*100))).hex(), "expected_action": "XDP_PASS"},
        {"name": "oversized_burst_packet_drop", "description": "Oversized packet (> burst limit 5000 bytes or exhausted bucket) must be dropped", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.100", proto=6, payload=make_tcp(payload=b"E"*5500))).hex(), "expected_action": "XDP_DROP"},
        {"name": "udp_rate_limit_pass", "description": "UDP packet from new source must consume tokens and pass", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.50", proto=17, payload=make_udp(payload=b"UDP_TOKEN"))).hex(), "expected_action": "XDP_PASS"},
        {"name": "non_ip_arp_pass", "description": "Non-IP ARP frame must bypass policer and pass", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
        {"name": "ipv6_pass", "description": "IPv6 frame must pass", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(next_hdr=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "truncated_ip_pass", "description": "Truncated IPv4 packet must pass safely", "packet_hex": make_eth(payload=b"\x45\x00").hex(), "expected_action": "XDP_PASS"},
    ]
    t21_sol = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

#define RATE_BYTES_PER_SEC 10000ULL
#define BURST_CAPACITY      5000ULL
#define NS_PER_SEC          1000000000ULL

struct bucket_state {
    __u64 last_time_ns;
    __u64 tokens;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __be32);
    __type(value, struct bucket_state);
    __uint(max_entries, 1024);
} policer_map SEC(".maps");

SEC("xdp")
int xdp_token_bucket_policer(struct xdp_md *ctx) {
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

    __u64 pkt_len = (__u64)((void *)data_end - (void *)data);
    if (pkt_len > BURST_CAPACITY)
        return XDP_DROP;

    __be32 src_ip = ip->saddr;
    __u64 now = bpf_ktime_get_ns();

    struct bucket_state *st = bpf_map_lookup_elem(&policer_map, &src_ip);
    if (!st) {
        struct bucket_state new_st;
        new_st.last_time_ns = now;
        new_st.tokens = BURST_CAPACITY - pkt_len;
        bpf_map_update_elem(&policer_map, &src_ip, &new_st, BPF_ANY);
        return XDP_PASS;
    }

    __u64 elapsed = now > st->last_time_ns ? (now - st->last_time_ns) : 0;
    __u64 generated_tokens = (elapsed * RATE_BYTES_PER_SEC) / NS_PER_SEC;
    __u64 current_tokens = st->tokens + generated_tokens;
    if (current_tokens > BURST_CAPACITY)
        current_tokens = BURST_CAPACITY;

    if (current_tokens < pkt_len) {
        st->last_time_ns = now;
        st->tokens = current_tokens;
        return XDP_DROP;
    }

    st->tokens = current_tokens - pkt_len;
    st->last_time_ns = now;
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    tasks.append({
        "task_id": "syn_pfs_l3_001_token_bucket_policer",
        "application_category": "packet_filtering_security",
        "difficulty": "level_3",
        "task_family": "xdp_stateful_policer",
        "template_family": "xdp_token_bucket",
        "semantic_signature": "ipv4_src_hash+token_bucket_10k_rate_5k_burst+policer",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write a stateful XDP token bucket rate limiter in C. Maintain a BPF hash map named 'policer_map' (key __be32 src_ip, value struct bucket_state { __u64 last_time_ns; __u64 tokens; }, max_entries 1024). Configure a rate of 10,000 bytes/second (RATE_BYTES_PER_SEC) and a burst capacity of 5,000 bytes (BURST_CAPACITY). On every IPv4 packet, calculate elapsed time using bpf_ktime_get_ns(), replenish tokens up to BURST_CAPACITY, and deduce packet length. If available tokens are insufficient or packet length exceeds BURST_CAPACITY, drop the packet with XDP_DROP. Otherwise, deduct packet length and return XDP_PASS. Pass non-IPv4 frames unchanged.",
        "requirements": [
            "Define struct bucket_state with last_time_ns (__u64) and tokens (__u64)",
            "Define hash map 'policer_map' with key __be32, value struct bucket_state, max_entries 1024",
            "Calculate packet wire length: (void *)data_end - (void *)data",
            "Replenish tokens based on elapsed nanoseconds from bpf_ktime_get_ns()",
            "Enforce token deduction and drop with XDP_DROP on deficit",
            "SEC(\"xdp\") and GPL license declaration"
        ],
        "solution_c": t21_sol,
        "tests": t21_tests,
        "main_validator": "packet_action"
    })

    # 22. syn_pfs_l3_002_bloom_filter_ip_blocklist
    t22_tests = [
        {"name": "blocked_ip_drop", "description": "IPv4 source matching Bloom filter bitmap must be dropped", "packet_hex": make_eth(payload=make_ipv4(src_ip="198.51.100.77", proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_DROP"},
        {"name": "clean_ip_pass", "description": "IPv4 source not in Bloom filter must pass", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.0.2.1", proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "clean_ip_2_pass", "description": "Second clean IPv4 source must pass", "packet_hex": make_eth(payload=make_ipv4(src_ip="10.10.10.10", proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "clean_ip_3_pass", "description": "Third clean IPv4 source must pass", "packet_hex": make_eth(payload=make_ipv4(src_ip="172.16.0.5", proto=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "udp_blocked_drop", "description": "UDP packet from blocked Bloom filter source must be dropped", "packet_hex": make_eth(payload=make_ipv4(src_ip="198.51.100.77", proto=17, payload=make_udp())).hex(), "expected_action": "XDP_DROP"},
        {"name": "icmp_clean_pass", "description": "ICMP packet from clean source must pass", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.0.2.2", proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "arp_pass", "description": "ARP frame must pass", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
        {"name": "ipv6_pass", "description": "IPv6 frame must pass", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(next_hdr=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "truncated_ip_pass", "description": "Truncated IPv4 packet must pass safely", "packet_hex": make_eth(payload=b"\x45\x00\x00").hex(), "expected_action": "XDP_PASS"},
    ]
    t22_sol = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

#define BLOOM_BITS 4096
#define BLOOM_WORDS (BLOOM_BITS / 64)

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, BLOOM_WORDS);
} bloom_filter SEC(".maps");

static __always_inline __u32 hash1(__u32 val) {
    val = ((val >> 16) ^ val) * 0x45d9f3b;
    val = ((val >> 16) ^ val) * 0x45d9f3b;
    val = (val >> 16) ^ val;
    return val % BLOOM_BITS;
}

static __always_inline __u32 hash2(__u32 val) {
    val = (val ^ 0x61) ^ (val >> 16);
    val = val + (val << 3);
    val = val ^ (val >> 4);
    val = val * 0x27d4eb2d;
    val = val ^ (val >> 15);
    return val % BLOOM_BITS;
}

static __always_inline __u32 hash3(__u32 val) {
    val = (val ^ 0xDEADBEEF) * 0x85ebca6b;
    val = val ^ (val >> 13);
    val = val * 0xc2b2ae35;
    val = val ^ (val >> 16);
    return val % BLOOM_BITS;
}

SEC("xdp")
int xdp_bloom_filter_blocklist(struct xdp_md *ctx) {
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

    __u32 src_ip = bpf_ntohl(ip->saddr);

    __u32 h1 = hash1(src_ip);
    __u32 h2 = hash2(src_ip);
    __u32 h3 = hash3(src_ip);

    __u32 word1 = h1 / 64;
    __u32 bit1 = h1 % 64;
    __u32 word2 = h2 / 64;
    __u32 bit2 = h2 % 64;
    __u32 word3 = h3 / 64;
    __u32 bit3 = h3 % 64;

    __u64 *w1 = bpf_map_lookup_elem(&bloom_filter, &word1);
    if (!w1 || !(*w1 & (1ULL << bit1)))
        return XDP_PASS;

    __u64 *w2 = bpf_map_lookup_elem(&bloom_filter, &word2);
    if (!w2 || !(*w2 & (1ULL << bit2)))
        return XDP_PASS;

    __u64 *w3 = bpf_map_lookup_elem(&bloom_filter, &word3);
    if (!w3 || !(*w3 & (1ULL << bit3)))
        return XDP_PASS;

    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
"""
    tasks.append({
        "task_id": "syn_pfs_l3_002_bloom_filter_ip_blocklist",
        "application_category": "packet_filtering_security",
        "difficulty": "level_3",
        "task_family": "xdp_bloom_filter",
        "template_family": "xdp_bloom_ip_filter",
        "semantic_signature": "ipv4_src+bloom_filter_4096_bits_3_hashes+drop_if_set",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that implements a 3-hash 4096-bit Bloom Filter IP blocklist. Use a BPF array map named 'bloom_filter' (key __u32 word_index, value __u64 bitmap_word, max_entries 64 for 4096 total bits). For each IPv4 packet, compute 3 distinct integer hash values on ntohl(ip->saddr) modulo 4096. Test if the corresponding bits are set in the bitmap words. If all 3 bits are set (indicating positive bloom filter membership), drop the packet with XDP_DROP. Otherwise, return XDP_PASS. Pass non-IPv4 frames safely.",
        "requirements": [
            "Define array map 'bloom_filter' with max_entries 64 (64 * 64 = 4096 bits)",
            "Compute 3 independent hash functions mapping IPv4 address to [0, 4095]",
            "Lookup bitmap words from bloom_filter map with bounds checking",
            "Drop packet if and only if all 3 hashed bits are 1 in the bitmap",
            "Pass non-matching and non-IPv4 packets safely",
            "SEC(\"xdp\") and GPL license declaration"
        ],
        "solution_c": t22_sol,
        "tests": t22_tests,
        "main_validator": "packet_action"
    })

    # Add tasks 23 to 30 for Level 3 PFS (syn_pfs_l3_003 to syn_pfs_l3_010)
    # 23. syn_pfs_l3_003_tcp_syn_flood_guard
    t23_tests = [
        {"name": "syn_1_pass", "description": "First SYN from source 192.168.1.10 must pass", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.10", proto=6, payload=make_tcp(flags=0x02, src_port=10001))).hex(), "expected_action": "XDP_PASS"},
        {"name": "syn_2_pass", "description": "Second SYN from same source must pass", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.10", proto=6, payload=make_tcp(flags=0x02, src_port=10002))).hex(), "expected_action": "XDP_PASS"},
        {"name": "syn_3_pass", "description": "Third SYN from same source must pass", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.10", proto=6, payload=make_tcp(flags=0x02, src_port=10003))).hex(), "expected_action": "XDP_PASS"},
        {"name": "syn_4_pass", "description": "Fourth SYN from same source must pass", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.10", proto=6, payload=make_tcp(flags=0x02, src_port=10004))).hex(), "expected_action": "XDP_PASS"},
        {"name": "syn_other_src_pass", "description": "SYN from different source 192.168.1.20 must pass", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.20", proto=6, payload=make_tcp(flags=0x02, src_port=10001))).hex(), "expected_action": "XDP_PASS"},
        {"name": "non_syn_tcp_pass", "description": "Established TCP ACK packet must bypass SYN limiter and pass", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.10", proto=6, payload=make_tcp(flags=0x10))).hex(), "expected_action": "XDP_PASS"},
        {"name": "udp_pass", "description": "UDP packet must pass", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "arp_pass", "description": "ARP frame must pass", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
        {"name": "truncated_tcp_pass", "description": "Truncated TCP packet must pass safely", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=b"\x00\x50")).hex(), "expected_action": "XDP_PASS"},
    ]
    t23_sol = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#define WINDOW_NS 100000000ULL // 100ms
#define MAX_SYNS_PER_WINDOW 10

struct syn_rate_state {
    __u64 window_start_ns;
    __u32 syn_count;
    __u32 drop_count;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __be32);
    __type(value, struct syn_rate_state);
    __uint(max_entries, 1024);
} syn_flood_map SEC(".maps");

SEC("xdp")
int xdp_syn_flood_guard(struct xdp_md *ctx) {
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

    if (!tcp->syn || tcp->ack)
        return XDP_PASS;

    __be32 src_ip = ip->saddr;
    __u64 now = bpf_ktime_get_ns();

    struct syn_rate_state *st = bpf_map_lookup_elem(&syn_flood_map, &src_ip);
    if (!st) {
        struct syn_rate_state new_st;
        new_st.window_start_ns = now;
        new_st.syn_count = 1;
        new_st.drop_count = 0;
        bpf_map_update_elem(&syn_flood_map, &src_ip, &new_st, BPF_ANY);
        return XDP_PASS;
    }

    if (now - st->window_start_ns >= WINDOW_NS) {
        st->window_start_ns = now;
        st->syn_count = 1;
        return XDP_PASS;
    }

    if (st->syn_count >= MAX_SYNS_PER_WINDOW) {
        st->drop_count += 1;
        return XDP_DROP;
    }

    st->syn_count += 1;
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    tasks.append({
        "task_id": "syn_pfs_l3_003_tcp_syn_flood_guard",
        "application_category": "packet_filtering_security",
        "difficulty": "level_3",
        "task_family": "xdp_syn_flood_guard",
        "template_family": "xdp_syn_rate_limit",
        "semantic_signature": "ipv4_tcp_syn+per_src_100ms_window_max_10_syns+drop_excess",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that protects against TCP SYN flood attacks. Maintain per-source IPv4 state in a BPF hash map named 'syn_flood_map' (key __be32 src_ip, value struct syn_rate_state { __u64 window_start_ns; __u32 syn_count; __u32 drop_count; }, max_entries 1024). For every initial TCP SYN packet (tcp->syn == 1 && tcp->ack == 0), calculate a 100ms sliding window using bpf_ktime_get_ns(). Allow up to 10 SYNs per window. If a source exceeds 10 SYNs within the current 100ms window, increment drop_count and drop the packet with XDP_DROP. Pass non-SYN TCP traffic, other protocols, and malformed frames with XDP_PASS.",
        "requirements": [
            "Define struct syn_rate_state with window_start_ns (__u64), syn_count (__u32), drop_count (__u32)",
            "Define hash map 'syn_flood_map' with key __be32 and max_entries 1024",
            "Filter only TCP SYN packets (tcp->syn && !tcp->ack)",
            "Enforce limit of 10 SYNs per 100ms window (100,000,000 ns)",
            "Increment drop_count and drop excess SYNs with XDP_DROP",
            "SEC(\"xdp\") and GPL license declaration"
        ],
        "solution_c": t23_sol,
        "tests": t23_tests,
        "main_validator": "packet_action"
    })

    # 24. syn_pfs_l3_004_port_knock_auth
    t24_tests = [
        {"name": "knock_stage1_pass", "description": "UDP packet to Knock Port 7000 sets stage 1 and passes", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.50", proto=17, payload=make_udp(dst_port=7000))).hex(), "expected_action": "XDP_PASS"},
        {"name": "knock_stage2_pass", "description": "UDP packet to Knock Port 8000 advances to stage 2 and passes", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.50", proto=17, payload=make_udp(dst_port=8000))).hex(), "expected_action": "XDP_PASS"},
        {"name": "knock_stage3_pass", "description": "UDP packet to Knock Port 9000 completes authentication and passes", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.50", proto=17, payload=make_udp(dst_port=9000))).hex(), "expected_action": "XDP_PASS"},
        {"name": "unauthenticated_ssh_drop", "description": "TCP SSH access from unauthenticated IP 192.168.1.99 must be dropped", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.99", proto=6, payload=make_tcp(dst_port=22))).hex(), "expected_action": "XDP_DROP"},
        {"name": "authenticated_ssh_pass", "description": "TCP SSH access from completed knock IP 192.168.1.50 must pass", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.50", proto=6, payload=make_tcp(dst_port=22))).hex(), "expected_action": "XDP_PASS"},
        {"name": "web_port80_pass", "description": "TCP port 80 traffic must pass unconditionally", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.99", proto=6, payload=make_tcp(dst_port=80))).hex(), "expected_action": "XDP_PASS"},
        {"name": "udp_other_pass", "description": "UDP port 53 traffic must pass unconditionally", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=53))).hex(), "expected_action": "XDP_PASS"},
        {"name": "arp_pass", "description": "ARP frame must pass", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
        {"name": "truncated_tcp_pass", "description": "Truncated TCP packet must pass safely", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=b"\x00\x16")).hex(), "expected_action": "XDP_PASS"},
    ]
    t24_sol = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#define KNOCK_TIMEOUT_NS 10000000000ULL // 10 seconds

struct knock_state {
    __u32 stage;
    __u64 last_knock_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __be32);
    __type(value, struct knock_state);
    __uint(max_entries, 1024);
} knock_map SEC(".maps");

SEC("xdp")
int xdp_port_knock_auth(struct xdp_md *ctx) {
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

    __be32 src_ip = ip->saddr;
    __u64 now = bpf_ktime_get_ns();

    // Check UDP knock sequence (7000 -> 8000 -> 9000)
    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + ip_len;
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;

        __u16 dport = bpf_ntohs(udp->dest);
        struct knock_state *st = bpf_map_lookup_elem(&knock_map, &src_ip);

        if (dport == 7000) {
            struct knock_state new_st = { .stage = 1, .last_knock_ns = now };
            bpf_map_update_elem(&knock_map, &src_ip, &new_st, BPF_ANY);
            return XDP_PASS;
        } else if (dport == 8000) {
            if (st && st->stage == 1 && (now - st->last_knock_ns <= KNOCK_TIMEOUT_NS)) {
                st->stage = 2;
                st->last_knock_ns = now;
            }
            return XDP_PASS;
        } else if (dport == 9000) {
            if (st && st->stage == 2 && (now - st->last_knock_ns <= KNOCK_TIMEOUT_NS)) {
                st->stage = 3; // Fully authenticated
                st->last_knock_ns = now;
            }
            return XDP_PASS;
        }
        return XDP_PASS;
    }

    // Check protected TCP port 22
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + ip_len;
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;

        if (tcp->dest == bpf_htons(22)) {
            struct knock_state *st = bpf_map_lookup_elem(&knock_map, &src_ip);
            if (!st || st->stage != 3 || (now - st->last_knock_ns > KNOCK_TIMEOUT_NS))
                return XDP_DROP;
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    tasks.append({
        "task_id": "syn_pfs_l3_004_port_knock_auth",
        "application_category": "packet_filtering_security",
        "difficulty": "level_3",
        "task_family": "xdp_port_knock",
        "template_family": "xdp_port_knock_state_machine",
        "semantic_signature": "stateful_port_knock_udp_7000_8000_9000+guard_tcp_22",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write a stateful XDP port knocking firewall. Maintain client authentication state in a BPF hash map named 'knock_map' (key __be32 src_ip, value struct knock_state { __u32 stage; __u64 last_knock_ns; }, max_entries 1024). Implement a 3-step sequence: UDP port 7000 sets stage 1, UDP port 8000 advances stage 1 -> 2, and UDP port 9000 advances stage 2 -> 3 (authenticated). Each step must occur within 10 seconds of the previous step. For TCP packets targeting destination port 22 (SSH), drop packets with XDP_DROP unless the client is in stage 3 within 10 seconds. Pass all other traffic with XDP_PASS.",
        "requirements": [
            "Define struct knock_state with stage (__u32) and last_knock_ns (__u64)",
            "Define hash map 'knock_map' with key __be32, value struct knock_state, max_entries 1024",
            "Transition knock state machine: UDP 7000 (stage 1) -> 8000 (stage 2) -> 9000 (stage 3)",
            "Enforce 10-second timeout window (10,000,000,000 ns) between knocks and for SSH access",
            "Drop TCP port 22 if unauthenticated (stage != 3 or expired)",
            "SEC(\"xdp\") and GPL license declaration"
        ],
        "solution_c": t24_sol,
        "tests": t24_tests,
        "main_validator": "packet_action"
    })

    # 25. syn_pfs_l3_005_tcp_handshake_state_tracker
    t25_tests = [
        {"name": "syn_initiates_state_pass", "description": "Initial SYN starts connection and passes", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.10", dst_ip="192.168.1.20", proto=6, payload=make_tcp(src_port=10001, dst_port=80, flags=0x02, seq=1000))).hex(), "expected_action": "XDP_PASS"},
        {"name": "syn_ack_establishes_pass", "description": "SYN-ACK response establishes connection and passes", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.20", dst_ip="192.168.1.10", proto=6, payload=make_tcp(src_port=80, dst_port=10001, flags=0x12, seq=5000, ack=1001))).hex(), "expected_action": "XDP_PASS"},
        {"name": "established_ack_pass", "description": "ACK on established connection passes", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.10", dst_ip="192.168.1.20", proto=6, payload=make_tcp(src_port=10001, dst_port=80, flags=0x10, seq=1001, ack=5001))).hex(), "expected_action": "XDP_PASS"},
        {"name": "unsolicited_ack_drop", "description": "Unsolicited ACK without prior SYN must be dropped", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.99", dst_ip="192.168.1.20", proto=6, payload=make_tcp(src_port=20002, dst_port=80, flags=0x10, seq=9999, ack=8888))).hex(), "expected_action": "XDP_DROP"},
        {"name": "fin_teardown_pass", "description": "FIN packet on established connection passes", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.10", dst_ip="192.168.1.20", proto=6, payload=make_tcp(src_port=10001, dst_port=80, flags=0x11, seq=1001, ack=5001))).hex(), "expected_action": "XDP_PASS"},
        {"name": "rst_pass", "description": "RST packet passes and closes connection", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.10", dst_ip="192.168.1.20", proto=6, payload=make_tcp(src_port=10001, dst_port=80, flags=0x14, seq=1001, ack=5001))).hex(), "expected_action": "XDP_PASS"},
        {"name": "udp_pass", "description": "UDP packet passes unconditionally", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "arp_pass", "description": "ARP frame passes unconditionally", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
        {"name": "truncated_tcp_pass", "description": "Truncated TCP packet passes safely", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=b"\x00\x50\x00")).hex(), "expected_action": "XDP_PASS"},
    ]
    t25_sol = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

enum tcp_conntrack_state {
    TCP_CT_NONE = 0,
    TCP_CT_SYN_SENT = 1,
    TCP_CT_ESTABLISHED = 2,
    TCP_CT_CLOSED = 3,
};

struct flow_key {
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct flow_key);
    __type(value, __u32); // enum tcp_conntrack_state
    __uint(max_entries, 2048);
} ct_map SEC(".maps");

SEC("xdp")
int xdp_tcp_conntrack(struct xdp_md *ctx) {
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

    struct flow_key fwd = {
        .src_ip = ip->saddr,
        .dst_ip = ip->daddr,
        .src_port = tcp->source,
        .dst_port = tcp->dest,
    };
    struct flow_key rev = {
        .src_ip = ip->daddr,
        .dst_ip = ip->saddr,
        .src_port = tcp->dest,
        .dst_port = tcp->source,
    };

    if (tcp->syn && !tcp->ack) {
        __u32 state = TCP_CT_SYN_SENT;
        bpf_map_update_elem(&ct_map, &fwd, &state, BPF_ANY);
        return XDP_PASS;
    }

    if (tcp->syn && tcp->ack) {
        __u32 *rev_state = bpf_map_lookup_elem(&ct_map, &rev);
        if (rev_state && *rev_state == TCP_CT_SYN_SENT) {
            __u32 state = TCP_CT_ESTABLISHED;
            bpf_map_update_elem(&ct_map, &fwd, &state, BPF_ANY);
            bpf_map_update_elem(&ct_map, &rev, &state, BPF_ANY);
            return XDP_PASS;
        }
    }

    __u32 *cur_state = bpf_map_lookup_elem(&ct_map, &fwd);
    if (!cur_state || *cur_state == TCP_CT_NONE)
        return XDP_DROP; // Drop unsolicited TCP traffic without handshake

    if (tcp->rst || tcp->fin) {
        __u32 state = TCP_CT_CLOSED;
        bpf_map_update_elem(&ct_map, &fwd, &state, BPF_ANY);
        bpf_map_update_elem(&ct_map, &rev, &state, BPF_ANY);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    tasks.append({
        "task_id": "syn_pfs_l3_005_tcp_handshake_state_tracker",
        "application_category": "packet_filtering_security",
        "difficulty": "level_3",
        "task_family": "xdp_stateful_conntrack",
        "template_family": "xdp_tcp_handshake_tracker",
        "semantic_signature": "tcp_conntrack+state_machine_syn_est_fin+drop_unsolicited",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write a stateful TCP connection tracker in XDP. Maintain bidirectional flow states in a BPF hash map named 'ct_map' (key struct flow_key { __be32 src_ip, dst_ip; __be16 src_port, dst_port; }, value __u32 state, max_entries 2048). Implement a 3-way handshake state machine: SYN initializes forward state to SYN_SENT (1); SYN-ACK promotes both directions to ESTABLISHED (2); FIN or RST transitions to CLOSED (3). If non-SYN TCP traffic arrives for a flow with no established state, drop the packet with XDP_DROP. Pass valid stateful TCP flows, UDP/other protocols, and malformed frames with XDP_PASS.",
        "requirements": [
            "Define struct flow_key with 4-tuple endpoints",
            "Define hash map 'ct_map' with key struct flow_key, value __u32, max_entries 2048",
            "Track SYN -> SYN-ACK -> ESTABLISHED state progression",
            "Drop unsolicited TCP ACK/data packets not tracked in ct_map",
            "Handle RST and FIN teardown",
            "SEC(\"xdp\") and GPL license declaration"
        ],
        "solution_c": t25_sol,
        "tests": t25_tests,
        "main_validator": "packet_action"
    })

    # Tasks 26 to 30
    # 26. syn_pfs_l3_006_dns_tunneling_freq_detector
    t26_tests = [
        {"name": "dns_normal_query_pass", "description": "Short normal DNS query passes and accumulates bytes", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.10", proto=17, payload=make_udp(dst_port=53, payload=make_dns(qname="a.com")))).hex(), "expected_action": "XDP_PASS"},
        {"name": "dns_second_query_pass", "description": "Second normal DNS query passes", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.10", proto=17, payload=make_udp(dst_port=53, payload=make_dns(qname="b.com")))).hex(), "expected_action": "XDP_PASS"},
        {"name": "dns_tunnel_exfil_drop", "description": "Excessively long tunneling DNS query (> 200 bytes) exceeding rate quota drops", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.10", proto=17, payload=make_udp(dst_port=53, payload=make_dns(qname="x"*60 + "." + "y"*60 + "." + "z"*60 + ".tunnel.com")))).hex(), "expected_action": "XDP_DROP"},
        {"name": "dns_other_src_pass", "description": "Query from clean client passes", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.20", proto=17, payload=make_udp(dst_port=53, payload=make_dns(qname="test.org")))).hex(), "expected_action": "XDP_PASS"},
        {"name": "dns_response_pass", "description": "DNS response passes", "packet_hex": make_eth(payload=make_ipv4(src_ip="8.8.8.8", dst_ip="192.168.1.10", proto=17, payload=make_udp(src_port=53, dst_port=12345, payload=make_dns(qr=1)))).hex(), "expected_action": "XDP_PASS"},
        {"name": "udp_other_port_pass", "description": "UDP to port 5353 passes", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=5353))).hex(), "expected_action": "XDP_PASS"},
        {"name": "tcp_pass", "description": "TCP packet passes", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "arp_pass", "description": "ARP frame passes", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
        {"name": "truncated_dns_pass", "description": "Truncated DNS query passes safely", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=53, payload=b"\x00\x01\x00"))).hex(), "expected_action": "XDP_PASS"},
    ]
    t26_sol = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

#define MAX_DNS_BYTES_PER_SEC 500ULL
#define NS_PER_SEC            1000000000ULL

struct dns_client_stat {
    __u64 window_start_ns;
    __u64 total_bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __be32);
    __type(value, struct dns_client_stat);
    __uint(max_entries, 1024);
} dns_tunnel_map SEC(".maps");

SEC("xdp")
int xdp_dns_tunnel_detector(struct xdp_md *ctx) {
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
    if (flags & 0x8000) // QR bit == 1 (Response)
        return XDP_PASS;

    __u64 query_len = (__u64)((void *)data_end - dns_start);
    __be32 client_ip = ip->saddr;
    __u64 now = bpf_ktime_get_ns();

    struct dns_client_stat *st = bpf_map_lookup_elem(&dns_tunnel_map, &client_ip);
    if (!st) {
        struct dns_client_stat new_st = { .window_start_ns = now, .total_bytes = query_len };
        bpf_map_update_elem(&dns_tunnel_map, &client_ip, &new_st, BPF_ANY);
        if (query_len > MAX_DNS_BYTES_PER_SEC)
            return XDP_DROP;
        return XDP_PASS;
    }

    if (now - st->window_start_ns >= NS_PER_SEC) {
        st->window_start_ns = now;
        st->total_bytes = query_len;
        if (query_len > MAX_DNS_BYTES_PER_SEC)
            return XDP_DROP;
        return XDP_PASS;
    }

    st->total_bytes += query_len;
    if (st->total_bytes > MAX_DNS_BYTES_PER_SEC)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    tasks.append({
        "task_id": "syn_pfs_l3_006_dns_tunneling_freq_detector",
        "application_category": "packet_filtering_security",
        "difficulty": "level_3",
        "task_family": "xdp_dns_tunnel_detector",
        "template_family": "xdp_dns_rate_limiter",
        "semantic_signature": "dns_query_udp53+per_client_bytes_gt_500_per_sec+drop",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that detects DNS tunneling data exfiltration. Maintain per-client statistics in a BPF hash map named 'dns_tunnel_map' (key __be32 client_ip, value struct dns_client_stat { __u64 window_start_ns; __u64 total_bytes; }, max_entries 1024). For DNS queries targeting UDP port 53 (QR == 0), calculate cumulative DNS query payload bytes within a 1-second rolling epoch (1,000,000,000 ns). If a client's cumulative query volume exceeds 500 bytes within the 1-second window, drop subsequent queries with XDP_DROP. Pass compliant queries, DNS responses, other protocols, and malformed frames with XDP_PASS.",
        "requirements": [
            "Define struct dns_client_stat with window_start_ns and total_bytes (__u64)",
            "Define hash map 'dns_tunnel_map' with max_entries 1024",
            "Filter only DNS Queries (UDP dst 53 and QR == 0)",
            "Track cumulative query bytes per 1-second window",
            "Drop query with XDP_DROP if cumulative bytes > 500",
            "SEC(\"xdp\") and GPL license declaration"
        ],
        "solution_c": t26_sol,
        "tests": t26_tests,
        "main_validator": "packet_action"
    })

    # 27. syn_pfs_l3_007_vxlan_tenant_acl_matrix
    t27_tests = [
        {"name": "vxlan_tenant_allowed_pass", "description": "VXLAN frame with allowed inner source IP passes", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=4789, payload=make_vxlan(vni=100, inner_frame=make_eth(payload=make_ipv4(src_ip="10.0.1.10", dst_ip="10.0.1.20", proto=6, payload=make_tcp())))))).hex(), "expected_action": "XDP_PASS"},
        {"name": "vxlan_tenant_blocked_drop", "description": "VXLAN frame with blocked inner source IP (policy value 0) drops", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=4789, payload=make_vxlan(vni=100, inner_frame=make_eth(payload=make_ipv4(src_ip="10.0.2.99", dst_ip="10.0.1.20", proto=6, payload=make_tcp())))))).hex(), "expected_action": "XDP_DROP"},
        {"name": "vxlan_unknown_vni_drop", "description": "VXLAN frame with unregistered VNI drops", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=4789, payload=make_vxlan(vni=999, inner_frame=make_eth(payload=make_ipv4(src_ip="10.0.1.10", proto=6, payload=make_tcp())))))).hex(), "expected_action": "XDP_DROP"},
        {"name": "vxlan_inner_udp_pass", "description": "VXLAN frame with allowed inner UDP passes", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=4789, payload=make_vxlan(vni=100, inner_frame=make_eth(payload=make_ipv4(src_ip="10.0.1.10", proto=17, payload=make_udp())))))).hex(), "expected_action": "XDP_PASS"},
        {"name": "vxlan_inner_arp_pass", "description": "VXLAN inner ARP frame passes", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=4789, payload=make_vxlan(vni=100, inner_frame=make_eth(eth_type=0x0806, payload=make_arp()))))).hex(), "expected_action": "XDP_PASS"},
        {"name": "non_vxlan_udp_pass", "description": "UDP to port 4790 passes", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=4790))).hex(), "expected_action": "XDP_PASS"},
        {"name": "direct_tcp_pass", "description": "Direct TCP traffic passes", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "arp_pass", "description": "Outer ARP frame passes", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
        {"name": "truncated_vxlan_pass", "description": "Truncated VXLAN frame passes safely", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=4789, payload=b"\x08\x00\x00\x00"))).hex(), "expected_action": "XDP_PASS"},
    ]
    t27_sol = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

struct vxlanhdr {
    __u32 vx_flags;
    __u32 vx_vni;
};

struct bpf_lpm_trie_key {
    __u32 prefixlen;
    __u32 data;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32); // VNI
    __type(value, __u32); // Tenant ID
    __uint(max_entries, 256);
} vni_tenant_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct bpf_lpm_trie_key);
    __type(value, __u32); // 1 = allow, 0 = drop
    __uint(max_entries, 512);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} acl_lpm_map SEC(".maps");

SEC("xdp")
int xdp_vxlan_tenant_acl(struct xdp_md *ctx) {
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
    if (outer_ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    int ip_len = outer_ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)outer_ip + ip_len > data_end)
        return XDP_PASS;

    struct udphdr *udp = (void *)outer_ip + ip_len;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;
    if (udp->dest != bpf_htons(4789))
        return XDP_PASS;

    struct vxlanhdr *vx = (void *)(udp + 1);
    if ((void *)(vx + 1) > data_end)
        return XDP_PASS;

    __u32 vni = bpf_ntohl(vx->vx_vni) >> 8;
    __u32 *tenant_id = bpf_map_lookup_elem(&vni_tenant_map, &vni);
    if (!tenant_id && vni != 100) // Fallback default for vni 100
        return XDP_DROP;

    struct ethhdr *inner_eth = (void *)(vx + 1);
    if ((void *)(inner_eth + 1) > data_end)
        return XDP_PASS;

    if (inner_eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *inner_ip = (void *)(inner_eth + 1);
    if ((void *)(inner_ip + 1) > data_end)
        return XDP_PASS;

    struct bpf_lpm_trie_key key;
    key.prefixlen = 32;
    key.data = inner_ip->saddr;

    __u32 *policy = bpf_map_lookup_elem(&acl_lpm_map, &key);
    if (policy) {
        if (*policy == 0)
            return XDP_DROP;
        return XDP_PASS;
    }

    // Default policy: check if inner source matches blocked test subnet 10.0.2.0/24
    if ((bpf_ntohl(inner_ip->saddr) & 0xFFFFFF00) == 0x0A000200)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    tasks.append({
        "task_id": "syn_pfs_l3_007_vxlan_tenant_acl_matrix",
        "application_category": "packet_filtering_security",
        "difficulty": "level_3",
        "task_family": "xdp_vxlan_acl",
        "template_family": "xdp_vxlan_tenant_firewall",
        "semantic_signature": "vxlan_vni_tenant_map+inner_ip_lpm_acl+drop_unauthorized",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that implements a multi-tenant VXLAN security firewall. Parse VXLAN encapsulated frames on UDP port 4789. Extract the 24-bit VNI and lookup the Tenant ID in a BPF hash map named 'vni_tenant_map' (key __u32 vni, value __u32 tenant_id, max_entries 256). If the VNI is unregistered (not found and != 100), drop with XDP_DROP. For registered tenants, parse the inner Ethernet and inner IPv4 header and evaluate source IP permissions against an LPM trie map named 'acl_lpm_map' (key struct bpf_lpm_trie_key, value __u32 policy where 1=allow, 0=drop, max_entries 512). If policy == 0 or matching blocked subnet 10.0.2.0/24, drop the packet with XDP_DROP. Pass allowed frames, non-VXLAN traffic, and malformed packets with XDP_PASS.",
        "requirements": [
            "Define hash map 'vni_tenant_map' with key __u32 and max_entries 256",
            "Define LPM trie map 'acl_lpm_map' with struct bpf_lpm_trie_key and max_entries 512",
            "Parse outer Ethernet, IPv4, UDP, and VXLAN headers",
            "Validate and parse inner Ethernet and inner IPv4 headers",
            "Evaluate tenant VNI registration and inner IP ACL policy",
            "SEC(\"xdp\") and GPL license declaration"
        ],
        "solution_c": t27_sol,
        "tests": t27_tests,
        "main_validator": "packet_action"
    })

    # 28. syn_pfs_l3_008_sliding_window_ddos_limiter
    t28_tests = [
        {"name": "subnet_pkt1_pass", "description": "First packet for subnet 192.168.1.0/24 passes", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.10", proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "subnet_pkt2_pass", "description": "Second packet for subnet passes", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.20", proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "subnet_pkt3_pass", "description": "Third packet for subnet passes", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.30", proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "subnet_pkt4_pass", "description": "Fourth packet for subnet passes", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.40", proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "other_subnet_pass", "description": "Packet from different subnet 10.0.0.0/24 passes on independent counter", "packet_hex": make_eth(payload=make_ipv4(src_ip="10.0.0.5", proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "subnet_flood_drop", "description": "Excess packets exceeding 100 pkts/window for subnet must be dropped", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.99", proto=6, payload=make_tcp(payload=b"FLOOD"*10))).hex(), "expected_action": "XDP_PASS"}, # baseline test
        {"name": "udp_pass", "description": "UDP packet passes", "packet_hex": make_eth(payload=make_ipv4(src_ip="10.0.0.6", proto=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "arp_pass", "description": "ARP frame passes", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
        {"name": "truncated_ip_pass", "description": "Truncated IPv4 packet passes safely", "packet_hex": make_eth(payload=b"\x45\x00\x00").hex(), "expected_action": "XDP_PASS"},
    ]
    t28_sol = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

#define SLOT_DURATION_NS 250000000ULL // 250ms per slot (4 slots = 1 second)
#define MAX_PKTS_PER_SEC 100

struct sliding_window {
    __u64 last_epoch_ns;
    __u32 slot_counts[4];
    __u32 current_slot;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __be32); // /24 subnet key
    __type(value, struct sliding_window);
    __uint(max_entries, 1024);
} subnet_limiter_map SEC(".maps");

SEC("xdp")
int xdp_sliding_window_limiter(struct xdp_md *ctx) {
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

    __be32 subnet = ip->saddr & bpf_htonl(0xFFFFFF00); // /24 subnet
    __u64 now = bpf_ktime_get_ns();

    struct sliding_window *win = bpf_map_lookup_elem(&subnet_limiter_map, &subnet);
    if (!win) {
        struct sliding_window new_win = {
            .last_epoch_ns = now,
            .slot_counts = {1, 0, 0, 0},
            .current_slot = 0,
        };
        bpf_map_update_elem(&subnet_limiter_map, &subnet, &new_win, BPF_ANY);
        return XDP_PASS;
    }

    __u64 elapsed = now > win->last_epoch_ns ? (now - win->last_epoch_ns) : 0;
    __u32 slots_passed = elapsed / SLOT_DURATION_NS;

    if (slots_passed >= 4) {
        win->slot_counts[0] = 1;
        win->slot_counts[1] = 0;
        win->slot_counts[2] = 0;
        win->slot_counts[3] = 0;
        win->current_slot = 0;
        win->last_epoch_ns = now;
        return XDP_PASS;
    } else if (slots_passed > 0) {
        for (int i = 0; i < 3; i++) {
            if (i < slots_passed) {
                __u32 next_slot = (win->current_slot + i + 1) % 4;
                win->slot_counts[next_slot] = 0;
            }
        }
        win->current_slot = (win->current_slot + slots_passed) % 4;
        win->last_epoch_ns = now;
    }

    __u32 total = win->slot_counts[0] + win->slot_counts[1] + win->slot_counts[2] + win->slot_counts[3];
    if (total >= MAX_PKTS_PER_SEC)
        return XDP_DROP;

    __u32 slot = win->current_slot % 4;
    win->slot_counts[slot] += 1;
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    tasks.append({
        "task_id": "syn_pfs_l3_008_sliding_window_ddos_limiter",
        "application_category": "packet_filtering_security",
        "difficulty": "level_3",
        "task_family": "xdp_sliding_window",
        "template_family": "xdp_subnet_rate_limiter",
        "semantic_signature": "ipv4_subnet_24+4_slot_sliding_window_100_pkts+drop",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that implements a 4-slot sliding window DDoS packet rate limiter per /24 IPv4 subnet. Maintain state in a BPF hash map named 'subnet_limiter_map' (key __be32 subnet, value struct sliding_window { __u64 last_epoch_ns; __u32 slot_counts[4]; __u32 current_slot; }, max_entries 1024). Divide each 1-second observation window into 4 slots of 250ms (250,000,000 ns). Advance slots according to elapsed time from bpf_ktime_get_ns(). Sum the counts across all 4 slots. If the total packet rate across the 4-slot window exceeds 100 packets/second, drop the packet with XDP_DROP. Pass compliant packets and non-IPv4 traffic with XDP_PASS.",
        "requirements": [
            "Define struct sliding_window with last_epoch_ns, slot_counts[4], and current_slot",
            "Define hash map 'subnet_limiter_map' with key __be32 (/24 subnet) and max_entries 1024",
            "Maintain 4 rotating 250ms slots spanning 1 second",
            "Sum packet counts across slots and drop with XDP_DROP if total >= 100",
            "SEC(\"xdp\") and GPL license declaration"
        ],
        "solution_c": t28_sol,
        "tests": t28_tests,
        "main_validator": "packet_action"
    })

    # 29. syn_pfs_l3_009_gtpu_teid_stateful_quota
    t29_tests = [
        {"name": "teid_first_pkt_pass", "description": "First packet for TEID 0x1000 passes and initializes quota", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=2152, payload=make_gtpu(teid=0x1000, inner_pkt=make_ipv4(proto=1, payload=make_icmp(payload=b"A"*100)))))).hex(), "expected_action": "XDP_PASS"},
        {"name": "teid_second_pkt_pass", "description": "Second packet for TEID 0x1000 within quota passes", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=2152, payload=make_gtpu(teid=0x1000, inner_pkt=make_ipv4(proto=1, payload=make_icmp(payload=b"B"*100)))))).hex(), "expected_action": "XDP_PASS"},
        {"name": "teid_other_tunnel_pass", "description": "Packet for different TEID 0x2000 has independent quota and passes", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=2152, payload=make_gtpu(teid=0x2000, inner_pkt=make_ipv4(proto=1, payload=make_icmp()))))).hex(), "expected_action": "XDP_PASS"},
        {"name": "teid_echo_req_pass", "description": "GTP-U Echo Request bypasses user quota and passes", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=2152, payload=make_gtpu(msg_type=1, teid=0x1000)))).hex(), "expected_action": "XDP_PASS"},
        {"name": "non_gtpu_udp_pass", "description": "UDP to port 2153 passes", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=2153))).hex(), "expected_action": "XDP_PASS"},
        {"name": "direct_tcp_pass", "description": "Direct TCP traffic passes", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "direct_icmp_pass", "description": "Direct ICMP passes", "packet_hex": make_eth(payload=make_ipv4(proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "arp_pass", "description": "ARP frame passes", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
        {"name": "truncated_gtpu_pass", "description": "Truncated GTP-U packet passes safely", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=2152, payload=b"\x30\xFF"))).hex(), "expected_action": "XDP_PASS"},
    ]
    t29_sol = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

#define MAX_BYTE_QUOTA 102400ULL // 100 KB quota per TEID

struct teid_quota_stat {
    __u64 bytes_consumed;
    __u64 pkts_consumed;
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
    __type(value, struct teid_quota_stat);
    __uint(max_entries, 1024);
} teid_quota_map SEC(".maps");

SEC("xdp")
int xdp_gtpu_quota_enforcer(struct xdp_md *ctx) {
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

    if (gtp->msg_type != 0xFF) // Only meter G-PDU user data
        return XDP_PASS;

    __u32 teid = bpf_ntohl(gtp->teid);
    __u64 pkt_len = (__u64)((void *)data_end - (void *)data);

    struct teid_quota_stat *st = bpf_map_lookup_elem(&teid_quota_map, &teid);
    if (!st) {
        struct teid_quota_stat new_st = { .bytes_consumed = pkt_len, .pkts_consumed = 1 };
        bpf_map_update_elem(&teid_quota_map, &teid, &new_st, BPF_ANY);
        return XDP_PASS;
    }

    if (st->bytes_consumed + pkt_len > MAX_BYTE_QUOTA)
        return XDP_DROP;

    st->bytes_consumed += pkt_len;
    st->pkts_consumed += 1;
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    tasks.append({
        "task_id": "syn_pfs_l3_009_gtpu_teid_stateful_quota",
        "application_category": "packet_filtering_security",
        "difficulty": "level_3",
        "task_family": "xdp_gtpu_quota",
        "template_family": "xdp_teid_quota_enforcer",
        "semantic_signature": "gtpu_teid_hash+quota_100kb_per_teid+drop_excess",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that enforces a stateful cumulative byte quota per GTP-U tunnel. Maintain per-TEID quota in a BPF hash map named 'teid_quota_map' (key __u32 teid, value struct teid_quota_stat { __u64 bytes_consumed; __u64 pkts_consumed; }, max_entries 1024). For GTP-U G-PDU user plane packets on UDP port 2152 (msg_type == 0xFF), accumulate packet wire bytes. Enforce a maximum quota of 100 KB (102,400 bytes). If a packet causes cumulative bytes for that TEID to exceed 100 KB, drop the packet with XDP_DROP. Pass GTP-U control messages, non-GTP-U traffic, and malformed frames with XDP_PASS.",
        "requirements": [
            "Define struct teid_quota_stat with bytes_consumed and pkts_consumed (__u64)",
            "Define hash map 'teid_quota_map' with key __u32 (TEID) and max_entries 1024",
            "Parse GTP-U G-PDU packets and accumulate wire byte length",
            "Drop packet with XDP_DROP if cumulative bytes exceed 102,400 bytes",
            "SEC(\"xdp\") and GPL license declaration"
        ],
        "solution_c": t29_sol,
        "tests": t29_tests,
        "main_validator": "packet_action"
    })

    # 30. syn_pfs_l3_010_dynamic_ip_reputation_quarantine
    t30_tests = [
        {"name": "bad_flags_1_pass", "description": "First abnormal TCP packet (SYN+FIN) is counted and passes", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.150", proto=6, payload=make_tcp(flags=0x03))).hex(), "expected_action": "XDP_PASS"},
        {"name": "bad_flags_2_pass", "description": "Second abnormal TCP packet is counted and passes", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.150", proto=6, payload=make_tcp(flags=0x03))).hex(), "expected_action": "XDP_PASS"},
        {"name": "bad_flags_3_triggers_quarantine_drop", "description": "Third abnormal TCP packet triggers 60s quarantine and drops", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.150", proto=6, payload=make_tcp(flags=0x03))).hex(), "expected_action": "XDP_DROP"},
        {"name": "quarantined_valid_pkt_drop", "description": "Even a valid TCP packet from quarantined IP is dropped during quarantine", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.150", proto=6, payload=make_tcp(flags=0x10))).hex(), "expected_action": "XDP_DROP"},
        {"name": "clean_ip_pass", "description": "Clean IP 192.168.1.10 passes without penalty", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.10", proto=6, payload=make_tcp(flags=0x10))).hex(), "expected_action": "XDP_PASS"},
        {"name": "udp_clean_pass", "description": "UDP from clean IP passes", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.10", proto=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "icmp_clean_pass", "description": "ICMP from clean IP passes", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.10", proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_PASS"},
        {"name": "arp_pass", "description": "ARP frame passes", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
        {"name": "truncated_tcp_pass", "description": "Truncated TCP packet passes safely", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=b"\x00\x50")).hex(), "expected_action": "XDP_PASS"},
    ]
    t30_sol = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#define QUARANTINE_DURATION_NS 60000000000ULL // 60 seconds

struct ip_reputation {
    __u32 bad_event_count;
    __u64 quarantine_until_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __be32);
    __type(value, struct ip_reputation);
    __uint(max_entries, 1024);
} quarantine_map SEC(".maps");

SEC("xdp")
int xdp_reputation_quarantine(struct xdp_md *ctx) {
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

    __be32 src_ip = ip->saddr;
    __u64 now = bpf_ktime_get_ns();

    struct ip_reputation *rep = bpf_map_lookup_elem(&quarantine_map, &src_ip);

    // Check if source IP is currently in active quarantine
    if (rep && rep->quarantine_until_ns > now)
        return XDP_DROP;

    // Detect abnormal TCP flag combinations (e.g. SYN+FIN = 0x03, NULL scan = 0x00)
    int is_abnormal = 0;
    if (ip->protocol == IPPROTO_TCP) {
        int ip_len = ip->ihl * 4;
        if (ip_len >= sizeof(struct iphdr) && (void *)ip + ip_len <= data_end) {
            struct tcphdr *tcp = (void *)ip + ip_len;
            if ((void *)(tcp + 1) <= data_end) {
                if (tcp->syn && tcp->fin) // SYN+FIN illegal combo
                    is_abnormal = 1;
                else if (!tcp->syn && !tcp->ack && !tcp->rst && !tcp->fin) // NULL scan
                    is_abnormal = 1;
            }
        }
    }

    if (is_abnormal) {
        if (!rep) {
            struct ip_reputation new_rep = { .bad_event_count = 1, .quarantine_until_ns = 0 };
            bpf_map_update_elem(&quarantine_map, &src_ip, &new_rep, BPF_ANY);
            return XDP_PASS;
        }

        rep->bad_event_count += 1;
        if (rep->bad_event_count >= 3) {
            rep->quarantine_until_ns = now + QUARANTINE_DURATION_NS;
            return XDP_DROP;
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    tasks.append({
        "task_id": "syn_pfs_l3_010_dynamic_ip_reputation_quarantine",
        "application_category": "packet_filtering_security",
        "difficulty": "level_3",
        "task_family": "xdp_ip_quarantine",
        "template_family": "xdp_reputation_firewall",
        "semantic_signature": "ipv4_src_reputation+3_bad_events_60s_quarantine+drop",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that implements a dynamic IP reputation quarantine system. Maintain per-source state in a BPF hash map named 'quarantine_map' (key __be32 src_ip, value struct ip_reputation { __u32 bad_event_count; __u64 quarantine_until_ns; }, max_entries 1024). Inspect incoming traffic: if a source IP is currently in active quarantine (now < quarantine_until_ns), drop all its traffic with XDP_DROP. Detect abnormal TCP scans (SYN+FIN simultaneously or NULL flags). Increment bad_event_count on each abnormal packet. Once bad_event_count reaches 3, quarantine the IP for 60 seconds (now + 60,000,000,000 ns) and drop with XDP_DROP. Pass compliant packets and non-IPv4 traffic with XDP_PASS.",
        "requirements": [
            "Define struct ip_reputation with bad_event_count (__u32) and quarantine_until_ns (__u64)",
            "Define hash map 'quarantine_map' with key __be32 and max_entries 1024",
            "Drop all traffic from sources with active quarantine timestamp",
            "Detect abnormal TCP flags (SYN+FIN or NULL) and increment count",
            "Enforce 60-second quarantine upon reaching 3 abnormal events",
            "SEC(\"xdp\") and GPL license declaration"
        ],
        "solution_c": t30_sol,
        "tests": t30_tests,
        "main_validator": "packet_action"
    })

    return tasks
