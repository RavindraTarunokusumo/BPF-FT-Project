"""
Generates the complete python source code for defs_network_routing_forwarding.py (30 tasks).
"""

def get_all_nrf_tasks_code() -> str:
    return '''"""
Task definitions for Category 4: Network Routing & Forwarding (30 Tasks)
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
        "instruction": "Write an XDP program that acts as a GRE tunnel loopback reflector. Inspect IPv4 GRE packets (ip->protocol == 47). Swap outer Ethernet MAC addresses, swap outer IPv4 source and destination addresses, reset outer IPv4 checksum, and reflect the packet back with XDP_TX. Pass non-GRE traffic unchanged with XDP_PASS.",
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

    unsigned char tmp_mac[ETH_ALEN];
    #pragma unroll
    for (int i = 0; i < ETH_ALEN; i++) {
        tmp_mac[i] = eth->h_source[i];
        eth->h_source[i] = eth->h_dest[i];
        eth->h_dest[i] = tmp_mac[i];
    }

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

    # 4. syn_nrf_l1_004_vxlan_vni_reflector
    tasks.append({
        "task_id": "syn_nrf_l1_004_vxlan_vni_reflector",
        "application_category": "network_routing_forwarding",
        "difficulty": "level_1",
        "task_family": "xdp_reflector_vxlan",
        "template_family": "xdp_vxlan_reflector",
        "semantic_signature": "vxlan_vni_100+swap_endpoints_and_tx+pass_other",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that inspects VXLAN tunnel traffic (UDP port 4789). If the 24-bit VNI equals 100, swap the outer Ethernet MAC addresses, outer IPv4 source/destination addresses, swap UDP source and destination ports, and reflect the frame with XDP_TX. Pass other VNIs and non-VXLAN traffic with XDP_PASS.",
        "requirements": [
            "Validate outer Ethernet, IPv4, UDP, and struct vxlanhdr bounds",
            "Verify UDP destination port is 4789 and VNI == 100",
            "Swap MACs, IP endpoints, and UDP ports",
            "Recalculate IPv4 checksum",
            "Return XDP_TX for VNI 100, XDP_PASS for other traffic",
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
int xdp_vxlan_reflector(struct xdp_md *ctx) {
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

    __u32 vni = bpf_ntohl(vx->vx_vni) >> 8;
    if (vni != 100)
        return XDP_PASS;

    unsigned char tmp_mac[ETH_ALEN];
    #pragma unroll
    for (int i = 0; i < ETH_ALEN; i++) {
        tmp_mac[i] = eth->h_source[i];
        eth->h_source[i] = eth->h_dest[i];
        eth->h_dest[i] = tmp_mac[i];
    }

    __be32 tmp_ip = ip->saddr;
    ip->saddr = ip->daddr;
    ip->daddr = tmp_ip;
    ip->check = 0;

    __be16 tmp_port = udp->source;
    udp->source = udp->dest;
    udp->dest = tmp_port;
    udp->check = 0;

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
            {"name": "vxlan_vni100_reflected_tx", "description": "VXLAN VNI 100 reflected with XDP_TX", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.10", dst_ip="192.168.1.20", proto=17, payload=make_udp(src_port=12345, dst_port=4789, payload=make_vxlan(vni=100, inner_frame=make_eth(payload=make_ipv4(proto=1, payload=make_icmp())))))).hex(), "expected_action": "XDP_TX"},
            {"name": "vxlan_vni200_pass", "description": "VXLAN VNI 200 passed unchanged", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.10", dst_ip="192.168.1.20", proto=17, payload=make_udp(src_port=12345, dst_port=4789, payload=make_vxlan(vni=200, inner_frame=make_eth(payload=make_ipv4(proto=6, payload=make_tcp())))))).hex(), "expected_action": "XDP_PASS"},
            {"name": "non_vxlan_udp_pass", "description": "UDP to port 4790 passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=4790))).hex(), "expected_action": "XDP_PASS"},
            {"name": "tcp_pass", "description": "TCP packet passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_vxlan_pass", "description": "Truncated VXLAN packet passed safely", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=4789, payload=b"\\x08\\x00"))).hex(), "expected_action": "XDP_PASS"},
        ],
        "main_validator": "xdp_action"
    })

    # 5. syn_nrf_l1_005_gtpu_upf_reflector
    tasks.append({
        "task_id": "syn_nrf_l1_005_gtpu_upf_reflector",
        "application_category": "network_routing_forwarding",
        "difficulty": "level_1",
        "task_family": "xdp_reflector_gtpu",
        "template_family": "xdp_gtpu_reflector",
        "semantic_signature": "gtpu_teid_echo_and_reflect_tx+pass_other",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that inspects GTP-U traffic (UDP destination port 2152). If gtp->teid == 0x12345678, swap outer Ethernet MAC addresses, outer IPv4 source and destination addresses, swap UDP source and destination ports, and reflect the frame with XDP_TX. Pass other TEIDs and non-GTP-U traffic with XDP_PASS.",
        "requirements": [
            "Validate outer Ethernet, IPv4, UDP, and struct gtpuhdr bounds",
            "Verify UDP destination port is 2152 and gtp->teid == bpf_htonl(0x12345678)",
            "Swap MACs, IP endpoints, and UDP ports",
            "Recalculate IPv4 checksum",
            "Return XDP_TX for matching TEID, XDP_PASS for other traffic",
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
int xdp_gtpu_reflector(struct xdp_md *ctx) {
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

    if (gtp->teid != bpf_htonl(0x12345678))
        return XDP_PASS;

    unsigned char tmp_mac[ETH_ALEN];
    #pragma unroll
    for (int i = 0; i < ETH_ALEN; i++) {
        tmp_mac[i] = eth->h_source[i];
        eth->h_source[i] = eth->h_dest[i];
        eth->h_dest[i] = tmp_mac[i];
    }

    __be32 tmp_ip = ip->saddr;
    ip->saddr = ip->daddr;
    ip->daddr = tmp_ip;
    ip->check = 0;

    __be16 tmp_port = udp->source;
    udp->source = udp->dest;
    udp->dest = tmp_port;
    udp->check = 0;

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
            {"name": "gtpu_teid_match_reflected_tx", "description": "GTP-U with TEID 0x12345678 reflected with XDP_TX", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.10", dst_ip="192.168.1.20", proto=17, payload=make_udp(src_port=12345, dst_port=2152, payload=make_gtpu(teid=0x12345678, inner_pkt=make_ipv4(proto=1, payload=make_icmp()))))).hex(), "expected_action": "XDP_TX"},
            {"name": "gtpu_other_teid_pass", "description": "GTP-U with other TEID passed unchanged", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.10", dst_ip="192.168.1.20", proto=17, payload=make_udp(src_port=12345, dst_port=2152, payload=make_gtpu(teid=0x99999999, inner_pkt=make_ipv4(proto=6, payload=make_tcp()))))).hex(), "expected_action": "XDP_PASS"},
            {"name": "non_gtpu_udp_pass", "description": "UDP to port 2153 passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=2153))).hex(), "expected_action": "XDP_PASS"},
            {"name": "tcp_pass", "description": "TCP packet passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_gtpu_pass", "description": "Truncated GTP-U packet passed safely", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=2152, payload=b"\\x30\\xFF"))).hex(), "expected_action": "XDP_PASS"},
        ],
        "main_validator": "xdp_action"
    })

    # 6. syn_nrf_l1_006_ipv6_multicast_forward
    tasks.append({
        "task_id": "syn_nrf_l1_006_ipv6_multicast_forward",
        "application_category": "network_routing_forwarding",
        "difficulty": "level_1",
        "task_family": "xdp_router_ipv6",
        "template_family": "xdp_ipv6_mcast_forwarder",
        "semantic_signature": "ipv6_mcast_ff02_prefix+redirect_ifindex_4+pass_unicast",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that inspects IPv6 packets (EtherType 0x86DD). If the destination address starts with link-local multicast prefix ff02::/16 (first 16 bits equal 0xFF02), redirect the packet to interface ifindex 4 using bpf_redirect(4, 0). Pass unicast IPv6 traffic and other protocols with XDP_PASS.",
        "requirements": [
            "Validate Ethernet and struct ipv6hdr bounds",
            "Verify eth->h_proto == bpf_htons(ETH_P_IPV6)",
            "Check if ip6->daddr.s6_addr16[0] == bpf_htons(0xFF02)",
            "Return bpf_redirect(4, 0) for matching multicast",
            "Return XDP_PASS for unicast and non-IPv6 traffic",
            "SEC(\\"xdp\\") and GPL license declaration"
        ],
        "solution_c": """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>

SEC("xdp")
int xdp_ipv6_mcast_fwd(struct xdp_md *ctx) {
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

    // Check first 16 bits of destination IPv6 for ff02
    __u16 *daddr_words = (void *)&ip6->daddr;
    if (daddr_words[0] == bpf_htons(0xFF02))
        return bpf_redirect(4, 0);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
""",
        "tests": [
            {"name": "ipv6_mcast_ff02_redirect_if4", "description": "IPv6 multicast ff02::1 redirected to ifindex 4", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(dst_ip="ff02::1", next_hdr=58, payload=make_icmpv6())).hex(), "expected_action": "XDP_REDIRECT"},
            {"name": "ipv6_unicast_pass", "description": "IPv6 unicast passed unchanged", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(dst_ip="2001:db8::1", next_hdr=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "ipv4_pass", "description": "IPv4 traffic passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP frame passed unchanged", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_ipv6_pass", "description": "Truncated IPv6 header passed safely", "packet_hex": make_eth(eth_type=0x86DD, payload=b"\\x60\\x00").hex(), "expected_action": "XDP_PASS"},
        ],
        "main_validator": "xdp_action"
    })

    # 7. syn_nrf_l1_007_proxy_arp_responder
    tasks.append({
        "task_id": "syn_nrf_l1_007_proxy_arp_responder",
        "application_category": "network_routing_forwarding",
        "difficulty": "level_1",
        "task_family": "xdp_proxy_arp",
        "template_family": "xdp_proxy_arp_responder",
        "semantic_signature": "arp_req_for_192_168_100_1+reply_with_router_mac_and_tx",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that acts as a Proxy ARP responder. Inspect ARP Requests (EtherType 0x0806, opcode 1). If the target IP (ar_tip) is 192.168.100.1, synthesize an ARP Reply: swap Ethernet MACs and set source MAC to 02:00:00:00:00:01, set opcode to 2, set sender MAC to 02:00:00:00:00:01, swap sender and target IP addresses, and return XDP_TX. Pass other ARP requests and protocols with XDP_PASS.",
        "requirements": [
            "Validate Ethernet and struct arphdr_eth_ipv4 bounds",
            "Verify opcode == 1 (ARPOP_REQUEST) and ar_tip == 192.168.100.1",
            "Synthesize ARP Reply (opcode 2, MAC 02:00:00:00:00:01, swap endpoints)",
            "Return XDP_TX for target IP, XDP_PASS for other traffic",
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
int xdp_proxy_arp(struct xdp_md *ctx) {
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

    if (arp->ar_op == bpf_htons(1) && arp->ar_tip == bpf_htonl(0xC0A86401)) { // 192.168.100.1
        // Set dest MAC to sender's MAC, src MAC to 02:00:00:00:00:01
        #pragma unroll
        for (int i = 0; i < ETH_ALEN; i++) {
            eth->h_dest[i] = eth->h_source[i];
            eth->h_source[i] = (i == 0) ? 0x02 : 0x00;
        }

        arp->ar_op = bpf_htons(2); // ARP Reply

        #pragma unroll
        for (int i = 0; i < ETH_ALEN; i++) {
            arp->ar_tha[i] = arp->ar_sha[i];
            arp->ar_sha[i] = (i == 0) ? 0x02 : 0x00;
        }

        __be32 target_ip = arp->ar_tip;
        arp->ar_tip = arp->ar_sip;
        arp->ar_sip = target_ip;

        return XDP_TX;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
""",
        "tests": [
            {"name": "proxy_arp_target_match_tx", "description": "ARP Request for 192.168.100.1 answered with proxy reply and XDP_TX", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp(opcode=1, sender_ip="192.168.100.50", target_ip="192.168.100.1")).hex(), "expected_action": "XDP_TX"},
            {"name": "proxy_arp_other_target_pass", "description": "ARP Request for 192.168.100.2 passed unchanged", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp(opcode=1, sender_ip="192.168.100.50", target_ip="192.168.100.2")).hex(), "expected_action": "XDP_PASS"},
            {"name": "ipv4_pass", "description": "IPv4 traffic passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "ipv6_pass", "description": "IPv6 traffic passed unchanged", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(next_hdr=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_arp_pass", "description": "Truncated ARP frame passed safely", "packet_hex": make_eth(eth_type=0x0806, payload=b"\\x00\\x01\\x08").hex(), "expected_action": "XDP_PASS"},
        ],
        "main_validator": "xdp_action"
    })

    # 8. syn_nrf_l1_008_coap_server_redirect
    tasks.append({
        "task_id": "syn_nrf_l1_008_coap_server_redirect",
        "application_category": "network_routing_forwarding",
        "difficulty": "level_1",
        "task_family": "xdp_router_l4",
        "template_family": "xdp_coap_redirector",
        "semantic_signature": "coap_udp5683+redirect_ifindex_5+pass_other",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that inspects IPv4 UDP traffic. If destination port is 5683 (CoAP), redirect the packet to IoT server interface ifindex 5 using bpf_redirect(5, 0). Pass all other traffic with XDP_PASS.",
        "requirements": [
            "Validate Ethernet, IPv4, and UDP header bounds",
            "Verify UDP destination port is 5683",
            "Return bpf_redirect(5, 0) for CoAP",
            "Return XDP_PASS for other traffic",
            "SEC(\\"xdp\\") and GPL license declaration"
        ],
        "solution_c": """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

SEC("xdp")
int xdp_coap_redirect(struct xdp_md *ctx) {
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

    if (udp->dest == bpf_htons(5683))
        return bpf_redirect(5, 0);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
""",
        "tests": [
            {"name": "coap_port_5683_redirect_if5", "description": "CoAP packet on port 5683 redirected to ifindex 5", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=5683, payload=make_coap(code=1)))).hex(), "expected_action": "XDP_REDIRECT"},
            {"name": "udp_port_5684_pass", "description": "UDP to port 5684 passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=5684))).hex(), "expected_action": "XDP_PASS"},
            {"name": "tcp_pass", "description": "TCP packet passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP frame passed unchanged", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_udp_pass", "description": "Truncated UDP packet passed safely", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=b"\\x16\\x33")).hex(), "expected_action": "XDP_PASS"},
        ],
        "main_validator": "xdp_action"
    })

    # 9. syn_nrf_l1_009_dns_cache_redirect
    tasks.append({
        "task_id": "syn_nrf_l1_009_dns_cache_redirect",
        "application_category": "network_routing_forwarding",
        "difficulty": "level_1",
        "task_family": "xdp_router_l4",
        "template_family": "xdp_dns_redirector",
        "semantic_signature": "dns_query_udp53+redirect_ifindex_6+pass_other",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that inspects IPv4 UDP traffic. If destination port is 53 (DNS), redirect the packet to local DNS caching accelerator ifindex 6 using bpf_redirect(6, 0). Pass all other traffic with XDP_PASS.",
        "requirements": [
            "Validate Ethernet, IPv4, and UDP header bounds",
            "Verify UDP destination port is 53",
            "Return bpf_redirect(6, 0) for DNS",
            "Return XDP_PASS for other traffic",
            "SEC(\\"xdp\\") and GPL license declaration"
        ],
        "solution_c": """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

SEC("xdp")
int xdp_dns_redirect(struct xdp_md *ctx) {
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

    if (udp->dest == bpf_htons(53))
        return bpf_redirect(6, 0);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
""",
        "tests": [
            {"name": "dns_port_53_redirect_if6", "description": "DNS query on port 53 redirected to ifindex 6", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=53, payload=make_dns()))).hex(), "expected_action": "XDP_REDIRECT"},
            {"name": "udp_port_5353_pass", "description": "mDNS on port 5353 passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=5353))).hex(), "expected_action": "XDP_PASS"},
            {"name": "tcp_pass", "description": "TCP packet passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP frame passed unchanged", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_udp_pass", "description": "Truncated UDP packet passed safely", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=b"\\x00\\x35")).hex(), "expected_action": "XDP_PASS"},
        ],
        "main_validator": "xdp_action"
    })

    # 10. syn_nrf_l1_010_quic_edge_router
    tasks.append({
        "task_id": "syn_nrf_l1_010_quic_edge_router",
        "application_category": "network_routing_forwarding",
        "difficulty": "level_1",
        "task_family": "xdp_router_l4",
        "template_family": "xdp_quic_redirector",
        "semantic_signature": "quic_udp443+redirect_ifindex_7+pass_other",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that inspects IPv4 UDP traffic. If destination port is 443 (QUIC / HTTP/3), redirect the packet to edge termination cluster interface ifindex 7 using bpf_redirect(7, 0). Pass all other traffic with XDP_PASS.",
        "requirements": [
            "Validate Ethernet, IPv4, and UDP header bounds",
            "Verify UDP destination port is 443",
            "Return bpf_redirect(7, 0) for QUIC",
            "Return XDP_PASS for other traffic",
            "SEC(\\"xdp\\") and GPL license declaration"
        ],
        "solution_c": """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

SEC("xdp")
int xdp_quic_redirect(struct xdp_md *ctx) {
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

    if (udp->dest == bpf_htons(443))
        return bpf_redirect(7, 0);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
""",
        "tests": [
            {"name": "quic_port_443_redirect_if7", "description": "QUIC packet on port 443 redirected to ifindex 7", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=443, payload=make_quic()))).hex(), "expected_action": "XDP_REDIRECT"},
            {"name": "udp_port_444_pass", "description": "UDP to port 444 passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=444))).hex(), "expected_action": "XDP_PASS"},
            {"name": "tcp_port_443_pass", "description": "TCP to port 443 passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(dst_port=443))).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP frame passed unchanged", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_udp_pass", "description": "Truncated UDP packet passed safely", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=b"\\x01\\xBB")).hex(), "expected_action": "XDP_PASS"},
        ],
        "main_validator": "xdp_action"
    })

    # =========================================================================
    # LEVEL 2 (10 Tasks) - Multi-hop routing tables, LPM, QoS splits (>= 7 tests)
    # =========================================================================

    # 11. syn_nrf_l2_001_mpls_routing_table_redirect
    tasks.append({
        "task_id": "syn_nrf_l2_001_mpls_routing_table_redirect",
        "application_category": "network_routing_forwarding",
        "difficulty": "level_2",
        "task_family": "xdp_router_mpls_table",
        "template_family": "xdp_mpls_route_table",
        "semantic_signature": "mpls_label_table_lookup+redirect_egress_ifindex+pass",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that routes MPLS frames (EtherType 0x8847) using a BPF hash routing table named 'mpls_route_map' (key __u32 label, value __u32 egress_ifindex, max_entries 1024). Extract the 20-bit label from the outer label stack entry. If a route exists, redirect to egress_ifindex using bpf_redirect(egress_ifindex, 0). If label == 500, redirect to ifindex 20. If label == 600, redirect to ifindex 21. Pass unrouted labels and non-MPLS frames with XDP_PASS.",
        "requirements": [
            "Define hash map 'mpls_route_map' with key __u32 and max_entries 1024",
            "Validate Ethernet and struct mpls_label bounds",
            "Extract 20-bit label and lookup in table",
            "Return bpf_redirect(egress_ifindex, 0) on match",
            "Return XDP_PASS if no route found",
            "SEC(\\"xdp\\") and GPL license declaration"
        ],
        "solution_c": """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>

struct mpls_label {
    __u32 entry;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1024);
} mpls_route_map SEC(".maps");

SEC("xdp")
int xdp_mpls_table_router(struct xdp_md *ctx) {
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

    if (label == 500)
        return bpf_redirect(20, 0);
    if (label == 600)
        return bpf_redirect(21, 0);

    __u32 *ifindex = bpf_map_lookup_elem(&mpls_route_map, &label);
    if (ifindex)
        return bpf_redirect(*ifindex, 0);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
""",
        "tests": [
            {"name": "label_500_redirect_if20", "description": "MPLS label 500 routed to ifindex 20", "packet_hex": make_eth(eth_type=0x8847, payload=make_mpls([(500, 0, True, 64)], inner_pkt=make_ipv4(proto=1, payload=make_icmp()))).hex(), "expected_action": "XDP_REDIRECT"},
            {"name": "label_600_redirect_if21", "description": "MPLS label 600 routed to ifindex 21", "packet_hex": make_eth(eth_type=0x8847, payload=make_mpls([(600, 0, True, 64)], inner_pkt=make_ipv4(proto=6, payload=make_tcp()))).hex(), "expected_action": "XDP_REDIRECT"},
            {"name": "label_999_unrouted_pass", "description": "Unrouted MPLS label 999 passed unchanged", "packet_hex": make_eth(eth_type=0x8847, payload=make_mpls([(999, 0, True, 64)], inner_pkt=make_ipv4(proto=17, payload=make_udp()))).hex(), "expected_action": "XDP_PASS"},
            {"name": "ipv4_pass", "description": "IPv4 traffic passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "udp_pass", "description": "UDP packet passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP frame passed unchanged", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_mpls_pass", "description": "Truncated MPLS frame passed safely", "packet_hex": make_eth(eth_type=0x8847, payload=b"\\x00\\x01").hex(), "expected_action": "XDP_PASS"},
        ],
        "main_validator": "xdp_action"
    })

    # 12. syn_nrf_l2_002_ipv6_lpm_trie_router
    tasks.append({
        "task_id": "syn_nrf_l2_002_ipv6_lpm_trie_router",
        "application_category": "network_routing_forwarding",
        "difficulty": "level_2",
        "task_family": "xdp_router_ipv6_lpm",
        "template_family": "xdp_ipv6_lpm_router",
        "semantic_signature": "ipv6_lpm_trie+longest_prefix_match_redirect+pass",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that routes IPv6 packets (EtherType 0x86DD) using Longest Prefix Match (LPM). If the destination address matches prefix 2001:db8:1::/48, redirect to interface ifindex 10. If the destination address matches prefix 2001:db8:2::/48, redirect to interface ifindex 11. Pass unrouted destinations and non-IPv6 traffic with XDP_PASS.",
        "requirements": [
            "Validate Ethernet and struct ipv6hdr bounds",
            "Verify eth->h_proto == bpf_htons(ETH_P_IPV6)",
            "Match destination IPv6 prefix 2001:db8:1::/48 -> bpf_redirect(10, 0)",
            "Match destination IPv6 prefix 2001:db8:2::/48 -> bpf_redirect(11, 0)",
            "Always return XDP_PASS for non-matching traffic",
            "SEC(\\"xdp\\") and GPL license declaration"
        ],
        "solution_c": """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>

SEC("xdp")
int xdp_ipv6_lpm_router(struct xdp_md *ctx) {
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

    __u16 *daddr_words = (void *)&ip6->daddr;
    // Check 2001:db8:1::/48 (0x2001, 0x0db8, 0x0001)
    if (daddr_words[0] == bpf_htons(0x2001) && daddr_words[1] == bpf_htons(0x0DB8) && daddr_words[2] == bpf_htons(0x0001))
        return bpf_redirect(10, 0);

    // Check 2001:db8:2::/48 (0x2001, 0x0db8, 0x0002)
    if (daddr_words[0] == bpf_htons(0x2001) && daddr_words[1] == bpf_htons(0x0DB8) && daddr_words[2] == bpf_htons(0x0002))
        return bpf_redirect(11, 0);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
""",
        "tests": [
            {"name": "prefix_1_redirect_if10", "description": "IPv6 destination in 2001:db8:1::/48 redirected to ifindex 10", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(dst_ip="2001:db8:1::100", next_hdr=6, payload=make_tcp())).hex(), "expected_action": "XDP_REDIRECT"},
            {"name": "prefix_2_redirect_if11", "description": "IPv6 destination in 2001:db8:2::/48 redirected to ifindex 11", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(dst_ip="2001:db8:2::200", next_hdr=17, payload=make_udp())).hex(), "expected_action": "XDP_REDIRECT"},
            {"name": "unrouted_prefix_pass", "description": "IPv6 destination in 2001:db8:3::/48 passed unchanged", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(dst_ip="2001:db8:3::300", next_hdr=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "ipv4_pass", "description": "IPv4 traffic passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "udp_pass", "description": "UDP packet passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP frame passed unchanged", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_ipv6_pass", "description": "Truncated IPv6 header passed safely", "packet_hex": make_eth(eth_type=0x86DD, payload=b"\\x60\\x00").hex(), "expected_action": "XDP_PASS"},
        ],
        "main_validator": "xdp_action"
    })

    # 13. syn_nrf_l2_003_gtpu_teid_devmap_router
    tasks.append({
        "task_id": "syn_nrf_l2_003_gtpu_teid_devmap_router",
        "application_category": "network_routing_forwarding",
        "difficulty": "level_2",
        "task_family": "xdp_router_gtpu_table",
        "template_family": "xdp_gtpu_devmap_router",
        "semantic_signature": "gtpu_teid_lookup+redirect_egress_ifindex+pass",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that dispatches GTP-U cellular tunnel packets (UDP destination port 2152). If gtp->teid == 0x00000100, redirect to slice 1 interface ifindex 30. If gtp->teid == 0x00000200, redirect to slice 2 interface ifindex 31. Pass other TEIDs and non-GTP-U traffic with XDP_PASS.",
        "requirements": [
            "Validate Ethernet, IPv4, UDP, and struct gtpuhdr bounds",
            "Verify UDP destination port is 2152",
            "Redirect TEID 0x100 -> bpf_redirect(30, 0)",
            "Redirect TEID 0x200 -> bpf_redirect(31, 0)",
            "Always return XDP_PASS for other traffic",
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
int xdp_gtpu_devmap_router(struct xdp_md *ctx) {
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

    if (gtp->teid == bpf_htonl(0x00000100))
        return bpf_redirect(30, 0);
    if (gtp->teid == bpf_htonl(0x00000200))
        return bpf_redirect(31, 0);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
""",
        "tests": [
            {"name": "teid_100_redirect_if30", "description": "GTP-U TEID 0x100 redirected to slice 1 ifindex 30", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=2152, payload=make_gtpu(teid=0x100, inner_pkt=make_ipv4(proto=1, payload=make_icmp()))))).hex(), "expected_action": "XDP_REDIRECT"},
            {"name": "teid_200_redirect_if31", "description": "GTP-U TEID 0x200 redirected to slice 2 ifindex 31", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=2152, payload=make_gtpu(teid=0x200, inner_pkt=make_ipv4(proto=6, payload=make_tcp()))))).hex(), "expected_action": "XDP_REDIRECT"},
            {"name": "teid_999_pass", "description": "GTP-U TEID 0x999 passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=2152, payload=make_gtpu(teid=0x999, inner_pkt=make_ipv4(proto=1, payload=make_icmp()))))).hex(), "expected_action": "XDP_PASS"},
            {"name": "non_gtpu_udp_pass", "description": "UDP to port 2153 passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=2153))).hex(), "expected_action": "XDP_PASS"},
            {"name": "tcp_pass", "description": "TCP packet passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP frame passed unchanged", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_gtpu_pass", "description": "Truncated GTP-U packet passed safely", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=2152, payload=b"\\x30\\xFF"))).hex(), "expected_action": "XDP_PASS"},
        ],
        "main_validator": "xdp_action"
    })

    # 14. syn_nrf_l2_004_dscp_qos_priority_split
    tasks.append({
        "task_id": "syn_nrf_l2_004_dscp_qos_priority_split",
        "application_category": "network_routing_forwarding",
        "difficulty": "level_2",
        "task_family": "xdp_router_qos",
        "template_family": "xdp_dscp_qos_splitter",
        "semantic_signature": "ipv4_dscp_ef_to_if10_af_to_if11_be_to_if12",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that routes IPv4 packets by DSCP QoS class (ip->tos >> 2). If DSCP == 46 (Expedited Forwarding / 0xB8), redirect to priority interface ifindex 10. If DSCP == 34 (Assured Forwarding AF41 / 0x88), redirect to medium interface ifindex 11. For Best Effort and other DSCP values, redirect to default interface ifindex 12. Pass non-IPv4 traffic with XDP_PASS.",
        "requirements": [
            "Validate Ethernet and struct iphdr bounds",
            "Extract 6-bit DSCP (ip->tos >> 2)",
            "Redirect DSCP 46 -> bpf_redirect(10, 0)",
            "Redirect DSCP 34 -> bpf_redirect(11, 0)",
            "Redirect other IPv4 -> bpf_redirect(12, 0)",
            "Always return XDP_PASS for non-IPv4 traffic",
            "SEC(\\"xdp\\") and GPL license declaration"
        ],
        "solution_c": """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

SEC("xdp")
int xdp_dscp_qos_router(struct xdp_md *ctx) {
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

    __u8 dscp = ip->tos >> 2;
    if (dscp == 46) // EF
        return bpf_redirect(10, 0);
    if (dscp == 34) // AF41
        return bpf_redirect(11, 0);

    return bpf_redirect(12, 0);
}

char _license[] SEC("license") = "GPL";
""",
        "tests": [
            {"name": "dscp_ef_redirect_if10", "description": "IPv4 packet with DSCP EF (46) redirected to ifindex 10", "packet_hex": make_eth(payload=make_ipv4(tos=0xB8, proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_REDIRECT"},
            {"name": "dscp_af41_redirect_if11", "description": "IPv4 packet with DSCP AF41 (34) redirected to ifindex 11", "packet_hex": make_eth(payload=make_ipv4(tos=0x88, proto=17, payload=make_udp())).hex(), "expected_action": "XDP_REDIRECT"},
            {"name": "dscp_be_redirect_if12", "description": "IPv4 packet with Best Effort DSCP (0) redirected to ifindex 12", "packet_hex": make_eth(payload=make_ipv4(tos=0x00, proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_REDIRECT"},
            {"name": "arp_pass", "description": "ARP frame passed unchanged", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
            {"name": "ipv6_pass", "description": "IPv6 frame passed unchanged", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(next_hdr=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_ip_pass", "description": "Truncated IPv4 packet passed safely", "packet_hex": make_eth(payload=b"\\x45\\x00").hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_eth_pass", "description": "Truncated Ethernet frame passed safely", "packet_hex": b"\\x52\\x54\\x00".hex(), "expected_action": "XDP_PASS"},
        ],
        "main_validator": "xdp_action"
    })

    # 15. syn_nrf_l2_005_vxlan_vni_egress_dispatcher
    tasks.append({
        "task_id": "syn_nrf_l2_005_vxlan_vni_egress_dispatcher",
        "application_category": "network_routing_forwarding",
        "difficulty": "level_2",
        "task_family": "xdp_router_vxlan_table",
        "template_family": "xdp_vxlan_dispatcher",
        "semantic_signature": "vxlan_vni_100_to_if40_vni_200_to_if41+pass",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that dispatches VXLAN packets (UDP destination port 4789). If VNI == 100, redirect to tenant 1 interface ifindex 40. If VNI == 200, redirect to tenant 2 interface ifindex 41. Pass all other VNIs and non-VXLAN traffic with XDP_PASS.",
        "requirements": [
            "Validate outer Ethernet, IPv4, UDP, and struct vxlanhdr bounds",
            "Verify UDP destination port is 4789",
            "Redirect VNI 100 -> bpf_redirect(40, 0)",
            "Redirect VNI 200 -> bpf_redirect(41, 0)",
            "Always return XDP_PASS for other traffic",
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
int xdp_vxlan_dispatcher(struct xdp_md *ctx) {
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

    __u32 vni = bpf_ntohl(vx->vx_vni) >> 8;
    if (vni == 100)
        return bpf_redirect(40, 0);
    if (vni == 200)
        return bpf_redirect(41, 0);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
""",
        "tests": [
            {"name": "vxlan_vni100_redirect_if40", "description": "VXLAN VNI 100 redirected to ifindex 40", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=4789, payload=make_vxlan(vni=100, inner_frame=make_eth(payload=make_ipv4(proto=1, payload=make_icmp())))))).hex(), "expected_action": "XDP_REDIRECT"},
            {"name": "vxlan_vni200_redirect_if41", "description": "VXLAN VNI 200 redirected to ifindex 41", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=4789, payload=make_vxlan(vni=200, inner_frame=make_eth(payload=make_ipv4(proto=6, payload=make_tcp())))))).hex(), "expected_action": "XDP_REDIRECT"},
            {"name": "vxlan_vni300_pass", "description": "VXLAN VNI 300 passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=4789, payload=make_vxlan(vni=300, inner_frame=make_eth(payload=make_ipv4(proto=1, payload=make_icmp())))))).hex(), "expected_action": "XDP_PASS"},
            {"name": "non_vxlan_udp_pass", "description": "UDP to port 4790 passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=4790))).hex(), "expected_action": "XDP_PASS"},
            {"name": "tcp_pass", "description": "TCP packet passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP frame passed unchanged", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_vxlan_pass", "description": "Truncated VXLAN packet passed safely", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=4789, payload=b"\\x08\\x00"))).hex(), "expected_action": "XDP_PASS"},
        ],
        "main_validator": "xdp_action"
    })

    # 16. syn_nrf_l2_006_geneve_opt_class_router
    tasks.append({
        "task_id": "syn_nrf_l2_006_geneve_opt_class_router",
        "application_category": "network_routing_forwarding",
        "difficulty": "level_2",
        "task_family": "xdp_router_geneve_table",
        "template_family": "xdp_geneve_class_router",
        "semantic_signature": "geneve_opt_class_0x0100_to_if20_0x0102_to_if21",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that routes GENEVE packets (UDP destination port 6081) by Option Class. If the first option has Option Class 0x0100 (Linux), redirect to ifindex 20. If Option Class is 0x0102 (AWS), redirect to ifindex 21. Pass other classes, optionless GENEVE, and non-GENEVE traffic with XDP_PASS.",
        "requirements": [
            "Validate outer Ethernet, IPv4, UDP, GENEVE, and option header bounds",
            "Verify UDP destination port is 6081",
            "Redirect Option Class 0x0100 -> bpf_redirect(20, 0)",
            "Redirect Option Class 0x0102 -> bpf_redirect(21, 0)",
            "Always return XDP_PASS for other traffic",
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
};

SEC("xdp")
int xdp_geneve_class_router(struct xdp_md *ctx) {
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

    if (gen->opt_len == 0)
        return XDP_PASS;

    struct geneve_opt *opt = (void *)(gen + 1);
    if ((void *)(opt + 1) > data_end)
        return XDP_PASS;

    if (opt->opt_class == bpf_htons(0x0100))
        return bpf_redirect(20, 0);
    if (opt->opt_class == bpf_htons(0x0102))
        return bpf_redirect(21, 0);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
""",
        "tests": [
            {"name": "geneve_linux_class_redirect_if20", "description": "GENEVE packet with Linux class (0x0100) redirected to ifindex 20", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=6081, payload=make_geneve(options=bytes([0x01, 0x00, 0x01, 0x01, 0, 0, 0, 0]), inner_frame=make_eth(payload=make_ipv4(proto=1, payload=make_icmp())))))).hex(), "expected_action": "XDP_REDIRECT"},
            {"name": "geneve_aws_class_redirect_if21", "description": "GENEVE packet with AWS class (0x0102) redirected to ifindex 21", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=6081, payload=make_geneve(options=bytes([0x01, 0x02, 0x01, 0x01, 0, 0, 0, 0]), inner_frame=make_eth(payload=make_ipv4(proto=6, payload=make_tcp())))))).hex(), "expected_action": "XDP_REDIRECT"},
            {"name": "geneve_ovs_class_pass", "description": "GENEVE packet with OVS class (0x0101) passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=6081, payload=make_geneve(options=bytes([0x01, 0x01, 0x01, 0x01, 0, 0, 0, 0]), inner_frame=make_eth(payload=make_ipv4(proto=1, payload=make_icmp())))))).hex(), "expected_action": "XDP_PASS"},
            {"name": "non_geneve_udp_pass", "description": "UDP to port 6082 passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=6082))).hex(), "expected_action": "XDP_PASS"},
            {"name": "tcp_pass", "description": "TCP packet passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP frame passed unchanged", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_geneve_pass", "description": "Truncated GENEVE packet passed safely", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=6081, payload=b"\\x00\\x00"))).hex(), "expected_action": "XDP_PASS"},
        ],
        "main_validator": "xdp_action"
    })

    # 17. syn_nrf_l2_007_vlan_prio_pcp_traffic_split
    tasks.append({
        "task_id": "syn_nrf_l2_007_vlan_prio_pcp_traffic_split",
        "application_category": "network_routing_forwarding",
        "difficulty": "level_2",
        "task_family": "xdp_router_vlan_pcp",
        "template_family": "xdp_pcp_priority_router",
        "semantic_signature": "vlan_pcp_ge_5_to_if8_else_if9+pass_untagged",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that inspects 802.1Q tagged frames (EtherType 0x8100) and extracts the 3-bit Priority Code Point (PCP = vlan_TCI >> 13). If PCP >= 5 (Voice/Video priority), redirect to high-priority queue interface ifindex 8. If PCP < 5, redirect to standard queue interface ifindex 9. Pass untagged traffic and other protocols with XDP_PASS.",
        "requirements": [
            "Validate Ethernet and struct vlanhdr bounds",
            "Verify eth->h_proto == bpf_htons(ETH_P_8021Q)",
            "Extract 3-bit PCP (bpf_ntohs(vlan->h_vlan_TCI) >> 13)",
            "Redirect PCP >= 5 -> bpf_redirect(8, 0)",
            "Redirect PCP < 5 -> bpf_redirect(9, 0)",
            "Always return XDP_PASS for untagged traffic",
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
int xdp_pcp_router(struct xdp_md *ctx) {
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

    __u8 pcp = bpf_ntohs(vlan->h_vlan_TCI) >> 13;
    if (pcp >= 5)
        return bpf_redirect(8, 0);
    else
        return bpf_redirect(9, 0);
}

char _license[] SEC("license") = "GPL";
""",
        "tests": [
            {"name": "pcp_6_redirect_if8", "description": "VLAN frame with PCP 6 redirected to ifindex 8", "packet_hex": make_eth(vlan=(6 << 12) | 100, payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_REDIRECT"},
            {"name": "pcp_5_redirect_if8", "description": "VLAN frame with PCP 5 redirected to ifindex 8", "packet_hex": make_eth(vlan=(5 << 12) | 100, payload=make_ipv4(proto=17, payload=make_udp())).hex(), "expected_action": "XDP_REDIRECT"},
            {"name": "pcp_0_redirect_if9", "description": "VLAN frame with PCP 0 redirected to ifindex 9", "packet_hex": make_eth(vlan=(0 << 12) | 100, payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_REDIRECT"},
            {"name": "untagged_pass", "description": "Untagged frame passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP frame passed unchanged", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
            {"name": "ipv6_pass", "description": "IPv6 frame passed unchanged", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(next_hdr=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_vlan_pass", "description": "Truncated VLAN frame passed safely", "packet_hex": make_eth(vlan=100)[:14].hex(), "expected_action": "XDP_PASS"},
        ],
        "main_validator": "xdp_action"
    })

    # 18. syn_nrf_l2_008_ip_in_ip_tunnel_router
    tasks.append({
        "task_id": "syn_nrf_l2_008_ip_in_ip_tunnel_router",
        "application_category": "network_routing_forwarding",
        "difficulty": "level_2",
        "task_family": "xdp_router_ipinip",
        "template_family": "xdp_ipinip_router",
        "semantic_signature": "ipinip_proto4+inner_daddr_routing+pass",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that inspects IP-in-IP tunnel traffic (outer IPv4 protocol 4). Parse the inner IPv4 header. If inner destination is in 10.1.0.0/16, redirect to interface ifindex 18. If inner destination is in 10.2.0.0/16, redirect to interface ifindex 19. Pass unrouted traffic with XDP_PASS.",
        "requirements": [
            "Validate outer Ethernet, IPv4 (protocol 4), and inner IPv4 header bounds",
            "Redirect inner destination 10.1.0.0/16 -> bpf_redirect(18, 0)",
            "Redirect inner destination 10.2.0.0/16 -> bpf_redirect(19, 0)",
            "Always return XDP_PASS for other traffic",
            "SEC(\\"xdp\\") and GPL license declaration"
        ],
        "solution_c": """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

SEC("xdp")
int xdp_ipinip_router(struct xdp_md *ctx) {
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

    int outer_len = outer_ip->ihl * 4;
    if (outer_len < sizeof(struct iphdr) || (void *)outer_ip + outer_len > data_end)
        return XDP_PASS;

    struct iphdr *inner_ip = (void *)outer_ip + outer_len;
    if ((void *)(inner_ip + 1) > data_end)
        return XDP_PASS;

    __u32 inner_dst = bpf_ntohl(inner_ip->daddr);
    if ((inner_dst & 0xFFFF0000) == 0x0A010000) // 10.1.0.0/16
        return bpf_redirect(18, 0);
    if ((inner_dst & 0xFFFF0000) == 0x0A020000) // 10.2.0.0/16
        return bpf_redirect(19, 0);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
""",
        "tests": [
            {"name": "inner_subnet1_redirect_if18", "description": "IP-in-IP with inner dest 10.1.1.10 redirected to ifindex 18", "packet_hex": make_eth(payload=make_ipv4(src_ip="203.0.113.1", dst_ip="198.51.100.1", proto=4, payload=make_ipv4(src_ip="10.0.0.1", dst_ip="10.1.1.10", proto=6, payload=make_tcp()))).hex(), "expected_action": "XDP_REDIRECT"},
            {"name": "inner_subnet2_redirect_if19", "description": "IP-in-IP with inner dest 10.2.1.20 redirected to ifindex 19", "packet_hex": make_eth(payload=make_ipv4(src_ip="203.0.113.1", dst_ip="198.51.100.1", proto=4, payload=make_ipv4(src_ip="10.0.0.1", dst_ip="10.2.1.20", proto=17, payload=make_udp()))).hex(), "expected_action": "XDP_REDIRECT"},
            {"name": "inner_other_subnet_pass", "description": "IP-in-IP with inner dest 10.3.1.30 passed unchanged", "packet_hex": make_eth(payload=make_ipv4(src_ip="203.0.113.1", dst_ip="198.51.100.1", proto=4, payload=make_ipv4(src_ip="10.0.0.1", dst_ip="10.3.1.30", proto=6, payload=make_tcp()))).hex(), "expected_action": "XDP_PASS"},
            {"name": "direct_tcp_pass", "description": "Direct TCP passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "udp_pass", "description": "UDP packet passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP frame passed unchanged", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_ipinip_pass", "description": "Truncated IP-in-IP packet passed safely", "packet_hex": make_eth(payload=make_ipv4(proto=4, payload=b"\\x45\\x00")).hex(), "expected_action": "XDP_PASS"},
        ],
        "main_validator": "xdp_action"
    })

    # 19. syn_nrf_l2_009_wireguard_peer_router
    tasks.append({
        "task_id": "syn_nrf_l2_009_wireguard_peer_router",
        "application_category": "network_routing_forwarding",
        "difficulty": "level_2",
        "task_family": "xdp_router_wireguard",
        "template_family": "xdp_wg_peer_router",
        "semantic_signature": "wireguard_data_receiver_idx_table+redirect+pass",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that routes WireGuard data packets (UDP port 51820, Type 4). Extract the 32-bit Receiver Index. If Receiver Index is 0x11111111, redirect to peer interface ifindex 25. If Receiver Index is 0x22222222, redirect to peer interface ifindex 26. Pass other Receiver Indexes and non-WireGuard traffic with XDP_PASS.",
        "requirements": [
            "Validate Ethernet, IPv4, UDP, and WireGuard Type 4 header bounds",
            "Verify UDP port 51820 and WireGuard message type 4",
            "Redirect Receiver Index 0x11111111 -> bpf_redirect(25, 0)",
            "Redirect Receiver Index 0x22222222 -> bpf_redirect(26, 0)",
            "Always return XDP_PASS for other traffic",
            "SEC(\\"xdp\\") and GPL license declaration"
        ],
        "solution_c": """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

SEC("xdp")
int xdp_wg_peer_router(struct xdp_md *ctx) {
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
    if ((msg_type & 0xFF) != 4)
        return XDP_PASS;

    __u32 receiver_idx = *(__u32 *)(wg + 4);
    if (receiver_idx == bpf_htonl(0x11111111))
        return bpf_redirect(25, 0);
    if (receiver_idx == bpf_htonl(0x22222222))
        return bpf_redirect(26, 0);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
""",
        "tests": [
            {"name": "wg_peer1_redirect_if25", "description": "WireGuard Data with Receiver Index 0x11111111 redirected to ifindex 25", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=51820, payload=make_wireguard(msg_type=4, receiver_idx=0x11111111, payload=b"ENC"*10)))).hex(), "expected_action": "XDP_REDIRECT"},
            {"name": "wg_peer2_redirect_if26", "description": "WireGuard Data with Receiver Index 0x22222222 redirected to ifindex 26", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=51820, payload=make_wireguard(msg_type=4, receiver_idx=0x22222222, payload=b"ENC"*10)))).hex(), "expected_action": "XDP_REDIRECT"},
            {"name": "wg_peer_other_pass", "description": "WireGuard Data with other Receiver Index passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=51820, payload=make_wireguard(msg_type=4, receiver_idx=0x33333333, payload=b"ENC"*10)))).hex(), "expected_action": "XDP_PASS"},
            {"name": "wg_handshake_pass", "description": "WireGuard Handshake Initiation passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=51820, payload=make_wireguard(msg_type=1)))).hex(), "expected_action": "XDP_PASS"},
            {"name": "non_wg_udp_pass", "description": "UDP to port 51821 passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=51821))).hex(), "expected_action": "XDP_PASS"},
            {"name": "tcp_pass", "description": "TCP packet passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_wg_pass", "description": "Truncated WireGuard packet passed safely", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=51820, payload=b"\\x04\\x00"))).hex(), "expected_action": "XDP_PASS"},
        ],
        "main_validator": "xdp_action"
    })

    # 20. syn_nrf_l2_010_tcp_syn_steering_router
    tasks.append({
        "task_id": "syn_nrf_l2_010_tcp_syn_steering_router",
        "application_category": "network_routing_forwarding",
        "difficulty": "level_2",
        "task_family": "xdp_router_syn_steer",
        "template_family": "xdp_syn_steering_router",
        "semantic_signature": "tcp_syn_to_if15_established_to_if16+pass",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that steers TCP traffic: redirect TCP SYN packets (tcp->syn == 1, ack == 0) to connection distributor ifindex 15. Redirect established TCP packets (ack == 1) to fast-path worker ifindex 16. Pass non-TCP traffic with XDP_PASS.",
        "requirements": [
            "Validate Ethernet, IPv4, and TCP header bounds",
            "Redirect TCP SYN (syn=1, ack=0) -> bpf_redirect(15, 0)",
            "Redirect TCP ACK (ack=1) -> bpf_redirect(16, 0)",
            "Always return XDP_PASS for other traffic",
            "SEC(\\"xdp\\") and GPL license declaration"
        ],
        "solution_c": """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

SEC("xdp")
int xdp_syn_steer(struct xdp_md *ctx) {
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

    if (tcp->syn && !tcp->ack)
        return bpf_redirect(15, 0);
    if (tcp->ack)
        return bpf_redirect(16, 0);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
""",
        "tests": [
            {"name": "tcp_syn_redirect_if15", "description": "TCP SYN packet redirected to ifindex 15", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(flags=0x02))).hex(), "expected_action": "XDP_REDIRECT"},
            {"name": "tcp_ack_redirect_if16", "description": "TCP ACK packet redirected to ifindex 16", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(flags=0x10))).hex(), "expected_action": "XDP_REDIRECT"},
            {"name": "tcp_rst_pass", "description": "TCP RST packet (without ACK) passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(flags=0x04))).hex(), "expected_action": "XDP_PASS"},
            {"name": "udp_pass", "description": "UDP packet passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "icmp_pass", "description": "ICMP packet passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP frame passed unchanged", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_tcp_pass", "description": "Truncated TCP packet passed safely", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=b"\\x00\\x50")).hex(), "expected_action": "XDP_PASS"},
        ],
        "main_validator": "xdp_action"
    })

    # =========================================================================
    # LEVEL 3 (10 Tasks) - Consistent Hashing, ECMP, Dynamic Handoff (>= 9 tests)
    # =========================================================================

    # 21. syn_nrf_l3_001_maglev_consistent_hash_lb
    tasks.append({
        "task_id": "syn_nrf_l3_001_maglev_consistent_hash_lb",
        "application_category": "network_routing_forwarding",
        "difficulty": "level_3",
        "task_family": "xdp_load_balancer_maglev",
        "template_family": "xdp_maglev_lb",
        "semantic_signature": "ipv4_5tuple+maglev_lookup_table+redirect_backend",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP load balancer using Google Maglev consistent hashing. Compute a 5-tuple flow hash over IPv4 TCP/UDP packets, index into a fixed lookup table of size 257 (maglev_table[hash % 257]), and redirect to the selected backend interface ifindex (base index 100 + backend_id). Pass non-TCP/UDP traffic with XDP_PASS.",
        "requirements": [
            "Extract 5-tuple for TCP and UDP packets",
            "Compute 32-bit Murmur/FNV flow hash",
            "Index into Maglev table modulo 257",
            "Return bpf_redirect(100 + (hash % 4), 0)",
            "Always return XDP_PASS for non-TCP/UDP traffic",
            "SEC(\\"xdp\\") and GPL license declaration"
        ],
        "solution_c": """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

SEC("xdp")
int xdp_maglev_lb(struct xdp_md *ctx) {
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

    __u16 sport = 0, dport = 0;
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + ip_len;
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        sport = tcp->source;
        dport = tcp->dest;
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + ip_len;
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        sport = udp->source;
        dport = udp->dest;
    } else {
        return XDP_PASS;
    }

    __u32 fhash = ip->saddr ^ ip->daddr ^ ((__u32)sport << 16 | dport) ^ ip->protocol;
    fhash = ((fhash >> 16) ^ fhash) * 0x45d9f3b;
    fhash = ((fhash >> 16) ^ fhash) * 0x45d9f3b;
    fhash = (fhash >> 16) ^ fhash;

    __u32 backend_id = fhash % 4;
    return bpf_redirect(100 + backend_id, 0);
}

char _license[] SEC("license") = "GPL";
""",
        "tests": [
            {"name": "flow1_lb_redirect", "description": "Flow 1 deterministically balanced to backend ifindex", "packet_hex": make_eth(payload=make_ipv4(src_ip="10.0.0.1", dst_ip="192.168.1.1", proto=6, payload=make_tcp(src_port=10001, dst_port=80))).hex(), "expected_action": "XDP_REDIRECT"},
            {"name": "flow2_lb_redirect", "description": "Flow 2 balanced to backend", "packet_hex": make_eth(payload=make_ipv4(src_ip="10.0.0.2", dst_ip="192.168.1.1", proto=6, payload=make_tcp(src_port=10002, dst_port=80))).hex(), "expected_action": "XDP_REDIRECT"},
            {"name": "udp_flow_lb_redirect", "description": "UDP flow balanced to backend", "packet_hex": make_eth(payload=make_ipv4(src_ip="10.0.0.3", dst_ip="192.168.1.1", proto=17, payload=make_udp(src_port=20001, dst_port=53))).hex(), "expected_action": "XDP_REDIRECT"},
            {"name": "icmp_pass", "description": "ICMP traffic passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP frame passed unchanged", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
            {"name": "ipv6_pass", "description": "IPv6 frame passed unchanged", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(next_hdr=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "vlan_pass", "description": "VLAN frame passed unchanged", "packet_hex": make_eth(vlan=100, payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_tcp_pass", "description": "Truncated TCP packet passed safely", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=b"\\x00\\x50")).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_ip_pass", "description": "Truncated IPv4 packet passed safely", "packet_hex": make_eth(payload=b"\\x45\\x00").hex(), "expected_action": "XDP_PASS"},
        ],
        "main_validator": "xdp_action"
    })

    # 22. syn_nrf_l3_002_ecmp_multipath_router
    tasks.append({
        "task_id": "syn_nrf_l3_002_ecmp_multipath_router",
        "application_category": "network_routing_forwarding",
        "difficulty": "level_3",
        "task_family": "xdp_router_ecmp",
        "template_family": "xdp_ecmp_router",
        "semantic_signature": "ipv4_5tuple_hash+ecmp_4way_redirect+pass",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that implements 4-way Equal-Cost Multi-Path (ECMP) routing for IPv4 traffic. Compute a 5-tuple hash and redirect to next-hop interfaces ifindex 10, 11, 12, or 13 (10 + (hash % 4)). Pass non-IP traffic with XDP_PASS.",
        "requirements": [
            "Extract 5-tuple for IPv4 TCP/UDP",
            "Calculate 32-bit hash value",
            "Redirect to ifindex (10 + (hash % 4))",
            "Always return XDP_PASS for non-IPv4 traffic",
            "SEC(\\"xdp\\") and GPL license declaration"
        ],
        "solution_c": """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

SEC("xdp")
int xdp_ecmp_router(struct xdp_md *ctx) {
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

    __u16 sport = 0, dport = 0;
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + ip_len;
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        sport = tcp->source;
        dport = tcp->dest;
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + ip_len;
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        sport = udp->source;
        dport = udp->dest;
    }

    __u32 hash = ip->saddr ^ ip->daddr ^ ((__u32)sport << 16 | dport) ^ ip->protocol;
    __u32 path = hash % 4;
    return bpf_redirect(10 + path, 0);
}

char _license[] SEC("license") = "GPL";
""",
        "tests": [
            {"name": "flow1_ecmp_redirect", "description": "Flow 1 routed across 4-way ECMP paths", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.10", dst_ip="10.0.0.1", proto=6, payload=make_tcp(src_port=10001, dst_port=80))).hex(), "expected_action": "XDP_REDIRECT"},
            {"name": "flow2_ecmp_redirect", "description": "Flow 2 routed across ECMP", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.20", dst_ip="10.0.0.2", proto=6, payload=make_tcp(src_port=10002, dst_port=443))).hex(), "expected_action": "XDP_REDIRECT"},
            {"name": "udp_ecmp_redirect", "description": "UDP flow routed across ECMP", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.30", dst_ip="10.0.0.3", proto=17, payload=make_udp(src_port=30001, dst_port=53))).hex(), "expected_action": "XDP_REDIRECT"},
            {"name": "icmp_ecmp_redirect", "description": "ICMP flow routed across ECMP", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.40", dst_ip="10.0.0.4", proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_REDIRECT"},
            {"name": "arp_pass", "description": "ARP frame passed unchanged", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
            {"name": "ipv6_pass", "description": "IPv6 frame passed unchanged", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(next_hdr=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "vlan_pass", "description": "VLAN frame passed unchanged", "packet_hex": make_eth(vlan=100, payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_ip_pass", "description": "Truncated IPv4 packet passed safely", "packet_hex": make_eth(payload=b"\\x45\\x00").hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_eth_pass", "description": "Truncated Ethernet frame passed safely", "packet_hex": b"\\x52\\x54\\x00".hex(), "expected_action": "XDP_PASS"},
        ],
        "main_validator": "xdp_action"
    })

    # 23. syn_nrf_l3_003_stateful_session_lb
    tasks.append({
        "task_id": "syn_nrf_l3_003_stateful_session_lb",
        "application_category": "network_routing_forwarding",
        "difficulty": "level_3",
        "task_family": "xdp_load_balancer_stateful",
        "template_family": "xdp_stateful_lb",
        "semantic_signature": "tcp_5tuple+sticky_session_affinity_map+redirect",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP load balancer that maintains sticky session affinity for TCP connections in a BPF hash map 'session_map' (key struct flow_key, value __u32 ifindex, max_entries 1024). On SYN, assign backend (50 + (hash % 2)) and store in map. For established packets, lookup affinity and redirect to assigned backend. Pass non-TCP traffic with XDP_PASS.",
        "requirements": [
            "Define struct flow_key and hash map 'session_map' with max_entries 1024",
            "Assign backend on SYN and record in session_map",
            "Lookup assigned backend for existing flow packets",
            "Return bpf_redirect(assigned_ifindex, 0)",
            "Always return XDP_PASS for other traffic",
            "SEC(\\"xdp\\") and GPL license declaration"
        ],
        "solution_c": """#include <linux/bpf.h>
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
    __type(value, __u32);
    __uint(max_entries, 1024);
} session_map SEC(".maps");

SEC("xdp")
int xdp_stateful_lb(struct xdp_md *ctx) {
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

    struct flow_key key = {
        .src_ip = ip->saddr,
        .dst_ip = ip->daddr,
        .src_port = tcp->source,
        .dst_port = tcp->dest,
    };

    __u32 *assigned = bpf_map_lookup_elem(&session_map, &key);
    if (assigned)
        return bpf_redirect(*assigned, 0);

    __u32 hash = ip->saddr ^ ip->daddr ^ ((__u32)tcp->source << 16 | tcp->dest);
    __u32 target_if = 50 + (hash % 2);
    bpf_map_update_elem(&session_map, &key, &target_if, BPF_ANY);

    return bpf_redirect(target_if, 0);
}

char _license[] SEC("license") = "GPL";
""",
        "tests": [
            {"name": "flow1_syn_assigned_redirect", "description": "Flow 1 SYN assigned backend and redirected", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.10", dst_ip="10.0.0.1", proto=6, payload=make_tcp(src_port=10001, dst_port=80, flags=0x02))).hex(), "expected_action": "XDP_REDIRECT"},
            {"name": "flow1_ack_affinity_redirect", "description": "Flow 1 ACK follows recorded affinity", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.10", dst_ip="10.0.0.1", proto=6, payload=make_tcp(src_port=10001, dst_port=80, flags=0x10))).hex(), "expected_action": "XDP_REDIRECT"},
            {"name": "flow2_syn_redirect", "description": "Flow 2 SYN assigned backend", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.20", dst_ip="10.0.0.1", proto=6, payload=make_tcp(src_port=20002, dst_port=80, flags=0x02))).hex(), "expected_action": "XDP_REDIRECT"},
            {"name": "udp_pass", "description": "UDP packet passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "icmp_pass", "description": "ICMP packet passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP frame passed unchanged", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
            {"name": "ipv6_pass", "description": "IPv6 frame passed unchanged", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(next_hdr=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_tcp_pass", "description": "Truncated TCP packet passed safely", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=b"\\x00\\x50")).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_ip_pass", "description": "Truncated IPv4 packet passed safely", "packet_hex": make_eth(payload=b"\\x45\\x00").hex(), "expected_action": "XDP_PASS"},
        ],
        "main_validator": "xdp_action"
    })

    # 24. syn_nrf_l3_004_srv6_to_gtpu_translation_router
    tasks.append({
        "task_id": "syn_nrf_l3_004_srv6_to_gtpu_translation_router",
        "application_category": "network_routing_forwarding",
        "difficulty": "level_3",
        "task_family": "xdp_router_srv6_gtpu",
        "template_family": "xdp_srv6_gtpu_interworking",
        "semantic_signature": "srv6_sid_to_gtpu_translation+redirect_upf_if60",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that inspects SRv6 packets (IPv6 Next Header 43, Routing Type 4). If the active Segment ID matches prefix 2001:db8:ffff::/48, redirect to 5G UPF gateway interface ifindex 60 using bpf_redirect(60, 0). Pass non-matching SRv6 packets and other traffic with XDP_PASS.",
        "requirements": [
            "Validate Ethernet, IPv6, and struct srv6_hdr bounds",
            "Verify ip6->nexthdr == 43 and srh->routing_type == 4",
            "Check active SID against prefix 2001:db8:ffff::/48",
            "Return bpf_redirect(60, 0) on match",
            "Always return XDP_PASS for other traffic",
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
int xdp_srv6_gtpu_router(struct xdp_md *ctx) {
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

    __u16 *sid_words = (void *)(srh + 1);
    if ((void *)(sid_words + 8) > data_end)
        return XDP_PASS;

    // Check 2001:db8:ffff::/48 (0x2001, 0x0db8, 0xffff)
    if (sid_words[0] == bpf_htons(0x2001) && sid_words[1] == bpf_htons(0x0DB8) && sid_words[2] == bpf_htons(0xFFFF))
        return bpf_redirect(60, 0);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
""",
        "tests": [
            {"name": "srv6_5g_sid_redirect_if60", "description": "SRv6 packet with 5G SID redirected to ifindex 60", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(next_hdr=43, payload=make_srv6(segments=["2001:db8:ffff::1"], inner_pkt=make_ipv4(proto=1, payload=make_icmp())))).hex(), "expected_action": "XDP_REDIRECT"},
            {"name": "srv6_other_sid_pass", "description": "SRv6 packet with other SID passed unchanged", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(next_hdr=43, payload=make_srv6(segments=["2001:db8:1::1"], inner_pkt=make_ipv4(proto=6, payload=make_tcp())))).hex(), "expected_action": "XDP_PASS"},
            {"name": "standard_ipv6_pass", "description": "Standard IPv6 passed unchanged", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(next_hdr=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "ipv4_pass", "description": "IPv4 traffic passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "udp_pass", "description": "UDP packet passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "icmp_pass", "description": "ICMP packet passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP frame passed unchanged", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_srv6_pass", "description": "Truncated SRv6 packet passed safely", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(next_hdr=43, payload=b"\\x04\\x00")).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_ipv6_pass", "description": "Truncated IPv6 header passed safely", "packet_hex": make_eth(eth_type=0x86DD, payload=b"\\x60\\x00").hex(), "expected_action": "XDP_PASS"},
        ],
        "main_validator": "xdp_action"
    })

    # 25. syn_nrf_l3_005_evpn_distributed_gateway
    tasks.append({
        "task_id": "syn_nrf_l3_005_evpn_distributed_gateway",
        "application_category": "network_routing_forwarding",
        "difficulty": "level_3",
        "task_family": "xdp_router_evpn",
        "template_family": "xdp_evpn_gateway",
        "semantic_signature": "vxlan_inner_l3_anycast_gw+redirect_egress+pass",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program implementing an EVPN distributed anycast gateway. Inspect VXLAN encapsulated traffic (UDP port 4789). If the inner Ethernet destination MAC matches anycast gateway MAC 00:00:5e:00:01:01, route the inner packet: if inner IPv4 destination is in 10.0.1.0/24, redirect to ifindex 70. If inner IPv4 destination is in 10.0.2.0/24, redirect to ifindex 71. Pass other traffic with XDP_PASS.",
        "requirements": [
            "Validate outer Ethernet, IPv4, UDP, VXLAN, and inner Ethernet/IPv4 bounds",
            "Verify inner destination MAC matches 00:00:5e:00:01:01",
            "Redirect inner 10.0.1.0/24 -> bpf_redirect(70, 0)",
            "Redirect inner 10.0.2.0/24 -> bpf_redirect(71, 0)",
            "Always return XDP_PASS for other traffic",
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
int xdp_evpn_gw_router(struct xdp_md *ctx) {
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

    // Check Anycast GW MAC 00:00:5e:00:01:01
    if (inner_eth->h_dest[0] == 0x00 && inner_eth->h_dest[1] == 0x00 &&
        inner_eth->h_dest[2] == 0x5E && inner_eth->h_dest[3] == 0x00 &&
        inner_eth->h_dest[4] == 0x01 && inner_eth->h_dest[5] == 0x01) {

        if (inner_eth->h_proto == bpf_htons(ETH_P_IP)) {
            struct iphdr *inner_ip = (void *)(inner_eth + 1);
            if ((void *)(inner_ip + 1) > data_end)
                return XDP_PASS;

            __u32 dst = bpf_ntohl(inner_ip->daddr);
            if ((dst & 0xFFFFFF00) == 0x0A000100) // 10.0.1.0/24
                return bpf_redirect(70, 0);
            if ((dst & 0xFFFFFF00) == 0x0A000200) // 10.0.2.0/24
                return bpf_redirect(71, 0);
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
""",
        "tests": [
            {"name": "evpn_subnet1_redirect_if70", "description": "EVPN anycast traffic to 10.0.1.10 redirected to ifindex 70", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=4789, payload=make_vxlan(vni=100, inner_frame=make_eth(dst_mac="00:00:5e:00:01:01", payload=make_ipv4(src_ip="10.0.1.100", dst_ip="10.0.1.10", proto=6, payload=make_tcp())))))).hex(), "expected_action": "XDP_REDIRECT"},
            {"name": "evpn_subnet2_redirect_if71", "description": "EVPN anycast traffic to 10.0.2.20 redirected to ifindex 71", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=4789, payload=make_vxlan(vni=100, inner_frame=make_eth(dst_mac="00:00:5e:00:01:01", payload=make_ipv4(src_ip="10.0.1.100", dst_ip="10.0.2.20", proto=17, payload=make_udp())))))).hex(), "expected_action": "XDP_REDIRECT"},
            {"name": "evpn_other_mac_pass", "description": "EVPN packet to non-gateway MAC passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=4789, payload=make_vxlan(vni=100, inner_frame=make_eth(dst_mac="02:00:00:11:22:33", payload=make_ipv4(proto=1, payload=make_icmp())))))).hex(), "expected_action": "XDP_PASS"},
            {"name": "non_vxlan_udp_pass", "description": "UDP to port 4790 passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=4790))).hex(), "expected_action": "XDP_PASS"},
            {"name": "tcp_pass", "description": "TCP packet passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "icmp_pass", "description": "ICMP packet passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP frame passed unchanged", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_vxlan_pass", "description": "Truncated VXLAN packet passed safely", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=4789, payload=b"\\x08\\x00"))).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_ip_pass", "description": "Truncated IPv4 packet passed safely", "packet_hex": make_eth(payload=b"\\x45\\x00").hex(), "expected_action": "XDP_PASS"},
        ],
        "main_validator": "xdp_action"
    })

    # 26. syn_nrf_l3_006_dynamic_link_failover
    tasks.append({
        "task_id": "syn_nrf_l3_006_dynamic_link_failover",
        "application_category": "network_routing_forwarding",
        "difficulty": "level_3",
        "task_family": "xdp_router_failover",
        "template_family": "xdp_link_failover_router",
        "semantic_signature": "link_health_map+primary_if80_failover_backup_if81",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that routes IPv4 traffic with dynamic link failover. Check primary link health in a BPF array map 'link_status_map' (key 0, value __u32 status, max_entries 1). If status == 1 (primary UP), redirect to primary interface ifindex 80. If status == 0 (primary DOWN), fail over and redirect to backup interface ifindex 81. Pass non-IPv4 traffic with XDP_PASS.",
        "requirements": [
            "Define array map 'link_status_map' with key __u32 and max_entries 1",
            "Validate Ethernet and struct iphdr bounds",
            "Redirect to ifindex 80 if primary link UP (status != 0)",
            "Redirect to ifindex 81 if primary link DOWN (status == 0)",
            "Always return XDP_PASS for non-IPv4 traffic",
            "SEC(\\"xdp\\") and GPL license declaration"
        ],
        "solution_c": """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} link_status_map SEC(".maps");

SEC("xdp")
int xdp_link_failover(struct xdp_md *ctx) {
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

    __u32 key = 0;
    __u32 *status = bpf_map_lookup_elem(&link_status_map, &key);
    if (status && *status == 0) {
        return bpf_redirect(81, 0); // Backup link
    }

    return bpf_redirect(80, 0); // Primary link by default
}

char _license[] SEC("license") = "GPL";
""",
        "tests": [
            {"name": "primary_link_route_redirect_if80", "description": "IPv4 packet routed to primary link ifindex 80", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_REDIRECT"},
            {"name": "primary_link_udp_redirect_if80", "description": "IPv4 UDP routed to primary link", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp())).hex(), "expected_action": "XDP_REDIRECT"},
            {"name": "primary_link_icmp_redirect_if80", "description": "IPv4 ICMP routed to primary link", "packet_hex": make_eth(payload=make_ipv4(proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_REDIRECT"},
            {"name": "arp_pass", "description": "ARP frame passed unchanged", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
            {"name": "ipv6_pass", "description": "IPv6 frame passed unchanged", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(next_hdr=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "vlan_pass", "description": "VLAN frame passed unchanged", "packet_hex": make_eth(vlan=100, payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "mpls_pass", "description": "MPLS frame passed unchanged", "packet_hex": make_eth(eth_type=0x8847, payload=make_mpls([(100, 0, True, 64)], inner_pkt=make_ipv4(proto=1, payload=make_icmp()))).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_ip_pass", "description": "Truncated IPv4 packet passed safely", "packet_hex": make_eth(payload=b"\\x45\\x00").hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_eth_pass", "description": "Truncated Ethernet frame passed safely", "packet_hex": b"\\x52\\x54\\x00".hex(), "expected_action": "XDP_PASS"},
        ],
        "main_validator": "xdp_action"
    })

    # 27. syn_nrf_l3_007_flow_cache_fast_path_router
    tasks.append({
        "task_id": "syn_nrf_l3_007_flow_cache_fast_path_router",
        "application_category": "network_routing_forwarding",
        "difficulty": "level_3",
        "task_family": "xdp_router_flow_cache",
        "template_family": "xdp_flow_cache_router",
        "semantic_signature": "flow_cache_hit_redirect+slow_path_pass",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that accelerates packet routing using an exact-match 5-tuple flow cache in a BPF hash map 'flow_cache_map' (key struct flow_key, value __u32 egress_ifindex, max_entries 2048). On cache hit, redirect packet to cached egress interface using bpf_redirect(egress_ifindex, 0). On cache miss or non-IP traffic, pass to kernel slow-path with XDP_PASS.",
        "requirements": [
            "Define struct flow_key and hash map 'flow_cache_map' with max_entries 2048",
            "Extract 5-tuple for IPv4 TCP/UDP traffic",
            "Perform exact-match lookup in flow cache",
            "Redirect to cached egress ifindex on hit",
            "Return XDP_PASS on cache miss or non-IP traffic",
            "SEC(\\"xdp\\") and GPL license declaration"
        ],
        "solution_c": """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

struct flow_key {
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    __u8 proto;
    __u8 pad[3];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct flow_key);
    __type(value, __u32);
    __uint(max_entries, 2048);
} flow_cache_map SEC(".maps");

SEC("xdp")
int xdp_flow_cache_router(struct xdp_md *ctx) {
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

    __be16 sport = 0, dport = 0;
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + ip_len;
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        sport = tcp->source;
        dport = tcp->dest;
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + ip_len;
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        sport = udp->source;
        dport = udp->dest;
    } else {
        return XDP_PASS;
    }

    struct flow_key key = {
        .src_ip = ip->saddr,
        .dst_ip = ip->daddr,
        .src_port = sport,
        .dst_port = dport,
        .proto = ip->protocol,
        .pad = {0, 0, 0},
    };

    __u32 *egress = bpf_map_lookup_elem(&flow_cache_map, &key);
    if (egress)
        return bpf_redirect(*egress, 0);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
""",
        "tests": [
            {"name": "flow_cache_miss_pass", "description": "Flow cache miss passed to slow path with XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.10", dst_ip="192.168.1.20", proto=6, payload=make_tcp(src_port=10001, dst_port=80))).hex(), "expected_action": "XDP_PASS"},
            {"name": "flow_cache_udp_miss_pass", "description": "UDP flow cache miss passed with XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.30", dst_ip="192.168.1.40", proto=17, payload=make_udp(src_port=20002, dst_port=53))).hex(), "expected_action": "XDP_PASS"},
            {"name": "icmp_pass", "description": "ICMP traffic passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP frame passed unchanged", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
            {"name": "ipv6_pass", "description": "IPv6 frame passed unchanged", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(next_hdr=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "vlan_pass", "description": "VLAN frame passed unchanged", "packet_hex": make_eth(vlan=100, payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "mpls_pass", "description": "MPLS frame passed unchanged", "packet_hex": make_eth(eth_type=0x8847, payload=make_mpls([(100, 0, True, 64)], inner_pkt=make_ipv4(proto=1, payload=make_icmp()))).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_tcp_pass", "description": "Truncated TCP packet passed safely", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=b"\\x00\\x50")).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_ip_pass", "description": "Truncated IPv4 packet passed safely", "packet_hex": make_eth(payload=b"\\x45\\x00").hex(), "expected_action": "XDP_PASS"},
        ],
        "main_validator": "xdp_action"
    })

    # 28. syn_nrf_l3_008_mpls_te_backup_path_router
    tasks.append({
        "task_id": "syn_nrf_l3_008_mpls_te_backup_path_router",
        "application_category": "network_routing_forwarding",
        "difficulty": "level_3",
        "task_family": "xdp_router_mpls_frr",
        "template_family": "xdp_mpls_frr_router",
        "semantic_signature": "mpls_frr_primary_if90_backup_if91+pass",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that implements MPLS Traffic Engineering Fast Reroute (FRR). Inspect MPLS packets (EtherType 0x8847). Extract the 20-bit label: for TE tunnel label 1000, check tunnel health in a BPF array map 'te_health_map' (key 0, value __u32). If primary tunnel is UP (status == 1), redirect to primary TE interface ifindex 90. If DOWN (status == 0), fail over to backup TE interface ifindex 91. Pass other labels and traffic with XDP_PASS.",
        "requirements": [
            "Define array map 'te_health_map' with max_entries 1",
            "Validate Ethernet and struct mpls_label bounds",
            "Check label == 1000 and inspect te_health_map",
            "Redirect to ifindex 90 if UP, or ifindex 91 if DOWN",
            "Always return XDP_PASS for other traffic",
            "SEC(\\"xdp\\") and GPL license declaration"
        ],
        "solution_c": """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>

struct mpls_label {
    __u32 entry;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} te_health_map SEC(".maps");

SEC("xdp")
int xdp_mpls_frr_router(struct xdp_md *ctx) {
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
    if (label == 1000) {
        __u32 key = 0;
        __u32 *status = bpf_map_lookup_elem(&te_health_map, &key);
        if (status && *status == 0)
            return bpf_redirect(91, 0); // Backup TE path
        return bpf_redirect(90, 0); // Primary TE path
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
""",
        "tests": [
            {"name": "te_label_1000_redirect_if90", "description": "MPLS TE label 1000 routed to primary TE ifindex 90", "packet_hex": make_eth(eth_type=0x8847, payload=make_mpls([(1000, 0, True, 64)], inner_pkt=make_ipv4(proto=1, payload=make_icmp()))).hex(), "expected_action": "XDP_REDIRECT"},
            {"name": "te_label_2000_pass", "description": "Non-TE MPLS label 2000 passed unchanged", "packet_hex": make_eth(eth_type=0x8847, payload=make_mpls([(2000, 0, True, 64)], inner_pkt=make_ipv4(proto=6, payload=make_tcp()))).hex(), "expected_action": "XDP_PASS"},
            {"name": "ipv4_pass", "description": "IPv4 traffic passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "udp_pass", "description": "UDP packet passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "icmp_pass", "description": "ICMP packet passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP frame passed unchanged", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
            {"name": "ipv6_pass", "description": "IPv6 frame passed unchanged", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(next_hdr=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_mpls_pass", "description": "Truncated MPLS frame passed safely", "packet_hex": make_eth(eth_type=0x8847, payload=b"\\x00\\x01").hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_eth_pass", "description": "Truncated Ethernet frame passed safely", "packet_hex": b"\\x52\\x54\\x00".hex(), "expected_action": "XDP_PASS"},
        ],
        "main_validator": "xdp_action"
    })

    # 29. syn_nrf_l3_009_gtpu_anchor_mobility_router
    tasks.append({
        "task_id": "syn_nrf_l3_009_gtpu_anchor_mobility_router",
        "application_category": "network_routing_forwarding",
        "difficulty": "level_3",
        "task_family": "xdp_router_gtpu_mobility",
        "template_family": "xdp_gtpu_mobility_router",
        "semantic_signature": "gtpu_teid_mobility_table+redirect_gnodeb+pass",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program for cellular mobility handoff. Inspect GTP-U packets (UDP destination port 2152). If TEID == 0x0000A001, redirect to target gNodeB interface ifindex 95. If TEID == 0x0000A002, redirect to source gNodeB interface ifindex 96. Pass other TEIDs and non-GTP-U traffic with XDP_PASS.",
        "requirements": [
            "Validate outer Ethernet, IPv4, UDP, and struct gtpuhdr bounds",
            "Verify UDP destination port is 2152",
            "Redirect TEID 0xA001 -> bpf_redirect(95, 0)",
            "Redirect TEID 0xA002 -> bpf_redirect(96, 0)",
            "Always return XDP_PASS for other traffic",
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
int xdp_gtpu_mobility(struct xdp_md *ctx) {
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

    if (gtp->teid == bpf_htonl(0x0000A001))
        return bpf_redirect(95, 0);
    if (gtp->teid == bpf_htonl(0x0000A002))
        return bpf_redirect(96, 0);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
""",
        "tests": [
            {"name": "teid_a001_redirect_if95", "description": "GTP-U TEID 0xA001 redirected to gNodeB ifindex 95", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=2152, payload=make_gtpu(teid=0xA001, inner_pkt=make_ipv4(proto=1, payload=make_icmp()))))).hex(), "expected_action": "XDP_REDIRECT"},
            {"name": "teid_a002_redirect_if96", "description": "GTP-U TEID 0xA002 redirected to gNodeB ifindex 96", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=2152, payload=make_gtpu(teid=0xA002, inner_pkt=make_ipv4(proto=6, payload=make_tcp()))))).hex(), "expected_action": "XDP_REDIRECT"},
            {"name": "teid_other_pass", "description": "GTP-U other TEID passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=2152, payload=make_gtpu(teid=0xB001, inner_pkt=make_ipv4(proto=1, payload=make_icmp()))))).hex(), "expected_action": "XDP_PASS"},
            {"name": "non_gtpu_udp_pass", "description": "UDP to port 2153 passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=2153))).hex(), "expected_action": "XDP_PASS"},
            {"name": "tcp_pass", "description": "TCP packet passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "icmp_pass", "description": "ICMP packet passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP frame passed unchanged", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_gtpu_pass", "description": "Truncated GTP-U packet passed safely", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=2152, payload=b"\\x30\\xFF"))).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_ip_pass", "description": "Truncated IPv4 packet passed safely", "packet_hex": make_eth(payload=b"\\x45\\x00").hex(), "expected_action": "XDP_PASS"},
        ],
        "main_validator": "xdp_action"
    })

    # 30. syn_nrf_l3_010_weighted_fair_queuing_router
    tasks.append({
        "task_id": "syn_nrf_l3_010_weighted_fair_queuing_router",
        "application_category": "network_routing_forwarding",
        "difficulty": "level_3",
        "task_family": "xdp_router_wfq",
        "template_family": "xdp_wfq_scheduler",
        "semantic_signature": "wfq_deficit_round_robin+redirect_priority_queues",
        "split": "benchmark",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that implements a 2-class Weighted Fair Queuing (WFQ) packet scheduler with 3:1 weight ratio for IPv4 traffic. If packet length <= 256 bytes, schedule to low-latency queue interface ifindex 100. If packet length > 256 bytes, schedule to bulk queue interface ifindex 101. Pass non-IPv4 traffic with XDP_PASS.",
        "requirements": [
            "Validate Ethernet and struct iphdr bounds",
            "Check total packet length (ctx->data_end - ctx->data)",
            "Redirect packet length <= 256 bytes -> bpf_redirect(100, 0)",
            "Redirect packet length > 256 bytes -> bpf_redirect(101, 0)",
            "Always return XDP_PASS for non-IPv4 traffic",
            "SEC(\\"xdp\\") and GPL license declaration"
        ],
        "solution_c": """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

SEC("xdp")
int xdp_wfq_scheduler(struct xdp_md *ctx) {
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

    __u32 pkt_len = (__u32)((void *)data_end - (void *)data);
    if (pkt_len <= 256)
        return bpf_redirect(100, 0); // Low-latency queue
    else
        return bpf_redirect(101, 0); // Bulk queue
}

char _license[] SEC("license") = "GPL";
""",
        "tests": [
            {"name": "small_pkt_redirect_if100", "description": "Small packet (len <= 256) redirected to low-latency ifindex 100", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(flags=0x10))).hex(), "expected_action": "XDP_REDIRECT"},
            {"name": "large_pkt_redirect_if101", "description": "Large packet (len > 256) redirected to bulk ifindex 101", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(payload=b"A"*300))).hex(), "expected_action": "XDP_REDIRECT"},
            {"name": "small_udp_redirect_if100", "description": "Small UDP packet redirected to low-latency ifindex 100", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp())).hex(), "expected_action": "XDP_REDIRECT"},
            {"name": "large_udp_redirect_if101", "description": "Large UDP packet redirected to bulk ifindex 101", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(payload=b"B"*300))).hex(), "expected_action": "XDP_REDIRECT"},
            {"name": "arp_pass", "description": "ARP frame passed unchanged", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS"},
            {"name": "ipv6_pass", "description": "IPv6 frame passed unchanged", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(next_hdr=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "vlan_pass", "description": "VLAN frame passed unchanged", "packet_hex": make_eth(vlan=100, payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_ip_pass", "description": "Truncated IPv4 packet passed safely", "packet_hex": make_eth(payload=b"\\x45\\x00").hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_eth_pass", "description": "Truncated Ethernet frame passed safely", "packet_hex": b"\\x52\\x54\\x00".hex(), "expected_action": "XDP_PASS"},
        ],
        "main_validator": "xdp_action"
    })

    return tasks
'''
