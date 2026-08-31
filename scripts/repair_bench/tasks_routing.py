#!/usr/bin/env python3
"""
Task definitions for network_routing_forwarding (30 tasks).
Distribution:
- Level 1: 4 compilation, 4 verifier, 2 behavioral (10)
- Level 2: 4 compilation, 4 verifier, 2 behavioral (10)
- Level 3: 5 compilation, 3 verifier, 2 behavioral (10)
Total: 13 compilation, 11 verifier, 6 behavioral = 30 tasks.
"""

from __future__ import annotations

import binascii
from typing import List

from .common import (
    RepairTaskSpec,
    make_arp,
    make_eth,
    make_icmp,
    make_ipv4,
    make_tcp,
    make_udp,
)


def get_routing_tasks() -> List[RepairTaskSpec]:
    tasks: List[RepairTaskSpec] = []

    # =========================================================================
    # LEVEL 1 (10 tasks: 4 compilation, 4 verifier, 2 behavioral)
    # =========================================================================

    # 91. repair_nrf_l1_udp_reflector_tx (compilation_error: undeclared identifier XDP_TX / missing <linux/bpf.h>)
    t91_p_udp = binascii.hexlify(make_eth(dst_mac="52:54:00:12:34:56", src_mac="52:54:00:65:43:21") + make_ipv4(proto=17) + make_udp()).decode()
    t91_p_tcp = binascii.hexlify(make_eth() + make_ipv4(proto=6) + make_tcp()).decode()
    t91_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_nrf_l1_udp_reflector_tx",
            application_category="network_routing_forwarding",
            difficulty="level_1",
            task_family="xdp_l2_reflector",
            template_family="xdp_packet_reflector",
            semantic_signature="ipv4+udp+swap_mac_and_tx",
            diagnostic_category="compilation_error",
            failure_reason="Compilation error: undeclared identifier 'XDP_TX' due to missing include <linux/bpf.h>",
            instruction="Fix the missing include header in the UDP reflector program. Swap Ethernet source and destination MAC addresses on valid IPv4 UDP packets and transmit them back out on the same interface using XDP_TX; pass other traffic with XDP_PASS.",
            requirements=[
                "Include <linux/bpf.h>",
                "Check Ethernet, IPv4, and UDP bounds",
                "Swap Ethernet source and destination MACs for IPv4 UDP packets",
                "Return XDP_TX for UDP traffic; return XDP_PASS for other traffic",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_forward(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
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

    __u32 ip_len = (__u32)ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip_len;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    __u8 tmp[ETH_ALEN];
    #pragma unroll
    for (int i = 0; i < ETH_ALEN; i++) {
        tmp[i] = eth->h_dest[i];
        eth->h_dest[i] = eth->h_source[i];
        eth->h_source[i] = tmp[i];
    }

    // Compilation error: XDP_TX undeclared without <linux/bpf.h>
    return XDP_TX;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""faulty.c:41:12: error: use of undeclared identifier 'XDP_TX'
    return XDP_TX;
           ^
1 error generated.""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_forward(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
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

    __u32 ip_len = (__u32)ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip_len;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    __u8 tmp[ETH_ALEN];
    #pragma unroll
    for (int i = 0; i < ETH_ALEN; i++) {
        tmp[i] = eth->h_dest[i];
        eth->h_dest[i] = eth->h_source[i];
        eth->h_source[i] = tmp[i];
    }

    return XDP_TX;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "tx_udp_reflector", "description": "Reflect UDP packet back out interface", "packet_hex": t91_p_udp, "expected_action": "XDP_TX"},
                {"name": "pass_tcp", "description": "Pass TCP packet unchanged", "packet_hex": t91_p_tcp, "expected_action": "XDP_PASS"},
                {"name": "pass_arp", "description": "Pass ARP frame unchanged", "packet_hex": t91_p_arp, "expected_action": "XDP_PASS"},
            ],
            validator_type="packet_action",
        )
    )

    # 92. repair_nrf_l1_icmp_reflector_tx (compilation_error: type mismatch in eth->h_proto comparison)
    t92_p_icmp = binascii.hexlify(make_eth(dst_mac="52:54:00:12:34:56", src_mac="52:54:00:65:43:21") + make_ipv4(proto=1) + make_icmp()).decode()
    t92_p_tcp = binascii.hexlify(make_eth() + make_ipv4(proto=6) + make_tcp()).decode()
    t92_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_nrf_l1_icmp_reflector_tx",
            application_category="network_routing_forwarding",
            difficulty="level_1",
            task_family="xdp_l2_reflector",
            template_family="xdp_packet_reflector",
            semantic_signature="ipv4+icmp+swap_mac_and_tx",
            diagnostic_category="compilation_error",
            failure_reason="Compilation error: invalid type comparison between __be16 and pointer string literal",
            instruction="Fix the EtherType comparison in the ICMP reflector filter. Swap layer-2 Ethernet addresses on valid IPv4 ICMP packets and transmit back with XDP_TX, passing other traffic with XDP_PASS.",
            requirements=[
                "Check Ethernet, IPv4, and ICMP bounds",
                "Verify eth->h_proto == bpf_htons(ETH_P_IP)",
                "Swap Ethernet source and destination MACs on ICMP traffic",
                "Return XDP_TX for ICMP; return XDP_PASS for other packets",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_forward(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Compilation error: comparing integer against string
    if (eth->h_proto != "0x0800")
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_ICMP)
        return XDP_PASS;

    __u8 tmp[ETH_ALEN];
    #pragma unroll
    for (int i = 0; i < ETH_ALEN; i++) {
        tmp[i] = eth->h_dest[i];
        eth->h_dest[i] = eth->h_source[i];
        eth->h_source[i] = tmp[i];
    }

    return XDP_TX;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""faulty.c:16:22: error: comparison between pointer and integer ('__be16' (aka 'unsigned short') and 'char *')
    if (eth->h_proto != "0x0800")
        ~~~~~~~~~~~~ ^  ~~~~~~~~
1 error generated.""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_forward(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_ICMP)
        return XDP_PASS;

    __u8 tmp[ETH_ALEN];
    #pragma unroll
    for (int i = 0; i < ETH_ALEN; i++) {
        tmp[i] = eth->h_dest[i];
        eth->h_dest[i] = eth->h_source[i];
        eth->h_source[i] = tmp[i];
    }

    return XDP_TX;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "tx_icmp_reflector", "description": "Reflect ICMP packet back out interface", "packet_hex": t92_p_icmp, "expected_action": "XDP_TX"},
                {"name": "pass_tcp", "description": "Pass TCP packet unchanged", "packet_hex": t92_p_tcp, "expected_action": "XDP_PASS"},
                {"name": "pass_arp", "description": "Pass ARP frame unchanged", "packet_hex": t92_p_arp, "expected_action": "XDP_PASS"},
            ],
            validator_type="packet_action",
        )
    )

    # 93. repair_nrf_l1_subnet_reflector_tx (compilation_error: missing include for bpf_helpers.h)
    t93_p_match = binascii.hexlify(make_eth(dst_mac="52:54:00:12:34:56", src_mac="52:54:00:65:43:21") + make_ipv4(dst_ip="192.0.2.45") + make_tcp()).decode()
    t93_p_other = binascii.hexlify(make_eth() + make_ipv4(dst_ip="198.51.100.1") + make_tcp()).decode()
    t93_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_nrf_l1_subnet_reflector_tx",
            application_category="network_routing_forwarding",
            difficulty="level_1",
            task_family="xdp_l2_reflector",
            template_family="xdp_packet_reflector",
            semantic_signature="ipv4+dst_subnet_192_0_2_0_24+swap_mac_and_tx",
            diagnostic_category="compilation_error",
            failure_reason="Compilation error: undefined macro 'SEC' due to missing include <bpf/bpf_helpers.h>",
            instruction="Fix the missing include in the subnet reflector filter. For packets whose IPv4 destination is in 192.0.2.0/24, swap Ethernet addresses and return XDP_TX; pass other traffic with XDP_PASS.",
            requirements=[
                "Include <bpf/bpf_helpers.h>",
                "Check Ethernet and IPv4 bounds",
                "Match IPv4 destination in 192.0.2.0/24 (daddr & 0xFFFFFF00 == 192.0.2.0)",
                "Swap MACs and return XDP_TX; return XDP_PASS otherwise",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int xdp_forward(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u32 subnet = bpf_htonl(0xC0000200); // 192.0.2.0
    __u32 mask = bpf_htonl(0xFFFFFF00);

    if ((ip->daddr & mask) == subnet) {
        __u8 tmp[ETH_ALEN];
        #pragma unroll
        for (int i = 0; i < ETH_ALEN; i++) {
            tmp[i] = eth->h_dest[i];
            eth->h_dest[i] = eth->h_source[i];
            eth->h_source[i] = tmp[i];
        }
        return XDP_TX;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""faulty.c:7:1: error: expected identifier or '('
SEC("xdp")
^
1 error generated.""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_forward(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u32 subnet = bpf_htonl(0xC0000200); // 192.0.2.0
    __u32 mask = bpf_htonl(0xFFFFFF00);

    if ((ip->daddr & mask) == subnet) {
        __u8 tmp[ETH_ALEN];
        #pragma unroll
        for (int i = 0; i < ETH_ALEN; i++) {
            tmp[i] = eth->h_dest[i];
            eth->h_dest[i] = eth->h_source[i];
            eth->h_source[i] = tmp[i];
        }
        return XDP_TX;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "tx_subnet_match", "description": "Reflect destination in 192.0.2.0/24 with XDP_TX", "packet_hex": t93_p_match, "expected_action": "XDP_TX"},
                {"name": "pass_other_subnet", "description": "Pass destination in 198.51.100.0/24 with XDP_PASS", "packet_hex": t93_p_other, "expected_action": "XDP_PASS"},
                {"name": "pass_arp", "description": "Pass ARP frame unchanged", "packet_hex": t93_p_arp, "expected_action": "XDP_PASS"},
            ],
            validator_type="packet_action",
        )
    )

    # 94. repair_nrf_l1_direct_egress_redirect (compilation_error: wrong function signature for bpf_redirect)
    t94_p_in = binascii.hexlify(make_eth() + make_ipv4() + make_tcp()).decode()
    t94_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_nrf_l1_direct_egress_redirect",
            application_category="network_routing_forwarding",
            difficulty="level_1",
            task_family="xdp_redirect_direct",
            template_family="xdp_direct_redirect",
            semantic_signature="direct_redirect_ifindex_2+redirect",
            diagnostic_category="compilation_error",
            failure_reason="Compilation error: too few arguments to function call 'bpf_redirect' (expected 2 arguments: ifindex and flags)",
            instruction="Fix the bpf_redirect call arguments in the direct forwarding filter. Redirect all valid Ethernet frames to interface index 2 with flags 0 (bpf_redirect(2, 0)), passing truncated frames.",
            requirements=[
                "Check Ethernet header bounds",
                "Call bpf_redirect(2, 0) for valid frames",
                "Return XDP_PASS for malformed/truncated frames",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_forward(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Compilation error: bpf_redirect requires 2 parameters (ifindex, flags)
    return bpf_redirect(2);
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""faulty.c:15:12: error: too few arguments to function call, expected 2, have 1
    return bpf_redirect(2);
           ~~~~~~~~~~~~  ^
1 error generated.""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_forward(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    return bpf_redirect(2, 0);
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_redirect_tcp", "description": "Redirect TCP frame to ifindex 2", "packet_hex": t94_p_in, "expected_action": "XDP_REDIRECT"},
                {"name": "pass_redirect_arp", "description": "Redirect ARP frame to ifindex 2", "packet_hex": t94_p_arp, "expected_action": "XDP_REDIRECT"},
            ],
            validator_type="packet_action",
        )
    )

    # 95. repair_nrf_l1_eth_hairpin_tx (verifier_rejection: missing check for Ethernet boundary before MAC swap)
    t95_p_in = binascii.hexlify(make_eth(dst_mac="52:54:00:12:34:56", src_mac="52:54:00:65:43:21") + make_ipv4() + make_tcp()).decode()
    t95_p_trunc = binascii.hexlify(make_eth()[:10]).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_nrf_l1_eth_hairpin_tx",
            application_category="network_routing_forwarding",
            difficulty="level_1",
            task_family="xdp_l2_reflector",
            template_family="xdp_packet_reflector",
            semantic_signature="hairpin_eth_mac_swap+tx",
            diagnostic_category="verifier_rejection",
            failure_reason="Kernel verifier rejection: writing Ethernet MAC addresses before checking eth + 1 <= data_end",
            instruction="Fix the verifier boundary check in the Ethernet hairpin reflector. Verify that (eth + 1 <= data_end) before swapping MAC addresses and returning XDP_TX.",
            requirements=[
                "Check Ethernet header bounds (eth + 1 <= data_end)",
                "Swap Ethernet source and destination MACs",
                "Return XDP_TX on valid frames; return XDP_PASS on truncated frames",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_forward(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    // Verifier error: missing (eth + 1 <= data_end) check before dereferencing eth
    __u8 tmp[ETH_ALEN];
    #pragma unroll
    for (int i = 0; i < ETH_ALEN; i++) {
        tmp[i] = eth->h_dest[i];
        eth->h_dest[i] = eth->h_source[i];
        eth->h_source[i] = tmp[i];
    }

    return XDP_TX;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""0: R1=ctx(off=0,imm=0) R10=fp0
; struct ethhdr *eth = data;
1: (61) r2 = *(u32 *)(r1 +0)
; tmp[i] = eth->h_dest[i];
2: (71) r3 = *(u8 *)(r2 +0)
invalid access to packet, id=0, off=0, size=1, R2_w=pkt(off=0,r=0,imm=0)
processed 3 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
-- END PROG LOAD LOG --""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_forward(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u8 tmp[ETH_ALEN];
    #pragma unroll
    for (int i = 0; i < ETH_ALEN; i++) {
        tmp[i] = eth->h_dest[i];
        eth->h_dest[i] = eth->h_source[i];
        eth->h_source[i] = tmp[i];
    }

    return XDP_TX;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "tx_hairpin_valid", "description": "Hairpin reflect valid Ethernet frame with XDP_TX", "packet_hex": t95_p_in, "expected_action": "XDP_TX"},
                {"name": "pass_trunc", "description": "Pass truncated Ethernet frame with XDP_PASS", "packet_hex": t95_p_trunc, "expected_action": "XDP_PASS"},
            ],
            validator_type="packet_action",
        )
    )

    # 96. repair_nrf_l1_ip_subnet_forward (verifier_rejection: dereferencing IP destination without verifying ip + 1 <= data_end)
    t96_p_match = binascii.hexlify(make_eth() + make_ipv4(dst_ip="10.0.0.5") + make_tcp()).decode()
    t96_p_other = binascii.hexlify(make_eth() + make_ipv4(dst_ip="192.168.1.1") + make_tcp()).decode()
    t96_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_nrf_l1_ip_subnet_forward",
            application_category="network_routing_forwarding",
            difficulty="level_1",
            task_family="xdp_subnet_forward",
            template_family="xdp_direct_redirect",
            semantic_signature="subnet_10_0_0_0_8_redirect_3+pass",
            diagnostic_category="verifier_rejection",
            failure_reason="Kernel verifier rejection: accessing ip->daddr without checking ip + 1 <= data_end",
            instruction="Fix the verifier boundary rejection when matching the destination IP. Redirect packets destined to 10.0.0.0/8 (0x0A000000) to interface index 3 with bpf_redirect(3, 0), passing other traffic with XDP_PASS.",
            requirements=[
                "Check Ethernet and IPv4 bounds",
                "Match ip->daddr in 10.0.0.0/8",
                "Redirect matching traffic to ifindex 3 using bpf_redirect(3, 0)",
                "Pass non-matching and non-IP traffic with XDP_PASS",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_forward(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    // Verifier error: missing (ip + 1 <= data_end) check before reading daddr
    if ((ip->daddr & bpf_htonl(0xFF000000)) == bpf_htonl(0x0A000000))
        return bpf_redirect(3, 0);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""0: R1=ctx(off=0,imm=0) R10=fp0
...
6: (61) r3 = *(u32 *)(r2 +30)
invalid access to packet, id=0, off=30, size=4, R2_w=pkt(off=0,r=14,imm=0)
processed 7 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
-- END PROG LOAD LOG --""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_forward(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if ((ip->daddr & bpf_htonl(0xFF000000)) == bpf_htonl(0x0A000000))
        return bpf_redirect(3, 0);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_redirect_10_net", "description": "Redirect 10.0.0.0/8 traffic to ifindex 3", "packet_hex": t96_p_match, "expected_action": "XDP_REDIRECT"},
                {"name": "pass_outside_subnet", "description": "Pass 192.168.1.1 traffic with XDP_PASS", "packet_hex": t96_p_other, "expected_action": "XDP_PASS"},
                {"name": "pass_arp", "description": "Pass ARP frame unchanged", "packet_hex": t96_p_arp, "expected_action": "XDP_PASS"},
            ],
            validator_type="packet_action",
        )
    )

    # 97. repair_nrf_l1_port_forward_static (verifier_rejection: packet pointer invalid memory access on TCP header check)
    t97_p_match = binascii.hexlify(make_eth() + make_ipv4(proto=6) + make_tcp(dst_port=8080)).decode()
    t97_p_other = binascii.hexlify(make_eth() + make_ipv4(proto=6) + make_tcp(dst_port=80)).decode()
    t97_p_udp = binascii.hexlify(make_eth() + make_ipv4(proto=17) + make_udp()).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_nrf_l1_port_forward_static",
            application_category="network_routing_forwarding",
            difficulty="level_1",
            task_family="xdp_port_forward",
            template_family="xdp_direct_redirect",
            semantic_signature="tcp_dport_8080_redirect_4+pass",
            diagnostic_category="verifier_rejection",
            failure_reason="Kernel verifier rejection: accessing tcp->dest without verifying variable IHL offset + TCP header bounds",
            instruction="Fix the verifier boundary check on the TCP header. Forward IPv4 TCP packets destined to port 8080 to interface index 4 using bpf_redirect(4, 0), passing other traffic with XDP_PASS.",
            requirements=[
                "Check Ethernet, IPv4 (variable IHL), and TCP bounds",
                "Ensure (void *)(tcp + 1) <= data_end before reading tcp->dest",
                "Redirect TCP dport 8080 to interface 4",
                "Pass all other traffic with XDP_PASS",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_forward(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
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

    __u32 ip_len = (__u32)ip->ihl * 4;
    struct tcphdr *tcp = (void *)ip + ip_len;
    // Verifier error: missing (tcp + 1 <= data_end) check

    if (tcp->dest == bpf_htons(8080))
        return bpf_redirect(4, 0);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""0: R1=ctx(off=0,imm=0) R10=fp0
...
16: (69) r4 = *(u16 *)(r3 +2)
invalid access to packet, id=1, off=2, size=2, R3_w=pkt(off=14,r=34,var_off=(0x0; 0x3c),imm=0)
processed 17 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
-- END PROG LOAD LOG --""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_forward(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
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

    __u32 ip_len = (__u32)ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip_len;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    if (tcp->dest == bpf_htons(8080))
        return bpf_redirect(4, 0);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_redirect_tcp8080", "description": "Redirect TCP 8080 to ifindex 4", "packet_hex": t97_p_match, "expected_action": "XDP_REDIRECT"},
                {"name": "pass_tcp80", "description": "Pass TCP 80 with XDP_PASS", "packet_hex": t97_p_other, "expected_action": "XDP_PASS"},
                {"name": "pass_udp", "description": "Pass UDP with XDP_PASS", "packet_hex": t97_p_udp, "expected_action": "XDP_PASS"},
            ],
            validator_type="packet_action",
        )
    )

    # 98. repair_nrf_l1_broadcast_forward (verifier_rejection: scalar value compared against pointer)
    t98_p_bcast = binascii.hexlify(make_eth(dst_mac="ff:ff:ff:ff:ff:ff") + make_arp()).decode()
    t98_p_ucast = binascii.hexlify(make_eth(dst_mac="52:54:00:12:34:56") + make_ipv4() + make_tcp()).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_nrf_l1_broadcast_forward",
            application_category="network_routing_forwarding",
            difficulty="level_1",
            task_family="xdp_broadcast_forward",
            template_family="xdp_direct_redirect",
            semantic_signature="bcast_redirect_ifindex_5+pass",
            diagnostic_category="verifier_rejection",
            failure_reason="Kernel verifier rejection: prohibited comparison between pointer eth->h_dest and scalar integer 0",
            instruction="Fix the broadcast MAC check in the forwarding program. Check that all 6 bytes of eth->h_dest are 0xFF, redirect broadcast frames to interface index 5, and pass unicast frames with XDP_PASS.",
            requirements=[
                "Check Ethernet header bounds",
                "Verify if destination MAC is broadcast (FF:FF:FF:FF:FF:FF)",
                "Redirect broadcast frames with bpf_redirect(5, 0)",
                "Pass unicast frames with XDP_PASS",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_forward(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Verifier error: comparing pointer to scalar 0
    if (eth->h_dest == 0)
        return XDP_PASS;

    if (eth->h_dest[0] == 0xFF && eth->h_dest[1] == 0xFF &&
        eth->h_dest[2] == 0xFF && eth->h_dest[3] == 0xFF &&
        eth->h_dest[4] == 0xFF && eth->h_dest[5] == 0xFF) {
        return bpf_redirect(5, 0);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""0: R1=ctx(off=0,imm=0) R10=fp0
...
4: (15) if r2 == 0x0 goto pc+18
R2 pointer comparison prohibited
processed 5 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
-- END PROG LOAD LOG --""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_forward(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_dest[0] == 0xFF && eth->h_dest[1] == 0xFF &&
        eth->h_dest[2] == 0xFF && eth->h_dest[3] == 0xFF &&
        eth->h_dest[4] == 0xFF && eth->h_dest[5] == 0xFF) {
        return bpf_redirect(5, 0);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_redirect_bcast", "description": "Redirect broadcast frame to ifindex 5", "packet_hex": t98_p_bcast, "expected_action": "XDP_REDIRECT"},
                {"name": "pass_unicast", "description": "Pass unicast frame with XDP_PASS", "packet_hex": t98_p_ucast, "expected_action": "XDP_PASS"},
            ],
            validator_type="packet_action",
        )
    )

    # 99. repair_nrf_l1_arp_request_reflector (behavioral_logic_bug: swapping MACs but returning XDP_PASS instead of XDP_TX)
    t99_p_arp_req = binascii.hexlify(make_eth(dst_mac="52:54:00:12:34:56", src_mac="52:54:00:65:43:21", eth_type=0x0806) + make_arp(op=1)).decode()
    t99_p_ip = binascii.hexlify(make_eth() + make_ipv4() + make_tcp()).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_nrf_l1_arp_request_reflector",
            application_category="network_routing_forwarding",
            difficulty="level_1",
            task_family="xdp_arp_reflector",
            template_family="xdp_packet_reflector",
            semantic_signature="arp_request_reflect+tx",
            diagnostic_category="behavioral_logic_bug",
            failure_reason="Behavioral bug: swapped MAC addresses on ARP request but returned XDP_PASS instead of XDP_TX",
            instruction="Fix the return action in the ARP reflector filter so that reflected ARP request frames are transmitted back out the interface with XDP_TX rather than being passed to the network stack.",
            requirements=[
                "Check Ethernet and ARP header bounds",
                "Verify EtherType is ETH_P_ARP (0x0806)",
                "Swap Ethernet source and destination MACs",
                "Return XDP_TX for ARP frames; return XDP_PASS for other traffic",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_forward(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto == bpf_htons(ETH_P_ARP)) {
        __u8 tmp[ETH_ALEN];
        #pragma unroll
        for (int i = 0; i < ETH_ALEN; i++) {
            tmp[i] = eth->h_dest[i];
            eth->h_dest[i] = eth->h_source[i];
            eth->h_source[i] = tmp[i];
        }
        // Behavioral bug: returns XDP_PASS instead of XDP_TX
        return XDP_PASS;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""FAIL: test_case 'reflect_arp_tx' failed:
  Expected action: XDP_TX
  Observed action: XDP_PASS (ARP frame was modified but passed instead of reflected)
1 of 2 test cases failed.""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_forward(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto == bpf_htons(ETH_P_ARP)) {
        __u8 tmp[ETH_ALEN];
        #pragma unroll
        for (int i = 0; i < ETH_ALEN; i++) {
            tmp[i] = eth->h_dest[i];
            eth->h_dest[i] = eth->h_source[i];
            eth->h_source[i] = tmp[i];
        }
        return XDP_TX;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "tx_arp_reflect", "description": "Reflect ARP request frame with XDP_TX", "packet_hex": t99_p_arp_req, "expected_action": "XDP_TX"},
                {"name": "pass_ip_traffic", "description": "Pass IP traffic with XDP_PASS", "packet_hex": t99_p_ip, "expected_action": "XDP_PASS"},
            ],
            validator_type="packet_action",
        )
    )

    # 100. repair_nrf_l1_subnet_match_endian (behavioral_logic_bug: comparing host-endian subnet IP constant with network-endian packet IP)
    t100_p_match = binascii.hexlify(make_eth(dst_mac="52:54:00:12:34:56", src_mac="52:54:00:65:43:21") + make_ipv4(dst_ip="172.16.10.5") + make_tcp()).decode()
    t100_p_other = binascii.hexlify(make_eth() + make_ipv4(dst_ip="192.168.1.1") + make_tcp()).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_nrf_l1_subnet_match_endian",
            application_category="network_routing_forwarding",
            difficulty="level_1",
            task_family="xdp_l2_reflector",
            template_family="xdp_packet_reflector",
            semantic_signature="dst_subnet_172_16_reflect+tx",
            diagnostic_category="behavioral_logic_bug",
            failure_reason="Behavioral bug: subnet mask comparison evaluated host-endian integer literal against network-endian ip->daddr",
            instruction="Fix the byte-order comparison bug in the subnet reflector filter. For packets destined to 172.16.0.0/16, swap Ethernet MACs and return XDP_TX, passing other traffic with XDP_PASS.",
            requirements=[
                "Check Ethernet and IPv4 bounds",
                "Compare ip->daddr & bpf_htonl(0xFFFF0000) == bpf_htonl(0xAC100000)",
                "Swap Ethernet source and destination MAC addresses on match",
                "Return XDP_TX for matched packets, XDP_PASS for others",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_forward(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // Behavioral bug: 0xAC100000 in host order compared against raw network order ip->daddr
    if ((ip->daddr & 0xFFFF0000) == 0xAC100000) {
        __u8 tmp[ETH_ALEN];
        #pragma unroll
        for (int i = 0; i < ETH_ALEN; i++) {
            tmp[i] = eth->h_dest[i];
            eth->h_dest[i] = eth->h_source[i];
            eth->h_source[i] = tmp[i];
        }
        return XDP_TX;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""FAIL: test_case 'match_172_16_subnet' failed:
  Expected action: XDP_TX
  Observed action: XDP_PASS (endian mismatch: ip->daddr in network order did not match host constant 0xAC100000)
1 of 2 test cases failed.""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_forward(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if ((ip->daddr & bpf_htonl(0xFFFF0000)) == bpf_htonl(0xAC100000)) {
        __u8 tmp[ETH_ALEN];
        #pragma unroll
        for (int i = 0; i < ETH_ALEN; i++) {
            tmp[i] = eth->h_dest[i];
            eth->h_dest[i] = eth->h_source[i];
            eth->h_source[i] = tmp[i];
        }
        return XDP_TX;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "tx_172_16_match", "description": "Reflect 172.16.0.0/16 traffic with XDP_TX", "packet_hex": t100_p_match, "expected_action": "XDP_TX"},
                {"name": "pass_other_ip", "description": "Pass other IP traffic with XDP_PASS", "packet_hex": t100_p_other, "expected_action": "XDP_PASS"},
            ],
            validator_type="packet_action",
        )
    )

    # =========================================================================
    # LEVEL 2 (10 tasks: 4 compilation, 4 verifier, 2 behavioral)
    # =========================================================================

    # 101. repair_nrf_l2_array_devmap_redirect (compilation_error: missing devmap type definition BPF_MAP_TYPE_DEVMAP)
    t101_p_in = binascii.hexlify(make_eth() + make_ipv4() + make_tcp()).decode()
    t101_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_nrf_l2_array_devmap_redirect",
            application_category="network_routing_forwarding",
            difficulty="level_2",
            task_family="xdp_devmap_redirect",
            template_family="xdp_map_redirect",
            semantic_signature="devmap_redirect_key_0+redirect",
            diagnostic_category="compilation_error",
            failure_reason="Compilation error: undeclared identifier 'BPF_MAP_TYPE_DEVMAP' due to missing <linux/bpf.h>",
            instruction="Fix the missing include header and redirect valid Ethernet frames using devmap named tx_devmap at key 0 (bpf_redirect_map(&tx_devmap, 0, 0)), passing truncated frames with XDP_PASS.",
            requirements=[
                "Define BPF_MAP_TYPE_DEVMAP map named tx_devmap with 4 entries",
                "Call bpf_redirect_map(&tx_devmap, 0, 0) for valid frames",
                "Return XDP_PASS on malformed frames",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP); // Compilation error: BPF_MAP_TYPE_DEVMAP undeclared without linux/bpf.h
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 4);
} tx_devmap SEC(".maps");

SEC("xdp")
int xdp_forward(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    return bpf_redirect_map(&tx_devmap, 0, 0);
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""faulty.c:6:18: error: use of undeclared identifier 'BPF_MAP_TYPE_DEVMAP'
    __uint(type, BPF_MAP_TYPE_DEVMAP);
                 ^
1 error generated.""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 4);
} tx_devmap SEC(".maps");

SEC("xdp")
int xdp_forward(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    return bpf_redirect_map(&tx_devmap, 0, 0);
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_redirect_tcp", "description": "Redirect frame through DEVMAP key 0", "packet_hex": t101_p_in, "expected_action": "XDP_REDIRECT"},
                {"name": "pass_redirect_arp", "description": "Redirect ARP frame through DEVMAP key 0", "packet_hex": t101_p_arp, "expected_action": "XDP_REDIRECT"},
            ],
            validator_type="packet_action",
        )
    )

    # 102. repair_nrf_l2_proto_based_redirect (compilation_error: wrong argument types to bpf_redirect_map)
    t102_p_tcp = binascii.hexlify(make_eth() + make_ipv4(proto=6) + make_tcp()).decode()
    t102_p_udp = binascii.hexlify(make_eth() + make_ipv4(proto=17) + make_udp()).decode()
    t102_p_icmp = binascii.hexlify(make_eth() + make_ipv4(proto=1) + make_icmp()).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_nrf_l2_proto_based_redirect",
            application_category="network_routing_forwarding",
            difficulty="level_2",
            task_family="xdp_proto_redirect",
            template_family="xdp_map_redirect",
            semantic_signature="proto_redirect_tcp_slot0_udp_slot1+redirect",
            diagnostic_category="compilation_error",
            failure_reason="Compilation error: passing devmap by value instead of pointer to bpf_redirect_map",
            instruction="Fix the bpf_redirect_map pointer parameter. Redirect IPv4 TCP packets through DEVMAP key 0 and IPv4 UDP packets through DEVMAP key 1, passing other traffic with XDP_PASS.",
            requirements=[
                "Define proto_devmap (BPF_MAP_TYPE_DEVMAP) with 2 entries",
                "Check Ethernet and IPv4 bounds",
                "Redirect TCP to slot 0 and UDP to slot 1 using &proto_devmap",
                "Pass other protocols with XDP_PASS",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 2);
} proto_devmap SEC(".maps");

SEC("xdp")
int xdp_forward(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->protocol == IPPROTO_TCP) {
        // Compilation error: passing map by value
        return bpf_redirect_map(proto_devmap, 0, 0);
    } else if (ip->protocol == IPPROTO_UDP) {
        return bpf_redirect_map(proto_devmap, 1, 0);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""faulty.c:29:33: error: passing 'struct <anonymous at faulty.c:8:1>' to parameter of type 'void *' [-Werror]
        return bpf_redirect_map(proto_devmap, 0, 0);
                                ^~~~~~~~~~~~
1 error generated.""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 2);
} proto_devmap SEC(".maps");

SEC("xdp")
int xdp_forward(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->protocol == IPPROTO_TCP) {
        return bpf_redirect_map(&proto_devmap, 0, 0);
    } else if (ip->protocol == IPPROTO_UDP) {
        return bpf_redirect_map(&proto_devmap, 1, 0);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_redirect_tcp", "description": "Redirect TCP to proto_devmap slot 0", "packet_hex": t102_p_tcp, "expected_action": "XDP_REDIRECT"},
                {"name": "pass_redirect_udp", "description": "Redirect UDP to proto_devmap slot 1", "packet_hex": t102_p_udp, "expected_action": "XDP_REDIRECT"},
                {"name": "pass_icmp", "description": "Pass ICMP with XDP_PASS", "packet_hex": t102_p_icmp, "expected_action": "XDP_PASS"},
            ],
            validator_type="packet_action",
        )
    )

    # 103. repair_nrf_l2_prefix_based_routing (compilation_error: missing map struct definition or wrong key size)
    t103_p_match = binascii.hexlify(make_eth() + make_ipv4(dst_ip="192.168.10.1") + make_tcp()).decode()
    t103_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_nrf_l2_prefix_based_routing",
            application_category="network_routing_forwarding",
            difficulty="level_2",
            task_family="xdp_prefix_routing",
            template_family="xdp_map_redirect",
            semantic_signature="prefix_lookup_redirect+redirect_or_pass",
            diagnostic_category="compilation_error",
            failure_reason="Compilation error: undefined struct 'lpm_key' in routing lookup",
            instruction="Fix the missing struct declaration in the prefix routing filter. Lookup destination IP in lpm_routes (LPM trie) and redirect to the returned interface index, passing non-matching traffic with XDP_PASS.",
            requirements=[
                "Define struct lpm_key with prefixlen and addr",
                "Define lpm_routes LPM trie map",
                "Lookup ip->daddr in lpm_routes",
                "If route found, redirect to *ifindex using bpf_redirect(*ifindex, 0)",
                "Return XDP_PASS if route not found",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_key); // Compilation error: struct lpm_key not declared yet
    __type(value, __u32);
    __uint(max_entries, 256);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} lpm_routes SEC(".maps");

SEC("xdp")
int xdp_forward(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""faulty.c:10:17: error: variable has incomplete type 'struct lpm_key'
    __type(key, struct lpm_key);
                ^
faulty.c:10:17: note: forward declaration of 'struct lpm_key'
1 error generated.""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct lpm_key {
    __u32 prefixlen;
    __u32 addr;
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_key);
    __type(value, __u32);
    __uint(max_entries, 256);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} lpm_routes SEC(".maps");

SEC("xdp")
int xdp_forward(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    struct lpm_key key = {
        .prefixlen = 32,
        .addr = ip->daddr,
    };

    __u32 *ifindex = bpf_map_lookup_elem(&lpm_routes, &key);
    if (ifindex)
        return bpf_redirect(*ifindex, 0);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_unmatched_route", "description": "Pass route lookup miss with XDP_PASS", "packet_hex": t103_p_match, "expected_action": "XDP_PASS"},
                {"name": "pass_arp", "description": "Pass non-IP ARP frame with XDP_PASS", "packet_hex": t103_p_arp, "expected_action": "XDP_PASS"},
            ],
            validator_type="packet_action",
        )
    )

    # 104. repair_nrf_l2_vlan_interface_switch (compilation_error: missing parenthesis in conditional expression)
    t104_p_vlan10 = binascii.hexlify(make_eth(vlan=10) + make_ipv4() + make_tcp()).decode()
    t104_p_vlan20 = binascii.hexlify(make_eth(vlan=20) + make_ipv4() + make_tcp()).decode()
    t104_p_untag = binascii.hexlify(make_eth() + make_ipv4() + make_tcp()).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_nrf_l2_vlan_interface_switch",
            application_category="network_routing_forwarding",
            difficulty="level_2",
            task_family="xdp_vlan_switch",
            template_family="xdp_direct_redirect",
            semantic_signature="vlan_10_to_if2_vlan_20_to_if3+redirect",
            diagnostic_category="compilation_error",
            failure_reason="Compilation error: syntax error / mismatched parenthesis in conditional",
            instruction="Fix the syntax error in the VLAN switching filter. Forward VLAN 10 frames to interface 2, VLAN 20 frames to interface 3, and pass untagged frames with XDP_PASS.",
            requirements=[
                "Check Ethernet and VLAN header bounds",
                "Extract VLAN ID: bpf_ntohs(vlh->h_vlan_TCI) & 0x0FFF",
                "Redirect VID 10 to ifindex 2 (bpf_redirect(2, 0))",
                "Redirect VID 20 to ifindex 3 (bpf_redirect(3, 0))",
                "Pass other frames with XDP_PASS",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

SEC("xdp")
int xdp_forward(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto == bpf_htons(ETH_P_8021Q)) {
        struct vlan_hdr *vlh = (void *)(eth + 1);
        if ((void *)(vlh + 1) > data_end)
            return XDP_PASS;

        __u16 vid = bpf_ntohs(vlh->h_vlan_TCI) & 0x0FFF;
        // Compilation error: syntax error mismatched parentheses
        if ((vid == 10)
            return bpf_redirect(2, 0);
        else if (vid == 20)
            return bpf_redirect(3, 0);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""faulty.c:26:13: error: expected ')'
            return bpf_redirect(2, 0);
            ^
faulty.c:25:12: note: to match this '('
        if ((vid == 10)
           ^
1 error generated.""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

SEC("xdp")
int xdp_forward(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto == bpf_htons(ETH_P_8021Q)) {
        struct vlan_hdr *vlh = (void *)(eth + 1);
        if ((void *)(vlh + 1) > data_end)
            return XDP_PASS;

        __u16 vid = bpf_ntohs(vlh->h_vlan_TCI) & 0x0FFF;
        if (vid == 10)
            return bpf_redirect(2, 0);
        else if (vid == 20)
            return bpf_redirect(3, 0);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_redirect_vlan10", "description": "Redirect VLAN 10 to ifindex 2", "packet_hex": t104_p_vlan10, "expected_action": "XDP_REDIRECT"},
                {"name": "pass_redirect_vlan20", "description": "Redirect VLAN 20 to ifindex 3", "packet_hex": t104_p_vlan20, "expected_action": "XDP_REDIRECT"},
                {"name": "pass_untagged", "description": "Pass untagged frame with XDP_PASS", "packet_hex": t104_p_untag, "expected_action": "XDP_PASS"},
            ],
            validator_type="packet_action",
        )
    )

    # 105. repair_nrf_l2_map_redirect_fallback (verifier_rejection: map lookup result pointer not checked against NULL before reading ifindex)
    t105_p_in = binascii.hexlify(make_eth() + make_ipv4() + make_tcp()).decode()
    t105_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_nrf_l2_map_redirect_fallback",
            application_category="network_routing_forwarding",
            difficulty="level_2",
            task_family="xdp_redirect_config",
            template_family="xdp_map_redirect",
            semantic_signature="config_map_redirect_or_aborted+redirect",
            diagnostic_category="verifier_rejection",
            failure_reason="Kernel verifier rejection: dereferencing config map lookup result without NULL check",
            instruction="Fix the verifier rejection by checking the return value of bpf_map_lookup_elem for NULL. Redirect frames to the interface stored at key 0 of forwarding_config; if missing or 0, return XDP_ABORTED.",
            requirements=[
                "Define forwarding_config array map with 1 entry of __u32",
                "Lookup key 0; if result is NULL or *val == 0, return XDP_ABORTED",
                "Otherwise redirect to *val with bpf_redirect(*val, 0)",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} forwarding_config SEC(".maps");

SEC("xdp")
int xdp_forward(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u32 key = 0;
    __u32 *ifindex = bpf_map_lookup_elem(&forwarding_config, &key);
    // Verifier error: dereferencing ifindex without NULL check
    if (*ifindex == 0)
        return XDP_ABORTED;

    return bpf_redirect(*ifindex, 0);
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""0: R1=ctx(off=0,imm=0) R10=fp0
...
10: (85) call bpf_map_lookup_elem#1
11: R0=map_value_or_null(id=1,off=0,r=0,imm=0)
; if (*ifindex == 0)
12: (61) r1 = *(u32 *)(r0 +0)
R0 invalid mem access 'map_value_or_null'
processed 13 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
-- END PROG LOAD LOG --""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} forwarding_config SEC(".maps");

SEC("xdp")
int xdp_forward(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u32 key = 0;
    __u32 *ifindex = bpf_map_lookup_elem(&forwarding_config, &key);
    if (!ifindex || *ifindex == 0)
        return XDP_ABORTED;

    return bpf_redirect(*ifindex, 0);
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_unconfigured_aborted", "description": "Return XDP_ABORTED when config map entry is 0", "packet_hex": t105_p_in, "expected_action": "XDP_ABORTED"},
                {"name": "pass_arp_aborted", "description": "Return XDP_ABORTED on unconfigured ARP", "packet_hex": t105_p_arp, "expected_action": "XDP_ABORTED"},
            ],
            validator_type="packet_action",
        )
    )

    # 106. repair_nrf_l2_longest_prefix_forward (verifier_rejection: LPM lookup key struct pointer passed uninitialized to helper)
    t106_p_match = binascii.hexlify(make_eth() + make_ipv4(dst_ip="10.1.2.3") + make_tcp()).decode()
    t106_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_nrf_l2_longest_prefix_forward",
            application_category="network_routing_forwarding",
            difficulty="level_2",
            task_family="xdp_lpm_forward",
            template_family="xdp_map_redirect",
            semantic_signature="lpm_longest_prefix_forward+redirect",
            diagnostic_category="verifier_rejection",
            failure_reason="Kernel verifier rejection: uninitialized stack memory passed in LPM key struct",
            instruction="Fix the verifier rejection by fully initializing the LPM key struct (setting prefixlen and addr) before calling bpf_map_lookup_elem. Redirect matching destinations and pass non-matching traffic.",
            requirements=[
                "Initialize struct lpm_key key = { .prefixlen = 32, .addr = ip->daddr }",
                "Lookup in LPM trie map prefix_routes",
                "Redirect if match found; return XDP_PASS otherwise",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct lpm_key {
    __u32 prefixlen;
    __u32 addr;
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_key);
    __type(value, __u32);
    __uint(max_entries, 1024);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} prefix_routes SEC(".maps");

SEC("xdp")
int xdp_forward(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // Verifier error: prefixlen is uninitialized
    struct lpm_key key;
    key.addr = ip->daddr;

    __u32 *egress = bpf_map_lookup_elem(&prefix_routes, &key);
    if (egress)
        return bpf_redirect(*egress, 0);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""0: R1=ctx(off=0,imm=0) R10=fp0
...
14: (bf) r2 = r10
15: (07) r2 += -8
16: (85) call bpf_map_lookup_elem#1
invalid indirect read from stack R2 off -8+0 size 4 (uninitialized prefixlen)
processed 17 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
-- END PROG LOAD LOG --""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct lpm_key {
    __u32 prefixlen;
    __u32 addr;
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_key);
    __type(value, __u32);
    __uint(max_entries, 1024);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} prefix_routes SEC(".maps");

SEC("xdp")
int xdp_forward(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    struct lpm_key key = {
        .prefixlen = 32,
        .addr = ip->daddr,
    };

    __u32 *egress = bpf_map_lookup_elem(&prefix_routes, &key);
    if (egress)
        return bpf_redirect(*egress, 0);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_unmatched", "description": "Pass route lookup miss with XDP_PASS", "packet_hex": t106_p_match, "expected_action": "XDP_PASS"},
                {"name": "pass_arp", "description": "Pass ARP frame with XDP_PASS", "packet_hex": t106_p_arp, "expected_action": "XDP_PASS"},
            ],
            validator_type="packet_action",
        )
    )

    # 107. repair_nrf_l2_gateway_mac_rewrite (verifier_rejection: memory access out of bounds when writing next-hop MAC)
    t107_p_match = binascii.hexlify(make_eth() + make_ipv4(dst_ip="192.168.1.50") + make_tcp()).decode()
    t107_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_nrf_l2_gateway_mac_rewrite",
            application_category="network_routing_forwarding",
            difficulty="level_2",
            task_family="xdp_nexthop_forward",
            template_family="xdp_stateless_rewrite",
            semantic_signature="nexthop_mac_rewrite_and_redirect_2+redirect",
            diagnostic_category="verifier_rejection",
            failure_reason="Kernel verifier rejection: loop copying 8 bytes into 6-byte MAC address array exceeds struct ethhdr boundary",
            instruction="Fix the loop boundary when rewriting next-hop gateway MAC address (copy exactly 6 bytes / ETH_ALEN). Rewrite destination MAC to 52:54:00:11:22:33 and redirect to interface index 2.",
            requirements=[
                "Check Ethernet header bounds",
                "Copy exactly 6 bytes (i < 6) for next-hop MAC",
                "Redirect to interface 2 with bpf_redirect(2, 0)",
                "Return XDP_PASS on malformed frames",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_forward(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u8 nexthop_mac[6] = {0x52, 0x54, 0x00, 0x11, 0x22, 0x33};
    // Verifier error: loop bound is 8 instead of 6, overwriting into h_source and past bounds
    #pragma unroll
    for (int i = 0; i < 8; i++) {
        eth->h_dest[i] = nexthop_mac[i];
    }

    return bpf_redirect(2, 0);
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""0: R1=ctx(off=0,imm=0) R10=fp0
...
14: (71) r4 = *(u8 *)(r10 -2)
invalid indirect read from stack R10 off -2 size 1 (out of bounds array read)
processed 15 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
-- END PROG LOAD LOG --""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_forward(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u8 nexthop_mac[ETH_ALEN] = {0x52, 0x54, 0x00, 0x11, 0x22, 0x33};
    #pragma unroll
    for (int i = 0; i < ETH_ALEN; i++) {
        eth->h_dest[i] = nexthop_mac[i];
    }

    return bpf_redirect(2, 0);
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_rewrite_nexthop", "description": "Rewrite gateway MAC and redirect to ifindex 2", "packet_hex": t107_p_match, "expected_action": "XDP_REDIRECT"},
                {"name": "pass_arp", "description": "Rewrite ARP gateway MAC and redirect", "packet_hex": t107_p_arp, "expected_action": "XDP_REDIRECT"},
            ],
            validator_type="packet_action",
        )
    )

    # 108. repair_nrf_l2_session_stickiness (verifier_rejection: devmap lookup key not bounded within table size)
    t108_p_tcp1 = binascii.hexlify(make_eth() + make_ipv4(src_ip="10.0.0.1", proto=6) + make_tcp(src_port=1000, dst_port=80)).decode()
    t108_p_tcp2 = binascii.hexlify(make_eth() + make_ipv4(src_ip="10.0.0.2", proto=6) + make_tcp(src_port=1001, dst_port=80)).decode()
    t108_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_nrf_l2_session_stickiness",
            application_category="network_routing_forwarding",
            difficulty="level_2",
            task_family="xdp_load_balancer",
            template_family="xdp_map_redirect",
            semantic_signature="flow_hash_backend_select+devmap_redirect",
            diagnostic_category="verifier_rejection",
            failure_reason="Kernel verifier rejection: computed DEVMAP backend index not statically bounded to [0..1]",
            instruction="Fix the verifier boundary check on the backend selection index. Hash the 5-tuple, constrain backend index to 0 or 1 ((hash) & 1), and redirect through backend_map (BPF_MAP_TYPE_DEVMAP).",
            requirements=[
                "Define backend_map DEVMAP with 2 entries",
                "Hash 5-tuple and constrain backend key to 0 or 1",
                "Redirect through backend_map with bpf_redirect_map(&backend_map, key, 0)",
                "Return XDP_PASS for non-IP/malformed frames",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 2);
} backend_map SEC(".maps");

SEC("xdp")
int xdp_forward(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // Verifier error: raw hash passed to devmap lookup without masking
    __u32 hash = ip->saddr ^ ip->daddr;
    return bpf_redirect_map(&backend_map, hash, 0);
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""0: R1=ctx(off=0,imm=0) R10=fp0
...
10: (85) call bpf_redirect_map#51
R2 invalid map key out of range for DEVMAP (max_entries 2)
processed 11 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
-- END PROG LOAD LOG --""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 2);
} backend_map SEC(".maps");

SEC("xdp")
int xdp_forward(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u32 hash = (ip->saddr ^ ip->daddr) & 1;
    return bpf_redirect_map(&backend_map, hash, 0);
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_backend_tcp1", "description": "Redirect flow 1 through backend map", "packet_hex": t108_p_tcp1, "expected_action": "XDP_REDIRECT"},
                {"name": "pass_backend_tcp2", "description": "Redirect flow 2 through backend map", "packet_hex": t108_p_tcp2, "expected_action": "XDP_REDIRECT"},
                {"name": "pass_arp", "description": "Pass ARP frame with XDP_PASS", "packet_hex": t108_p_arp, "expected_action": "XDP_PASS"},
            ],
            validator_type="packet_action",
        )
    )

    # 109. repair_nrf_l2_default_route_action (behavioral_logic_bug: returning XDP_PASS instead of XDP_ABORTED on unmapped destination)
    t109_p_known = binascii.hexlify(make_eth() + make_ipv4(dst_ip="10.0.0.1") + make_tcp()).decode()
    t109_p_unknown = binascii.hexlify(make_eth() + make_ipv4(dst_ip="192.168.1.1") + make_tcp()).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_nrf_l2_default_route_action",
            application_category="network_routing_forwarding",
            difficulty="level_2",
            task_family="xdp_strict_routing",
            template_family="xdp_map_redirect",
            semantic_signature="strict_routing_table+aborted_on_miss",
            diagnostic_category="behavioral_logic_bug",
            failure_reason="Behavioral bug: returned XDP_PASS instead of required XDP_ABORTED when route lookup failed in strict forwarding table",
            instruction="Fix the default routing failure action in the strict forwarder. If the destination IP exists in routing_table, redirect to the mapped egress; otherwise return XDP_ABORTED.",
            requirements=[
                "Define routing_table hash map keyed by __u32 dst IP storing __u32 egress ifindex",
                "Lookup ip->daddr in routing_table",
                "If route exists, return bpf_redirect(*egress, 0)",
                "If route is absent, return XDP_ABORTED",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 256);
} routing_table SEC(".maps");

SEC("xdp")
int xdp_forward(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_ABORTED;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_ABORTED;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_ABORTED;

    __u32 dst = ip->daddr;
    __u32 *egress = bpf_map_lookup_elem(&routing_table, &dst);
    if (egress)
        return bpf_redirect(*egress, 0);

    // Behavioral bug: returned XDP_PASS instead of XDP_ABORTED on route miss
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""FAIL: test_case 'unmapped_destination_aborted' failed:
  Expected action: XDP_ABORTED
  Observed action: XDP_PASS (strict router leaked unrouted frame to local stack)
1 of 2 test cases failed.""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 256);
} routing_table SEC(".maps");

SEC("xdp")
int xdp_forward(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_ABORTED;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_ABORTED;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_ABORTED;

    __u32 dst = ip->daddr;
    __u32 *egress = bpf_map_lookup_elem(&routing_table, &dst);
    if (egress)
        return bpf_redirect(*egress, 0);

    return XDP_ABORTED;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "aborted_unmapped_dst", "description": "Abort unmapped destination with XDP_ABORTED", "packet_hex": t109_p_unknown, "expected_action": "XDP_ABORTED"},
                {"name": "pass_known_route", "description": "Pass known route miss check", "packet_hex": t109_p_known, "expected_action": "XDP_ABORTED"},
            ],
            validator_type="packet_action",
        )
    )

    # 110. repair_nrf_l2_proto_port_demux (behavioral_logic_bug: routing UDP traffic to TCP interface and vice versa)
    t110_p_tcp = binascii.hexlify(make_eth() + make_ipv4(proto=6) + make_tcp()).decode()
    t110_p_udp = binascii.hexlify(make_eth() + make_ipv4(proto=17) + make_udp()).decode()
    t110_p_icmp = binascii.hexlify(make_eth() + make_ipv4(proto=1) + make_icmp()).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_nrf_l2_proto_port_demux",
            application_category="network_routing_forwarding",
            difficulty="level_2",
            task_family="xdp_proto_demux",
            template_family="xdp_direct_redirect",
            semantic_signature="tcp_to_if2_udp_to_if3+redirect",
            diagnostic_category="behavioral_logic_bug",
            failure_reason="Behavioral bug: protocol demux logic inverted (redirected TCP to interface 3 and UDP to interface 2)",
            instruction="Fix the interface index mapping in the protocol demux filter so IPv4 TCP packets redirect to interface 2 and IPv4 UDP packets redirect to interface 3, passing other traffic with XDP_PASS.",
            requirements=[
                "Check Ethernet and IPv4 bounds",
                "Redirect TCP traffic to ifindex 2 (bpf_redirect(2, 0))",
                "Redirect UDP traffic to ifindex 3 (bpf_redirect(3, 0))",
                "Pass non-TCP/UDP traffic with XDP_PASS",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_forward(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // Behavioral bug: swapped ifindex assignments
    if (ip->protocol == IPPROTO_TCP) {
        return bpf_redirect(3, 0); // Should be 2
    } else if (ip->protocol == IPPROTO_UDP) {
        return bpf_redirect(2, 0); // Should be 3
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""FAIL: test_case 'demux_tcp_to_if2' failed:
  Expected redirect to ifindex 2
  Observed redirect to ifindex 3 (protocol demux interface mismatch)
1 of 3 test cases failed.""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_forward(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->protocol == IPPROTO_TCP) {
        return bpf_redirect(2, 0);
    } else if (ip->protocol == IPPROTO_UDP) {
        return bpf_redirect(3, 0);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_redirect_tcp", "description": "Redirect TCP to ifindex 2", "packet_hex": t110_p_tcp, "expected_action": "XDP_REDIRECT"},
                {"name": "pass_redirect_udp", "description": "Redirect UDP to ifindex 3", "packet_hex": t110_p_udp, "expected_action": "XDP_REDIRECT"},
                {"name": "pass_icmp", "description": "Pass ICMP with XDP_PASS", "packet_hex": t110_p_icmp, "expected_action": "XDP_PASS"},
            ],
            validator_type="packet_action",
        )
    )

    # =========================================================================
    # LEVEL 3 (10 tasks: 5 compilation, 3 verifier, 2 behavioral)
    # =========================================================================

    # 111. repair_nrf_l3_fib_lookup_router (compilation_error: missing struct bpf_fib_lookup definition)
    t111_p_tcp = binascii.hexlify(make_eth() + make_ipv4(src_ip="192.168.1.10", dst_ip="10.0.0.1") + make_tcp()).decode()
    t111_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_nrf_l3_fib_lookup_router",
            application_category="network_routing_forwarding",
            difficulty="level_3",
            task_family="xdp_fib_router",
            template_family="xdp_helper_router",
            semantic_signature="bpf_fib_lookup_forward+redirect",
            diagnostic_category="compilation_error",
            failure_reason="Compilation error: variable has incomplete type 'struct bpf_fib_lookup'",
            instruction="Fix the struct definition and parameters for bpf_fib_lookup. Use the kernel FIB helper to query the routing table, update layer-2 Ethernet addresses, decrement TTL, and redirect to fib_params.ifindex.",
            requirements=[
                "Define or include struct bpf_fib_lookup",
                "Populate family=AF_INET, ipv4_src, ipv4_dst, ifindex=ctx->ingress_ifindex",
                "Call bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0)",
                "If BPF_FIB_LKUP_RET_SUCCESS (0), rewrite MACs and redirect to fib_params.ifindex",
                "Return XDP_PASS if lookup fails or for non-IP frames",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_forward(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // Compilation error: struct bpf_fib_lookup incomplete
    struct bpf_fib_lookup fib_params = {0};
    fib_params.family = 2; // AF_INET
    fib_params.ipv4_src = ip->saddr;
    fib_params.ipv4_dst = ip->daddr;
    fib_params.ifindex = ctx->ingress_ifindex;

    int rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
    if (rc == 0) {
        #pragma unroll
        for (int i = 0; i < ETH_ALEN; i++) {
            eth->h_dest[i] = fib_params.dmac[i];
            eth->h_source[i] = fib_params.smac[i];
        }
        return bpf_redirect(fib_params.ifindex, 0);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""faulty.c:23:28: error: variable has incomplete type 'struct bpf_fib_lookup'
    struct bpf_fib_lookup fib_params = {0};
                          ^
faulty.c:23:12: note: forward declaration of 'struct bpf_fib_lookup'
1 error generated.""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct bpf_fib_lookup {
    __u8 family;
    __u8 l4_protocol;
    __be16 sport;
    __be16 dport;
    union {
        __u8 tos;
        __be32 flowinfo;
    };
    __u32 ifindex;
    union {
        __u8 dmac[6];
        __u16 dmac_u16[3];
    };
    union {
        __u8 smac[6];
        __u16 smac_u16[3];
    };
    union {
        __be32 ipv4_src;
        __u32 ipv6_src[4];
    };
    union {
        __be32 ipv4_dst;
        __u32 ipv6_dst[4];
    };
};

SEC("xdp")
int xdp_forward(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    struct bpf_fib_lookup fib_params = {0};
    fib_params.family = 2; // AF_INET
    fib_params.ipv4_src = ip->saddr;
    fib_params.ipv4_dst = ip->daddr;
    fib_params.ifindex = ctx->ingress_ifindex;

    int rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
    if (rc == 0) {
        #pragma unroll
        for (int i = 0; i < ETH_ALEN; i++) {
            eth->h_dest[i] = fib_params.dmac[i];
            eth->h_source[i] = fib_params.smac[i];
        }
        return bpf_redirect(fib_params.ifindex, 0);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_unresolved_fib", "description": "Pass unresolved FIB query with XDP_PASS", "packet_hex": t111_p_tcp, "expected_action": "XDP_PASS"},
                {"name": "pass_arp", "description": "Pass ARP frame unchanged", "packet_hex": t111_p_arp, "expected_action": "XDP_PASS"},
            ],
            validator_type="packet_action",
        )
    )

    # 112. repair_nrf_l3_policy_multihop_router (compilation_error: missing include <bpf/bpf_endian.h> causing implicit declaration)
    t112_p_tcp = binascii.hexlify(make_eth() + make_ipv4(src_ip="10.0.0.1", dst_ip="10.1.0.1", proto=6) + make_tcp(dst_port=80)).decode()
    t112_p_udp = binascii.hexlify(make_eth() + make_ipv4(src_ip="10.0.0.1", dst_ip="10.1.0.1", proto=17) + make_udp()).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_nrf_l3_policy_multihop_router",
            application_category="network_routing_forwarding",
            difficulty="level_3",
            task_family="xdp_policy_routing",
            template_family="xdp_devmap_router",
            semantic_signature="policy_routing_matrix+devmap_redirect",
            diagnostic_category="compilation_error",
            failure_reason="Compilation error: undefined identifier 'bpf_htons' due to missing <bpf/bpf_endian.h>",
            instruction="Fix the missing endian conversion include in the policy routing filter. Route matching source/dest policy flows through devmap interfaces, passing non-matching traffic with XDP_PASS.",
            requirements=[
                "Include <bpf/bpf_endian.h>",
                "Define policy_devmap DEVMAP with 4 entries",
                "Match 3-tuple policy (saddr prefix, daddr prefix, protocol)",
                "Redirect matching policy traffic to devmap slot; return XDP_PASS otherwise",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 4);
} policy_devmap SEC(".maps");

SEC("xdp")
int xdp_forward(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    // Missing <bpf/bpf_endian.h>
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->protocol == IPPROTO_TCP) {
        return bpf_redirect_map(&policy_devmap, 0, 0);
    } else if (ip->protocol == IPPROTO_UDP) {
        return bpf_redirect_map(&policy_devmap, 1, 0);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""faulty.c:20:25: error: call to undeclared function 'bpf_htons'; ISO C99 and later do not support implicit function declarations [-Wimplicit-function-declaration]
    if (eth->h_proto != bpf_htons(ETH_P_IP))
                        ^
1 error generated.""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 4);
} policy_devmap SEC(".maps");

SEC("xdp")
int xdp_forward(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->protocol == IPPROTO_TCP) {
        return bpf_redirect_map(&policy_devmap, 0, 0);
    } else if (ip->protocol == IPPROTO_UDP) {
        return bpf_redirect_map(&policy_devmap, 1, 0);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_policy_tcp", "description": "Redirect policy TCP traffic to devmap slot 0", "packet_hex": t112_p_tcp, "expected_action": "XDP_REDIRECT"},
                {"name": "pass_policy_udp", "description": "Redirect policy UDP traffic to devmap slot 1", "packet_hex": t112_p_udp, "expected_action": "XDP_REDIRECT"},
            ],
            validator_type="packet_action",
        )
    )

    # 113. repair_nrf_l3_ecmp_hash_load_balancer (compilation_error: undefined helper function name bpf_jhash)
    t113_p_tcp1 = binascii.hexlify(make_eth() + make_ipv4(src_ip="10.0.0.1", proto=6) + make_tcp(src_port=5000, dst_port=80)).decode()
    t113_p_tcp2 = binascii.hexlify(make_eth() + make_ipv4(src_ip="10.0.0.2", proto=6) + make_tcp(src_port=5001, dst_port=80)).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_nrf_l3_ecmp_hash_load_balancer",
            application_category="network_routing_forwarding",
            difficulty="level_3",
            task_family="xdp_ecmp_balancer",
            template_family="xdp_devmap_balancer",
            semantic_signature="ecmp_5tuple_hash_balance+redirect",
            diagnostic_category="compilation_error",
            failure_reason="Compilation error: call to undeclared function 'bpf_jhash' (using non-existent helper instead of inline hash or lookup)",
            instruction="Fix the hashing function in the ECMP load balancer. Compute an inline 5-tuple hash ((saddr ^ daddr ^ sport ^ dport ^ proto) & 3) and redirect through ecmp_devmap with 4 egress interfaces.",
            requirements=[
                "Define ecmp_devmap DEVMAP with 4 entries",
                "Extract 5-tuple fields safely",
                "Calculate backend slot: (saddr ^ daddr ^ sport ^ dport ^ proto) & 3",
                "Redirect through ecmp_devmap with bpf_redirect_map(&ecmp_devmap, slot, 0)",
                "Return XDP_PASS for non-IP traffic",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 4);
} ecmp_devmap SEC(".maps");

SEC("xdp")
int xdp_forward(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
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

    __u32 ip_len = (__u32)ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip_len;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    // Compilation error: bpf_jhash is not a valid BPF helper
    __u32 slot = bpf_jhash(ip->saddr, ip->daddr, tcp->source);
    return bpf_redirect_map(&ecmp_devmap, slot, 0);
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""faulty.c:40:18: error: call to undeclared function 'bpf_jhash'; ISO C99 and later do not support implicit function declarations [-Wimplicit-function-declaration]
    __u32 slot = bpf_jhash(ip->saddr, ip->daddr, tcp->source);
                 ^
1 error generated.""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 4);
} ecmp_devmap SEC(".maps");

SEC("xdp")
int xdp_forward(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
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

    __u32 ip_len = (__u32)ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip_len;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    __u32 slot = (ip->saddr ^ ip->daddr ^ tcp->source ^ tcp->dest) & 3;
    return bpf_redirect_map(&ecmp_devmap, slot, 0);
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_ecmp_flow1", "description": "Redirect flow 1 through ECMP devmap", "packet_hex": t113_p_tcp1, "expected_action": "XDP_REDIRECT"},
                {"name": "pass_ecmp_flow2", "description": "Redirect flow 2 through ECMP devmap", "packet_hex": t113_p_tcp2, "expected_action": "XDP_REDIRECT"},
            ],
            validator_type="packet_action",
        )
    )

    # 114. repair_nrf_l3_maglev_consistent_hash (compilation_error: array index out of bounds in lookup table definition)
    t114_p_tcp = binascii.hexlify(make_eth() + make_ipv4(src_ip="10.0.0.1", proto=6) + make_tcp(src_port=5000, dst_port=80)).decode()
    t114_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_nrf_l3_maglev_consistent_hash",
            application_category="network_routing_forwarding",
            difficulty="level_3",
            task_family="xdp_maglev_balancer",
            template_family="xdp_devmap_balancer",
            semantic_signature="maglev_lookup_table_redirect+redirect",
            diagnostic_category="compilation_error",
            failure_reason="Compilation error: variable has incomplete type 'struct maglev_lut' in map definition",
            instruction="Fix the Maglev lookup table map definition. Map 5-tuple flows through a 257-slot Maglev permutation array map to select one of two backend devmap targets, returning XDP_REDIRECT.",
            requirements=[
                "Define maglev_lut array map with 257 entries of __u32",
                "Define maglev_devmap DEVMAP with 2 entries",
                "Hash 5-tuple modulo 257 to query maglev_lut, then redirect via maglev_devmap",
                "Return XDP_PASS for non-IP traffic",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct maglev_entry); // Compilation error: struct maglev_entry undefined
    __uint(max_entries, 257);
} maglev_lut SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 2);
} maglev_devmap SEC(".maps");

SEC("xdp")
int xdp_forward(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
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

    __u32 ip_len = (__u32)ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip_len;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    __u32 hash = (ip->saddr ^ ip->daddr ^ tcp->source ^ tcp->dest) % 257;
    __u32 *backend = bpf_map_lookup_elem(&maglev_lut, &hash);
    if (backend) {
        __u32 b_idx = *backend & 1;
        return bpf_redirect_map(&maglev_devmap, b_idx, 0);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""faulty.c:12:19: error: variable has incomplete type 'struct maglev_entry'
    __type(value, struct maglev_entry);
                  ^
faulty.c:12:19: note: forward declaration of 'struct maglev_entry'
1 error generated.""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 257);
} maglev_lut SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 2);
} maglev_devmap SEC(".maps");

SEC("xdp")
int xdp_forward(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
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

    __u32 ip_len = (__u32)ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip_len;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    __u32 hash = (ip->saddr ^ ip->daddr ^ tcp->source ^ tcp->dest) % 257;
    __u32 *backend = bpf_map_lookup_elem(&maglev_lut, &hash);
    if (backend) {
        __u32 b_idx = *backend & 1;
        return bpf_redirect_map(&maglev_devmap, b_idx, 0);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_maglev_tcp", "description": "Redirect TCP flow via Maglev consistent hash table", "packet_hex": t114_p_tcp, "expected_action": "XDP_REDIRECT"},
                {"name": "pass_arp", "description": "Pass ARP frame unchanged", "packet_hex": t114_p_arp, "expected_action": "XDP_PASS"},
            ],
            validator_type="packet_action",
        )
    )

    # 115. repair_nrf_l3_vrf_table_forwarding (compilation_error: missing type cast when looking up VRF route)
    t115_p_vrf1 = binascii.hexlify(make_eth() + make_ipv4(src_ip="10.1.1.1", dst_ip="192.168.1.1") + make_tcp()).decode()
    t115_p_vrf2 = binascii.hexlify(make_eth() + make_ipv4(src_ip="10.2.2.2", dst_ip="192.168.1.1") + make_tcp()).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_nrf_l3_vrf_table_forwarding",
            application_category="network_routing_forwarding",
            difficulty="level_3",
            task_family="xdp_vrf_routing",
            template_family="xdp_map_redirect",
            semantic_signature="vrf_id_and_dst_ip_routing+redirect",
            diagnostic_category="compilation_error",
            failure_reason="Compilation error: struct vrf_key definition missing vrf_id field causing member access failure",
            instruction="Fix the VRF routing key struct definition. Match the compound key (VRF ID from ingress interface + destination IP) in vrf_routes and redirect to the returned interface, returning XDP_PASS on miss.",
            requirements=[
                "Define struct vrf_key with vrf_id (__u32) and dst_ip (__u32)",
                "Define vrf_routes hash map",
                "Lookup (ingress_ifindex, ip->daddr) in vrf_routes",
                "Redirect if route found; return XDP_PASS otherwise",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct vrf_key {
    __u32 dst_ip;
    // Compilation error: missing vrf_id field
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct vrf_key);
    __type(value, __u32);
    __uint(max_entries, 1024);
} vrf_routes SEC(".maps");

SEC("xdp")
int xdp_forward(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    struct vrf_key key = {
        .vrf_id = ctx->ingress_ifindex, // Compilation error: no member named 'vrf_id'
        .dst_ip = ip->daddr,
    };

    __u32 *egress = bpf_map_lookup_elem(&vrf_routes, &key);
    if (egress)
        return bpf_redirect(*egress, 0);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""faulty.c:35:10: error: no member named 'vrf_id' in 'struct vrf_key'
        .vrf_id = ctx->ingress_ifindex,
        ~^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
1 error generated.""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct vrf_key {
    __u32 vrf_id;
    __u32 dst_ip;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct vrf_key);
    __type(value, __u32);
    __uint(max_entries, 1024);
} vrf_routes SEC(".maps");

SEC("xdp")
int xdp_forward(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    struct vrf_key key = {
        .vrf_id = ctx->ingress_ifindex,
        .dst_ip = ip->daddr,
    };

    __u32 *egress = bpf_map_lookup_elem(&vrf_routes, &key);
    if (egress)
        return bpf_redirect(*egress, 0);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_unmatched_vrf1", "description": "Pass unmapped VRF 1 destination with XDP_PASS", "packet_hex": t115_p_vrf1, "expected_action": "XDP_PASS"},
                {"name": "pass_unmatched_vrf2", "description": "Pass unmapped VRF 2 destination with XDP_PASS", "packet_hex": t115_p_vrf2, "expected_action": "XDP_PASS"},
            ],
            validator_type="packet_action",
        )
    )

    # 116. repair_nrf_l3_fib_nexthop_update (verifier_rejection: bpf_fib_lookup params struct allocated on stack with uninitialized fields)
    t116_p_tcp = binascii.hexlify(make_eth() + make_ipv4(src_ip="192.168.1.10", dst_ip="10.0.0.1") + make_tcp()).decode()
    t116_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_nrf_l3_fib_nexthop_update",
            application_category="network_routing_forwarding",
            difficulty="level_3",
            task_family="xdp_fib_router",
            template_family="xdp_helper_router",
            semantic_signature="fib_lookup_full_init+redirect",
            diagnostic_category="verifier_rejection",
            failure_reason="Kernel verifier rejection: passing partially uninitialized struct bpf_fib_lookup on stack to bpf_fib_lookup helper",
            instruction="Fix the verifier rejection by zero-initializing the entire struct bpf_fib_lookup before calling bpf_fib_lookup. Rewrite layer-2 addresses and redirect on BPF_FIB_LKUP_RET_SUCCESS.",
            requirements=[
                "Zero-initialize struct bpf_fib_lookup fib_params = {0}",
                "Populate family, ipv4_src, ipv4_dst, ifindex",
                "Call bpf_fib_lookup and verify return code == 0",
                "Rewrite Ethernet source and destination MACs",
                "Return bpf_redirect(fib_params.ifindex, 0)",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct bpf_fib_lookup {
    __u8 family;
    __u8 l4_protocol;
    __be16 sport;
    __be16 dport;
    union {
        __u8 tos;
        __be32 flowinfo;
    };
    __u32 ifindex;
    union {
        __u8 dmac[6];
        __u16 dmac_u16[3];
    };
    union {
        __u8 smac[6];
        __u16 smac_u16[3];
    };
    union {
        __be32 ipv4_src;
        __u32 ipv6_src[4];
    };
    union {
        __be32 ipv4_dst;
        __u32 ipv6_dst[4];
    };
};

SEC("xdp")
int xdp_forward(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // Verifier error: fib_params has uninitialized fields on stack
    struct bpf_fib_lookup fib_params;
    fib_params.family = 2;
    fib_params.ipv4_src = ip->saddr;
    fib_params.ipv4_dst = ip->daddr;
    fib_params.ifindex = ctx->ingress_ifindex;

    int rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
    if (rc == 0) {
        #pragma unroll
        for (int i = 0; i < ETH_ALEN; i++) {
            eth->h_dest[i] = fib_params.dmac[i];
            eth->h_source[i] = fib_params.smac[i];
        }
        return bpf_redirect(fib_params.ifindex, 0);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""0: R1=ctx(off=0,imm=0) R10=fp0
...
16: (bf) r2 = r10
17: (07) r2 += -64
; int rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
18: (85) call bpf_fib_lookup#88
invalid indirect read from stack R2 off -64+2 size 2 (uninitialized field sport/dport)
processed 19 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
-- END PROG LOAD LOG --""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct bpf_fib_lookup {
    __u8 family;
    __u8 l4_protocol;
    __be16 sport;
    __be16 dport;
    union {
        __u8 tos;
        __be32 flowinfo;
    };
    __u32 ifindex;
    union {
        __u8 dmac[6];
        __u16 dmac_u16[3];
    };
    union {
        __u8 smac[6];
        __u16 smac_u16[3];
    };
    union {
        __be32 ipv4_src;
        __u32 ipv6_src[4];
    };
    union {
        __be32 ipv4_dst;
        __u32 ipv6_dst[4];
    };
};

SEC("xdp")
int xdp_forward(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    struct bpf_fib_lookup fib_params = {0};
    fib_params.family = 2;
    fib_params.ipv4_src = ip->saddr;
    fib_params.ipv4_dst = ip->daddr;
    fib_params.ifindex = ctx->ingress_ifindex;

    int rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
    if (rc == 0) {
        #pragma unroll
        for (int i = 0; i < ETH_ALEN; i++) {
            eth->h_dest[i] = fib_params.dmac[i];
            eth->h_source[i] = fib_params.smac[i];
        }
        return bpf_redirect(fib_params.ifindex, 0);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_unresolved_fib", "description": "Pass unresolved FIB query with XDP_PASS", "packet_hex": t116_p_tcp, "expected_action": "XDP_PASS"},
                {"name": "pass_arp", "description": "Pass ARP frame with XDP_PASS", "packet_hex": t116_p_arp, "expected_action": "XDP_PASS"},
            ],
            validator_type="packet_action",
        )
    )

    # 117. repair_nrf_l3_flow_affinity_table (verifier_rejection: unbounded loop for table lookup)
    t117_p_tcp = binascii.hexlify(make_eth() + make_ipv4(src_ip="10.0.0.1", proto=6) + make_tcp(src_port=1000, dst_port=80)).decode()
    t117_p_udp = binascii.hexlify(make_eth() + make_ipv4(src_ip="10.0.0.2", proto=17) + make_udp()).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_nrf_l3_flow_affinity_table",
            application_category="network_routing_forwarding",
            difficulty="level_3",
            task_family="xdp_flow_affinity",
            template_family="xdp_map_redirect",
            semantic_signature="flow_affinity_table_redirect+redirect",
            diagnostic_category="verifier_rejection",
            failure_reason="Kernel verifier rejection: unbounded while loop searching flow affinity table",
            instruction="Fix the verifier loop rejection by unrolling the affinity table linear scan (#pragma unroll max 4 iterations). Redirect to the affinity backend if found, or default to backend 0.",
            requirements=[
                "Scan flow affinity slots with bounded loop (max 4 iterations)",
                "Define affinity_devmap DEVMAP with 4 entries",
                "Redirect matching flow to assigned devmap slot",
                "Return XDP_PASS on non-IP traffic",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 4);
} affinity_devmap SEC(".maps");

SEC("xdp")
int xdp_forward(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u32 src = ip->saddr;
    __u32 i = 0;
    // Verifier error: unbounded while loop
    while (i < (src & 3)) {
        i++;
    }

    return bpf_redirect_map(&affinity_devmap, i & 3, 0);
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""0: R1=ctx(off=0,imm=0) R10=fp0
...
10: (2d) if r3 >= r4 goto pc+5
11: (07) r3 += 1
back-edge from insn 11 to 10
processed 12 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
-- END PROG LOAD LOG --""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 4);
} affinity_devmap SEC(".maps");

SEC("xdp")
int xdp_forward(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u32 slot = ip->saddr & 3;
    return bpf_redirect_map(&affinity_devmap, slot, 0);
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_affinity_tcp", "description": "Redirect TCP flow via affinity devmap", "packet_hex": t117_p_tcp, "expected_action": "XDP_REDIRECT"},
                {"name": "pass_affinity_udp", "description": "Redirect UDP flow via affinity devmap", "packet_hex": t117_p_udp, "expected_action": "XDP_REDIRECT"},
            ],
            validator_type="packet_action",
        )
    )

    # 118. repair_nrf_l3_dynamic_devmap_xmit (verifier_rejection: map value pointer arithmetic without bounds proof)
    t118_p_tcp = binascii.hexlify(make_eth() + make_ipv4(src_ip="10.0.0.1", proto=6) + make_tcp()).decode()
    t118_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_nrf_l3_dynamic_devmap_xmit",
            application_category="network_routing_forwarding",
            difficulty="level_3",
            task_family="xdp_dynamic_devmap",
            template_family="xdp_devmap_router",
            semantic_signature="dynamic_devmap_egress_select+redirect",
            diagnostic_category="verifier_rejection",
            failure_reason="Kernel verifier rejection: variable offset access into map value memory",
            instruction="Fix the map value pointer dereference in the dynamic egress forwarder. Lookup source IP in egress_table, extract egress ifindex directly, and redirect through devmap.",
            requirements=[
                "Define egress_table hash map with __u32 value",
                "Define tx_ports DEVMAP with 4 entries",
                "Safely read egress port and redirect via bpf_redirect_map(&tx_ports, egress, 0)",
                "Return XDP_PASS on route miss",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 256);
} egress_table SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 4);
} tx_ports SEC(".maps");

SEC("xdp")
int xdp_forward(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u32 src = ip->saddr;
    __u32 *val = bpf_map_lookup_elem(&egress_table, &src);
    if (val) {
        // Verifier error: pointer arithmetic on map value
        __u32 *offset_p = (__u32 *)((void *)val + (src & 3));
        __u32 port = *offset_p & 3;
        return bpf_redirect_map(&tx_ports, port, 0);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""0: R1=ctx(off=0,imm=0) R10=fp0
...
16: (85) call bpf_map_lookup_elem#1
17: R0=map_value_or_null(id=1,off=0,r=4,imm=0)
18: (15) if r0 == 0x0 goto pc+8
; __u32 *offset_p = (__u32 *)((void *)val + (src & 3));
19: (0f) r0 += r6
variable offset access into map_value prohibited
processed 20 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
-- END PROG LOAD LOG --""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 256);
} egress_table SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 4);
} tx_ports SEC(".maps");

SEC("xdp")
int xdp_forward(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u32 src = ip->saddr;
    __u32 *val = bpf_map_lookup_elem(&egress_table, &src);
    if (val) {
        __u32 port = *val & 3;
        return bpf_redirect_map(&tx_ports, port, 0);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_unmatched", "description": "Pass route lookup miss with XDP_PASS", "packet_hex": t118_p_tcp, "expected_action": "XDP_PASS"},
                {"name": "pass_arp", "description": "Pass ARP frame unchanged", "packet_hex": t118_p_arp, "expected_action": "XDP_PASS"},
            ],
            validator_type="packet_action",
        )
    )

    # 119. repair_nrf_l3_fib_ttl_decrement (behavioral_logic_bug: failing to decrement TTL or recalculate IP checksum when FIB lookup succeeds)
    t119_p_in = binascii.hexlify(make_eth() + make_ipv4(src_ip="192.168.1.10", dst_ip="10.0.0.1", ttl=64) + make_tcp()).decode()
    t119_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_nrf_l3_fib_ttl_decrement",
            application_category="network_routing_forwarding",
            difficulty="level_3",
            task_family="xdp_fib_router",
            template_family="xdp_helper_router",
            semantic_signature="fib_router_with_ttl_decrement+redirect",
            diagnostic_category="behavioral_logic_bug",
            failure_reason="Behavioral bug: forwarded packet without decrementing TTL or updating IPv4 header checksum",
            instruction="Fix the IP header modification in the FIB routing filter. Decrement ip->ttl by 1, update the IPv4 checksum, rewrite MAC addresses, and redirect to the FIB egress.",
            requirements=[
                "Check Ethernet and IPv4 bounds",
                "On FIB resolution success (rc == 0), decrement ip->ttl and update ip->check",
                "Rewrite Ethernet source and destination MACs from FIB result",
                "Return bpf_redirect(fib_params.ifindex, 0)",
                "Return XDP_PASS if lookup fails",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct bpf_fib_lookup {
    __u8 family;
    __u8 l4_protocol;
    __be16 sport;
    __be16 dport;
    union {
        __u8 tos;
        __be32 flowinfo;
    };
    __u32 ifindex;
    union {
        __u8 dmac[6];
        __u16 dmac_u16[3];
    };
    union {
        __u8 smac[6];
        __u16 smac_u16[3];
    };
    union {
        __be32 ipv4_src;
        __u32 ipv6_src[4];
    };
    union {
        __be32 ipv4_dst;
        __u32 ipv6_dst[4];
    };
};

SEC("xdp")
int xdp_forward(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    struct bpf_fib_lookup fib_params = {0};
    fib_params.family = 2;
    fib_params.ipv4_src = ip->saddr;
    fib_params.ipv4_dst = ip->daddr;
    fib_params.ifindex = ctx->ingress_ifindex;

    int rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
    if (rc == 0) {
        // Behavioral bug: missing TTL decrement and checksum update
        #pragma unroll
        for (int i = 0; i < ETH_ALEN; i++) {
            eth->h_dest[i] = fib_params.dmac[i];
            eth->h_source[i] = fib_params.smac[i];
        }
        return bpf_redirect(fib_params.ifindex, 0);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""FAIL: test_case 'verify_ttl_decrement_on_forward' failed:
  Expected IPv4 TTL: 63, IPv4 checksum updated
  Observed IPv4 TTL: 64 (forwarded without standard layer-3 TTL decrement)
1 of 2 test cases failed.""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct bpf_fib_lookup {
    __u8 family;
    __u8 l4_protocol;
    __be16 sport;
    __be16 dport;
    union {
        __u8 tos;
        __be32 flowinfo;
    };
    __u32 ifindex;
    union {
        __u8 dmac[6];
        __u16 dmac_u16[3];
    };
    union {
        __u8 smac[6];
        __u16 smac_u16[3];
    };
    union {
        __be32 ipv4_src;
        __u32 ipv6_src[4];
    };
    union {
        __be32 ipv4_dst;
        __u32 ipv6_dst[4];
    };
};

SEC("xdp")
int xdp_forward(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->ttl <= 1)
        return XDP_DROP;

    struct bpf_fib_lookup fib_params = {0};
    fib_params.family = 2;
    fib_params.ipv4_src = ip->saddr;
    fib_params.ipv4_dst = ip->daddr;
    fib_params.ifindex = ctx->ingress_ifindex;

    int rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
    if (rc == 0) {
        ip->ttl -= 1;
        __u32 csum = bpf_ntohs(ip->check);
        csum += 0x0100;
        if (csum > 0xFFFF)
            csum = (csum & 0xFFFF) + (csum >> 16);
        ip->check = bpf_htons((__u16)csum);

        #pragma unroll
        for (int i = 0; i < ETH_ALEN; i++) {
            eth->h_dest[i] = fib_params.dmac[i];
            eth->h_source[i] = fib_params.smac[i];
        }
        return bpf_redirect(fib_params.ifindex, 0);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_unresolved", "description": "Pass unresolvable FIB query with XDP_PASS", "packet_hex": t119_p_in, "expected_action": "XDP_PASS"},
                {"name": "pass_arp", "description": "Pass ARP frame unchanged", "packet_hex": t119_p_arp, "expected_action": "XDP_PASS"},
            ],
            validator_type="packet_action",
        )
    )

    # 120. repair_nrf_l3_ecmp_weight_distribution (behavioral_logic_bug: modulo bias bug in hash backend selection)
    t120_p_tcp1 = binascii.hexlify(make_eth() + make_ipv4(src_ip="10.0.0.1", proto=6) + make_tcp(src_port=5000, dst_port=80)).decode()
    t120_p_tcp2 = binascii.hexlify(make_eth() + make_ipv4(src_ip="10.0.0.2", proto=6) + make_tcp(src_port=5001, dst_port=80)).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_nrf_l3_ecmp_weight_distribution",
            application_category="network_routing_forwarding",
            difficulty="level_3",
            task_family="xdp_ecmp_balancer",
            template_family="xdp_devmap_balancer",
            semantic_signature="ecmp_2backend_balanced_redirect+redirect",
            diagnostic_category="behavioral_logic_bug",
            failure_reason="Behavioral bug: modulo calculation (hash % 3) produced out-of-range backend slot 2 when only 2 backends (slots 0 and 1) were configured",
            instruction="Fix the modulo backend selection in the 2-way ECMP load balancer so flows are uniformly distributed between backends 0 and 1 (hash & 1). Redirect via ecmp_devmap.",
            requirements=[
                "Define ecmp_devmap DEVMAP with 2 entries",
                "Compute 5-tuple hash and select backend using (hash & 1)",
                "Redirect via bpf_redirect_map(&ecmp_devmap, slot, 0)",
                "Return XDP_PASS for non-TCP traffic",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 2);
} ecmp_devmap SEC(".maps");

SEC("xdp")
int xdp_forward(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
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

    __u32 ip_len = (__u32)ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip_len;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    __u32 hash = (ip->saddr ^ ip->daddr ^ tcp->source ^ tcp->dest);
    // Behavioral bug: modulo 3 on 2-entry devmap produces invalid key 2
    __u32 slot = hash % 3;

    return bpf_redirect_map(&ecmp_devmap, slot, 0);
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""FAIL: test_case 'flow_distribution_2_backends' failed:
  Expected backend slot in {0, 1}
  Observed backend slot = 2 (out of range key for 2-element devmap)
1 of 2 test cases failed.""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 2);
} ecmp_devmap SEC(".maps");

SEC("xdp")
int xdp_forward(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
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

    __u32 ip_len = (__u32)ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip_len;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    __u32 hash = (ip->saddr ^ ip->daddr ^ tcp->source ^ tcp->dest);
    __u32 slot = hash & 1;

    return bpf_redirect_map(&ecmp_devmap, slot, 0);
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_ecmp_flow1", "description": "Redirect flow 1 through 2-entry ECMP devmap", "packet_hex": t120_p_tcp1, "expected_action": "XDP_REDIRECT"},
                {"name": "pass_ecmp_flow2", "description": "Redirect flow 2 through 2-entry ECMP devmap", "packet_hex": t120_p_tcp2, "expected_action": "XDP_REDIRECT"},
            ],
            validator_type="packet_action",
        )
    )

    return tasks
