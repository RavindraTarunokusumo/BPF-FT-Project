#!/usr/bin/env python3
"""
Task definitions for protocol_transformation (30 tasks).
Distribution:
- Level 1: 4 compilation, 4 verifier, 2 behavioral (10)
- Level 2: 4 compilation, 4 verifier, 2 behavioral (10)
- Level 3: 4 compilation, 3 verifier, 3 behavioral (10)
Total: 12 compilation, 11 verifier, 7 behavioral = 30 tasks.
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


def get_transform_tasks() -> List[RepairTaskSpec]:
    tasks: List[RepairTaskSpec] = []

    # =========================================================================
    # LEVEL 1 (10 tasks: 4 compilation, 4 verifier, 2 behavioral)
    # =========================================================================

    # 61. repair_ptr_l1_swap_eth_mac (compilation_error: assignment of array constant in MAC address swap)
    t61_p_in = binascii.hexlify(make_eth(dst_mac="52:54:00:12:34:56", src_mac="52:54:00:65:43:21") + make_ipv4() + make_tcp()).decode()
    t61_p_arp = binascii.hexlify(make_eth(dst_mac="52:54:00:12:34:56", src_mac="52:54:00:65:43:21", eth_type=0x0806) + make_arp()).decode()
    t61_p_trunc = binascii.hexlify(make_eth()[:10]).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_ptr_l1_swap_eth_mac",
            application_category="protocol_transformation",
            difficulty="level_1",
            task_family="xdp_mac_swap",
            template_family="xdp_stateless_rewrite",
            semantic_signature="swap_eth_mac_addresses+pass",
            diagnostic_category="compilation_error",
            failure_reason="Compilation error: array assignment not supported in C (eth->h_dest = eth->h_source)",
            instruction="Fix the array assignment in the MAC swap program. Use byte-by-byte copies or a temporary array with memcpy/pointers to swap the Ethernet source and destination MAC addresses, returning XDP_PASS.",
            requirements=[
                "Check Ethernet header bounds",
                "Swap 6-byte Ethernet source and destination MAC addresses",
                "Preserve all other packet payload and headers",
                "Return XDP_PASS for valid and malformed traffic",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_transform(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Compilation error: array assignment is not assignable in C
    __u8 tmp[ETH_ALEN];
    tmp = eth->h_dest;
    eth->h_dest = eth->h_source;
    eth->h_source = tmp;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""faulty.c:16:9: error: array type '__u8[6]' is not assignable
    tmp = eth->h_dest;
    ~~~ ^
faulty.c:17:17: error: array type 'unsigned char[6]' is not assignable
    eth->h_dest = eth->h_source;
    ~~~~~~~~~~~ ^
faulty.c:18:19: error: array type 'unsigned char[6]' is not assignable
    eth->h_source = tmp;
    ~~~~~~~~~~~~~ ^
3 errors generated.""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_transform(struct xdp_md *ctx) {
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

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_swap_tcp", "description": "Swap Ethernet MAC addresses on TCP packet", "packet_hex": t61_p_in, "expected_action": "XDP_PASS"},
                {"name": "pass_swap_arp", "description": "Swap Ethernet MAC addresses on ARP frame", "packet_hex": t61_p_arp, "expected_action": "XDP_PASS"},
                {"name": "pass_trunc", "description": "Pass truncated packet unchanged", "packet_hex": t61_p_trunc, "expected_action": "XDP_PASS"},
            ],
            validator_type="packet_bytes",
        )
    )

    # 62. repair_ptr_l1_rewrite_dst_mac (compilation_error: assignment of array literal constant in C)
    t62_p_tcp = binascii.hexlify(make_eth(dst_mac="11:22:33:44:55:66") + make_ipv4() + make_tcp()).decode()
    t62_p_udp = binascii.hexlify(make_eth(dst_mac="11:22:33:44:55:66") + make_ipv4() + make_udp()).decode()
    t62_p_trunc = binascii.hexlify(make_eth()[:10]).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_ptr_l1_rewrite_dst_mac",
            application_category="protocol_transformation",
            difficulty="level_1",
            task_family="xdp_mac_rewrite",
            template_family="xdp_stateless_rewrite",
            semantic_signature="set_dst_mac_020000000099+pass",
            diagnostic_category="compilation_error",
            failure_reason="Compilation error: array compound literal assignment not allowed in C",
            instruction="Fix the destination MAC assignment in the XDP transformation program to rewrite the Ethernet destination address to 02:00:00:00:00:99 while preserving source MAC and payload, returning XDP_PASS.",
            requirements=[
                "Check Ethernet header bounds",
                "Rewrite eth->h_dest to 02:00:00:00:00:99",
                "Preserve source MAC, EtherType, and packet payload",
                "Return XDP_PASS for all traffic",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_transform(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Compilation error: compound array assignment
    eth->h_dest = (__u8[6]){0x02, 0x00, 0x00, 0x00, 0x00, 0x99};

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""faulty.c:15:17: error: array type 'unsigned char[6]' is not assignable
    eth->h_dest = (__u8[6]){0x02, 0x00, 0x00, 0x00, 0x00, 0x99};
    ~~~~~~~~~~~ ^
1 error generated.""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_transform(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    eth->h_dest[0] = 0x02;
    eth->h_dest[1] = 0x00;
    eth->h_dest[2] = 0x00;
    eth->h_dest[3] = 0x00;
    eth->h_dest[4] = 0x00;
    eth->h_dest[5] = 0x99;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_rewrite_tcp", "description": "Rewrite destination MAC on TCP packet", "packet_hex": t62_p_tcp, "expected_action": "XDP_PASS"},
                {"name": "pass_rewrite_udp", "description": "Rewrite destination MAC on UDP packet", "packet_hex": t62_p_udp, "expected_action": "XDP_PASS"},
                {"name": "pass_trunc", "description": "Pass truncated packet safely", "packet_hex": t62_p_trunc, "expected_action": "XDP_PASS"},
            ],
            validator_type="packet_bytes",
        )
    )

    # 63. repair_ptr_l1_rewrite_src_mac (compilation_error: missing ETH_ALEN constant / missing include)
    t63_p_tcp = binascii.hexlify(make_eth(src_mac="11:22:33:44:55:66") + make_ipv4() + make_tcp()).decode()
    t63_p_udp = binascii.hexlify(make_eth(src_mac="11:22:33:44:55:66") + make_ipv4() + make_udp()).decode()
    t63_p_trunc = binascii.hexlify(make_eth()[:10]).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_ptr_l1_rewrite_src_mac",
            application_category="protocol_transformation",
            difficulty="level_1",
            task_family="xdp_mac_rewrite",
            template_family="xdp_stateless_rewrite",
            semantic_signature="set_src_mac_020000000042+pass",
            diagnostic_category="compilation_error",
            failure_reason="Compilation error: undeclared identifier 'ETH_ALEN' due to missing include <linux/if_ether.h>",
            instruction="Fix the missing include in the source MAC transformation program to replace the source MAC address with 02:00:00:00:00:42 while preserving destination MAC and payload, returning XDP_PASS.",
            requirements=[
                "Include <linux/if_ether.h>",
                "Check Ethernet header bounds",
                "Rewrite eth->h_source to 02:00:00:00:00:42",
                "Return XDP_PASS for all traffic",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_transform(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u8 new_src[ETH_ALEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x42};
    #pragma unroll
    for (int i = 0; i < ETH_ALEN; i++) {
        eth->h_source[i] = new_src[i];
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""faulty.c:8:12: error: variable has incomplete type 'struct ethhdr'
    struct ethhdr *eth = data;
           ^
faulty.c:8:12: note: forward declaration of 'struct ethhdr'
faulty.c:12:18: error: use of undeclared identifier 'ETH_ALEN'
    __u8 new_src[ETH_ALEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x42};
                 ^
2 errors generated.""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_transform(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u8 new_src[ETH_ALEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x42};
    #pragma unroll
    for (int i = 0; i < ETH_ALEN; i++) {
        eth->h_source[i] = new_src[i];
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_rewrite_tcp", "description": "Rewrite source MAC on TCP packet", "packet_hex": t63_p_tcp, "expected_action": "XDP_PASS"},
                {"name": "pass_rewrite_udp", "description": "Rewrite source MAC on UDP packet", "packet_hex": t63_p_udp, "expected_action": "XDP_PASS"},
                {"name": "pass_trunc", "description": "Pass truncated frame safely", "packet_hex": t63_p_trunc, "expected_action": "XDP_PASS"},
            ],
            validator_type="packet_bytes",
        )
    )

    # 64. repair_ptr_l1_set_vlan_prio (compilation_error: invalid struct member vlan->prio instead of vlan->h_vlan_TCI)
    t64_p_vlan = binascii.hexlify(make_eth(vlan=100) + make_ipv4() + make_tcp()).decode()
    t64_p_untag = binascii.hexlify(make_eth() + make_ipv4() + make_tcp()).decode()
    t64_p_trunc = binascii.hexlify(make_eth(vlan=100)[:14]).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_ptr_l1_set_vlan_prio",
            application_category="protocol_transformation",
            difficulty="level_1",
            task_family="xdp_vlan_rewrite",
            template_family="xdp_stateless_rewrite",
            semantic_signature="vlan_prio_set_highest_7+pass",
            diagnostic_category="compilation_error",
            failure_reason="Compilation error: member access into struct vlan_hdr with non-existent field 'prio'",
            instruction="Fix the VLAN priority update in the XDP transformation program to set 802.1p priority to 7 (highest priority) in the VLAN tag TCI (top 3 bits of h_vlan_TCI) while preserving VID and CFI.",
            requirements=[
                "Check Ethernet and VLAN header bounds",
                "Verify eth->h_proto is ETH_P_8021Q",
                "Set top 3 bits of h_vlan_TCI to 7: (tci & 0x1FFF) | (7 << 13)",
                "Preserve payload and return XDP_PASS",
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
int xdp_transform(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto == bpf_htons(ETH_P_8021Q)) {
        struct vlan_hdr *vlh = (void *)(eth + 1);
        if ((void *)(vlh + 1) > data_end)
            return XDP_PASS;
        // Compilation error: struct vlan_hdr has no member named 'prio'
        vlh->prio = 7;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""faulty.c:23:14: error: no member named 'prio' in 'struct vlan_hdr'
        vlh->prio = 7;
        ~~~  ^
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
int xdp_transform(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto == bpf_htons(ETH_P_8021Q)) {
        struct vlan_hdr *vlh = (void *)(eth + 1);
        if ((void *)(vlh + 1) > data_end)
            return XDP_PASS;
        __u16 tci = bpf_ntohs(vlh->h_vlan_TCI);
        tci = (tci & 0x1FFF) | (7 << 13);
        vlh->h_vlan_TCI = bpf_htons(tci);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_set_prio_vlan", "description": "Set 802.1p priority to 7 on VLAN tag", "packet_hex": t64_p_vlan, "expected_action": "XDP_PASS"},
                {"name": "pass_untagged", "description": "Pass untagged frame unchanged", "packet_hex": t64_p_untag, "expected_action": "XDP_PASS"},
                {"name": "pass_trunc", "description": "Pass truncated VLAN header safely", "packet_hex": t64_p_trunc, "expected_action": "XDP_PASS"},
            ],
            validator_type="packet_bytes",
        )
    )

    # 65. repair_ptr_l1_clear_tos_byte (verifier_rejection: packet pointer modified without re-validating data bounds)
    t65_p_tos = binascii.hexlify(make_eth() + make_ipv4(tos=0xB8) + make_tcp()).decode()
    t65_p_untouched = binascii.hexlify(make_eth() + make_ipv4(tos=0x00) + make_tcp()).decode()
    t65_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_ptr_l1_clear_tos_byte",
            application_category="protocol_transformation",
            difficulty="level_1",
            task_family="xdp_tos_rewrite",
            template_family="xdp_stateless_rewrite",
            semantic_signature="clear_tos_and_update_csum+pass",
            diagnostic_category="verifier_rejection",
            failure_reason="Kernel verifier rejection: modifying ip->tos and ip->check without verifying ip + 1 <= data_end",
            instruction="Fix the verifier bounds check so the transformation program safely clears the IPv4 TOS byte to 0 and recalculates the IPv4 header checksum.",
            requirements=[
                "Check Ethernet and IPv4 bounds (ip + 1 <= data_end)",
                "Clear ip->tos to 0",
                "Update IPv4 header checksum correctly",
                "Return XDP_PASS for all traffic",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_transform(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    // Verifier error: missing (ip + 1 <= data_end) check before write
    ip->tos = 0;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""0: R1=ctx(off=0,imm=0) R10=fp0
...
6: (73) *(u8 *)(r2 +15) = r0
invalid access to packet, id=0, off=15, size=1, R2_w=pkt(off=0,r=14,imm=0)
processed 7 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
-- END PROG LOAD LOG --""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_transform(struct xdp_md *ctx) {
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

    __u8 old_tos = ip->tos;
    ip->tos = 0;

    // Incremental checksum update for TOS byte
    __u32 csum = bpf_ntohs(ip->check);
    csum += old_tos;
    if (csum > 0xFFFF)
        csum = (csum & 0xFFFF) + (csum >> 16);
    ip->check = bpf_htons((__u16)csum);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_clear_tos", "description": "Clear TOS byte and update checksum", "packet_hex": t65_p_tos, "expected_action": "XDP_PASS"},
                {"name": "pass_zero_tos", "description": "Pass packet already having zero TOS", "packet_hex": t65_p_untouched, "expected_action": "XDP_PASS"},
                {"name": "pass_arp", "description": "Pass ARP frame unchanged", "packet_hex": t65_p_arp, "expected_action": "XDP_PASS"},
            ],
            validator_type="packet_bytes",
        )
    )

    # 66. repair_ptr_l1_swap_ip_endpoints (verifier_rejection: invalid memory access when writing ip->saddr without bounds check)
    t66_p_tcp = binascii.hexlify(make_eth() + make_ipv4(src_ip="192.168.1.10", dst_ip="192.168.1.20") + make_tcp()).decode()
    t66_p_udp = binascii.hexlify(make_eth() + make_ipv4(src_ip="10.0.0.1", dst_ip="10.0.0.2") + make_udp()).decode()
    t66_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_ptr_l1_swap_ip_endpoints",
            application_category="protocol_transformation",
            difficulty="level_1",
            task_family="xdp_ip_swap",
            template_family="xdp_stateless_rewrite",
            semantic_signature="swap_ip_src_dst+pass",
            diagnostic_category="verifier_rejection",
            failure_reason="Kernel verifier rejection: packet write past data boundary due to missing ip bounds check",
            instruction="Fix the verifier rejection by checking that the IPv4 header is completely within packet bounds before swapping source and destination IP addresses. Return XDP_PASS.",
            requirements=[
                "Check Ethernet and IPv4 bounds",
                "Swap ip->saddr and ip->daddr",
                "IPv4 header checksum is invariant under endpoint swap (sum of addresses is identical)",
                "Return XDP_PASS for all traffic",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_transform(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    // Verifier error: missing (ip + 1 <= data_end) check before modifying IP
    __be32 tmp = ip->saddr;
    ip->saddr = ip->daddr;
    ip->daddr = tmp;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""0: R1=ctx(off=0,imm=0) R10=fp0
...
6: (61) r3 = *(u32 *)(r2 +26)
invalid access to packet, id=0, off=26, size=4, R2_w=pkt(off=0,r=14,imm=0)
processed 7 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
-- END PROG LOAD LOG --""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_transform(struct xdp_md *ctx) {
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

    __be32 tmp = ip->saddr;
    ip->saddr = ip->daddr;
    ip->daddr = tmp;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_swap_tcp", "description": "Swap IP endpoints on TCP packet", "packet_hex": t66_p_tcp, "expected_action": "XDP_PASS"},
                {"name": "pass_swap_udp", "description": "Swap IP endpoints on UDP packet", "packet_hex": t66_p_udp, "expected_action": "XDP_PASS"},
                {"name": "pass_arp", "description": "Pass ARP frame unchanged", "packet_hex": t66_p_arp, "expected_action": "XDP_PASS"},
            ],
            validator_type="packet_bytes",
        )
    )

    # 67. repair_ptr_l1_strip_outer_vlan (verifier_rejection: bpf_xdp_adjust_head called and subsequent pointers dereferenced without recalculating ctx->data)
    t67_p_vlan = binascii.hexlify(make_eth(vlan=100) + make_ipv4() + make_tcp()).decode()
    t67_p_untag = binascii.hexlify(make_eth() + make_ipv4() + make_tcp()).decode()
    t67_p_trunc = binascii.hexlify(make_eth(vlan=100)[:14]).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_ptr_l1_strip_outer_vlan",
            application_category="protocol_transformation",
            difficulty="level_1",
            task_family="xdp_vlan_pop",
            template_family="xdp_head_adjust",
            semantic_signature="vlan_pop_single_tag+pass",
            diagnostic_category="verifier_rejection",
            failure_reason="Kernel verifier rejection: dereferencing old ctx->data pointers after bpf_xdp_adjust_head invalidates all packet registers",
            instruction="Fix the verifier rejection when calling bpf_xdp_adjust_head to pop a 4-byte VLAN tag. Reload ctx->data and ctx->data_end after the adjust_head helper call and verify bounds before writing the new Ethernet header.",
            requirements=[
                "Copy source/dest MAC before adjusting head",
                "Call bpf_xdp_adjust_head(ctx, 4) to pop VLAN header",
                "Reload data and data_end from ctx",
                "Write Ethernet header with inner EtherType and return XDP_PASS",
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
int xdp_transform(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_8021Q))
        return XDP_PASS;

    struct vlan_hdr *vlh = (void *)(eth + 1);
    if ((void *)(vlh + 1) > data_end)
        return XDP_PASS;

    __be16 inner_proto = vlh->h_vlan_encapsulated_proto;
    struct ethhdr eth_copy = *eth;

    bpf_xdp_adjust_head(ctx, 4);

    // Verifier error: modifying eth pointer after adjust_head without re-reading ctx->data
    eth->h_proto = inner_proto;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""0: R1=ctx(off=0,imm=0) R10=fp0
...
16: (85) call bpf_xdp_adjust_head#44
; eth->h_proto = inner_proto;
17: (6b) *(u16 *)(r6 +12) = r7
R6 invalid mem access 'inv' (registers pointing to packet invalidated after adjust_head)
processed 18 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
-- END PROG LOAD LOG --""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

SEC("xdp")
int xdp_transform(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_8021Q))
        return XDP_PASS;

    struct vlan_hdr *vlh = (void *)(eth + 1);
    if ((void *)(vlh + 1) > data_end)
        return XDP_PASS;

    __be16 inner_proto = vlh->h_vlan_encapsulated_proto;
    struct ethhdr eth_copy = *eth;

    if (bpf_xdp_adjust_head(ctx, 4))
        return XDP_DROP;

    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;
    eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;

    #pragma unroll
    for (int i = 0; i < ETH_ALEN; i++) {
        eth->h_dest[i] = eth_copy.h_dest[i];
        eth->h_source[i] = eth_copy.h_source[i];
    }
    eth->h_proto = inner_proto;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_strip_vlan", "description": "Strip 802.1Q VLAN header and restore EtherType", "packet_hex": t67_p_vlan, "expected_action": "XDP_PASS"},
                {"name": "pass_untagged", "description": "Pass untagged frame untouched", "packet_hex": t67_p_untag, "expected_action": "XDP_PASS"},
                {"name": "pass_trunc", "description": "Pass truncated VLAN header safely", "packet_hex": t67_p_trunc, "expected_action": "XDP_PASS"},
            ],
            validator_type="packet_bytes",
        )
    )

    # 68. repair_ptr_l1_push_dummy_tag (verifier_rejection: unverified offset after head adjustment)
    t68_p_in = binascii.hexlify(make_eth() + make_ipv4() + make_tcp()).decode()
    t68_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_ptr_l1_push_dummy_tag",
            application_category="protocol_transformation",
            difficulty="level_1",
            task_family="xdp_vlan_push",
            template_family="xdp_head_adjust",
            semantic_signature="vlan_push_tag_100+pass",
            diagnostic_category="verifier_rejection",
            failure_reason="Kernel verifier rejection: accessing packet data after negative adjust_head without checking eth + 1 <= data_end",
            instruction="Fix the verifier rejection in the VLAN push transformation. Call bpf_xdp_adjust_head(ctx, -4) to expand the packet header, then write an 802.1Q VLAN tag (VID 100) and return XDP_PASS.",
            requirements=[
                "Copy Ethernet header to temporary stack variable",
                "Call bpf_xdp_adjust_head(ctx, -4)",
                "Reload ctx->data and ctx->data_end and check boundary",
                "Write Ethernet header with 0x8100, VLAN tag 100, and encapsulated EtherType",
                "Return XDP_PASS",
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
int xdp_transform(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    struct ethhdr eth_copy = *eth;
    if (bpf_xdp_adjust_head(ctx, -4))
        return XDP_DROP;

    // Verifier error: missing (void *)(new_eth + 1) > data_end check
    data = (void *)(long)ctx->data;
    struct ethhdr *new_eth = data;
    *new_eth = eth_copy;
    new_eth->h_proto = bpf_htons(ETH_P_8021Q);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""0: R1=ctx(off=0,imm=0) R10=fp0
...
15: (85) call bpf_xdp_adjust_head#44
16: (61) r2 = *(u32 *)(r6 +0)
; *new_eth = eth_copy;
17: (7b) *(u64 *)(r2 +0) = r7
invalid access to packet, id=0, off=0, size=8, R2_w=pkt(off=0,r=0,imm=0)
processed 18 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
-- END PROG LOAD LOG --""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

SEC("xdp")
int xdp_transform(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    struct ethhdr eth_copy = *eth;
    if (bpf_xdp_adjust_head(ctx, -4))
        return XDP_DROP;

    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;
    struct ethhdr *new_eth = data;
    if ((void *)(new_eth + 1) > data_end)
        return XDP_DROP;

    #pragma unroll
    for (int i = 0; i < ETH_ALEN; i++) {
        new_eth->h_dest[i] = eth_copy.h_dest[i];
        new_eth->h_source[i] = eth_copy.h_source[i];
    }
    new_eth->h_proto = bpf_htons(ETH_P_8021Q);

    struct vlan_hdr *vlh = (void *)(new_eth + 1);
    if ((void *)(vlh + 1) > data_end)
        return XDP_DROP;

    vlh->h_vlan_TCI = bpf_htons(100);
    vlh->h_vlan_encapsulated_proto = eth_copy.h_proto;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_push_vlan_tcp", "description": "Push VLAN tag 100 on TCP frame", "packet_hex": t68_p_in, "expected_action": "XDP_PASS"},
                {"name": "pass_push_vlan_arp", "description": "Push VLAN tag 100 on ARP frame", "packet_hex": t68_p_arp, "expected_action": "XDP_PASS"},
            ],
            validator_type="packet_bytes",
        )
    )

    # 69. repair_ptr_l1_set_broadcast_mac (behavioral_logic_bug: setting source MAC instead of destination MAC to broadcast)
    t69_p_in = binascii.hexlify(make_eth(dst_mac="00:11:22:33:44:55", src_mac="52:54:00:12:34:56") + make_ipv4() + make_tcp()).decode()
    t69_p_arp = binascii.hexlify(make_eth(dst_mac="00:11:22:33:44:55", src_mac="52:54:00:12:34:56", eth_type=0x0806) + make_arp()).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_ptr_l1_set_broadcast_mac",
            application_category="protocol_transformation",
            difficulty="level_1",
            task_family="xdp_mac_rewrite",
            template_family="xdp_stateless_rewrite",
            semantic_signature="set_dst_mac_broadcast_ff+pass",
            diagnostic_category="behavioral_logic_bug",
            failure_reason="Behavioral bug: modified eth->h_source instead of eth->h_dest to broadcast ff:ff:ff:ff:ff:ff",
            instruction="Fix the field assignment bug in the transformation program to set the Ethernet destination MAC (eth->h_dest) to FF:FF:FF:FF:FF:FF while keeping the original source MAC, returning XDP_PASS.",
            requirements=[
                "Check Ethernet header bounds",
                "Set eth->h_dest to FF:FF:FF:FF:FF:FF",
                "Preserve original eth->h_source and payload",
                "Return XDP_PASS for all traffic",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_transform(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Behavioral bug: writing to h_source instead of h_dest
    #pragma unroll
    for (int i = 0; i < ETH_ALEN; i++) {
        eth->h_source[i] = 0xFF;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""FAIL: test_case 'set_broadcast_dmac' failed:
  Expected Ethernet dst MAC: ff:ff:ff:ff:ff:ff, src MAC: 52:54:00:12:34:56
  Observed Ethernet dst MAC: 00:11:22:33:44:55, src MAC: ff:ff:ff:ff:ff:ff (overwrote source MAC instead of dest MAC)
1 of 2 test cases failed.""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_transform(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    #pragma unroll
    for (int i = 0; i < ETH_ALEN; i++) {
        eth->h_dest[i] = 0xFF;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_broadcast_tcp", "description": "Set destination MAC to broadcast on TCP packet", "packet_hex": t69_p_in, "expected_action": "XDP_PASS"},
                {"name": "pass_broadcast_arp", "description": "Set destination MAC to broadcast on ARP frame", "packet_hex": t69_p_arp, "expected_action": "XDP_PASS"},
            ],
            validator_type="packet_bytes",
        )
    )

    # 70. repair_ptr_l1_zero_ip_id (behavioral_logic_bug: forgetting to adjust IPv4 checksum after modifying ip->id field)
    t70_p_in = binascii.hexlify(make_eth() + make_ipv4(tos=0) + make_tcp()).decode()
    t70_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_ptr_l1_zero_ip_id",
            application_category="protocol_transformation",
            difficulty="level_1",
            task_family="xdp_ip_id_zero",
            template_family="xdp_stateless_rewrite",
            semantic_signature="zero_ip_id_with_csum_update+pass",
            diagnostic_category="behavioral_logic_bug",
            failure_reason="Behavioral bug: modified ip->id to 0 without updating the IPv4 header checksum, producing invalid checksums on wire",
            instruction="Fix the IPv4 header checksum calculation when zeroing the 16-bit IPv4 ID field (ip->id = 0) so the resulting packet carries a valid checksum. Return XDP_PASS.",
            requirements=[
                "Check Ethernet and IPv4 bounds",
                "Set ip->id = 0",
                "Update IPv4 header checksum (ip->check) accurately",
                "Return XDP_PASS for all traffic",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_transform(struct xdp_md *ctx) {
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

    // Behavioral bug: modified ip->id without updating ip->check
    ip->id = 0;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""FAIL: test_case 'verify_valid_ip_checksum' failed:
  Expected IPv4 checksum: 0xF761 (calculated over zeroed ID)
  Observed IPv4 checksum: 0xE52D (stale checksum from original non-zero ID 0x1234)
1 of 2 test cases failed.""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_transform(struct xdp_md *ctx) {
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

    __u16 old_id = bpf_ntohs(ip->id);
    ip->id = 0;

    __u32 csum = bpf_ntohs(ip->check);
    csum += old_id;
    if (csum > 0xFFFF)
        csum = (csum & 0xFFFF) + (csum >> 16);
    ip->check = bpf_htons((__u16)csum);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_zero_id", "description": "Zero IPv4 ID and update checksum", "packet_hex": t70_p_in, "expected_action": "XDP_PASS"},
                {"name": "pass_arp", "description": "Pass ARP frame unchanged", "packet_hex": t70_p_arp, "expected_action": "XDP_PASS"},
            ],
            validator_type="packet_bytes",
        )
    )

    # =========================================================================
    # LEVEL 2 (10 tasks: 4 compilation, 4 verifier, 2 behavioral)
    # =========================================================================

    # 71. repair_ptr_l2_decrement_ttl_csum (compilation_error: undefined function bpf_csum_diff with wrong arguments)
    t71_p_ttl64 = binascii.hexlify(make_eth() + make_ipv4(ttl=64) + make_tcp()).decode()
    t71_p_ttl1 = binascii.hexlify(make_eth() + make_ipv4(ttl=1) + make_tcp()).decode()
    t71_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_ptr_l2_decrement_ttl_csum",
            application_category="protocol_transformation",
            difficulty="level_2",
            task_family="xdp_ttl_decrement",
            template_family="xdp_stateless_rewrite",
            semantic_signature="ttl_decrement_and_csum_update+pass_or_drop",
            diagnostic_category="compilation_error",
            failure_reason="Compilation error: call to undeclared function 'bpf_csum_diff' with wrong argument count",
            instruction="Fix the TTL decrement and checksum update in the transformation filter. Decrement IPv4 TTL when > 1, update the IPv4 header checksum, and drop packets with TTL <= 1.",
            requirements=[
                "Check Ethernet and IPv4 bounds",
                "If ip->ttl <= 1, return XDP_DROP",
                "Decrement ip->ttl and update ip->check (e.g. csum += 0x0100)",
                "Return XDP_PASS for valid packets",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_transform(struct xdp_md *ctx) {
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

    ip->ttl -= 1;
    // Compilation error: calling bpf_csum_diff with wrong arguments
    ip->check = bpf_csum_diff(&ip->ttl, 1);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""faulty.c:26:17: error: too few arguments to function call, expected 5, have 2
    ip->check = bpf_csum_diff(&ip->ttl, 1);
                ~~~~~~~~~~~~~            ^
1 error generated.""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_transform(struct xdp_md *ctx) {
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

    ip->ttl -= 1;
    __u32 csum = bpf_ntohs(ip->check);
    csum += 0x0100;
    if (csum > 0xFFFF)
        csum = (csum & 0xFFFF) + (csum >> 16);
    ip->check = bpf_htons((__u16)csum);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_ttl_64", "description": "Decrement TTL from 64 to 63 with valid checksum", "packet_hex": t71_p_ttl64, "expected_action": "XDP_PASS"},
                {"name": "drop_ttl_1", "description": "Drop packet with TTL == 1", "packet_hex": t71_p_ttl1, "expected_action": "XDP_DROP"},
                {"name": "pass_arp", "description": "Pass ARP frame unchanged", "packet_hex": t71_p_arp, "expected_action": "XDP_PASS"},
            ],
            validator_type="packet_bytes",
        )
    )

    # 72. repair_ptr_l2_dnat_ipv4_single (compilation_error: missing <linux/in.h> for IPPROTO constants)
    t72_p_tcp = binascii.hexlify(make_eth() + make_ipv4(dst_ip="198.51.100.1") + make_tcp()).decode()
    t72_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_ptr_l2_dnat_ipv4_single",
            application_category="protocol_transformation",
            difficulty="level_2",
            task_family="xdp_dnat",
            template_family="xdp_stateless_rewrite",
            semantic_signature="dnat_to_203_0_113_9+csum_update+pass",
            diagnostic_category="compilation_error",
            failure_reason="Compilation error: undeclared identifier 'IPPROTO_IP' due to missing include <linux/in.h>",
            instruction="Fix the missing include header and rewrite IPv4 destination address to 203.0.113.9 (0xCB007109) with accurate checksum recalculation, returning XDP_PASS.",
            requirements=[
                "Include <linux/in.h>",
                "Check Ethernet and IPv4 bounds",
                "Rewrite ip->daddr to 203.0.113.9 (bpf_htonl(0xCB007109))",
                "Update IPv4 header checksum correctly",
                "Return XDP_PASS for all traffic",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_transform(struct xdp_md *ctx) {
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

    __be32 old_dst = ip->daddr;
    __be32 new_dst = bpf_htonl(0xCB007109);
    ip->daddr = new_dst;

    // Incremental csum update
    __u32 csum = bpf_ntohs(ip->check);
    __u32 old_hi = bpf_ntohl(old_dst) >> 16;
    __u32 old_lo = bpf_ntohl(old_dst) & 0xFFFF;
    __u32 new_hi = 0xCB00;
    __u32 new_lo = 0x7109;

    csum += old_hi + old_lo;
    csum = (csum & 0xFFFF) + (csum >> 16);
    csum += (~new_hi & 0xFFFF) + (~new_lo & 0xFFFF);
    while (csum >> 16)
        csum = (csum & 0xFFFF) + (csum >> 16);

    ip->check = bpf_htons((__u16)csum);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""faulty.c:4:10: fatal error: 'linux/in.h' file not found (simulated missing dependency on specific header)
#include <linux/in.h>
         ^~~~~~~~~~~~
1 error generated.""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_transform(struct xdp_md *ctx) {
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

    __be32 old_dst = ip->daddr;
    __be32 new_dst = bpf_htonl(0xCB007109);
    ip->daddr = new_dst;

    __u32 csum = bpf_ntohs(ip->check);
    __u32 old_hi = bpf_ntohl(old_dst) >> 16;
    __u32 old_lo = bpf_ntohl(old_dst) & 0xFFFF;
    __u32 new_hi = 0xCB00;
    __u32 new_lo = 0x7109;

    csum += old_hi + old_lo;
    csum = (csum & 0xFFFF) + (csum >> 16);
    csum += (~new_hi & 0xFFFF) + (~new_lo & 0xFFFF);
    while (csum >> 16)
        csum = (csum & 0xFFFF) + (csum >> 16);

    ip->check = bpf_htons((__u16)csum);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_dnat_tcp", "description": "DNAT destination IP to 203.0.113.9", "packet_hex": t72_p_tcp, "expected_action": "XDP_PASS"},
                {"name": "pass_arp", "description": "Pass ARP frame unchanged", "packet_hex": t72_p_arp, "expected_action": "XDP_PASS"},
            ],
            validator_type="packet_bytes",
        )
    )

    # 73. repair_ptr_l2_snat_ipv4_single (compilation_error: type error in checksum calculation)
    t73_p_tcp = binascii.hexlify(make_eth() + make_ipv4(src_ip="192.168.1.50") + make_tcp()).decode()
    t73_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_ptr_l2_snat_ipv4_single",
            application_category="protocol_transformation",
            difficulty="level_2",
            task_family="xdp_snat",
            template_family="xdp_stateless_rewrite",
            semantic_signature="snat_to_198_51_100_1+csum_update+pass",
            diagnostic_category="compilation_error",
            failure_reason="Compilation error: invalid operands to binary expression in checksum update",
            instruction="Fix the compilation error in the SNAT filter to rewrite the IPv4 source address to 198.51.100.1 (0xC6336401) with correct IP header checksum, returning XDP_PASS.",
            requirements=[
                "Check Ethernet and IPv4 bounds",
                "Rewrite ip->saddr to 198.51.100.1 (bpf_htonl(0xC6336401))",
                "Update IPv4 checksum accurately",
                "Return XDP_PASS for all traffic",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_transform(struct xdp_md *ctx) {
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

    __be32 old_src = ip->saddr;
    __be32 new_src = bpf_htonl(0xC6336401);
    ip->saddr = new_src;

    // Compilation error: applying pointer address to addition
    __u32 csum = bpf_ntohs(ip->check);
    csum += (&old_src);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""faulty.c:26:10: error: cannot initialize a variable of type '__u32' (aka 'unsigned int') with an rvalue of type '__be32 *' (aka 'unsigned int *')
    csum += (&old_src);
         ^  ~~~~~~~~~~
1 error generated.""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_transform(struct xdp_md *ctx) {
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

    __be32 old_src = ip->saddr;
    __be32 new_src = bpf_htonl(0xC6336401);
    ip->saddr = new_src;

    __u32 csum = bpf_ntohs(ip->check);
    __u32 old_hi = bpf_ntohl(old_src) >> 16;
    __u32 old_lo = bpf_ntohl(old_src) & 0xFFFF;
    __u32 new_hi = 0xC633;
    __u32 new_lo = 0x6401;

    csum += old_hi + old_lo;
    csum = (csum & 0xFFFF) + (csum >> 16);
    csum += (~new_hi & 0xFFFF) + (~new_lo & 0xFFFF);
    while (csum >> 16)
        csum = (csum & 0xFFFF) + (csum >> 16);

    ip->check = bpf_htons((__u16)csum);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_snat_tcp", "description": "SNAT source IP to 198.51.100.1", "packet_hex": t73_p_tcp, "expected_action": "XDP_PASS"},
                {"name": "pass_arp", "description": "Pass ARP frame unchanged", "packet_hex": t73_p_arp, "expected_action": "XDP_PASS"},
            ],
            validator_type="packet_bytes",
        )
    )

    # 74. repair_ptr_l2_rewrite_udp_port_csum (compilation_error: missing header <linux/udp.h>)
    t74_p_udp = binascii.hexlify(make_eth() + make_ipv4(proto=17) + make_udp(dst_port=53, with_csum=True)).decode()
    t74_p_tcp = binascii.hexlify(make_eth() + make_ipv4(proto=6) + make_tcp()).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_ptr_l2_rewrite_udp_port_csum",
            application_category="protocol_transformation",
            difficulty="level_2",
            task_family="xdp_udp_port_rewrite",
            template_family="xdp_stateless_rewrite",
            semantic_signature="udp_dport_rewrite_5353+csum_update+pass",
            diagnostic_category="compilation_error",
            failure_reason="Compilation error: variable has incomplete type 'struct udphdr' due to missing include <linux/udp.h>",
            instruction="Fix the missing include header in the UDP port rewriting filter. Rewrite the destination port of IPv4 UDP packets from 53 to 5353 (mDNS) and update non-zero UDP checksums, preserving zero checksums as zero.",
            requirements=[
                "Include <linux/udp.h>",
                "Check Ethernet, IPv4, and UDP bounds",
                "Rewrite udp->dest to bpf_htons(5353)",
                "If udp->check != 0, update UDP checksum with incremental delta",
                "Return XDP_PASS for all traffic",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_transform(struct xdp_md *ctx) {
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

    // Compilation error: struct udphdr incomplete without <linux/udp.h>
    struct udphdr *udp = (void *)ip + ip_len;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    if (udp->dest == bpf_htons(53)) {
        udp->dest = bpf_htons(5353);
        if (udp->check != 0) {
            __u32 csum = bpf_ntohs(udp->check);
            csum += 53 + (~5353 & 0xFFFF);
            while (csum >> 16)
                csum = (csum & 0xFFFF) + (csum >> 16);
            if (csum == 0)
                csum = 0xFFFF;
            udp->check = bpf_htons((__u16)csum);
        }
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""faulty.c:26:12: error: variable has incomplete type 'struct udphdr'
    struct udphdr *udp = (void *)ip + ip_len;
           ^
faulty.c:26:12: note: forward declaration of 'struct udphdr'
1 error generated.""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_transform(struct xdp_md *ctx) {
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

    if (udp->dest == bpf_htons(53)) {
        udp->dest = bpf_htons(5353);
        if (udp->check != 0) {
            __u32 csum = bpf_ntohs(udp->check);
            csum += 53 + (~5353 & 0xFFFF);
            while (csum >> 16)
                csum = (csum & 0xFFFF) + (csum >> 16);
            if (csum == 0)
                csum = 0xFFFF;
            udp->check = bpf_htons((__u16)csum);
        }
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_rewrite_udp_port", "description": "Rewrite UDP port from 53 to 5353 and update checksum", "packet_hex": t74_p_udp, "expected_action": "XDP_PASS"},
                {"name": "pass_tcp", "description": "Pass TCP unchanged", "packet_hex": t74_p_tcp, "expected_action": "XDP_PASS"},
            ],
            validator_type="packet_bytes",
        )
    )

    # 75. repair_ptr_l2_encap_ipip_tunnel (verifier_rejection: dereferencing old packet pointers after bpf_xdp_adjust_head)
    t75_p_in = binascii.hexlify(make_eth() + make_ipv4(src_ip="10.0.0.1", dst_ip="10.0.0.2") + make_tcp()).decode()
    t75_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_ptr_l2_encap_ipip_tunnel",
            application_category="protocol_transformation",
            difficulty="level_2",
            task_family="xdp_ipip_encap",
            template_family="xdp_head_adjust",
            semantic_signature="ipip_tunnel_encap+pass",
            diagnostic_category="verifier_rejection",
            failure_reason="Kernel verifier rejection: unverified access to packet pointer after head expansion",
            instruction="Fix the verifier rejection in the IPIP encapsulation filter. Push a 20-byte outer IPv4 header (protocol IPPROTO_IPIP = 4) using bpf_xdp_adjust_head(ctx, -20), re-validate packet bounds, and return XDP_PASS.",
            requirements=[
                "Preserve original Ethernet header before head adjustment",
                "Call bpf_xdp_adjust_head(ctx, -20)",
                "Re-validate that (eth + 1) + 1 <= data_end for outer Ethernet and IP headers",
                "Construct outer IPv4 header with proto=IPPROTO_IPIP",
                "Return XDP_PASS",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_transform(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct ethhdr eth_saved = *eth;

    if (bpf_xdp_adjust_head(ctx, -20))
        return XDP_DROP;

    // Verifier error: pointers not refreshed from ctx->data
    eth->h_proto = bpf_htons(ETH_P_IP);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""0: R1=ctx(off=0,imm=0) R10=fp0
...
12: (85) call bpf_xdp_adjust_head#44
; eth->h_proto = bpf_htons(ETH_P_IP);
13: (6b) *(u16 *)(r6 +12) = r7
R6 invalid mem access 'inv' (stale register after adjust_head)
processed 14 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
-- END PROG LOAD LOG --""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_transform(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct ethhdr eth_saved = *eth;

    if (bpf_xdp_adjust_head(ctx, -20))
        return XDP_DROP;

    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;
    struct ethhdr *new_eth = data;
    if ((void *)(new_eth + 1) > data_end)
        return XDP_DROP;

    *new_eth = eth_saved;

    struct iphdr *outer_ip = (void *)(new_eth + 1);
    if ((void *)(outer_ip + 1) > data_end)
        return XDP_DROP;

    outer_ip->version = 4;
    outer_ip->ihl = 5;
    outer_ip->tos = 0;
    outer_ip->tot_len = bpf_htons((__u16)((long)data_end - (long)outer_ip));
    outer_ip->id = 0;
    outer_ip->frag_off = 0;
    outer_ip->ttl = 64;
    outer_ip->protocol = 4; // IPPROTO_IPIP
    outer_ip->saddr = bpf_htonl(0xC0A80101); // 192.168.1.1
    outer_ip->daddr = bpf_htonl(0xC0A80102); // 192.168.1.2
    outer_ip->check = 0;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_encap_tcp", "description": "Encap IPv4 TCP in outer IPIP header", "packet_hex": t75_p_in, "expected_action": "XDP_PASS"},
                {"name": "pass_arp", "description": "Pass non-IP ARP frame unchanged", "packet_hex": t75_p_arp, "expected_action": "XDP_PASS"},
            ],
            validator_type="packet_bytes",
        )
    )

    # 76. repair_ptr_l2_tcp_port_rewrite (verifier_rejection: R1 invalid access when updating TCP checksum without variable IHL offset check)
    t76_p_tcp80 = binascii.hexlify(make_eth() + make_ipv4(proto=6) + make_tcp(dst_port=80)).decode()
    t76_p_tcp443 = binascii.hexlify(make_eth() + make_ipv4(proto=6) + make_tcp(dst_port=443)).decode()
    t76_p_udp = binascii.hexlify(make_eth() + make_ipv4(proto=17) + make_udp()).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_ptr_l2_tcp_port_rewrite",
            application_category="protocol_transformation",
            difficulty="level_2",
            task_family="xdp_tcp_port_rewrite",
            template_family="xdp_stateless_rewrite",
            semantic_signature="tcp_dport_80_to_8080+csum_update+pass",
            diagnostic_category="verifier_rejection",
            failure_reason="Kernel verifier rejection: writing tcp->dest and tcp->check without verifying that (tcp + 1 <= data_end)",
            instruction="Fix the verifier boundary rejection when rewriting TCP port 80 to 8080. Verify the TCP header bounds safely, update tcp->dest and the TCP checksum, and return XDP_PASS.",
            requirements=[
                "Check Ethernet, IPv4 (variable IHL), and TCP bounds",
                "Ensure (void *)(tcp + 1) <= data_end before modifying TCP header",
                "Rewrite TCP destination port from 80 to 8080",
                "Update TCP checksum accurately",
                "Return XDP_PASS for all traffic",
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
int xdp_transform(struct xdp_md *ctx) {
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

    if (tcp->dest == bpf_htons(80)) {
        tcp->dest = bpf_htons(8080);
        __u32 csum = bpf_ntohs(tcp->check);
        csum += 80 + (~8080 & 0xFFFF);
        while (csum >> 16)
            csum = (csum & 0xFFFF) + (csum >> 16);
        tcp->check = bpf_htons((__u16)csum);
    }

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
int xdp_transform(struct xdp_md *ctx) {
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

    if (tcp->dest == bpf_htons(80)) {
        tcp->dest = bpf_htons(8080);
        __u32 csum = bpf_ntohs(tcp->check);
        csum += 80 + (~8080 & 0xFFFF);
        while (csum >> 16)
            csum = (csum & 0xFFFF) + (csum >> 16);
        tcp->check = bpf_htons((__u16)csum);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_rewrite_tcp80", "description": "Rewrite TCP dport 80 to 8080 with valid checksum", "packet_hex": t76_p_tcp80, "expected_action": "XDP_PASS"},
                {"name": "pass_tcp443", "description": "Pass TCP 443 unchanged", "packet_hex": t76_p_tcp443, "expected_action": "XDP_PASS"},
                {"name": "pass_udp", "description": "Pass UDP unchanged", "packet_hex": t76_p_udp, "expected_action": "XDP_PASS"},
            ],
            validator_type="packet_bytes",
        )
    )

    # 77. repair_ptr_l2_decap_gre_tunnel (verifier_rejection: arithmetic on packet pointer causing negative offset)
    t77_p_in = binascii.hexlify(make_eth() + make_ipv4(proto=47) + b"\x00\x00\x08\x00" + make_ipv4() + make_tcp()).decode()
    t77_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_ptr_l2_decap_gre_tunnel",
            application_category="protocol_transformation",
            difficulty="level_2",
            task_family="xdp_gre_decap",
            template_family="xdp_head_adjust",
            semantic_signature="gre_tunnel_decap+pass",
            diagnostic_category="verifier_rejection",
            failure_reason="Kernel verifier rejection: adjust_head offset variable not verified to be positive constant",
            instruction="Fix the verifier rejection in the GRE decapsulation filter. Pop the outer 24 bytes (outer IPv4 20 bytes + GRE header 4 bytes) using bpf_xdp_adjust_head(ctx, 24), copy Ethernet addresses, and return XDP_PASS.",
            requirements=[
                "Check Ethernet, outer IPv4, and GRE header bounds",
                "Verify outer protocol is IPPROTO_GRE (47)",
                "Preserve inner Ethernet/IP frames after adjust_head(ctx, 24)",
                "Return XDP_PASS for decapsulated frames",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_transform(struct xdp_md *ctx) {
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
    if (ip->protocol != 47) // IPPROTO_GRE
        return XDP_PASS;

    struct ethhdr eth_saved = *eth;
    int decap_len = 24;

    // Verifier error: calling adjust_head with variable instead of constant
    if (bpf_xdp_adjust_head(ctx, decap_len))
        return XDP_DROP;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""0: R1=ctx(off=0,imm=0) R10=fp0
...
16: (85) call bpf_xdp_adjust_head#44
R2 variable offset adjust_head prohibited
processed 17 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
-- END PROG LOAD LOG --""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_transform(struct xdp_md *ctx) {
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
    if (ip->protocol != 47) // IPPROTO_GRE
        return XDP_PASS;

    struct ethhdr eth_saved = *eth;

    if (bpf_xdp_adjust_head(ctx, 24))
        return XDP_DROP;

    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;
    struct ethhdr *new_eth = data;
    if ((void *)(new_eth + 1) > data_end)
        return XDP_DROP;

    *new_eth = eth_saved;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_decap_gre", "description": "Decap GRE tunnel header and pass inner IPv4", "packet_hex": t77_p_in, "expected_action": "XDP_PASS"},
                {"name": "pass_arp", "description": "Pass ARP frame unchanged", "packet_hex": t77_p_arp, "expected_action": "XDP_PASS"},
            ],
            validator_type="packet_bytes",
        )
    )

    # 78. repair_ptr_l2_vxlan_header_strip (verifier_rejection: verifier rejected loop unrolling in tunnel decap)
    t78_p_vxlan = binascii.hexlify(make_eth() + make_ipv4(proto=17) + make_udp(dst_port=4789) + b"\x08\x00\x00\x00\x00\x01\x00\x00" + make_eth() + make_ipv4() + make_tcp()).decode()
    t78_p_other = binascii.hexlify(make_eth() + make_ipv4(proto=6) + make_tcp()).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_ptr_l2_vxlan_header_strip",
            application_category="protocol_transformation",
            difficulty="level_2",
            task_family="xdp_vxlan_decap",
            template_family="xdp_head_adjust",
            semantic_signature="vxlan_decap_50_bytes+pass",
            diagnostic_category="verifier_rejection",
            failure_reason="Kernel verifier rejection: dereferencing inner frame without checking (inner_eth + 1 <= data_end) after bpf_xdp_adjust_head",
            instruction="Fix the verifier rejection in the VXLAN decapsulation filter. Strip outer Ethernet, IPv4, UDP, and VXLAN headers (total 50 bytes) with bpf_xdp_adjust_head(ctx, 50), re-verify packet bounds, and return XDP_PASS.",
            requirements=[
                "Identify VXLAN packets on UDP port 4789",
                "Call bpf_xdp_adjust_head(ctx, 50)",
                "Re-validate packet boundaries after decap",
                "Return XDP_PASS for decapsulated inner frame",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_transform(struct xdp_md *ctx) {
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
    if (udp->dest != bpf_htons(4789))
        return XDP_PASS;

    if (bpf_xdp_adjust_head(ctx, 50))
        return XDP_DROP;

    // Verifier error: missing bounds check on data_end after adjust_head
    data = (void *)(long)ctx->data;
    struct ethhdr *inner_eth = data;
    __u16 proto = inner_eth->h_proto;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""0: R1=ctx(off=0,imm=0) R10=fp0
...
26: (85) call bpf_xdp_adjust_head#44
27: (61) r2 = *(u32 *)(r6 +0)
; __u16 proto = inner_eth->h_proto;
28: (69) r1 = *(u16 *)(r2 +12)
invalid access to packet, id=0, off=12, size=2, R2_w=pkt(off=0,r=0,imm=0)
processed 29 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
-- END PROG LOAD LOG --""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_transform(struct xdp_md *ctx) {
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
    if (udp->dest != bpf_htons(4789))
        return XDP_PASS;

    if (bpf_xdp_adjust_head(ctx, 50))
        return XDP_DROP;

    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;
    struct ethhdr *inner_eth = data;
    if ((void *)(inner_eth + 1) > data_end)
        return XDP_DROP;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_decap_vxlan", "description": "Decap VXLAN header and pass inner frame", "packet_hex": t78_p_vxlan, "expected_action": "XDP_PASS"},
                {"name": "pass_other", "description": "Pass standard TCP frame unchanged", "packet_hex": t78_p_other, "expected_action": "XDP_PASS"},
            ],
            validator_type="packet_bytes",
        )
    )

    # 79. repair_ptr_l2_ttl_decrement_action (behavioral_logic_bug: not dropping or aborting packet when incoming TTL is 1 or 0)
    t79_p_ttl64 = binascii.hexlify(make_eth() + make_ipv4(ttl=64) + make_tcp()).decode()
    t79_p_ttl1 = binascii.hexlify(make_eth() + make_ipv4(ttl=1) + make_tcp()).decode()
    t79_p_ttl0 = binascii.hexlify(make_eth() + make_ipv4(ttl=0) + make_tcp()).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_ptr_l2_ttl_decrement_action",
            application_category="protocol_transformation",
            difficulty="level_2",
            task_family="xdp_ttl_policy",
            template_family="xdp_stateless_rewrite",
            semantic_signature="ttl_underflow_guard+drop_or_pass",
            diagnostic_category="behavioral_logic_bug",
            failure_reason="Behavioral bug: decremented TTL when TTL == 0, underflowing to 255 and passing expired packets",
            instruction="Fix the TTL expiration logic in the transformation filter. Drop packets with incoming TTL <= 1 (XDP_DROP), decrement TTL for TTL > 1, update the IPv4 checksum, and return XDP_PASS.",
            requirements=[
                "Check Ethernet and IPv4 bounds",
                "If ip->ttl <= 1, return XDP_DROP",
                "If ip->ttl > 1, decrement ip->ttl and update checksum",
                "Return XDP_PASS for valid routed packets",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_transform(struct xdp_md *ctx) {
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

    // Behavioral bug: decrements without checking <= 1, causes underflow
    ip->ttl -= 1;

    __u32 csum = bpf_ntohs(ip->check);
    csum += 0x0100;
    if (csum > 0xFFFF)
        csum = (csum & 0xFFFF) + (csum >> 16);
    ip->check = bpf_htons((__u16)csum);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""FAIL: test_case 'drop_ttl_zero' failed:
  Expected action: XDP_DROP
  Observed action: XDP_PASS (TTL 0 was decremented to 255 and passed)
1 of 3 test cases failed.""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_transform(struct xdp_md *ctx) {
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

    ip->ttl -= 1;

    __u32 csum = bpf_ntohs(ip->check);
    csum += 0x0100;
    if (csum > 0xFFFF)
        csum = (csum & 0xFFFF) + (csum >> 16);
    ip->check = bpf_htons((__u16)csum);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_ttl_64", "description": "Decrement TTL from 64 to 63", "packet_hex": t79_p_ttl64, "expected_action": "XDP_PASS"},
                {"name": "drop_ttl_1", "description": "Drop packet with TTL == 1", "packet_hex": t79_p_ttl1, "expected_action": "XDP_DROP"},
                {"name": "drop_ttl_0", "description": "Drop packet with TTL == 0", "packet_hex": t79_p_ttl0, "expected_action": "XDP_DROP"},
            ],
            validator_type="packet_bytes",
        )
    )

    # 80. repair_ptr_l2_csum_incremental_delta (behavioral_logic_bug: wrong 1's complement delta addition logic for IP checksum update)
    t80_p_in = binascii.hexlify(make_eth() + make_ipv4(src_ip="10.0.0.1", dst_ip="10.0.0.2") + make_tcp()).decode()
    t80_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_ptr_l2_csum_incremental_delta",
            application_category="protocol_transformation",
            difficulty="level_2",
            task_family="xdp_checksum_repair",
            template_family="xdp_stateless_rewrite",
            semantic_signature="rfc1624_csum_update+pass",
            diagnostic_category="behavioral_logic_bug",
            failure_reason="Behavioral bug: RFC 1624 equation missing carry folding when updating 16-bit checksum",
            instruction="Fix the RFC 1624 incremental checksum calculation when modifying the destination IP address to 10.0.0.99 so the carry bits are correctly folded back into the 16-bit word.",
            requirements=[
                "Check Ethernet and IPv4 bounds",
                "Rewrite ip->daddr to 10.0.0.99 (bpf_htonl(0x0A000063))",
                "Perform RFC 1624 1's complement carry fold: while(csum >> 16) csum = (csum & 0xFFFF) + (csum >> 16)",
                "Return XDP_PASS for all traffic",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_transform(struct xdp_md *ctx) {
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

    __be32 old_dst = ip->daddr;
    __be32 new_dst = bpf_htonl(0x0A000063);
    ip->daddr = new_dst;

    __u32 csum = bpf_ntohs(ip->check);
    __u32 old_hi = bpf_ntohl(old_dst) >> 16;
    __u32 old_lo = bpf_ntohl(old_dst) & 0xFFFF;
    __u32 new_hi = 0x0A00;
    __u32 new_lo = 0x0063;

    // Behavioral bug: missing carry fold after additions
    csum += old_hi + old_lo;
    csum += (~new_hi & 0xFFFF) + (~new_lo & 0xFFFF);
    // Did not fold (csum >> 16) into lower 16 bits!

    ip->check = bpf_htons((__u16)csum);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""FAIL: test_case 'verify_folded_checksum' failed:
  Expected IPv4 checksum: 0xE4DE
  Observed IPv4 checksum: 0xE4DC (carry bits were truncated instead of folded)
1 of 2 test cases failed.""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_transform(struct xdp_md *ctx) {
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

    __be32 old_dst = ip->daddr;
    __be32 new_dst = bpf_htonl(0x0A000063);
    ip->daddr = new_dst;

    __u32 csum = bpf_ntohs(ip->check);
    __u32 old_hi = bpf_ntohl(old_dst) >> 16;
    __u32 old_lo = bpf_ntohl(old_dst) & 0xFFFF;
    __u32 new_hi = 0x0A00;
    __u32 new_lo = 0x0063;

    csum += old_hi + old_lo;
    csum = (csum & 0xFFFF) + (csum >> 16);
    csum += (~new_hi & 0xFFFF) + (~new_lo & 0xFFFF);
    while (csum >> 16)
        csum = (csum & 0xFFFF) + (csum >> 16);

    ip->check = bpf_htons((__u16)csum);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_csum_rewrite", "description": "Rewrite IP and verify folded checksum", "packet_hex": t80_p_in, "expected_action": "XDP_PASS"},
                {"name": "pass_arp", "description": "Pass ARP frame unchanged", "packet_hex": t80_p_arp, "expected_action": "XDP_PASS"},
            ],
            validator_type="packet_bytes",
        )
    )

    # =========================================================================
    # LEVEL 3 (10 tasks: 4 compilation, 3 verifier, 3 behavioral)
    # =========================================================================

    # 81. repair_ptr_l3_full_tcp_nat44 (compilation_error: missing include for bpf_htons / bpf_htonl in NAT44)
    t81_p_tcp = binascii.hexlify(make_eth() + make_ipv4(src_ip="10.0.0.5", dst_ip="1.2.3.4") + make_tcp(src_port=10000, dst_port=80)).decode()
    t81_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_ptr_l3_full_tcp_nat44",
            application_category="protocol_transformation",
            difficulty="level_3",
            task_family="xdp_full_nat44",
            template_family="xdp_stateless_rewrite",
            semantic_signature="tcp_nat44_dnat_and_snat+pass",
            diagnostic_category="compilation_error",
            failure_reason="Compilation error: undefined identifier 'bpf_htonl' due to missing include <bpf/bpf_endian.h>",
            instruction="Fix the missing endian conversion include in the full NAT44 transformation filter. Rewrite source IP to 198.51.100.1, source port to 20000, and update both IP and TCP checksums, returning XDP_PASS.",
            requirements=[
                "Include <bpf/bpf_endian.h>",
                "Check Ethernet, IPv4, and TCP bounds",
                "Rewrite ip->saddr to 198.51.100.1 and tcp->source to 20000",
                "Update IPv4 header and TCP L4 checksums",
                "Return XDP_PASS for all traffic",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_transform(struct xdp_md *ctx) {
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

    // Missing <bpf/bpf_endian.h>
    __be32 old_src = ip->saddr;
    __be32 new_src = bpf_htonl(0xC6336401);
    ip->saddr = new_src;

    __u16 old_sport = bpf_ntohs(tcp->source);
    tcp->source = bpf_htons(20000);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""faulty.c:16:25: error: call to undeclared function 'bpf_htons'; ISO C99 and later do not support implicit function declarations [-Wimplicit-function-declaration]
    if (eth->h_proto != bpf_htons(ETH_P_IP))
                        ^
faulty.c:35:22: error: call to undeclared function 'bpf_htonl'; ISO C99 and later do not support implicit function declarations [-Wimplicit-function-declaration]
    __be32 new_src = bpf_htonl(0xC6336401);
                     ^
2 errors generated.""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_transform(struct xdp_md *ctx) {
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

    __be32 old_src = ip->saddr;
    __be32 new_src = bpf_htonl(0xC6336401);
    ip->saddr = new_src;

    __u16 old_sport = bpf_ntohs(tcp->source);
    tcp->source = bpf_htons(20000);

    // IP checksum update
    __u32 csum = bpf_ntohs(ip->check);
    __u32 old_hi = bpf_ntohl(old_src) >> 16;
    __u32 old_lo = bpf_ntohl(old_src) & 0xFFFF;
    __u32 new_hi = 0xC633;
    __u32 new_lo = 0x6401;

    csum += old_hi + old_lo;
    csum = (csum & 0xFFFF) + (csum >> 16);
    csum += (~new_hi & 0xFFFF) + (~new_lo & 0xFFFF);
    while (csum >> 16)
        csum = (csum & 0xFFFF) + (csum >> 16);
    ip->check = bpf_htons((__u16)csum);

    // TCP checksum update for IP change + port change
    __u32 tcpcsum = bpf_ntohs(tcp->check);
    tcpcsum += old_hi + old_lo + old_sport;
    tcpcsum = (tcpcsum & 0xFFFF) + (tcpcsum >> 16);
    tcpcsum += (~new_hi & 0xFFFF) + (~new_lo & 0xFFFF) + (~20000 & 0xFFFF);
    while (tcpcsum >> 16)
        tcpcsum = (tcpcsum & 0xFFFF) + (tcpcsum >> 16);
    tcp->check = bpf_htons((__u16)tcpcsum);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_full_nat44", "description": "Rewrite source IP and source port with checksum updates", "packet_hex": t81_p_tcp, "expected_action": "XDP_PASS"},
                {"name": "pass_arp", "description": "Pass ARP frame unchanged", "packet_hex": t81_p_arp, "expected_action": "XDP_PASS"},
            ],
            validator_type="packet_bytes",
        )
    )

    # 82. repair_ptr_l3_icmp_echo_to_reply (compilation_error: missing struct icmphdr include)
    t82_p_echo = binascii.hexlify(make_eth(dst_mac="52:54:00:12:34:56", src_mac="52:54:00:65:43:21") + make_ipv4(src_ip="192.168.1.10", dst_ip="192.168.1.20", proto=1) + make_icmp(icmp_type=8)).decode()
    t82_p_tcp = binascii.hexlify(make_eth() + make_ipv4(proto=6) + make_tcp()).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_ptr_l3_icmp_echo_to_reply",
            application_category="protocol_transformation",
            difficulty="level_3",
            task_family="xdp_icmp_reply_gen",
            template_family="xdp_packet_reflector",
            semantic_signature="icmp_echo_req_to_reply_and_tx+tx",
            diagnostic_category="compilation_error",
            failure_reason="Compilation error: variable has incomplete type 'struct icmphdr' due to missing <linux/icmp.h>",
            instruction="Fix the missing ICMP header include. Convert an IPv4 ICMP Echo Request (type 8) into an ICMP Echo Reply (type 0) by swapping Ethernet and IP endpoints, updating the ICMP type and checksum, and transmitting with XDP_TX.",
            requirements=[
                "Include <linux/icmp.h>",
                "Check Ethernet, IPv4, and ICMP bounds",
                "Verify icmp->type == 8 (Echo Request)",
                "Swap Ethernet source/destination MAC addresses",
                "Swap IPv4 source/destination IP addresses",
                "Set icmp->type = 0 (Echo Reply) and update ICMP checksum (csum += 0x0800)",
                "Return XDP_TX for ICMP Echo, XDP_PASS for other traffic",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_transform(struct xdp_md *ctx) {
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

    __u32 ip_len = (__u32)ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    // Missing <linux/icmp.h>
    struct icmphdr *icmp = (void *)ip + ip_len;
    if ((void *)(icmp + 1) > data_end)
        return XDP_PASS;

    if (icmp->type == 8) {
        // Swap MACs
        __u8 tmp_mac[ETH_ALEN];
        #pragma unroll
        for (int i = 0; i < ETH_ALEN; i++) {
            tmp_mac[i] = eth->h_dest[i];
            eth->h_dest[i] = eth->h_source[i];
            eth->h_source[i] = tmp_mac[i];
        }

        // Swap IPs
        __be32 tmp_ip = ip->saddr;
        ip->saddr = ip->daddr;
        ip->daddr = tmp_ip;

        // Change type 8 -> 0
        icmp->type = 0;
        __u32 csum = bpf_ntohs(icmp->checksum);
        csum += 0x0800;
        if (csum > 0xFFFF)
            csum = (csum & 0xFFFF) + (csum >> 16);
        icmp->checksum = bpf_htons((__u16)csum);

        return XDP_TX;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""faulty.c:26:12: error: variable has incomplete type 'struct icmphdr'
    struct icmphdr *icmp = (void *)ip + ip_len;
           ^
faulty.c:26:12: note: forward declaration of 'struct icmphdr'
1 error generated.""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_transform(struct xdp_md *ctx) {
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

    __u32 ip_len = (__u32)ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct icmphdr *icmp = (void *)ip + ip_len;
    if ((void *)(icmp + 1) > data_end)
        return XDP_PASS;

    if (icmp->type == 8) {
        __u8 tmp_mac[ETH_ALEN];
        #pragma unroll
        for (int i = 0; i < ETH_ALEN; i++) {
            tmp_mac[i] = eth->h_dest[i];
            eth->h_dest[i] = eth->h_source[i];
            eth->h_source[i] = tmp_mac[i];
        }

        __be32 tmp_ip = ip->saddr;
        ip->saddr = ip->daddr;
        ip->daddr = tmp_ip;

        icmp->type = 0;
        __u32 csum = bpf_ntohs(icmp->checksum);
        csum += 0x0800;
        if (csum > 0xFFFF)
            csum = (csum & 0xFFFF) + (csum >> 16);
        icmp->checksum = bpf_htons((__u16)csum);

        return XDP_TX;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "tx_icmp_reply", "description": "Convert ICMP echo request to reply and reflect TX", "packet_hex": t82_p_echo, "expected_action": "XDP_TX"},
                {"name": "pass_tcp", "description": "Pass TCP packet unchanged", "packet_hex": t82_p_tcp, "expected_action": "XDP_PASS"},
            ],
            validator_type="packet_bytes",
        )
    )

    # 83. repair_ptr_l3_vlan_push_and_retag (compilation_error: duplicate struct typedef)
    t83_p_in = binascii.hexlify(make_eth() + make_ipv4() + make_tcp()).decode()
    t83_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_ptr_l3_vlan_push_and_retag",
            application_category="protocol_transformation",
            difficulty="level_3",
            task_family="xdp_vlan_retag",
            template_family="xdp_head_adjust",
            semantic_signature="vlan_push_outer_service_tag+pass",
            diagnostic_category="compilation_error",
            failure_reason="Compilation error: redefinition of 'struct vlan_hdr' with conflicting member names",
            instruction="Fix the struct definition and push an 802.1ad (0x88A8) service VLAN tag (VID 500) ahead of incoming traffic using bpf_xdp_adjust_head(ctx, -4). Return XDP_PASS.",
            requirements=[
                "Define single unambiguous struct vlan_hdr",
                "Call bpf_xdp_adjust_head(ctx, -4)",
                "Write Ethernet header with ETH_P_8021AD (0x88A8)",
                "Write VLAN tag with VID 500",
                "Return XDP_PASS",
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

struct vlan_hdr { // Compilation error: redefinition of struct vlan_hdr
    __be16 tci;
    __be16 proto;
};

SEC("xdp")
int xdp_transform(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    struct ethhdr eth_copy = *eth;
    if (bpf_xdp_adjust_head(ctx, -4))
        return XDP_DROP;

    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;
    struct ethhdr *new_eth = data;
    if ((void *)(new_eth + 1) > data_end)
        return XDP_DROP;

    *new_eth = eth_copy;
    new_eth->h_proto = bpf_htons(0x88A8);

    struct vlan_hdr *vlh = (void *)(new_eth + 1);
    if ((void *)(vlh + 1) > data_end)
        return XDP_DROP;

    vlh->h_vlan_TCI = bpf_htons(500);
    vlh->h_vlan_encapsulated_proto = eth_copy.h_proto;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""faulty.c:11:8: error: redefinition of 'struct vlan_hdr'
struct vlan_hdr {
       ^
faulty.c:6:8: note: previous definition is here
struct vlan_hdr {
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
int xdp_transform(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    struct ethhdr eth_copy = *eth;
    if (bpf_xdp_adjust_head(ctx, -4))
        return XDP_DROP;

    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;
    struct ethhdr *new_eth = data;
    if ((void *)(new_eth + 1) > data_end)
        return XDP_DROP;

    #pragma unroll
    for (int i = 0; i < ETH_ALEN; i++) {
        new_eth->h_dest[i] = eth_copy.h_dest[i];
        new_eth->h_source[i] = eth_copy.h_source[i];
    }
    new_eth->h_proto = bpf_htons(0x88A8);

    struct vlan_hdr *vlh = (void *)(new_eth + 1);
    if ((void *)(vlh + 1) > data_end)
        return XDP_DROP;

    vlh->h_vlan_TCI = bpf_htons(500);
    vlh->h_vlan_encapsulated_proto = eth_copy.h_proto;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_push_vlan_500", "description": "Push outer 802.1ad VLAN tag 500", "packet_hex": t83_p_in, "expected_action": "XDP_PASS"},
                {"name": "pass_arp", "description": "Push outer VLAN tag on ARP frame", "packet_hex": t83_p_arp, "expected_action": "XDP_PASS"},
            ],
            validator_type="packet_bytes",
        )
    )

    # 84. repair_ptr_l3_gtp_u_decap (compilation_error: undefined constant IPPROTO_UDP)
    t84_p_gtp = binascii.hexlify(make_eth() + make_ipv4(proto=17) + make_udp(dst_port=2152) + b"\x30\xff\x00\x14\x00\x00\x00\x01" + make_ipv4() + make_tcp()).decode()
    t84_p_tcp = binascii.hexlify(make_eth() + make_ipv4(proto=6) + make_tcp()).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_ptr_l3_gtp_u_decap",
            application_category="protocol_transformation",
            difficulty="level_3",
            task_family="xdp_gtpu_decap",
            template_family="xdp_head_adjust",
            semantic_signature="gtpu_decap_36_bytes+pass",
            diagnostic_category="compilation_error",
            failure_reason="Compilation error: implicit declaration of function 'bpf_htons' and missing UDP constant header",
            instruction="Fix the missing includes in the GTP-U decapsulation program. Pop the 36-byte outer header (outer IPv4 20 bytes + UDP 8 bytes + GTP-U 8 bytes) for UDP port 2152 traffic, returning XDP_PASS.",
            requirements=[
                "Include <linux/in.h>, <linux/udp.h>, <bpf/bpf_endian.h>",
                "Check outer UDP port == 2152",
                "Call bpf_xdp_adjust_head(ctx, 36) to strip outer encapsulation",
                "Re-validate packet bounds and return XDP_PASS",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_transform(struct xdp_md *ctx) {
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
    if (ip->protocol != IPPROTO_UDP) // Compilation error: IPPROTO_UDP undeclared without linux/in.h
        return XDP_PASS;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""faulty.c:18:25: error: use of undeclared identifier 'IPPROTO_UDP'
    if (ip->protocol != IPPROTO_UDP)
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
int xdp_transform(struct xdp_md *ctx) {
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
    if (udp->dest != bpf_htons(2152))
        return XDP_PASS;

    struct ethhdr eth_copy = *eth;

    if (bpf_xdp_adjust_head(ctx, 36))
        return XDP_DROP;

    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;
    struct ethhdr *new_eth = data;
    if ((void *)(new_eth + 1) > data_end)
        return XDP_DROP;

    *new_eth = eth_copy;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_decap_gtpu", "description": "Decap GTP-U encapsulation and pass inner IP", "packet_hex": t84_p_gtp, "expected_action": "XDP_PASS"},
                {"name": "pass_tcp", "description": "Pass unencapsulated TCP frame unchanged", "packet_hex": t84_p_tcp, "expected_action": "XDP_PASS"},
            ],
            validator_type="packet_bytes",
        )
    )

    # 85. repair_ptr_l3_nptv6_prefix_rewrite (verifier_rejection: IPv6 address pointer arithmetic causing verifier bounds loss)
    t85_p_v6 = binascii.hexlify(make_eth(eth_type=0x86DD) + b"\x60\x00\x00\x00\x00\x14\x06\x40" + b"\xfd\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01" + b"\xfd\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02" + make_tcp()).decode()
    t85_p_v4 = binascii.hexlify(make_eth(eth_type=0x0800) + make_ipv4() + make_tcp()).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_ptr_l3_nptv6_prefix_rewrite",
            application_category="protocol_transformation",
            difficulty="level_3",
            task_family="xdp_nptv6",
            template_family="xdp_stateless_rewrite",
            semantic_signature="nptv6_prefix_translation+pass",
            diagnostic_category="verifier_rejection",
            failure_reason="Kernel verifier rejection: IPv6 address buffer dereferenced without bounds check against data_end",
            instruction="Fix the verifier bounds check when translating IPv6 source prefix (NPTv6). Rewrite the /64 prefix to fd00:0099::/64 and return XDP_PASS.",
            requirements=[
                "Check Ethernet and IPv6 header bounds (40 bytes for IPv6)",
                "Ensure (void *)(ip6 + 1) <= data_end",
                "Rewrite upper 8 bytes of source address to fd00:0099::",
                "Return XDP_PASS for all traffic",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct ipv6hdr {
    __be32 vtcf;
    __be16 payload_len;
    __u8 nexthdr;
    __u8 hop_limit;
    __u8 saddr[16];
    __u8 daddr[16];
};

SEC("xdp")
int xdp_transform(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IPV6))
        return XDP_PASS;

    struct ipv6hdr *ip6 = (void *)(eth + 1);
    // Verifier error: missing (ip6 + 1 <= data_end) check
    ip6->saddr[0] = 0xFD;
    ip6->saddr[1] = 0x00;
    ip6->saddr[2] = 0x00;
    ip6->saddr[3] = 0x99;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""0: R1=ctx(off=0,imm=0) R10=fp0
...
6: (73) *(u8 *)(r2 +22) = r0
invalid access to packet, id=0, off=22, size=1, R2_w=pkt(off=0,r=14,imm=0)
processed 7 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
-- END PROG LOAD LOG --""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct ipv6hdr {
    __be32 vtcf;
    __be16 payload_len;
    __u8 nexthdr;
    __u8 hop_limit;
    __u8 saddr[16];
    __u8 daddr[16];
};

SEC("xdp")
int xdp_transform(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IPV6))
        return XDP_PASS;

    struct ipv6hdr *ip6 = (void *)(eth + 1);
    if ((void *)(ip6 + 1) > data_end)
        return XDP_PASS;

    ip6->saddr[0] = 0xFD;
    ip6->saddr[1] = 0x00;
    ip6->saddr[2] = 0x00;
    ip6->saddr[3] = 0x99;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_nptv6_translate", "description": "Translate IPv6 /64 prefix to fd00:0099::", "packet_hex": t85_p_v6, "expected_action": "XDP_PASS"},
                {"name": "pass_ipv4", "description": "Pass IPv4 traffic unchanged", "packet_hex": t85_p_v4, "expected_action": "XDP_PASS"},
            ],
            validator_type="packet_bytes",
        )
    )

    # 86. repair_ptr_l3_geneve_tunnel_push (verifier_rejection: stack variable overflow when constructing outer tunnel headers)
    t86_p_in = binascii.hexlify(make_eth() + make_ipv4() + make_tcp()).decode()
    t86_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_ptr_l3_geneve_tunnel_push",
            application_category="protocol_transformation",
            difficulty="level_3",
            task_family="xdp_geneve_encap",
            template_family="xdp_head_adjust",
            semantic_signature="geneve_encap_push+pass",
            diagnostic_category="verifier_rejection",
            failure_reason="Kernel verifier rejection: stack frame limit exceeded by declaring large local buffer for tunnel encapsulation",
            instruction="Fix the stack memory limit error in the GENEVE tunnel encapsulation program. Push 50 bytes of outer headers (Ethernet + IPv4 + UDP 6081 + GENEVE) using bpf_xdp_adjust_head(ctx, -50), and return XDP_PASS.",
            requirements=[
                "Keep stack frame under 512 bytes",
                "Expand header by 50 bytes using bpf_xdp_adjust_head",
                "Write outer Ethernet, IPv4, UDP (dst port 6081), and GENEVE header",
                "Return XDP_PASS",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_transform(struct xdp_md *ctx) {
    // Verifier error: 600-byte stack array exceeds limit
    char temp_encap_buf[600];
    temp_encap_buf[0] = 0;

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    struct ethhdr eth_saved = *eth;
    if (bpf_xdp_adjust_head(ctx, -50))
        return XDP_DROP;

    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;
    struct ethhdr *new_eth = data;
    if ((void *)(new_eth + 1) > data_end)
        return XDP_DROP;

    *new_eth = eth_saved;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""Looks like the BPF stack limit of 512 bytes is exceeded.
The following functions exceed the limit:
xdp_transform: stack frame size is 624 bytes
processed 0 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
-- END PROG LOAD LOG --""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_transform(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    struct ethhdr eth_saved = *eth;
    if (bpf_xdp_adjust_head(ctx, -50))
        return XDP_DROP;

    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;
    struct ethhdr *new_eth = data;
    if ((void *)(new_eth + 1) > data_end)
        return XDP_DROP;

    *new_eth = eth_saved;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_geneve_encap", "description": "Push GENEVE tunnel encapsulation", "packet_hex": t86_p_in, "expected_action": "XDP_PASS"},
                {"name": "pass_arp", "description": "Pass ARP frame", "packet_hex": t86_p_arp, "expected_action": "XDP_PASS"},
            ],
            validator_type="packet_bytes",
        )
    )

    # 87. repair_ptr_l3_tcp_mss_clamping (verifier_rejection: unbounded packet write when modifying TCP options MSS)
    t87_p_syn_large_mss = binascii.hexlify(make_eth() + make_ipv4(proto=6) + make_tcp(flags=0x02, data_offset=6, payload=b"\x02\x04\x05\xb4")).decode() # MSS = 1460 (0x05B4)
    t87_p_syn_small_mss = binascii.hexlify(make_eth() + make_ipv4(proto=6) + make_tcp(flags=0x02, data_offset=6, payload=b"\x02\x04\x04\x00")).decode() # MSS = 1024 (0x0400)
    t87_p_ack = binascii.hexlify(make_eth() + make_ipv4(proto=6) + make_tcp(flags=0x10)).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_ptr_l3_tcp_mss_clamping",
            application_category="protocol_transformation",
            difficulty="level_3",
            task_family="xdp_mss_clamp",
            template_family="xdp_stateless_rewrite",
            semantic_signature="tcp_mss_clamp_1220+csum_update+pass",
            diagnostic_category="verifier_rejection",
            failure_reason="Kernel verifier rejection: TCP option bytes inspected and modified without verifying (opt + 4 <= data_end)",
            instruction="Fix the verifier boundary check when clamping TCP MSS. If an IPv4 TCP SYN packet carries an MSS option greater than 1220 bytes (0x04C4), clamp it to 1220 and recalculate the TCP checksum, returning XDP_PASS.",
            requirements=[
                "Check Ethernet, IPv4, and TCP headers with options bounds",
                "Ensure (void *)(tcp_opt + 4) <= data_end",
                "If TCP SYN contains MSS option (kind=2, len=4) and value > 1220, clamp to 1220",
                "Update TCP checksum accurately",
                "Return XDP_PASS for all traffic",
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
int xdp_transform(struct xdp_md *ctx) {
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

    if (tcp->syn && tcp->doff > 5) {
        __u8 *opt = (void *)(tcp + 1);
        // Verifier error: missing check on (opt + 4 <= data_end)
        if (opt[0] == 2 && opt[1] == 4) {
            __u16 *mss_val = (__u16 *)(opt + 2);
            if (bpf_ntohs(*mss_val) > 1220) {
                *mss_val = bpf_htons(1220);
            }
        }
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""0: R1=ctx(off=0,imm=0) R10=fp0
...
22: (71) r4 = *(u8 *)(r3 +20)
invalid access to packet, id=0, off=54, size=1, R3_w=pkt(off=34,r=34,imm=0)
processed 23 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
-- END PROG LOAD LOG --""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_transform(struct xdp_md *ctx) {
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

    if (tcp->syn && tcp->doff > 5) {
        __u8 *opt = (void *)(tcp + 1);
        if ((void *)(opt + 4) <= data_end) {
            if (opt[0] == 2 && opt[1] == 4) {
                __u16 *mss_val = (__u16 *)(opt + 2);
                __u16 old_mss = bpf_ntohs(*mss_val);
                if (old_mss > 1220) {
                    *mss_val = bpf_htons(1220);
                    __u32 csum = bpf_ntohs(tcp->check);
                    csum += old_mss + (~1220 & 0xFFFF);
                    while (csum >> 16)
                        csum = (csum & 0xFFFF) + (csum >> 16);
                    tcp->check = bpf_htons((__u16)csum);
                }
            }
        }
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_clamp_mss", "description": "Clamp MSS 1460 down to 1220 and update checksum", "packet_hex": t87_p_syn_large_mss, "expected_action": "XDP_PASS"},
                {"name": "pass_keep_mss", "description": "Keep smaller MSS 1024 unchanged", "packet_hex": t87_p_syn_small_mss, "expected_action": "XDP_PASS"},
                {"name": "pass_ack", "description": "Pass ACK traffic unchanged", "packet_hex": t87_p_ack, "expected_action": "XDP_PASS"},
            ],
            validator_type="packet_bytes",
        )
    )

    # 88. repair_ptr_l3_dual_vlan_rewriting (behavioral_logic_bug: swapped inner and outer VLAN tags during rewriting)
    t88_p_qinq = binascii.hexlify(make_eth(vlan=100, vlan_inner=200) + make_ipv4() + make_tcp()).decode()
    t88_p_untag = binascii.hexlify(make_eth() + make_ipv4() + make_tcp()).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_ptr_l3_dual_vlan_rewriting",
            application_category="protocol_transformation",
            difficulty="level_3",
            task_family="xdp_qinq_rewrite",
            template_family="xdp_stateless_rewrite",
            semantic_signature="qinq_retag_outer300_inner400+pass",
            diagnostic_category="behavioral_logic_bug",
            failure_reason="Behavioral bug: swapped outer and inner VLAN IDs during QinQ retagging (wrote 400 to outer and 300 to inner)",
            instruction="Fix the QinQ retagging program to write outer VLAN VID = 300 and inner VLAN VID = 400 when processing QinQ double-tagged frames (0x88A8 followed by 0x8100), returning XDP_PASS.",
            requirements=[
                "Parse outer and inner 802.1Q/802.1ad VLAN tags safely",
                "Rewrite outer VLAN VID to 300 (preserving PCP/CFI)",
                "Rewrite inner VLAN VID to 400 (preserving PCP/CFI)",
                "Return XDP_PASS for all traffic",
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
int xdp_transform(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto == bpf_htons(0x88A8)) {
        struct vlan_hdr *vlh_out = (void *)(eth + 1);
        if ((void *)(vlh_out + 1) > data_end)
            return XDP_PASS;

        if (vlh_out->h_vlan_encapsulated_proto == bpf_htons(ETH_P_8021Q)) {
            struct vlan_hdr *vlh_in = (void *)(vlh_out + 1);
            if ((void *)(vlh_in + 1) > data_end)
                return XDP_PASS;

            // Behavioral bug: swapped outer VID 300 and inner VID 400
            __u16 tci_out = bpf_ntohs(vlh_out->h_vlan_TCI);
            vlh_out->h_vlan_TCI = bpf_htons((tci_out & 0xF000) | 400);

            __u16 tci_in = bpf_ntohs(vlh_in->h_vlan_TCI);
            vlh_in->h_vlan_TCI = bpf_htons((tci_in & 0xF000) | 300);
        }
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""FAIL: test_case 'verify_qinq_retag' failed:
  Expected outer VID: 300, inner VID: 400
  Observed outer VID: 400, inner VID: 300 (swapped VLAN identifiers)
1 of 2 test cases failed.""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

SEC("xdp")
int xdp_transform(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto == bpf_htons(0x88A8)) {
        struct vlan_hdr *vlh_out = (void *)(eth + 1);
        if ((void *)(vlh_out + 1) > data_end)
            return XDP_PASS;

        if (vlh_out->h_vlan_encapsulated_proto == bpf_htons(ETH_P_8021Q)) {
            struct vlan_hdr *vlh_in = (void *)(vlh_out + 1);
            if ((void *)(vlh_in + 1) > data_end)
                return XDP_PASS;

            __u16 tci_out = bpf_ntohs(vlh_out->h_vlan_TCI);
            vlh_out->h_vlan_TCI = bpf_htons((tci_out & 0xF000) | 300);

            __u16 tci_in = bpf_ntohs(vlh_in->h_vlan_TCI);
            vlh_in->h_vlan_TCI = bpf_htons((tci_in & 0xF000) | 400);
        }
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_retag_qinq", "description": "Retag QinQ outer VID to 300 and inner VID to 400", "packet_hex": t88_p_qinq, "expected_action": "XDP_PASS"},
                {"name": "pass_untagged", "description": "Pass untagged frame unchanged", "packet_hex": t88_p_untag, "expected_action": "XDP_PASS"},
            ],
            validator_type="packet_bytes",
        )
    )

    # 89. repair_ptr_l3_nat_tcp_csum_fold (behavioral_logic_bug: incorrect pseudo-header checksum fold causing invalid TCP checksums)
    t89_p_in = binascii.hexlify(make_eth() + make_ipv4(src_ip="192.168.1.10", dst_ip="192.168.1.20") + make_tcp(dst_port=80)).decode()
    t89_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_ptr_l3_nat_tcp_csum_fold",
            application_category="protocol_transformation",
            difficulty="level_3",
            task_family="xdp_tcp_csum_fold",
            template_family="xdp_stateless_rewrite",
            semantic_signature="tcp_pseudo_header_csum_repair+pass",
            diagnostic_category="behavioral_logic_bug",
            failure_reason="Behavioral bug: TCP checksum delta used addition instead of subtraction for old IP addresses, corrupting TCP pseudo-header checksum",
            instruction="Fix the pseudo-header checksum differential calculation when rewriting the destination IP to 10.10.10.10 so that the TCP checksum is correctly updated.",
            requirements=[
                "Check Ethernet, IPv4, and TCP bounds",
                "Rewrite ip->daddr to 10.10.10.10",
                "Apply accurate 1's complement delta to both ip->check and tcp->check",
                "Return XDP_PASS for all traffic",
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
int xdp_transform(struct xdp_md *ctx) {
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

    __be32 old_dst = ip->daddr;
    __be32 new_dst = bpf_htonl(0x0A0A0A0A);
    ip->daddr = new_dst;

    __u32 old_hi = bpf_ntohl(old_dst) >> 16;
    __u32 old_lo = bpf_ntohl(old_dst) & 0xFFFF;
    __u32 new_hi = 0x0A0A;
    __u32 new_lo = 0x0A0A;

    // Behavioral bug: inverted sign in delta for TCP checksum
    __u32 tcpcsum = bpf_ntohs(tcp->check);
    tcpcsum += new_hi + new_lo + (~old_hi & 0xFFFF) + (~old_lo & 0xFFFF);
    while (tcpcsum >> 16)
        tcpcsum = (tcpcsum & 0xFFFF) + (tcpcsum >> 16);
    tcp->check = bpf_htons((__u16)tcpcsum);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""FAIL: test_case 'verify_tcp_csum' failed:
  Expected TCP checksum: 0x34C8
  Observed TCP checksum: 0x9B37 (inverted delta sign applied to pseudo-header sum)
1 of 2 test cases failed.""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_transform(struct xdp_md *ctx) {
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

    __be32 old_dst = ip->daddr;
    __be32 new_dst = bpf_htonl(0x0A0A0A0A);
    ip->daddr = new_dst;

    __u32 old_hi = bpf_ntohl(old_dst) >> 16;
    __u32 old_lo = bpf_ntohl(old_dst) & 0xFFFF;
    __u32 new_hi = 0x0A0A;
    __u32 new_lo = 0x0A0A;

    // IP checksum
    __u32 ipcsum = bpf_ntohs(ip->check);
    ipcsum += old_hi + old_lo + (~new_hi & 0xFFFF) + (~new_lo & 0xFFFF);
    while (ipcsum >> 16)
        ipcsum = (ipcsum & 0xFFFF) + (ipcsum >> 16);
    ip->check = bpf_htons((__u16)ipcsum);

    // TCP pseudo-header checksum
    __u32 tcpcsum = bpf_ntohs(tcp->check);
    tcpcsum += old_hi + old_lo + (~new_hi & 0xFFFF) + (~new_lo & 0xFFFF);
    while (tcpcsum >> 16)
        tcpcsum = (tcpcsum & 0xFFFF) + (tcpcsum >> 16);
    tcp->check = bpf_htons((__u16)tcpcsum);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_tcp_dnat", "description": "DNAT destination IP and update TCP pseudo-checksum", "packet_hex": t89_p_in, "expected_action": "XDP_PASS"},
                {"name": "pass_arp", "description": "Pass ARP frame unchanged", "packet_hex": t89_p_arp, "expected_action": "XDP_PASS"},
            ],
            validator_type="packet_bytes",
        )
    )

    # 90. repair_ptr_l3_icmp_error_payload_gen (behavioral_logic_bug: inverted layer 3 addresses in generated ICMP time-exceeded payload)
    t90_p_expired = binascii.hexlify(make_eth(dst_mac="52:54:00:12:34:56", src_mac="52:54:00:65:43:21") + make_ipv4(src_ip="10.0.0.1", dst_ip="10.0.0.2", ttl=1, proto=17) + make_udp()).decode()
    t90_p_valid = binascii.hexlify(make_eth() + make_ipv4(ttl=64) + make_udp()).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_ptr_l3_icmp_error_payload_gen",
            application_category="protocol_transformation",
            difficulty="level_3",
            task_family="xdp_icmp_time_exceeded",
            template_family="xdp_packet_reflector",
            semantic_signature="icmp_time_exceeded_gen+tx",
            diagnostic_category="behavioral_logic_bug",
            failure_reason="Behavioral bug: outer IPv4 source address in generated ICMP Time Exceeded packet was set to sender IP instead of router gateway IP",
            instruction="Fix the ICMP Time Exceeded (type 11, code 0) packet generator. When an incoming packet has TTL == 1, send an ICMP Time Exceeded packet back to the sender (dst = original src, src = router IP 192.168.1.1) and return XDP_TX.",
            requirements=[
                "Identify packets with IPv4 TTL <= 1",
                "Set destination IP = original sender IP",
                "Set source IP = router IP 192.168.1.1 (0xC0A80101)",
                "Set ICMP type = 11 (Time Exceeded), code = 0",
                "Transmit response with XDP_TX; pass valid traffic with XDP_PASS",
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
int xdp_transform(struct xdp_md *ctx) {
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

    if (ip->ttl <= 1) {
        // Behavioral bug: set both src and dst to original src
        __be32 orig_src = ip->saddr;
        ip->daddr = orig_src;
        ip->saddr = orig_src; // Should be gateway IP 192.168.1.1

        __u8 tmp_mac[ETH_ALEN];
        #pragma unroll
        for (int i = 0; i < ETH_ALEN; i++) {
            tmp_mac[i] = eth->h_dest[i];
            eth->h_dest[i] = eth->h_source[i];
            eth->h_source[i] = tmp_mac[i];
        }

        ip->protocol = IPPROTO_ICMP;
        ip->ttl = 64;

        struct icmphdr *icmp = (void *)(ip + 1);
        if ((void *)(icmp + 1) > data_end)
            return XDP_DROP;

        icmp->type = 11; // Time Exceeded
        icmp->code = 0;
        icmp->checksum = 0;

        return XDP_TX;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""FAIL: test_case 'generate_time_exceeded' failed:
  Expected ICMP source IP: 192.168.1.1 (router gateway address)
  Observed ICMP source IP: 10.0.0.1 (reflection bug: router set source IP to sender IP)
1 of 2 test cases failed.""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_transform(struct xdp_md *ctx) {
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

    if (ip->ttl <= 1) {
        __be32 orig_src = ip->saddr;
        ip->daddr = orig_src;
        ip->saddr = bpf_htonl(0xC0A80101); // 192.168.1.1 router address

        __u8 tmp_mac[ETH_ALEN];
        #pragma unroll
        for (int i = 0; i < ETH_ALEN; i++) {
            tmp_mac[i] = eth->h_dest[i];
            eth->h_dest[i] = eth->h_source[i];
            eth->h_source[i] = tmp_mac[i];
        }

        ip->protocol = IPPROTO_ICMP;
        ip->ttl = 64;

        struct icmphdr *icmp = (void *)(ip + 1);
        if ((void *)(icmp + 1) > data_end)
            return XDP_DROP;

        icmp->type = 11;
        icmp->code = 0;
        icmp->checksum = 0;

        return XDP_TX;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "tx_time_exceeded", "description": "Generate ICMP Time Exceeded on TTL == 1 and reflect TX", "packet_hex": t90_p_expired, "expected_action": "XDP_TX"},
                {"name": "pass_valid_ttl", "description": "Pass packet with TTL > 1 unchanged", "packet_hex": t90_p_valid, "expected_action": "XDP_PASS"},
            ],
            validator_type="packet_bytes",
        )
    )

    return tasks
