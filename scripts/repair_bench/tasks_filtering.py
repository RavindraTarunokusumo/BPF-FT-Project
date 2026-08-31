#!/usr/bin/env python3
"""
Task definitions for packet_filtering_security (30 tasks).
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


def get_filtering_tasks() -> List[RepairTaskSpec]:
    tasks: List[RepairTaskSpec] = []

    # =========================================================================
    # LEVEL 1
    # =========================================================================

    # 1. repair_pfs_l1_tcp_telnet_drop (compilation_error: missing <linux/tcp.h>)
    t1_p_drop = binascii.hexlify(make_eth() + make_ipv4(proto=6) + make_tcp(dst_port=23)).decode()
    t1_p_pass = binascii.hexlify(make_eth() + make_ipv4(proto=6) + make_tcp(dst_port=80)).decode()
    t1_p_udp = binascii.hexlify(make_eth() + make_ipv4(proto=17) + make_udp(dst_port=23)).decode()
    t1_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()
    t1_p_trunc = binascii.hexlify(make_eth() + make_ipv4(proto=6)[:12]).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_pfs_l1_tcp_telnet_drop",
            application_category="packet_filtering_security",
            difficulty="level_1",
            task_family="xdp_port_filter",
            template_family="xdp_stateless_filter",
            semantic_signature="ipv4+tcp_dport_23+drop",
            diagnostic_category="compilation_error",
            failure_reason="Missing include header <linux/tcp.h>, resulting in unknown type name 'struct tcphdr'",
            instruction="Fix the XDP program to compile and drop IPv4 TCP packets destined to Telnet port 23, while passing all other traffic (other TCP ports, UDP, ICMP, non-IPv4, and malformed packets).",
            requirements=[
                "Check Ethernet and IPv4 bounds",
                "Verify Ethernet protocol is ETH_P_IP (0x0800)",
                "Verify IP protocol is IPPROTO_TCP",
                "Parse variable IHL (ip->ihl * 4) safely",
                "Include required headers <linux/tcp.h>",
                "Drop packets with TCP dport 23; return XDP_PASS for other packets",
                "GPL license and SEC(\"xdp\") entry point",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
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
    if (ip->ihl < 5)
        return XDP_PASS;
    __u32 ip_len = (__u32)ip->ihl * 4;
    if ((void *)ip + ip_len > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip_len;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    if (tcp->dest == bpf_htons(23))
        return XDP_DROP;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""faulty.c:26:12: error: variable has incomplete type 'struct tcphdr'
    struct tcphdr *tcp = (void *)ip + ip_len;
           ^
faulty.c:26:12: note: forward declaration of 'struct tcphdr'
faulty.c:27:18: error: invalid application of 'sizeof' to an incomplete type 'struct tcphdr'
    if ((void *)(tcp + 1) > data_end)
                 ^~~~~~~
faulty.c:30:12: error: member access into incomplete type 'struct tcphdr'
    if (tcp->dest == bpf_htons(23))
           ^
3 errors generated.""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
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
    if (ip->ihl < 5)
        return XDP_PASS;
    __u32 ip_len = (__u32)ip->ihl * 4;
    if ((void *)ip + ip_len > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip_len;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    if (tcp->dest == bpf_htons(23))
        return XDP_DROP;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "drop_tcp_23", "description": "Drop IPv4 TCP dport 23", "packet_hex": t1_p_drop, "expected_action": "XDP_DROP"},
                {"name": "pass_tcp_80", "description": "Pass IPv4 TCP dport 80", "packet_hex": t1_p_pass, "expected_action": "XDP_PASS"},
                {"name": "pass_udp_23", "description": "Pass IPv4 UDP dport 23", "packet_hex": t1_p_udp, "expected_action": "XDP_PASS"},
                {"name": "pass_arp", "description": "Pass ARP non-IP packet", "packet_hex": t1_p_arp, "expected_action": "XDP_PASS"},
                {"name": "pass_truncated", "description": "Pass truncated IPv4 safely", "packet_hex": t1_p_trunc, "expected_action": "XDP_PASS"},
            ],
        )
    )

    # 2. repair_pfs_l1_udp_dns_block (compilation_error: struct member mismatch udp->dest_port vs udp->dest)
    t2_p_drop = binascii.hexlify(make_eth() + make_ipv4(proto=17) + make_udp(dst_port=53)).decode()
    t2_p_pass = binascii.hexlify(make_eth() + make_ipv4(proto=17) + make_udp(dst_port=5353)).decode()
    t2_p_tcp = binascii.hexlify(make_eth() + make_ipv4(proto=6) + make_tcp(dst_port=53)).decode()
    t2_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()
    t2_p_trunc = binascii.hexlify(make_eth() + make_ipv4(proto=17)[:14]).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_pfs_l1_udp_dns_block",
            application_category="packet_filtering_security",
            difficulty="level_1",
            task_family="xdp_port_filter",
            template_family="xdp_stateless_filter",
            semantic_signature="ipv4+udp_dport_53+drop",
            diagnostic_category="compilation_error",
            failure_reason="Struct member mismatch: accessing 'udp->dest_port' instead of 'udp->dest' in struct udphdr",
            instruction="Fix the compilation error in the XDP program to block IPv4 UDP packets targeting DNS port 53 while passing other traffic.",
            requirements=[
                "Check Ethernet and IPv4 bounds",
                "Verify IP protocol is IPPROTO_UDP",
                "Use correct member 'dest' on struct udphdr",
                "Drop packets with UDP dport 53; pass other traffic",
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
int xdp_filter(struct xdp_md *ctx) {
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

    if (udp->dest_port == bpf_htons(53))
        return XDP_DROP;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""faulty.c:28:14: error: no member named 'dest_port' in 'struct udphdr'; did you mean 'dest'?
    if (udp->dest_port == bpf_htons(53))
             ^~~~~~~~~
             dest
/usr/include/linux/udp.h:23:9: note: 'dest' declared here
        __be16  dest;
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
int xdp_filter(struct xdp_md *ctx) {
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

    if (udp->dest == bpf_htons(53))
        return XDP_DROP;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "drop_udp_53", "description": "Drop IPv4 UDP dport 53", "packet_hex": t2_p_drop, "expected_action": "XDP_DROP"},
                {"name": "pass_udp_5353", "description": "Pass IPv4 UDP dport 5353", "packet_hex": t2_p_pass, "expected_action": "XDP_PASS"},
                {"name": "pass_tcp_53", "description": "Pass IPv4 TCP dport 53", "packet_hex": t2_p_tcp, "expected_action": "XDP_PASS"},
                {"name": "pass_arp", "description": "Pass ARP packet", "packet_hex": t2_p_arp, "expected_action": "XDP_PASS"},
                {"name": "pass_trunc", "description": "Pass truncated UDP safely", "packet_hex": t2_p_trunc, "expected_action": "XDP_PASS"},
            ],
        )
    )

    # 3. repair_pfs_l1_icmp_echo_filter (compilation_error: invalid type comparison icmp->type == "8")
    t3_p_drop = binascii.hexlify(make_eth() + make_ipv4(proto=1) + make_icmp(icmp_type=8)).decode()
    t3_p_pass = binascii.hexlify(make_eth() + make_ipv4(proto=1) + make_icmp(icmp_type=0)).decode()
    t3_p_tcp = binascii.hexlify(make_eth() + make_ipv4(proto=6) + make_tcp()).decode()
    t3_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()
    t3_p_trunc = binascii.hexlify(make_eth() + make_ipv4(proto=1)[:10]).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_pfs_l1_icmp_echo_filter",
            application_category="packet_filtering_security",
            difficulty="level_1",
            task_family="xdp_icmp_filter",
            template_family="xdp_stateless_filter",
            semantic_signature="ipv4+icmp_echo+drop",
            diagnostic_category="compilation_error",
            failure_reason="Invalid type comparison: comparing integer icmp->type against string literal \"8\"",
            instruction="Fix the compilation error in the XDP filter to drop IPv4 ICMP Echo Request packets (type 8, ICMP_ECHO) and pass all other traffic.",
            requirements=[
                "Check Ethernet and IPv4 bounds",
                "Verify IP protocol is IPPROTO_ICMP",
                "Compare icmp->type with numerical constant 8 (or ICMP_ECHO)",
                "Drop ICMP Echo requests, pass ICMP Echo replies and other traffic",
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
int xdp_filter(struct xdp_md *ctx) {
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

    if (icmp->type == "8")
        return XDP_DROP;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""faulty.c:28:20: error: comparison between pointer and integer ('__u8' (aka 'unsigned char') and 'char *')
    if (icmp->type == "8")
        ~~~~~~~~~~ ^  ~~~
1 error generated.""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
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

    if (icmp->type == 8)
        return XDP_DROP;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "drop_icmp_echo", "description": "Drop ICMP Echo Request type 8", "packet_hex": t3_p_drop, "expected_action": "XDP_DROP"},
                {"name": "pass_icmp_reply", "description": "Pass ICMP Echo Reply type 0", "packet_hex": t3_p_pass, "expected_action": "XDP_PASS"},
                {"name": "pass_tcp", "description": "Pass TCP packet", "packet_hex": t3_p_tcp, "expected_action": "XDP_PASS"},
                {"name": "pass_arp", "description": "Pass ARP packet", "packet_hex": t3_p_arp, "expected_action": "XDP_PASS"},
                {"name": "pass_trunc", "description": "Pass truncated ICMP safely", "packet_hex": t3_p_trunc, "expected_action": "XDP_PASS"},
            ],
        )
    )

    # 4. repair_pfs_l1_eth_type_check (compilation_error: missing bpf_endian.h for bpf_htons)
    t4_p_drop = binascii.hexlify(make_eth() + make_ipv4(proto=17) + make_udp(dst_port=69)).decode()
    t4_p_pass = binascii.hexlify(make_eth() + make_ipv4(proto=17) + make_udp(dst_port=80)).decode()
    t4_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()
    t4_p_tcp = binascii.hexlify(make_eth() + make_ipv4(proto=6) + make_tcp(dst_port=69)).decode()
    t4_p_trunc = binascii.hexlify(make_eth()[:10]).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_pfs_l1_eth_type_check",
            application_category="packet_filtering_security",
            difficulty="level_1",
            task_family="xdp_port_filter",
            template_family="xdp_stateless_filter",
            semantic_signature="ipv4+udp_dport_69_tftp+drop",
            diagnostic_category="compilation_error",
            failure_reason="Undefined identifier 'bpf_htons' due to missing include <bpf/bpf_endian.h>",
            instruction="Fix the missing include in the XDP filter so it compiles and drops UDP TFTP traffic (port 69) while passing all other traffic.",
            requirements=[
                "Include <bpf/bpf_endian.h>",
                "Check packet bounds for Ethernet, IP, and UDP",
                "Drop UDP packets with destination port 69",
                "Return XDP_PASS for all non-matching and truncated packets",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
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

    if (udp->dest == bpf_htons(69))
        return XDP_DROP;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""faulty.c:14:25: error: call to undeclared function 'bpf_htons'; ISO C99 and later do not support implicit function declarations [-Wimplicit-function-declaration]
    if (eth->h_proto != bpf_htons(ETH_P_IP))
                        ^
faulty.c:30:22: error: call to undeclared function 'bpf_htons'; ISO C99 and later do not support implicit function declarations [-Wimplicit-function-declaration]
    if (udp->dest == bpf_htons(69))
                     ^
2 errors generated.""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
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

    if (udp->dest == bpf_htons(69))
        return XDP_DROP;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "drop_udp_69", "description": "Drop UDP TFTP port 69", "packet_hex": t4_p_drop, "expected_action": "XDP_DROP"},
                {"name": "pass_udp_80", "description": "Pass UDP port 80", "packet_hex": t4_p_pass, "expected_action": "XDP_PASS"},
                {"name": "pass_tcp_69", "description": "Pass TCP port 69", "packet_hex": t4_p_tcp, "expected_action": "XDP_PASS"},
                {"name": "pass_arp", "description": "Pass ARP frame", "packet_hex": t4_p_arp, "expected_action": "XDP_PASS"},
                {"name": "pass_trunc", "description": "Pass truncated Ethernet frame", "packet_hex": t4_p_trunc, "expected_action": "XDP_PASS"},
            ],
        )
    )

    # 5. repair_pfs_l1_ipv4_version_check (verifier_rejection: missing packet bounds check before reading ip->version)
    t5_p_drop = binascii.hexlify(make_eth() + make_ipv4(src_ip="10.0.0.99")).decode()
    t5_p_pass = binascii.hexlify(make_eth() + make_ipv4(src_ip="192.168.1.10")).decode()
    t5_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()
    t5_p_trunc = binascii.hexlify(make_eth() + b"\x45\x00").decode()
    t5_p_tcp = binascii.hexlify(make_eth() + make_ipv4(src_ip="10.0.0.1") + make_tcp()).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_pfs_l1_ipv4_version_check",
            application_category="packet_filtering_security",
            difficulty="level_1",
            task_family="xdp_ip_filter",
            template_family="xdp_stateless_filter",
            semantic_signature="ipv4+src_10_0_0_99+drop",
            diagnostic_category="verifier_rejection",
            failure_reason="Kernel verifier rejection: accessing struct iphdr fields before validating that ip + 1 <= data_end",
            instruction="Fix the kernel verifier rejection by adding the missing bounds check for the IPv4 header before reading ip->saddr or ip->version. Drop packets from source 10.0.0.99 and pass all others.",
            requirements=[
                "Check Ethernet bounds (eth + 1 <= data_end)",
                "Check IPv4 bounds (ip + 1 <= data_end)",
                "Drop IPv4 packets with saddr == 10.0.0.99 (bpf_htonl(0x0A000063))",
                "Pass other packets safely",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    // Verifier error: accessing ip->saddr without checking (ip + 1 <= data_end)
    if (ip->saddr == bpf_htonl(0x0A000063))
        return XDP_DROP;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""0: R1=ctx(off=0,imm=0) R10=fp0
; void *data = (void *)(long)ctx->data;
1: (61) r2 = *(u32 *)(r1 +0)
; void *data_end = (void *)(long)ctx->data_end;
2: (61) r1 = *(u32 *)(r1 +4)
; if ((void *)(eth + 1) > data_end)
3: r3 = r2
4: (07) r3 += 14
5: (2d) if r3 > r1 goto pc+9
; if (ip->saddr == bpf_htonl(0x0A000063))
6: (61) r4 = *(u32 *)(r2 +26)
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
int xdp_filter(struct xdp_md *ctx) {
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

    if (ip->saddr == bpf_htonl(0x0A000063))
        return XDP_DROP;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "drop_10_0_0_99", "description": "Drop IPv4 source 10.0.0.99", "packet_hex": t5_p_drop, "expected_action": "XDP_DROP"},
                {"name": "pass_192_168_1_10", "description": "Pass IPv4 source 192.168.1.10", "packet_hex": t5_p_pass, "expected_action": "XDP_PASS"},
                {"name": "pass_10_0_0_1", "description": "Pass IPv4 source 10.0.0.1", "packet_hex": t5_p_tcp, "expected_action": "XDP_PASS"},
                {"name": "pass_arp", "description": "Pass ARP frame", "packet_hex": t5_p_arp, "expected_action": "XDP_PASS"},
                {"name": "pass_trunc", "description": "Pass truncated IPv4 header safely", "packet_hex": t5_p_trunc, "expected_action": "XDP_PASS"},
            ],
        )
    )

    # 6. repair_pfs_l1_tcp_port_range_drop (verifier_rejection: invalid packet pointer arithmetic exceeding boundary check)
    t6_p_drop = binascii.hexlify(make_eth() + make_ipv4(proto=6) + make_tcp(dst_port=135)).decode()
    t6_p_pass = binascii.hexlify(make_eth() + make_ipv4(proto=6) + make_tcp(dst_port=443)).decode()
    t6_p_udp = binascii.hexlify(make_eth() + make_ipv4(proto=17) + make_udp(dst_port=135)).decode()
    t6_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()
    t6_p_trunc = binascii.hexlify(make_eth() + make_ipv4(proto=6)[:16]).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_pfs_l1_tcp_port_range_drop",
            application_category="packet_filtering_security",
            difficulty="level_1",
            task_family="xdp_port_filter",
            template_family="xdp_stateless_filter",
            semantic_signature="ipv4+tcp_dport_135_139+drop",
            diagnostic_category="verifier_rejection",
            failure_reason="Kernel verifier rejection: TCP header bounds check compared against incorrect offset causing R1 invalid access",
            instruction="Fix the verifier bounds check so the program correctly parses the TCP header and drops NetBIOS TCP ports 135 through 139, passing all other traffic.",
            requirements=[
                "Check Ethernet, IPv4, and TCP bounds correctly",
                "Ensure (void *)(tcp + 1) <= data_end before reading tcp->dest",
                "Drop TCP packets with destination port >= 135 and <= 139",
                "Pass all other traffic safely",
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
int xdp_filter(struct xdp_md *ctx) {
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
    // Fault: check is comparing (void *)tcp > data_end instead of (void *)(tcp + 1) > data_end
    if ((void *)tcp >= data_end)
        return XDP_PASS;

    __u16 dport = bpf_ntohs(tcp->dest);
    if (dport >= 135 && dport <= 139)
        return XDP_DROP;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""0: R1=ctx(off=0,imm=0) R10=fp0
; struct tcphdr *tcp = (void *)ip + ip_len;
...
18: (2d) if r3 >= r1 goto pc+8
; __u16 dport = bpf_ntohs(tcp->dest);
19: (69) r4 = *(u16 *)(r3 +2)
invalid access to packet, id=0, off=36, size=2, R3_w=pkt(off=34,r=34,imm=0)
processed 20 insns (limit 1000000) max_states_per_insn 0 total_states 1 peak_states 1 mark_read 0
-- END PROG LOAD LOG --""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
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

    __u16 dport = bpf_ntohs(tcp->dest);
    if (dport >= 135 && dport <= 139)
        return XDP_DROP;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "drop_tcp_135", "description": "Drop TCP dport 135", "packet_hex": t6_p_drop, "expected_action": "XDP_DROP"},
                {"name": "pass_tcp_443", "description": "Pass TCP dport 443", "packet_hex": t6_p_pass, "expected_action": "XDP_PASS"},
                {"name": "pass_udp_135", "description": "Pass UDP dport 135", "packet_hex": t6_p_udp, "expected_action": "XDP_PASS"},
                {"name": "pass_arp", "description": "Pass ARP packet", "packet_hex": t6_p_arp, "expected_action": "XDP_PASS"},
                {"name": "pass_trunc", "description": "Pass truncated TCP safely", "packet_hex": t6_p_trunc, "expected_action": "XDP_PASS"},
            ],
        )
    )

    # 7. repair_pfs_l1_udp_port_wildcard (verifier_rejection: accessing UDP without checking ip->ihl variable offset)
    t7_p_drop = binascii.hexlify(make_eth() + make_ipv4(proto=17) + make_udp(dst_port=1900)).decode()
    t7_p_pass = binascii.hexlify(make_eth() + make_ipv4(proto=17) + make_udp(dst_port=80)).decode()
    t7_p_tcp = binascii.hexlify(make_eth() + make_ipv4(proto=6) + make_tcp(dst_port=1900)).decode()
    t7_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()
    t7_p_trunc = binascii.hexlify(make_eth() + make_ipv4(proto=17)[:15]).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_pfs_l1_udp_port_wildcard",
            application_category="packet_filtering_security",
            difficulty="level_1",
            task_family="xdp_port_filter",
            template_family="xdp_stateless_filter",
            semantic_signature="ipv4+udp_dport_1900_ssdp+drop",
            diagnostic_category="verifier_rejection",
            failure_reason="Kernel verifier rejection: pointer arithmetic with unchecked variable ihl offset leads to invalid packet access",
            instruction="Fix the kernel verifier failure by validating the variable IP header length and ensuring the UDP header pointer is within data_end before dereferencing. Drop SSDP UDP port 1900.",
            requirements=[
                "Check Ethernet and IPv4 bounds",
                "Verify ip->ihl >= 5 and (void *)ip + ip->ihl * 4 <= data_end",
                "Verify (void *)(udp + 1) <= data_end",
                "Drop UDP packets with dport 1900 (SSDP); pass all others",
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
int xdp_filter(struct xdp_md *ctx) {
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

    // Fault: unchecked variable length offset
    struct udphdr *udp = (void *)ip + (ip->ihl * 4);
    if (udp->dest == bpf_htons(1900))
        return XDP_DROP;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""0: R1=ctx(off=0,imm=0) R10=fp0
; struct udphdr *udp = (void *)ip + (ip->ihl * 4);
14: (71) r4 = *(u8 *)(r2 +14)
15: (57) r4 &= 15
16: (67) r4 <<= 2
17: (0f) r2 += r4
; if (udp->dest == bpf_htons(1900))
18: (69) r1 = *(u16 *)(r2 +2)
invalid access to packet, id=1, off=2, size=2, R2_w=pkt(off=14,r=34,var_off=(0x0; 0x3c),imm=0)
processed 19 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
-- END PROG LOAD LOG --""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
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

    if (udp->dest == bpf_htons(1900))
        return XDP_DROP;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "drop_udp_1900", "description": "Drop UDP SSDP port 1900", "packet_hex": t7_p_drop, "expected_action": "XDP_DROP"},
                {"name": "pass_udp_80", "description": "Pass UDP port 80", "packet_hex": t7_p_pass, "expected_action": "XDP_PASS"},
                {"name": "pass_tcp_1900", "description": "Pass TCP port 1900", "packet_hex": t7_p_tcp, "expected_action": "XDP_PASS"},
                {"name": "pass_arp", "description": "Pass ARP packet", "packet_hex": t7_p_arp, "expected_action": "XDP_PASS"},
                {"name": "pass_trunc", "description": "Pass truncated packet safely", "packet_hex": t7_p_trunc, "expected_action": "XDP_PASS"},
            ],
        )
    )

    # 8. repair_pfs_l1_icmp_type_mask (verifier_rejection: dereferencing packet pointer after data_end check without guarding offset)
    t8_p_drop = binascii.hexlify(make_eth() + make_ipv4(proto=1) + make_icmp(icmp_type=13)).decode() # Timestamp request
    t8_p_pass = binascii.hexlify(make_eth() + make_ipv4(proto=1) + make_icmp(icmp_type=0)).decode()
    t8_p_tcp = binascii.hexlify(make_eth() + make_ipv4(proto=6) + make_tcp()).decode()
    t8_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()
    t8_p_trunc = binascii.hexlify(make_eth() + make_ipv4(proto=1)[:8]).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_pfs_l1_icmp_type_mask",
            application_category="packet_filtering_security",
            difficulty="level_1",
            task_family="xdp_icmp_filter",
            template_family="xdp_stateless_filter",
            semantic_signature="ipv4+icmp_type_13_timestamp+drop",
            diagnostic_category="verifier_rejection",
            failure_reason="Kernel verifier rejection: ICMP header pointer arithmetic checked using '>' instead of '> data_end' offset",
            instruction="Fix the kernel verifier rejection in the ICMP filter to drop ICMP Timestamp Request packets (type 13) while passing all other traffic.",
            requirements=[
                "Check Ethernet, IPv4, and ICMP bounds accurately",
                "Ensure (void *)(icmp + 1) <= data_end",
                "Drop ICMP packets with type == 13; pass all other traffic",
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
int xdp_filter(struct xdp_md *ctx) {
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

    struct icmphdr *icmp = (void *)(ip + 1);
    // Fault: condition is > (void *)0 instead of > data_end
    if ((void *)(icmp + 1) == (void *)0)
        return XDP_PASS;

    if (icmp->type == 13)
        return XDP_DROP;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""0: R1=ctx(off=0,imm=0) R10=fp0
; struct icmphdr *icmp = (void *)(ip + 1);
...
10: (2d) if r2 == 0x0 goto pc+4
; if (icmp->type == 13)
11: (71) r1 = *(u8 *)(r3 +34)
invalid access to packet, id=0, off=34, size=1, R3_w=pkt(off=0,r=34,imm=0)
processed 12 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
-- END PROG LOAD LOG --""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
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

    if (icmp->type == 13)
        return XDP_DROP;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "drop_icmp_timestamp", "description": "Drop ICMP Timestamp Request type 13", "packet_hex": t8_p_drop, "expected_action": "XDP_DROP"},
                {"name": "pass_icmp_reply", "description": "Pass ICMP Echo Reply type 0", "packet_hex": t8_p_pass, "expected_action": "XDP_PASS"},
                {"name": "pass_tcp", "description": "Pass TCP packet", "packet_hex": t8_p_tcp, "expected_action": "XDP_PASS"},
                {"name": "pass_arp", "description": "Pass ARP frame", "packet_hex": t8_p_arp, "expected_action": "XDP_PASS"},
                {"name": "pass_trunc", "description": "Pass truncated ICMP safely", "packet_hex": t8_p_trunc, "expected_action": "XDP_PASS"},
            ],
        )
    )

    # 9. repair_pfs_l1_syn_only_filter (behavioral_logic_bug: inverted logic dropping non-SYN instead of SYN)
    t9_p_syn = binascii.hexlify(make_eth() + make_ipv4(proto=6) + make_tcp(dst_port=80, flags=0x02)).decode()
    t9_p_ack = binascii.hexlify(make_eth() + make_ipv4(proto=6) + make_tcp(dst_port=80, flags=0x10)).decode()
    t9_p_udp = binascii.hexlify(make_eth() + make_ipv4(proto=17) + make_udp(dst_port=80)).decode()
    t9_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()
    t9_p_trunc = binascii.hexlify(make_eth() + make_ipv4(proto=6)[:12]).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_pfs_l1_syn_only_filter",
            application_category="packet_filtering_security",
            difficulty="level_1",
            task_family="xdp_tcp_flags_filter",
            template_family="xdp_stateless_filter",
            semantic_signature="ipv4+tcp_syn_only_port80+drop",
            diagnostic_category="behavioral_logic_bug",
            failure_reason="Inverted verdict logic: program drops established TCP ACK traffic and passes TCP SYN packets on port 80",
            instruction="Fix the behavioral bug in the XDP filter so it drops TCP SYN packets destined to port 80 while passing established TCP traffic (ACK, FIN, RST, etc.), UDP, and non-IP traffic.",
            requirements=[
                "Check bounds for Ethernet, IP, and TCP headers",
                "Check if TCP destination port is 80 (bpf_htons(80))",
                "Check if SYN flag is set ((tcp->syn) or (flags & 0x02)) and ACK flag is NOT set",
                "Return XDP_DROP for TCP SYN packets to port 80; return XDP_PASS for other packets",
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
int xdp_filter(struct xdp_md *ctx) {
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
        // Behavioral Bug: inverted condition, dropping ACK instead of SYN
        if (tcp->syn)
            return XDP_PASS;
        else
            return XDP_DROP;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""FAIL: test_case 'drop_tcp_syn_80' failed:
  Expected action: XDP_DROP
  Observed action: XDP_PASS
FAIL: test_case 'pass_tcp_ack_80' failed:
  Expected action: XDP_PASS
  Observed action: XDP_DROP
2 of 5 test cases failed.""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
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

    if (tcp->dest == bpf_htons(80) && tcp->syn && !tcp->ack)
        return XDP_DROP;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "drop_tcp_syn_80", "description": "Drop TCP SYN on port 80", "packet_hex": t9_p_syn, "expected_action": "XDP_DROP"},
                {"name": "pass_tcp_ack_80", "description": "Pass TCP ACK on port 80", "packet_hex": t9_p_ack, "expected_action": "XDP_PASS"},
                {"name": "pass_udp_80", "description": "Pass UDP on port 80", "packet_hex": t9_p_udp, "expected_action": "XDP_PASS"},
                {"name": "pass_arp", "description": "Pass ARP packet", "packet_hex": t9_p_arp, "expected_action": "XDP_PASS"},
                {"name": "pass_trunc", "description": "Pass truncated packet safely", "packet_hex": t9_p_trunc, "expected_action": "XDP_PASS"},
            ],
        )
    )

    # 10. repair_pfs_l1_http_alt_filter (behavioral_logic_bug: endianness mismatch comparing tcp->dest == 8080 without bpf_htons)
    t10_p_drop = binascii.hexlify(make_eth() + make_ipv4(proto=6) + make_tcp(dst_port=8080)).decode()
    t10_p_pass = binascii.hexlify(make_eth() + make_ipv4(proto=6) + make_tcp(dst_port=80)).decode()
    t10_p_udp = binascii.hexlify(make_eth() + make_ipv4(proto=17) + make_udp(dst_port=8080)).decode()
    t10_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()
    t10_p_trunc = binascii.hexlify(make_eth() + make_ipv4(proto=6)[:12]).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_pfs_l1_http_alt_filter",
            application_category="packet_filtering_security",
            difficulty="level_1",
            task_family="xdp_port_filter",
            template_family="xdp_stateless_filter",
            semantic_signature="ipv4+tcp_dport_8080+drop",
            diagnostic_category="behavioral_logic_bug",
            failure_reason="Endianness bug: comparing tcp->dest against host-order literal 8080 instead of bpf_htons(8080)",
            instruction="Fix the byte-order comparison bug in the XDP filter so it drops TCP packets destined to alternate HTTP port 8080 while passing all other traffic.",
            requirements=[
                "Check bounds for Ethernet, IP, and TCP headers",
                "Compare tcp->dest with bpf_htons(8080) (or bpf_ntohs(tcp->dest) == 8080)",
                "Drop matching TCP packets; pass non-matching and malformed packets",
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
int xdp_filter(struct xdp_md *ctx) {
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

    // Behavioral bug: missing bpf_htons conversion
    if (tcp->dest == 8080)
        return XDP_DROP;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""FAIL: test_case 'drop_tcp_8080' failed:
  Expected action: XDP_DROP
  Observed action: XDP_PASS (tcp->dest in network byte order was 0x901F instead of host 8080 / 0x1F90)
1 of 5 test cases failed.""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
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
        return XDP_DROP;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "drop_tcp_8080", "description": "Drop TCP dport 8080", "packet_hex": t10_p_drop, "expected_action": "XDP_DROP"},
                {"name": "pass_tcp_80", "description": "Pass TCP dport 80", "packet_hex": t10_p_pass, "expected_action": "XDP_PASS"},
                {"name": "pass_udp_8080", "description": "Pass UDP dport 8080", "packet_hex": t10_p_udp, "expected_action": "XDP_PASS"},
                {"name": "pass_arp", "description": "Pass ARP frame", "packet_hex": t10_p_arp, "expected_action": "XDP_PASS"},
                {"name": "pass_trunc", "description": "Pass truncated TCP safely", "packet_hex": t10_p_trunc, "expected_action": "XDP_PASS"},
            ],
        )
    )

    # =========================================================================
    # LEVEL 2 (10 tasks: 4 compilation, 4 verifier, 2 behavioral)
    # =========================================================================

    # 11. repair_pfs_l2_subnet_blacklist (compilation_error: array subscript type error on IP)
    t11_p_drop = binascii.hexlify(make_eth() + make_ipv4(src_ip="198.51.100.15", proto=6) + make_tcp()).decode()
    t11_p_pass = binascii.hexlify(make_eth() + make_ipv4(src_ip="192.0.2.1", proto=6) + make_tcp()).decode()
    t11_p_dns_pass = binascii.hexlify(make_eth() + make_ipv4(src_ip="198.51.100.15", proto=17) + make_udp(dst_port=53)).decode()
    t11_p_udp_drop = binascii.hexlify(make_eth() + make_ipv4(src_ip="198.51.100.15", proto=17) + make_udp(dst_port=123)).decode()
    t11_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()
    t11_p_trunc = binascii.hexlify(make_eth() + make_ipv4(src_ip="198.51.100.15")[:10]).decode()
    t11_p_ihl6 = binascii.hexlify(make_eth() + make_ipv4(src_ip="198.51.100.15", ihl=6, proto=6) + make_tcp()).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_pfs_l2_subnet_blacklist",
            application_category="packet_filtering_security",
            difficulty="level_2",
            task_family="xdp_subnet_filter",
            template_family="xdp_multi_field_filter",
            semantic_signature="ipv4+src_198_51_100_drop_except_dns",
            diagnostic_category="compilation_error",
            failure_reason="Type error in subnet mask bitwise operation: invalid operand types to binary operator '&'",
            instruction="Fix the compilation error to drop traffic from IPv4 source subnet 198.51.100.0/24 except for UDP DNS traffic (dst port 53). Pass all other traffic.",
            requirements=[
                "Check Ethernet and IPv4 bounds, including variable IHL",
                "Match source IP in 198.51.100.0/24 (saddr & 0xFFFFFF00 == 198.51.100.0 in network byte order)",
                "Allow UDP port 53 traffic even from the blocked subnet",
                "Drop all other traffic from 198.51.100.0/24; pass outside traffic",
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
int xdp_filter(struct xdp_md *ctx) {
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
    __u32 ip_len = (__u32)ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    // Subnet check for 198.51.100.0/24 (0xC6336400)
    // Fault: type error assigning __u32 pointer to scalar bitwise
    __u32 subnet = bpf_htonl(0xC6336400);
    __u32 mask = bpf_htonl(0xFFFFFF00);
    if ((&ip->saddr & mask) == subnet) {
        if (ip->protocol == IPPROTO_UDP) {
            struct udphdr *udp = (void *)ip + ip_len;
            if ((void *)(udp + 1) <= data_end && udp->dest == bpf_htons(53))
                return XDP_PASS;
        }
        return XDP_DROP;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""faulty.c:29:21: error: invalid operands to binary expression ('__be32 *' (aka 'unsigned int *') and '__u32' (aka 'unsigned int'))
    if ((&ip->saddr & mask) == subnet) {
         ~~~~~~~~~~ ^ ~~~~
1 error generated.""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
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
    __u32 ip_len = (__u32)ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    __u32 subnet = bpf_htonl(0xC6336400);
    __u32 mask = bpf_htonl(0xFFFFFF00);
    if ((ip->saddr & mask) == subnet) {
        if (ip->protocol == IPPROTO_UDP) {
            struct udphdr *udp = (void *)ip + ip_len;
            if ((void *)(udp + 1) <= data_end && udp->dest == bpf_htons(53))
                return XDP_PASS;
        }
        return XDP_DROP;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "drop_subnet_tcp", "description": "Drop TCP from 198.51.100.15", "packet_hex": t11_p_drop, "expected_action": "XDP_DROP"},
                {"name": "pass_outside_ip", "description": "Pass IP from 192.0.2.1", "packet_hex": t11_p_pass, "expected_action": "XDP_PASS"},
                {"name": "pass_subnet_dns", "description": "Pass UDP DNS from 198.51.100.15", "packet_hex": t11_p_dns_pass, "expected_action": "XDP_PASS"},
                {"name": "drop_subnet_udp_other", "description": "Drop non-DNS UDP from 198.51.100.15", "packet_hex": t11_p_udp_drop, "expected_action": "XDP_DROP"},
                {"name": "drop_subnet_ihl6", "description": "Drop IHL=6 TCP from 198.51.100.15", "packet_hex": t11_p_ihl6, "expected_action": "XDP_DROP"},
                {"name": "pass_arp", "description": "Pass ARP frame", "packet_hex": t11_p_arp, "expected_action": "XDP_PASS"},
                {"name": "pass_trunc", "description": "Pass truncated safely", "packet_hex": t11_p_trunc, "expected_action": "XDP_PASS"},
            ],
        )
    )

    # 12. repair_pfs_l2_vlan_tagged_filter (compilation_error: missing struct vlan_hdr definition)
    t12_p_vlan_drop = binascii.hexlify(make_eth(vlan=100) + make_ipv4(proto=6) + make_tcp(dst_port=443)).decode()
    t12_p_untag_drop = binascii.hexlify(make_eth() + make_ipv4(proto=6) + make_tcp(dst_port=443)).decode()
    t12_p_vlan_pass = binascii.hexlify(make_eth(vlan=100) + make_ipv4(proto=6) + make_tcp(dst_port=80)).decode()
    t12_p_untag_pass = binascii.hexlify(make_eth() + make_ipv4(proto=6) + make_tcp(dst_port=80)).decode()
    t12_p_vlan_udp = binascii.hexlify(make_eth(vlan=100) + make_ipv4(proto=17) + make_udp(dst_port=443)).decode()
    t12_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()
    t12_p_trunc = binascii.hexlify(make_eth(vlan=100)[:16]).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_pfs_l2_vlan_tagged_filter",
            application_category="packet_filtering_security",
            difficulty="level_2",
            task_family="xdp_vlan_filter",
            template_family="xdp_encapsulation_filter",
            semantic_signature="untagged_or_single_vlan+tcp_443+drop",
            diagnostic_category="compilation_error",
            failure_reason="Compilation error: undefined type 'struct vlan_hdr' causing compile failure",
            instruction="Fix the missing struct declaration in the XDP filter to drop TCP port 443 packets inside either untagged Ethernet or single 802.1Q VLAN tagged frames.",
            requirements=[
                "Define or provide struct vlan_hdr with h_vlan_TCI and h_vlan_encapsulated_proto",
                "Handle untagged Ethernet (ETH_P_IP) and 802.1Q VLAN tagged Ethernet (ETH_P_8021Q)",
                "Parse IPv4 and TCP headers safely",
                "Drop TCP destination port 443; pass all other traffic",
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
int xdp_filter(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u16 eth_proto = bpf_ntohs(eth->h_proto);
    void *nh = (void *)(eth + 1);

    if (eth_proto == ETH_P_8021Q) {
        struct vlan_hdr *vlh = nh;
        if ((void *)(vlh + 1) > data_end)
            return XDP_PASS;
        eth_proto = bpf_ntohs(vlh->h_vlan_encapsulated_proto);
        nh = (void *)(vlh + 1);
    }

    if (eth_proto != ETH_P_IP)
        return XDP_PASS;

    struct iphdr *ip = nh;
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

    if (tcp->dest == bpf_htons(443))
        return XDP_DROP;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""faulty.c:20:16: error: variable has incomplete type 'struct vlan_hdr'
        struct vlan_hdr *vlh = nh;
               ^
faulty.c:20:16: note: forward declaration of 'struct vlan_hdr'
faulty.c:21:26: error: invalid application of 'sizeof' to an incomplete type 'struct vlan_hdr'
        if ((void *)(vlh + 1) > data_end)
                     ^~~~~~~
faulty.c:23:36: error: member access into incomplete type 'struct vlan_hdr'
        eth_proto = bpf_ntohs(vlh->h_vlan_encapsulated_proto);
                                  ^
3 errors generated.""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u16 eth_proto = bpf_ntohs(eth->h_proto);
    void *nh = (void *)(eth + 1);

    if (eth_proto == ETH_P_8021Q) {
        struct vlan_hdr *vlh = nh;
        if ((void *)(vlh + 1) > data_end)
            return XDP_PASS;
        eth_proto = bpf_ntohs(vlh->h_vlan_encapsulated_proto);
        nh = (void *)(vlh + 1);
    }

    if (eth_proto != ETH_P_IP)
        return XDP_PASS;

    struct iphdr *ip = nh;
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

    if (tcp->dest == bpf_htons(443))
        return XDP_DROP;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "drop_vlan_tcp_443", "description": "Drop VLAN tagged TCP 443", "packet_hex": t12_p_vlan_drop, "expected_action": "XDP_DROP"},
                {"name": "drop_untag_tcp_443", "description": "Drop untagged TCP 443", "packet_hex": t12_p_untag_drop, "expected_action": "XDP_DROP"},
                {"name": "pass_vlan_tcp_80", "description": "Pass VLAN tagged TCP 80", "packet_hex": t12_p_vlan_pass, "expected_action": "XDP_PASS"},
                {"name": "pass_untag_tcp_80", "description": "Pass untagged TCP 80", "packet_hex": t12_p_untag_pass, "expected_action": "XDP_PASS"},
                {"name": "pass_vlan_udp_443", "description": "Pass VLAN UDP 443", "packet_hex": t12_p_vlan_udp, "expected_action": "XDP_PASS"},
                {"name": "pass_arp", "description": "Pass ARP frame", "packet_hex": t12_p_arp, "expected_action": "XDP_PASS"},
                {"name": "pass_trunc", "description": "Pass truncated VLAN frame safely", "packet_hex": t12_p_trunc, "expected_action": "XDP_PASS"},
            ],
        )
    )

    # 13. repair_pfs_l2_tcp_flag_rst_ack (compilation_error: assignment typo = instead of & in flag check)
    t13_p_drop = binascii.hexlify(make_eth() + make_ipv4(proto=6) + make_tcp(flags=0x14)).decode() # RST|ACK
    t13_p_pass_syn = binascii.hexlify(make_eth() + make_ipv4(proto=6) + make_tcp(flags=0x02)).decode() # SYN
    t13_p_pass_ack = binascii.hexlify(make_eth() + make_ipv4(proto=6) + make_tcp(flags=0x10)).decode() # ACK
    t13_p_pass_rst = binascii.hexlify(make_eth() + make_ipv4(proto=6) + make_tcp(flags=0x04)).decode() # RST only
    t13_p_udp = binascii.hexlify(make_eth() + make_ipv4(proto=17) + make_udp()).decode()
    t13_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()
    t13_p_trunc = binascii.hexlify(make_eth() + make_ipv4(proto=6)[:14]).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_pfs_l2_tcp_flag_rst_ack",
            application_category="packet_filtering_security",
            difficulty="level_2",
            task_family="xdp_tcp_flags_filter",
            template_family="xdp_multi_field_filter",
            semantic_signature="ipv4+tcp_flags_rst_ack+drop",
            diagnostic_category="compilation_error",
            failure_reason="Compilation error: assignment in conditional instead of bitwise AND ('tcp->rst = 1' instead of 'tcp->rst && tcp->ack')",
            instruction="Fix the syntax error in the XDP filter to drop IPv4 TCP packets that have both RST and ACK flags simultaneously set, while passing all other packets.",
            requirements=[
                "Check bounds for Ethernet, IP, and TCP headers",
                "Check TCP flags for simultaneous presence of RST (0x04) and ACK (0x10)",
                "Drop matching RST+ACK packets, return XDP_PASS for others",
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
int xdp_filter(struct xdp_md *ctx) {
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

    // Syntax error: bitfield assignment in condition
    if ((tcp->rst = 1) && tcp->ack)
        return XDP_DROP;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""faulty.c:29:19: error: cannot assign to bit-field in struct tcphdr
    if ((tcp->rst = 1) && tcp->ack)
         ~~~~~~~~ ^ ~
1 error generated.""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
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

    if (tcp->rst && tcp->ack)
        return XDP_DROP;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "drop_rst_ack", "description": "Drop TCP packet with RST and ACK flags", "packet_hex": t13_p_drop, "expected_action": "XDP_DROP"},
                {"name": "pass_syn", "description": "Pass TCP SYN packet", "packet_hex": t13_p_pass_syn, "expected_action": "XDP_PASS"},
                {"name": "pass_ack", "description": "Pass TCP ACK only packet", "packet_hex": t13_p_pass_ack, "expected_action": "XDP_PASS"},
                {"name": "pass_rst_only", "description": "Pass TCP RST only packet", "packet_hex": t13_p_pass_rst, "expected_action": "XDP_PASS"},
                {"name": "pass_udp", "description": "Pass UDP traffic", "packet_hex": t13_p_udp, "expected_action": "XDP_PASS"},
                {"name": "pass_arp", "description": "Pass ARP frame", "packet_hex": t13_p_arp, "expected_action": "XDP_PASS"},
                {"name": "pass_trunc", "description": "Pass truncated safely", "packet_hex": t13_p_trunc, "expected_action": "XDP_PASS"},
            ],
        )
    )

    # 14. repair_pfs_l2_ip_options_parse (compilation_error: void pointer arithmetic error)
    t14_p_drop = binascii.hexlify(make_eth() + make_ipv4(ihl=6, payload=b"\x00\x00\x00\x00" + make_tcp())).decode()
    t14_p_pass = binascii.hexlify(make_eth() + make_ipv4(ihl=5, payload=make_tcp())).decode()
    t14_p_udp = binascii.hexlify(make_eth() + make_ipv4(ihl=5, proto=17, payload=make_udp())).decode()
    t14_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()
    t14_p_trunc = binascii.hexlify(make_eth() + make_ipv4(ihl=6)[:15]).decode()
    t14_p_icmp = binascii.hexlify(make_eth() + make_ipv4(ihl=5, proto=1, payload=make_icmp())).decode()
    t14_p_ihl7_drop = binascii.hexlify(make_eth() + make_ipv4(ihl=7, payload=b"\x00"*8 + make_tcp())).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_pfs_l2_ip_options_parse",
            application_category="packet_filtering_security",
            difficulty="level_2",
            task_family="xdp_ip_options_filter",
            template_family="xdp_multi_field_filter",
            semantic_signature="ipv4+options_present_ihl_gt_5+drop",
            diagnostic_category="compilation_error",
            failure_reason="Compilation error: invalid void pointer arithmetic in strict C compilation mode",
            instruction="Fix the pointer arithmetic in the XDP filter to detect and drop IPv4 packets carrying IP options (IHL > 5) while passing standard IPv4 (IHL == 5) and other non-IP traffic.",
            requirements=[
                "Check Ethernet and IPv4 bounds",
                "Check ip->ihl > 5 and drop packets with options",
                "Ensure variable length bounds checks before parsing payload",
                "Pass packets without IP options (IHL == 5)",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    void *ip_raw = (void *)(eth + 1);
    if (ip_raw + sizeof(struct iphdr) > data_end)
        return XDP_PASS;

    struct iphdr *ip = ip_raw;
    if (ip->ihl < 5)
        return XDP_PASS;

    // Fault: arithmetic on void * pointer
    if (ip->ihl > 5)
        return XDP_DROP;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""faulty.c:17:16: error: arithmetic on a pointer to void is a GNU extension [-Werror,-Wpointer-arith]
    if (ip_raw + sizeof(struct iphdr) > data_end)
        ~~~~~~ ^
1 error generated.""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
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

    if (ip->ihl < 5)
        return XDP_PASS;

    if (ip->ihl > 5)
        return XDP_DROP;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "drop_ihl6_options", "description": "Drop IPv4 with IHL=6 options", "packet_hex": t14_p_drop, "expected_action": "XDP_DROP"},
                {"name": "drop_ihl7_options", "description": "Drop IPv4 with IHL=7 options", "packet_hex": t14_p_ihl7_drop, "expected_action": "XDP_DROP"},
                {"name": "pass_standard_ipv4", "description": "Pass standard IPv4 without options", "packet_hex": t14_p_pass, "expected_action": "XDP_PASS"},
                {"name": "pass_udp_standard", "description": "Pass UDP without options", "packet_hex": t14_p_udp, "expected_action": "XDP_PASS"},
                {"name": "pass_icmp_standard", "description": "Pass ICMP without options", "packet_hex": t14_p_icmp, "expected_action": "XDP_PASS"},
                {"name": "pass_arp", "description": "Pass ARP frame", "packet_hex": t14_p_arp, "expected_action": "XDP_PASS"},
                {"name": "pass_trunc", "description": "Pass truncated packet safely", "packet_hex": t14_p_trunc, "expected_action": "XDP_PASS"},
            ],
        )
    )

    # 15. repair_pfs_l2_rate_limit_map (verifier_rejection: map lookup pointer not checked against NULL)
    t15_p_syn = binascii.hexlify(make_eth() + make_ipv4(src_ip="10.0.0.1", proto=6) + make_tcp(dst_port=80, flags=0x02)).decode()
    t15_p_ack = binascii.hexlify(make_eth() + make_ipv4(src_ip="10.0.0.1", proto=6) + make_tcp(dst_port=80, flags=0x10)).decode()
    t15_p_other_ip = binascii.hexlify(make_eth() + make_ipv4(src_ip="10.0.0.2", proto=6) + make_tcp(dst_port=80, flags=0x02)).decode()
    t15_p_udp = binascii.hexlify(make_eth() + make_ipv4(proto=17) + make_udp()).decode()
    t15_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()
    t15_p_trunc = binascii.hexlify(make_eth() + make_ipv4()[:12]).decode()
    t15_p_icmp = binascii.hexlify(make_eth() + make_ipv4(proto=1) + make_icmp()).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_pfs_l2_rate_limit_map",
            application_category="packet_filtering_security",
            difficulty="level_2",
            task_family="xdp_rate_limit",
            template_family="xdp_hash_map_filter",
            semantic_signature="ipv4+src_syn_limiter+drop_over_limit",
            diagnostic_category="verifier_rejection",
            failure_reason="Kernel verifier rejection: R0 invalid mem access dereferencing map lookup result without checking against NULL",
            instruction="Fix the verifier rejection by checking the return value of bpf_map_lookup_elem for NULL before dereferencing. If the key exists and counter exceeds 10, drop; otherwise increment and pass.",
            requirements=[
                "Define BPF hash map rate_map with __u32 key and __u64 value",
                "Check lookup return pointer for NULL",
                "If entry found and *cnt > 10, return XDP_DROP",
                "If entry found and *cnt <= 10, increment *cnt and return XDP_PASS",
                "If entry not found, return XDP_PASS",
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
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1024);
} rate_map SEC(".maps");

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
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

    __u32 key = ip->saddr;
    __u64 *cnt = bpf_map_lookup_elem(&rate_map, &key);
    // Verifier error: cnt dereferenced directly without NULL check
    if (*cnt > 10)
        return XDP_DROP;
    *cnt += 1;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""0: R1=ctx(off=0,imm=0) R10=fp0
...
15: (85) call bpf_map_lookup_elem#1
16: R0=map_value_or_null(id=1,off=0,r=0,imm=0)
; if (*cnt > 10)
17: (79) r1 = *(u64 *)(r0 +0)
R0 invalid mem access 'map_value_or_null'
processed 18 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
-- END PROG LOAD LOG --""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1024);
} rate_map SEC(".maps");

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
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

    __u32 key = ip->saddr;
    __u64 *cnt = bpf_map_lookup_elem(&rate_map, &key);
    if (cnt) {
        if (*cnt > 10)
            return XDP_DROP;
        *cnt += 1;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_untracked_src", "description": "Pass untracked source IP", "packet_hex": t15_p_syn, "expected_action": "XDP_PASS"},
                {"name": "pass_other_src", "description": "Pass second source IP", "packet_hex": t15_p_other_ip, "expected_action": "XDP_PASS"},
                {"name": "pass_ack", "description": "Pass TCP ACK", "packet_hex": t15_p_ack, "expected_action": "XDP_PASS"},
                {"name": "pass_udp", "description": "Pass UDP traffic", "packet_hex": t15_p_udp, "expected_action": "XDP_PASS"},
                {"name": "pass_icmp", "description": "Pass ICMP traffic", "packet_hex": t15_p_icmp, "expected_action": "XDP_PASS"},
                {"name": "pass_arp", "description": "Pass ARP frame", "packet_hex": t15_p_arp, "expected_action": "XDP_PASS"},
                {"name": "pass_trunc", "description": "Pass truncated header safely", "packet_hex": t15_p_trunc, "expected_action": "XDP_PASS"},
            ],
        )
    )

    # 16. repair_pfs_l2_port_bitmap_lookup (verifier_rejection: map value pointer arithmetic without bounds check on bitmap index)
    t16_p_drop = binascii.hexlify(make_eth() + make_ipv4(proto=6) + make_tcp(dst_port=22)).decode()
    t16_p_pass = binascii.hexlify(make_eth() + make_ipv4(proto=6) + make_tcp(dst_port=80)).decode()
    t16_p_udp = binascii.hexlify(make_eth() + make_ipv4(proto=17) + make_udp(dst_port=22)).decode()
    t16_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()
    t16_p_trunc = binascii.hexlify(make_eth() + make_ipv4(proto=6)[:12]).decode()
    t16_p_icmp = binascii.hexlify(make_eth() + make_ipv4(proto=1) + make_icmp()).decode()
    t16_p_high_port = binascii.hexlify(make_eth() + make_ipv4(proto=6) + make_tcp(dst_port=65000)).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_pfs_l2_port_bitmap_lookup",
            application_category="packet_filtering_security",
            difficulty="level_2",
            task_family="xdp_bitmap_filter",
            template_family="xdp_array_map_filter",
            semantic_signature="ipv4+port_bitmap_check+drop_if_set",
            diagnostic_category="verifier_rejection",
            failure_reason="Kernel verifier rejection: array index arithmetic on map value buffer not bounded within value size",
            instruction="Fix the verifier rejection by masking/bounding the port index when querying the port bitmap array map. Drop TCP ports whose bit in the bitmap is set.",
            requirements=[
                "Define port_bitmap array map with 2048 __u32 entries (65536 bits total)",
                "Safely compute word index (port / 32) and bit offset (port % 32)",
                "Ensure word index < 2048 before map lookup / access",
                "If bit is set (1), return XDP_DROP; otherwise XDP_PASS",
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
    __type(value, __u32);
    __uint(max_entries, 2048);
} port_bitmap SEC(".maps");

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
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

    __u16 dport = bpf_ntohs(tcp->dest);
    // Verifier issue: key variable unbounded u32 lookup without check
    __u32 word_idx = dport >> 5;
    __u32 bit_idx = dport & 31;

    __u32 *val = bpf_map_lookup_elem(&port_bitmap, &word_idx);
    if (!val)
        return XDP_PASS;

    if (*val & (1U << bit_idx))
        return XDP_DROP;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""0: R1=ctx(off=0,imm=0) R10=fp0
...
22: (85) call bpf_map_lookup_elem#1
23: R0=map_value_or_null(id=1,off=0,r=4,imm=0)
; if (*val & (1U << bit_idx))
24: (15) if r0 == 0x0 goto pc+6
25: (61) r1 = *(u32 *)(r0 +0)
26: (79) r2 = *(u64 *)(r10 -8)
27: (57) r2 &= 31
28: (77) r3 = 1
29: (6f) r3 <<= r2
30: (5f) r1 &= r3
31: (55) if r1 != 0x0 goto pc+1
32: (b7) r0 = 2
33: (95) exit
34: (b7) r0 = 1
35: (95) exit
processed 36 insns (limit 1000000) max_states_per_insn 0 total_states 1 peak_states 1 mark_read 0
-- END PROG LOAD LOG --""",
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
    __uint(max_entries, 2048);
} port_bitmap SEC(".maps");

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
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

    __u16 dport = bpf_ntohs(tcp->dest);
    __u32 word_idx = (dport >> 5) & 2047;
    __u32 bit_idx = dport & 31;

    __u32 *val = bpf_map_lookup_elem(&port_bitmap, &word_idx);
    if (!val)
        return XDP_PASS;

    if (*val & (1U << bit_idx))
        return XDP_DROP;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_default_bitmap", "description": "Pass when port not set in bitmap", "packet_hex": t16_p_pass, "expected_action": "XDP_PASS"},
                {"name": "pass_port_22", "description": "Pass port 22", "packet_hex": t16_p_drop, "expected_action": "XDP_PASS"},
                {"name": "pass_udp", "description": "Pass UDP port 22", "packet_hex": t16_p_udp, "expected_action": "XDP_PASS"},
                {"name": "pass_high_port", "description": "Pass high TCP port 65000", "packet_hex": t16_p_high_port, "expected_action": "XDP_PASS"},
                {"name": "pass_icmp", "description": "Pass ICMP", "packet_hex": t16_p_icmp, "expected_action": "XDP_PASS"},
                {"name": "pass_arp", "description": "Pass ARP frame", "packet_hex": t16_p_arp, "expected_action": "XDP_PASS"},
                {"name": "pass_trunc", "description": "Pass truncated header safely", "packet_hex": t16_p_trunc, "expected_action": "XDP_PASS"},
            ],
        )
    )

    # 17. repair_pfs_l2_vlan_double_tag (verifier_rejection: unbounded loop while walking nested VLAN tags)
    t17_p_qinq_drop = binascii.hexlify(make_eth(vlan=100, vlan_inner=200) + make_ipv4(proto=6) + make_tcp(dst_port=23)).decode()
    t17_p_single_drop = binascii.hexlify(make_eth(vlan=100) + make_ipv4(proto=6) + make_tcp(dst_port=23)).decode()
    t17_p_untag_drop = binascii.hexlify(make_eth() + make_ipv4(proto=6) + make_tcp(dst_port=23)).decode()
    t17_p_qinq_pass = binascii.hexlify(make_eth(vlan=100, vlan_inner=200) + make_ipv4(proto=6) + make_tcp(dst_port=80)).decode()
    t17_p_untag_pass = binascii.hexlify(make_eth() + make_ipv4(proto=6) + make_tcp(dst_port=80)).decode()
    t17_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()
    t17_p_trunc = binascii.hexlify(make_eth(vlan=100, vlan_inner=200)[:18]).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_pfs_l2_vlan_double_tag",
            application_category="packet_filtering_security",
            difficulty="level_2",
            task_family="xdp_vlan_filter",
            template_family="xdp_encapsulation_filter",
            semantic_signature="qinq_or_single_vlan+tcp_23+drop",
            diagnostic_category="verifier_rejection",
            failure_reason="Kernel verifier rejection: back-edge / loop detected without static bounds while parsing arbitrary VLAN tag chain",
            instruction="Fix the verifier loop rejection by using a bounded unrolled loop (up to 2 VLAN tags) or explicit constant unrolling. Drop TCP port 23 traffic across untagged, single-tagged, and QinQ double-tagged frames.",
            requirements=[
                "Handle 0, 1, or 2 802.1Q/802.1ad VLAN tags (0x8100, 0x88A8)",
                "Ensure statically bounded loop (#pragma unroll or max 2 iterations)",
                "Verify packet bounds at every stage",
                "Drop TCP destination port 23; pass all other traffic",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u16 eth_proto = bpf_ntohs(eth->h_proto);
    void *nh = (void *)(eth + 1);

    // Fault: unbounded while loop triggers verifier back-edge error
    while (eth_proto == ETH_P_8021Q || eth_proto == 0x88A8) {
        struct vlan_hdr *vlh = nh;
        if ((void *)(vlh + 1) > data_end)
            return XDP_PASS;
        eth_proto = bpf_ntohs(vlh->h_vlan_encapsulated_proto);
        nh = (void *)(vlh + 1);
    }

    if (eth_proto != ETH_P_IP)
        return XDP_PASS;

    struct iphdr *ip = nh;
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

    if (tcp->dest == bpf_htons(23))
        return XDP_DROP;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""0: R1=ctx(off=0,imm=0) R10=fp0
...
12: (2d) if r4 > r1 goto pc+20
13: (69) r3 = *(u16 *)(r2 +2)
14: (dc) r3 = be16 r3
15: (07) r2 += 4
; while (eth_proto == ETH_P_8021Q || eth_proto == 0x88A8)
16: (55) if r3 == 0x8100 goto pc-8
back-edge from insn 16 to 8
processed 17 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
-- END PROG LOAD LOG --""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u16 eth_proto = bpf_ntohs(eth->h_proto);
    void *nh = (void *)(eth + 1);

    #pragma unroll
    for (int i = 0; i < 2; i++) {
        if (eth_proto == ETH_P_8021Q || eth_proto == 0x88A8) {
            struct vlan_hdr *vlh = nh;
            if ((void *)(vlh + 1) > data_end)
                return XDP_PASS;
            eth_proto = bpf_ntohs(vlh->h_vlan_encapsulated_proto);
            nh = (void *)(vlh + 1);
        }
    }

    if (eth_proto != ETH_P_IP)
        return XDP_PASS;

    struct iphdr *ip = nh;
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

    if (tcp->dest == bpf_htons(23))
        return XDP_DROP;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "drop_qinq_tcp_23", "description": "Drop QinQ double VLAN TCP 23", "packet_hex": t17_p_qinq_drop, "expected_action": "XDP_DROP"},
                {"name": "drop_single_vlan_tcp_23", "description": "Drop single VLAN TCP 23", "packet_hex": t17_p_single_drop, "expected_action": "XDP_DROP"},
                {"name": "drop_untagged_tcp_23", "description": "Drop untagged TCP 23", "packet_hex": t17_p_untag_drop, "expected_action": "XDP_DROP"},
                {"name": "pass_qinq_tcp_80", "description": "Pass QinQ TCP 80", "packet_hex": t17_p_qinq_pass, "expected_action": "XDP_PASS"},
                {"name": "pass_untagged_tcp_80", "description": "Pass untagged TCP 80", "packet_hex": t17_p_untag_pass, "expected_action": "XDP_PASS"},
                {"name": "pass_arp", "description": "Pass ARP frame", "packet_hex": t17_p_arp, "expected_action": "XDP_PASS"},
                {"name": "pass_trunc", "description": "Pass truncated frame safely", "packet_hex": t17_p_trunc, "expected_action": "XDP_PASS"},
            ],
        )
    )

    # 18. repair_pfs_l2_multicast_drop (verifier_rejection: pointer comparison against scalar integer)
    t18_p_mcast = binascii.hexlify(make_eth(dst_mac="01:00:5e:00:00:01") + make_ipv4(dst_ip="224.0.0.1", proto=2)).decode()
    t18_p_bcast = binascii.hexlify(make_eth(dst_mac="ff:ff:ff:ff:ff:ff") + make_ipv4(dst_ip="255.255.255.255", proto=17) + make_udp()).decode()
    t18_p_ucast = binascii.hexlify(make_eth() + make_ipv4(proto=6) + make_tcp()).decode()
    t18_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()
    t18_p_trunc = binascii.hexlify(make_eth()[:10]).decode()
    t18_p_mcast_ip = binascii.hexlify(make_eth() + make_ipv4(dst_ip="239.255.255.250", proto=17) + make_udp(dst_port=1900)).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_pfs_l2_multicast_drop",
            application_category="packet_filtering_security",
            difficulty="level_2",
            task_family="xdp_multicast_filter",
            template_family="xdp_stateless_filter",
            semantic_signature="multicast_mac_or_ip+drop",
            diagnostic_category="verifier_rejection",
            failure_reason="Kernel verifier rejection: pointer compared against scalar constant 0",
            instruction="Fix the verifier rejection to drop Ethernet/IPv4 multicast packets (Ethernet dest MAC starts with 01:00:5E or IPv4 dest in 224.0.0.0/4) while passing unicast, broadcast, and ARP traffic.",
            requirements=[
                "Check Ethernet bounds before reading MAC",
                "Check multicast MAC bit: eth->h_dest[0] & 0x01",
                "Check multicast IPv4 class D: (ip->daddr & 0xF0) == 0xE0 in network order",
                "Drop multicast packets; pass unicast/broadcast",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Verifier error: comparing pointer eth->h_dest directly to scalar 0
    if (eth->h_dest == 0)
        return XDP_PASS;

    if (eth->h_dest[0] & 0x01) {
        // Exclude broadcast ff:ff:ff:ff:ff:ff
        if (eth->h_dest[0] == 0xff && eth->h_dest[1] == 0xff)
            return XDP_PASS;
        return XDP_DROP;
    }

    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end)
            return XDP_PASS;
        // Class D 224.0.0.0/4 (first byte 0xE0..0xEF)
        __u8 first_byte = *(__u8 *)&ip->daddr;
        if ((first_byte & 0xF0) == 0xE0)
            return XDP_DROP;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""0: R1=ctx(off=0,imm=0) R10=fp0
...
4: (15) if r2 == 0x0 goto pc+15
R2 pointer comparison prohibited
processed 5 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
-- END PROG LOAD LOG --""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_dest[0] & 0x01) {
        // Exclude broadcast ff:ff:ff:ff:ff:ff
        if (eth->h_dest[0] == 0xff && eth->h_dest[1] == 0xff)
            return XDP_PASS;
        return XDP_DROP;
    }

    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end)
            return XDP_PASS;
        __u8 first_byte = *(__u8 *)&ip->daddr;
        if ((first_byte & 0xF0) == 0xE0)
            return XDP_DROP;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "drop_ethernet_multicast", "description": "Drop Ethernet Multicast 01:00:5E", "packet_hex": t18_p_mcast, "expected_action": "XDP_DROP"},
                {"name": "drop_ip_multicast_ssdp", "description": "Drop IPv4 multicast 239.255.255.250", "packet_hex": t18_p_mcast_ip, "expected_action": "XDP_DROP"},
                {"name": "pass_broadcast", "description": "Pass broadcast traffic", "packet_hex": t18_p_bcast, "expected_action": "XDP_PASS"},
                {"name": "pass_unicast", "description": "Pass standard unicast TCP", "packet_hex": t18_p_ucast, "expected_action": "XDP_PASS"},
                {"name": "pass_arp", "description": "Pass ARP frame", "packet_hex": t18_p_arp, "expected_action": "XDP_PASS"},
                {"name": "pass_trunc", "description": "Pass truncated safely", "packet_hex": t18_p_trunc, "expected_action": "XDP_PASS"},
            ],
        )
    )

    # 19. repair_pfs_l2_subnet_range_guard (behavioral_logic_bug: off-by-one in netmask bitshift/mask calculation)
    t19_p_drop = binascii.hexlify(make_eth() + make_ipv4(src_ip="172.16.5.10", proto=6) + make_tcp()).decode()
    t19_p_pass_in_16 = binascii.hexlify(make_eth() + make_ipv4(src_ip="172.17.1.1", proto=6) + make_tcp()).decode()
    t19_p_pass_outside = binascii.hexlify(make_eth() + make_ipv4(src_ip="192.168.1.1", proto=6) + make_tcp()).decode()
    t19_p_udp = binascii.hexlify(make_eth() + make_ipv4(src_ip="172.16.1.1", proto=17) + make_udp()).decode()
    t19_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()
    t19_p_trunc = binascii.hexlify(make_eth() + make_ipv4(src_ip="172.16.5.10")[:10]).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_pfs_l2_subnet_range_guard",
            application_category="packet_filtering_security",
            difficulty="level_2",
            task_family="xdp_subnet_filter",
            template_family="xdp_multi_field_filter",
            semantic_signature="ipv4+src_172_16_0_0_16+drop",
            diagnostic_category="behavioral_logic_bug",
            failure_reason="Behavioral bug: wrong subnet mask (0xFF000000 /8 instead of 0xFFFF0000 /16) blocking entire 172.0.0.0/8 range",
            instruction="Fix the netmask calculation in the XDP filter to specifically block source IP addresses in 172.16.0.0/16 without blocking other RFC1918 subnets (such as 172.17.0.0/16 or 192.168.0.0/16).",
            requirements=[
                "Check Ethernet and IPv4 bounds",
                "Mask IPv4 saddr with 0xFFFF0000 (bpf_htonl(0xFFFF0000))",
                "Compare against 172.16.0.0 (bpf_htonl(0xAC100000))",
                "Drop matching traffic, pass all other traffic",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
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

    // Behavioral bug: mask is /8 (0xFF000000) instead of /16 (0xFFFF0000)
    __u32 mask = bpf_htonl(0xFF000000);
    __u32 subnet = bpf_htonl(0xAC100000);

    if ((ip->saddr & mask) == (subnet & mask))
        return XDP_DROP;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""FAIL: test_case 'pass_172_17_1_1' failed:
  Expected action: XDP_PASS
  Observed action: XDP_DROP (172.17.1.1 was incorrectly dropped by /8 subnet mask)
1 of 6 test cases failed.""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
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

    __u32 mask = bpf_htonl(0xFFFF0000);
    __u32 subnet = bpf_htonl(0xAC100000);

    if ((ip->saddr & mask) == subnet)
        return XDP_DROP;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "drop_172_16_5_10", "description": "Drop IP in 172.16.0.0/16", "packet_hex": t19_p_drop, "expected_action": "XDP_DROP"},
                {"name": "drop_172_16_1_1", "description": "Drop IP in 172.16.1.1", "packet_hex": t19_p_udp, "expected_action": "XDP_DROP"},
                {"name": "pass_172_17_1_1", "description": "Pass IP in 172.17.0.0/16", "packet_hex": t19_p_pass_in_16, "expected_action": "XDP_PASS"},
                {"name": "pass_192_168_1_1", "description": "Pass IP in 192.168.0.0/16", "packet_hex": t19_p_pass_outside, "expected_action": "XDP_PASS"},
                {"name": "pass_arp", "description": "Pass ARP frame", "packet_hex": t19_p_arp, "expected_action": "XDP_PASS"},
                {"name": "pass_trunc", "description": "Pass truncated safely", "packet_hex": t19_p_trunc, "expected_action": "XDP_PASS"},
            ],
        )
    )

    # 20. repair_pfs_l2_frag_offset_block (behavioral_logic_bug: wrong byte order on ip->frag_off flag check)
    t20_p_frag = binascii.hexlify(make_eth() + make_ipv4(frag_off=0x2000, proto=17) + make_udp()).decode() # More fragments flag (0x2000 in host order)
    t20_p_unfrag = binascii.hexlify(make_eth() + make_ipv4(frag_off=0x0000, proto=17) + make_udp()).decode()
    t20_p_df = binascii.hexlify(make_eth() + make_ipv4(frag_off=0x4000, proto=6) + make_tcp()).decode() # Don't fragment
    t20_p_offset = binascii.hexlify(make_eth() + make_ipv4(frag_off=0x0008, proto=17) + make_udp()).decode() # Fragment offset > 0
    t20_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()
    t20_p_trunc = binascii.hexlify(make_eth() + make_ipv4()[:8]).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_pfs_l2_frag_offset_block",
            application_category="packet_filtering_security",
            difficulty="level_2",
            task_family="xdp_frag_filter",
            template_family="xdp_multi_field_filter",
            semantic_signature="ipv4+fragmented_packet+drop",
            diagnostic_category="behavioral_logic_bug",
            failure_reason="Byte order bug: ip->frag_off bitmask evaluated in host endianness without bpf_ntohs, missing fragmented packets",
            instruction="Fix the byte-order extraction of ip->frag_off to drop all fragmented IPv4 packets (either MF flag is set or fragment offset > 0) while passing unfragmented packets.",
            requirements=[
                "Check bounds for Ethernet and IPv4 headers",
                "Convert ip->frag_off using bpf_ntohs",
                "Check for MF flag (0x2000) or fragment offset (0x1FFF & frag_off != 0)",
                "Drop fragmented packets; pass unfragmented IPv4, ARP, and malformed frames",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
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

    // Behavioral bug: frag_off is network endian __be16, checked against host constants without conversion
    if (ip->frag_off & (0x2000 | 0x1FFF))
        return XDP_DROP;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""FAIL: test_case 'drop_more_fragments' failed:
  Expected action: XDP_DROP
  Observed action: XDP_PASS (MF flag in network order 0x0020 did not match raw mask 0x3FFF)
1 of 6 test cases failed.""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
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

    __u16 frag_off = bpf_ntohs(ip->frag_off);
    if (frag_off & (0x2000 | 0x1FFF))
        return XDP_DROP;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "drop_more_fragments", "description": "Drop packet with MF flag set", "packet_hex": t20_p_frag, "expected_action": "XDP_DROP"},
                {"name": "drop_offset_fragment", "description": "Drop packet with fragment offset > 0", "packet_hex": t20_p_offset, "expected_action": "XDP_DROP"},
                {"name": "pass_unfragmented", "description": "Pass unfragmented UDP packet", "packet_hex": t20_p_unfrag, "expected_action": "XDP_PASS"},
                {"name": "pass_dont_fragment", "description": "Pass packet with DF flag only", "packet_hex": t20_p_df, "expected_action": "XDP_PASS"},
                {"name": "pass_arp", "description": "Pass ARP frame", "packet_hex": t20_p_arp, "expected_action": "XDP_PASS"},
                {"name": "pass_trunc", "description": "Pass truncated frame safely", "packet_hex": t20_p_trunc, "expected_action": "XDP_PASS"},
            ],
        )
    )

    # =========================================================================
    # LEVEL 3 (10 tasks: 5 compilation, 3 verifier, 2 behavioral)
    # =========================================================================

    # 21. repair_pfs_l3_lpm_trie_firewall (compilation_error: wrong struct bpf_lpm_trie_key layout in lookup)
    t21_p_drop = binascii.hexlify(make_eth() + make_ipv4(src_ip="198.51.100.42", proto=6) + make_tcp()).decode()
    t21_p_pass = binascii.hexlify(make_eth() + make_ipv4(src_ip="192.0.2.1", proto=6) + make_tcp()).decode()
    t21_p_udp = binascii.hexlify(make_eth() + make_ipv4(src_ip="198.51.100.42", proto=17) + make_udp()).decode()
    t21_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()
    t21_p_trunc = binascii.hexlify(make_eth() + make_ipv4()[:10]).decode()
    t21_p_ihl6 = binascii.hexlify(make_eth() + make_ipv4(src_ip="198.51.100.42", ihl=6, proto=6) + make_tcp()).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_pfs_l3_lpm_trie_firewall",
            application_category="packet_filtering_security",
            difficulty="level_3",
            task_family="xdp_lpm_trie_filter",
            template_family="xdp_lpm_trie_map",
            semantic_signature="ipv4+lpm_trie_lookup+drop_match",
            diagnostic_category="compilation_error",
            failure_reason="Compilation error: missing prefixlen field in struct bpf_lpm_trie_key definition",
            instruction="Fix the LPM Trie key struct definition and lookup so the XDP filter queries an LPM Trie blocklist and drops matched source IP addresses while passing unmatched and non-IP traffic.",
            requirements=[
                "Define LPM trie map lpm_blocklist with BPF_F_NO_PREALLOC flag",
                "Define LPM key struct with prefixlen (__u32) and data (__u32 saddr)",
                "Set prefixlen = 32 for exact source IP lookup",
                "Drop if lookup succeeds; return XDP_PASS otherwise",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct lpm_key {
    __u32 addr; // Compilation error: missing prefixlen field required by BPF LPM trie
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_key);
    __type(value, __u32);
    __uint(max_entries, 1024);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} lpm_blocklist SEC(".maps");

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
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

    struct lpm_key key;
    key.addr = ip->saddr;

    __u32 *val = bpf_map_lookup_elem(&lpm_blocklist, &key);
    if (val)
        return XDP_DROP;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""faulty.c:29:20: error: struct lpm_key must start with __u32 prefixlen for BPF_MAP_TYPE_LPM_TRIE
    struct lpm_key key;
                   ^
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
    __uint(max_entries, 1024);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} lpm_blocklist SEC(".maps");

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
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

    struct lpm_key key;
    key.prefixlen = 32;
    key.addr = ip->saddr;

    __u32 *val = bpf_map_lookup_elem(&lpm_blocklist, &key);
    if (val)
        return XDP_DROP;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_unmatched_lpm", "description": "Pass IP not in blocklist", "packet_hex": t21_p_pass, "expected_action": "XDP_PASS"},
                {"name": "pass_ip_udp", "description": "Pass UDP traffic", "packet_hex": t21_p_udp, "expected_action": "XDP_PASS"},
                {"name": "pass_arp", "description": "Pass ARP frame", "packet_hex": t21_p_arp, "expected_action": "XDP_PASS"},
                {"name": "pass_trunc", "description": "Pass truncated safely", "packet_hex": t21_p_trunc, "expected_action": "XDP_PASS"},
            ],
        )
    )

    # 22. repair_pfs_l3_stateful_quota_limiter (compilation_error: assignment of struct value to pointer in map update)
    t22_p_pass = binascii.hexlify(make_eth() + make_ipv4(src_ip="10.1.1.5", proto=6) + make_tcp()).decode()
    t22_p_pass2 = binascii.hexlify(make_eth() + make_ipv4(src_ip="10.1.1.6", proto=6) + make_tcp()).decode()
    t22_p_udp = binascii.hexlify(make_eth() + make_ipv4(src_ip="10.1.1.5", proto=17) + make_udp()).decode()
    t22_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()
    t22_p_trunc = binascii.hexlify(make_eth() + make_ipv4()[:12]).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_pfs_l3_stateful_quota_limiter",
            application_category="packet_filtering_security",
            difficulty="level_3",
            task_family="xdp_stateful_quota",
            template_family="xdp_hash_map_filter",
            semantic_signature="ipv4+src_quota_5+pass_then_drop",
            diagnostic_category="compilation_error",
            failure_reason="Compilation error: passing struct value instead of pointer to bpf_map_update_elem",
            instruction="Fix the map update invocation in the stateful quota filter. The filter must track per-source IPv4 packet counts in a hash map, passing the first 5 packets and dropping subsequent packets.",
            requirements=[
                "Define quota_map hash map with __u32 key and __u64 value",
                "Lookup source IP; if not found, initialize counter to 1 with bpf_map_update_elem and pass",
                "If counter < 5, increment counter and return XDP_PASS",
                "If counter >= 5, increment counter and return XDP_DROP",
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
    __type(value, __u64);
    __uint(max_entries, 10240);
} quota_map SEC(".maps");

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
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
    __u64 *val = bpf_map_lookup_elem(&quota_map, &src);
    if (!val) {
        __u64 init_val = 1;
        // Fault: passing init_val directly instead of &init_val pointer
        bpf_map_update_elem(&quota_map, &src, init_val, BPF_ANY);
        return XDP_PASS;
    }

    if (*val < 5) {
        *val += 1;
        return XDP_PASS;
    }

    *val += 1;
    return XDP_DROP;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""faulty.c:33:47: error: passing '__u64' (aka 'unsigned long long') to parameter of type 'const void *' [-Wint-conversion]
        bpf_map_update_elem(&quota_map, &src, init_val, BPF_ANY);
                                              ^~~~~~~~
/usr/include/bpf/bpf_helper_defs.h:42:61: note: passing argument to parameter 'value' here
long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *) 2;
                                                            ^
1 error generated.""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 10240);
} quota_map SEC(".maps");

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
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
    __u64 *val = bpf_map_lookup_elem(&quota_map, &src);
    if (!val) {
        __u64 init_val = 1;
        bpf_map_update_elem(&quota_map, &src, &init_val, BPF_ANY);
        return XDP_PASS;
    }

    if (*val < 5) {
        *val += 1;
        return XDP_PASS;
    }

    *val += 1;
    return XDP_DROP;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_initial_packet", "description": "Pass first packet from source", "packet_hex": t22_p_pass, "expected_action": "XDP_PASS"},
                {"name": "pass_second_src", "description": "Pass first packet from second source", "packet_hex": t22_p_pass2, "expected_action": "XDP_PASS"},
                {"name": "pass_udp", "description": "Pass UDP packet from first source", "packet_hex": t22_p_udp, "expected_action": "XDP_PASS"},
                {"name": "pass_arp", "description": "Pass ARP frame", "packet_hex": t22_p_arp, "expected_action": "XDP_PASS"},
                {"name": "pass_trunc", "description": "Pass truncated safely", "packet_hex": t22_p_trunc, "expected_action": "XDP_PASS"},
            ],
        )
    )

    # 23. repair_pfs_l3_conntrack_syn_cookie (compilation_error: undefined helper function / missing helper header include)
    t23_p_syn = binascii.hexlify(make_eth() + make_ipv4(proto=6) + make_tcp(dst_port=443, flags=0x02)).decode()
    t23_p_ack = binascii.hexlify(make_eth() + make_ipv4(proto=6) + make_tcp(dst_port=443, flags=0x10)).decode()
    t23_p_udp = binascii.hexlify(make_eth() + make_ipv4(proto=17) + make_udp()).decode()
    t23_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()
    t23_p_trunc = binascii.hexlify(make_eth() + make_ipv4()[:10]).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_pfs_l3_conntrack_syn_cookie",
            application_category="packet_filtering_security",
            difficulty="level_3",
            task_family="xdp_conntrack_filter",
            template_family="xdp_hash_map_filter",
            semantic_signature="ipv4+conntrack_table+syn_flood_guard",
            diagnostic_category="compilation_error",
            failure_reason="Compilation error: implicit declaration of function 'bpf_ktime_get_ns' due to missing helper header",
            instruction="Fix the missing helper declaration to implement an XDP stateful connection tracker map that records new SYN packets with timestamps and drops unsolicited SYN-ACK/ACK packets from unestablished peers.",
            requirements=[
                "Include <bpf/bpf_helpers.h>",
                "Define LRU hash map ct_map with 4-tuple key (saddr, daddr, sport, dport)",
                "Store arrival timestamp (bpf_ktime_get_ns()) on SYN",
                "Verify bounds on Ethernet, IP, and TCP headers",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>

struct flow_key {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct flow_key);
    __type(value, __u64);
    __uint(max_entries, 65536);
} ct_map SEC(".maps");

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
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

    struct flow_key key = {
        .saddr = ip->saddr,
        .daddr = ip->daddr,
        .sport = tcp->source,
        .dport = tcp->dest,
    };

    if (tcp->syn && !tcp->ack) {
        // Missing bpf/bpf_helpers.h causes implicit declaration error
        __u64 ts = bpf_ktime_get_ns();
        bpf_map_update_elem(&ct_map, &key, &ts, BPF_ANY);
        return XDP_PASS;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""faulty.c:54:20: error: call to undeclared function 'bpf_ktime_get_ns'; ISO C99 and later do not support implicit function declarations [-Wimplicit-function-declaration]
        __u64 ts = bpf_ktime_get_ns();
                   ^
faulty.c:55:9: error: call to undeclared function 'bpf_map_update_elem'; ISO C99 and later do not support implicit function declarations [-Wimplicit-function-declaration]
        bpf_map_update_elem(&ct_map, &key, &ts, BPF_ANY);
        ^
2 errors generated.""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct flow_key {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct flow_key);
    __type(value, __u64);
    __uint(max_entries, 65536);
} ct_map SEC(".maps");

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
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

    struct flow_key key = {
        .saddr = ip->saddr,
        .daddr = ip->daddr,
        .sport = tcp->source,
        .dport = tcp->dest,
    };

    if (tcp->syn && !tcp->ack) {
        __u64 ts = bpf_ktime_get_ns();
        bpf_map_update_elem(&ct_map, &key, &ts, BPF_ANY);
        return XDP_PASS;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_syn", "description": "Pass and track TCP SYN packet", "packet_hex": t23_p_syn, "expected_action": "XDP_PASS"},
                {"name": "pass_ack", "description": "Pass TCP ACK packet", "packet_hex": t23_p_ack, "expected_action": "XDP_PASS"},
                {"name": "pass_udp", "description": "Pass UDP traffic", "packet_hex": t23_p_udp, "expected_action": "XDP_PASS"},
                {"name": "pass_arp", "description": "Pass ARP frame", "packet_hex": t23_p_arp, "expected_action": "XDP_PASS"},
                {"name": "pass_trunc", "description": "Pass truncated safely", "packet_hex": t23_p_trunc, "expected_action": "XDP_PASS"},
            ],
        )
    )

    # 24. repair_pfs_l3_multivector_ddos_guard (compilation_error: conflicting typedef or missing enum declaration)
    t24_p_drop_syn = binascii.hexlify(make_eth() + make_ipv4(proto=6) + make_tcp(dst_port=22, flags=0x02)).decode()
    t24_p_drop_udp = binascii.hexlify(make_eth() + make_ipv4(proto=17) + make_udp(dst_port=123)).decode()
    t24_p_pass_tcp = binascii.hexlify(make_eth() + make_ipv4(proto=6) + make_tcp(dst_port=80, flags=0x10)).decode()
    t24_p_pass_udp = binascii.hexlify(make_eth() + make_ipv4(proto=17) + make_udp(dst_port=53)).decode()
    t24_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()
    t24_p_trunc = binascii.hexlify(make_eth() + make_ipv4()[:12]).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_pfs_l3_multivector_ddos_guard",
            application_category="packet_filtering_security",
            difficulty="level_3",
            task_family="xdp_multi_guard",
            template_family="xdp_stateful_multi_counter",
            semantic_signature="ipv4+multi_vector_guard_drop+stats_map",
            diagnostic_category="compilation_error",
            failure_reason="Compilation error: enum constant redeclaration and missing array bounds check in stats map update",
            instruction="Fix the compilation errors in the multi-vector DDoS guard. The filter drops TCP SYN packets to privileged ports (1-1023) and UDP NTP packets (port 123), maintaining separate drop counters in an array map.",
            requirements=[
                "Define enum drop_reason with DROP_SYN_PRIV=0, DROP_UDP_NTP=1, DROP_MALFORMED=2",
                "Define drop_stats array map with 4 entries",
                "Increment drop counter corresponding to the match reason",
                "Return XDP_DROP on match, XDP_PASS on normal traffic",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

enum drop_reason {
    DROP_SYN_PRIV = 0,
    DROP_UDP_NTP = 1,
    DROP_MALFORMED = 2,
    DROP_SYN_PRIV = 3, // Compilation error: duplicate enum constant
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 4);
} drop_stats SEC(".maps");

static __always_inline void record_drop(__u32 reason) {
    __u64 *cnt = bpf_map_lookup_elem(&drop_stats, &reason);
    if (cnt)
        *cnt += 1;
}

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
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

    __u32 ip_len = (__u32)ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end) {
        record_drop(DROP_MALFORMED);
        return XDP_DROP;
    }

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + ip_len;
        if ((void *)(tcp + 1) > data_end) {
            record_drop(DROP_MALFORMED);
            return XDP_DROP;
        }
        __u16 dport = bpf_ntohs(tcp->dest);
        if (tcp->syn && !tcp->ack && dport >= 1 && dport <= 1023) {
            record_drop(DROP_SYN_PRIV);
            return XDP_DROP;
        }
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + ip_len;
        if ((void *)(udp + 1) > data_end) {
            record_drop(DROP_MALFORMED);
            return XDP_DROP;
        }
        if (udp->dest == bpf_htons(123)) {
            record_drop(DROP_UDP_NTP);
            return XDP_DROP;
        }
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""faulty.c:15:5: error: redeclaration of enumerator 'DROP_SYN_PRIV'
    DROP_SYN_PRIV = 3,
    ^
faulty.c:12:5: note: previous definition is here
    DROP_SYN_PRIV = 0,
    ^
1 error generated.""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

enum drop_reason {
    DROP_SYN_PRIV = 0,
    DROP_UDP_NTP = 1,
    DROP_MALFORMED = 2,
    DROP_MAX = 3,
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 4);
} drop_stats SEC(".maps");

static __always_inline void record_drop(__u32 reason) {
    if (reason >= 4)
        return;
    __u64 *cnt = bpf_map_lookup_elem(&drop_stats, &reason);
    if (cnt)
        *cnt += 1;
}

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
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

    __u32 ip_len = (__u32)ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end) {
        record_drop(DROP_MALFORMED);
        return XDP_DROP;
    }

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + ip_len;
        if ((void *)(tcp + 1) > data_end) {
            record_drop(DROP_MALFORMED);
            return XDP_DROP;
        }
        __u16 dport = bpf_ntohs(tcp->dest);
        if (tcp->syn && !tcp->ack && dport >= 1 && dport <= 1023) {
            record_drop(DROP_SYN_PRIV);
            return XDP_DROP;
        }
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + ip_len;
        if ((void *)(udp + 1) > data_end) {
            record_drop(DROP_MALFORMED);
            return XDP_DROP;
        }
        if (udp->dest == bpf_htons(123)) {
            record_drop(DROP_UDP_NTP);
            return XDP_DROP;
        }
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "drop_syn_port_22", "description": "Drop TCP SYN on privileged port 22", "packet_hex": t24_p_drop_syn, "expected_action": "XDP_DROP"},
                {"name": "drop_udp_ntp_123", "description": "Drop UDP NTP port 123", "packet_hex": t24_p_drop_udp, "expected_action": "XDP_DROP"},
                {"name": "pass_tcp_ack_80", "description": "Pass TCP ACK on port 80", "packet_hex": t24_p_pass_tcp, "expected_action": "XDP_PASS"},
                {"name": "pass_udp_dns_53", "description": "Pass UDP DNS port 53", "packet_hex": t24_p_pass_udp, "expected_action": "XDP_PASS"},
                {"name": "pass_arp", "description": "Pass ARP frame", "packet_hex": t24_p_arp, "expected_action": "XDP_PASS"},
                {"name": "drop_trunc", "description": "Drop malformed truncated packet", "packet_hex": t24_p_trunc, "expected_action": "XDP_DROP"},
            ],
        )
    )

    # 25. repair_pfs_l3_dynamic_port_knocking (compilation_error: array bounds mismatch in struct initialization)
    t25_p_knock1 = binascii.hexlify(make_eth() + make_ipv4(src_ip="10.0.0.5", proto=6) + make_tcp(dst_port=1111)).decode()
    t25_p_knock2 = binascii.hexlify(make_eth() + make_ipv4(src_ip="10.0.0.5", proto=6) + make_tcp(dst_port=2222)).decode()
    t25_p_target_drop = binascii.hexlify(make_eth() + make_ipv4(src_ip="10.0.0.9", proto=6) + make_tcp(dst_port=22)).decode()
    t25_p_pass_web = binascii.hexlify(make_eth() + make_ipv4(src_ip="10.0.0.5", proto=6) + make_tcp(dst_port=80)).decode()
    t25_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()
    t25_p_trunc = binascii.hexlify(make_eth() + make_ipv4()[:12]).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_pfs_l3_dynamic_port_knocking",
            application_category="packet_filtering_security",
            difficulty="level_3",
            task_family="xdp_port_knocking",
            template_family="xdp_hash_map_filter",
            semantic_signature="ipv4+port_knock_sequence+dynamic_allow",
            diagnostic_category="compilation_error",
            failure_reason="Compilation error: struct knock_state initialization exceeds declared field width",
            instruction="Fix the struct definition and state machine logic for port knocking. Target port 22 is dropped unless the client IP has completed knock sequence port 1111 followed by 2222.",
            requirements=[
                "Define knock_map hash map keyed by __u32 src IP storing __u32 knock_stage",
                "Stage 0 -> if dst port 1111, advance to stage 1",
                "Stage 1 -> if dst port 2222, advance to stage 2",
                "If dst port 22 and stage == 2, return XDP_PASS; if dst port 22 and stage != 2, return XDP_DROP",
                "Pass all non-port-22 packets",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct knock_state {
    __u8 stage;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct knock_state);
    __uint(max_entries, 1024);
} knock_map SEC(".maps");

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
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

    __u32 src = ip->saddr;
    __u16 dport = bpf_ntohs(tcp->dest);
    struct knock_state *st = bpf_map_lookup_elem(&knock_map, &src);

    if (dport == 1111) {
        // Compilation error: struct field type mismatch
        struct knock_state new_st = { .stage = {1} };
        bpf_map_update_elem(&knock_map, &src, &new_st, BPF_ANY);
        return XDP_PASS;
    } else if (dport == 2222) {
        if (st && st->stage == 1) {
            struct knock_state new_st = { .stage = {2} };
            bpf_map_update_elem(&knock_map, &src, &new_st, BPF_ANY);
        }
        return XDP_PASS;
    } else if (dport == 22) {
        if (st && st->stage == 2)
            return XDP_PASS;
        return XDP_DROP;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""faulty.c:48:49: error: excess elements in scalar initializer
        struct knock_state new_st = { .stage = {1} };
                                                ^
faulty.c:53:53: error: excess elements in scalar initializer
            struct knock_state new_st = { .stage = {2} };
                                                    ^
2 errors generated.""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct knock_state {
    __u8 stage;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct knock_state);
    __uint(max_entries, 1024);
} knock_map SEC(".maps");

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
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

    __u32 src = ip->saddr;
    __u16 dport = bpf_ntohs(tcp->dest);
    struct knock_state *st = bpf_map_lookup_elem(&knock_map, &src);

    if (dport == 1111) {
        struct knock_state new_st = { .stage = 1 };
        bpf_map_update_elem(&knock_map, &src, &new_st, BPF_ANY);
        return XDP_PASS;
    } else if (dport == 2222) {
        if (st && st->stage == 1) {
            struct knock_state new_st = { .stage = 2 };
            bpf_map_update_elem(&knock_map, &src, &new_st, BPF_ANY);
        }
        return XDP_PASS;
    } else if (dport == 22) {
        if (st && st->stage == 2)
            return XDP_PASS;
        return XDP_DROP;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_knock_stage1", "description": "Pass initial knock port 1111", "packet_hex": t25_p_knock1, "expected_action": "XDP_PASS"},
                {"name": "pass_knock_stage2", "description": "Pass second knock port 2222", "packet_hex": t25_p_knock2, "expected_action": "XDP_PASS"},
                {"name": "drop_unknocked_port_22", "description": "Drop SSH port 22 for unknocked host", "packet_hex": t25_p_target_drop, "expected_action": "XDP_DROP"},
                {"name": "pass_web_traffic", "description": "Pass standard port 80 web traffic", "packet_hex": t25_p_pass_web, "expected_action": "XDP_PASS"},
                {"name": "pass_arp", "description": "Pass ARP frame", "packet_hex": t25_p_arp, "expected_action": "XDP_PASS"},
                {"name": "pass_trunc", "description": "Pass truncated header safely", "packet_hex": t25_p_trunc, "expected_action": "XDP_PASS"},
            ],
        )
    )

    # 26. repair_pfs_l3_lpm_counter_sync (verifier_rejection: stack frame limit > 512 bytes)
    t26_p_drop = binascii.hexlify(make_eth() + make_ipv4(src_ip="198.51.100.10", proto=6) + make_tcp()).decode()
    t26_p_pass = binascii.hexlify(make_eth() + make_ipv4(src_ip="192.0.2.1", proto=6) + make_tcp()).decode()
    t26_p_udp = binascii.hexlify(make_eth() + make_ipv4(src_ip="198.51.100.10", proto=17) + make_udp()).decode()
    t26_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()
    t26_p_trunc = binascii.hexlify(make_eth() + make_ipv4()[:12]).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_pfs_l3_lpm_counter_sync",
            application_category="packet_filtering_security",
            difficulty="level_3",
            task_family="xdp_lpm_trie_filter",
            template_family="xdp_lpm_counter_map",
            semantic_signature="ipv4+lpm_trie_with_rule_counter+drop",
            diagnostic_category="verifier_rejection",
            failure_reason="Kernel verifier rejection: stack frame size limit (512 bytes) exceeded by declaring large local buffer",
            instruction="Fix the kernel verifier stack overflow rejection by reducing local stack variable sizes. Query the LPM blocklist, increment the rule's match counter, and drop matching traffic.",
            requirements=[
                "Keep total stack memory usage well below 512 bytes",
                "Define LPM trie blocklist and matching rule statistics map",
                "On LPM match, lookup and increment rule drop counter",
                "Drop matching traffic, pass non-matching traffic",
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
    __type(value, __u32); // Rule ID
    __uint(max_entries, 1024);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} lpm_blocklist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 256);
} rule_stats SEC(".maps");

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
    // Verifier error: 600-byte stack array exceeds 512 byte limit
    char audit_buffer[600];
    audit_buffer[0] = 0;

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
        .addr = ip->saddr,
    };

    __u32 *rule_id = bpf_map_lookup_elem(&lpm_blocklist, &key);
    if (rule_id) {
        __u32 rid = *rule_id;
        __u64 *cnt = bpf_map_lookup_elem(&rule_stats, &rid);
        if (cnt)
            *cnt += 1;
        return XDP_DROP;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""Looks like the BPF stack limit of 512 bytes is exceeded.
The following functions exceed the limit:
xdp_filter: stack frame size is 624 bytes
processed 0 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
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
} lpm_blocklist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 256);
} rule_stats SEC(".maps");

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
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
        .addr = ip->saddr,
    };

    __u32 *rule_id = bpf_map_lookup_elem(&lpm_blocklist, &key);
    if (rule_id) {
        __u32 rid = *rule_id;
        __u64 *cnt = bpf_map_lookup_elem(&rule_stats, &rid);
        if (cnt)
            *cnt += 1;
        return XDP_DROP;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_unmatched", "description": "Pass unmatched IP address", "packet_hex": t26_p_pass, "expected_action": "XDP_PASS"},
                {"name": "pass_udp_unmatched", "description": "Pass UDP traffic", "packet_hex": t26_p_udp, "expected_action": "XDP_PASS"},
                {"name": "pass_arp", "description": "Pass ARP frame", "packet_hex": t26_p_arp, "expected_action": "XDP_PASS"},
                {"name": "pass_trunc", "description": "Pass truncated packet safely", "packet_hex": t26_p_trunc, "expected_action": "XDP_PASS"},
            ],
        )
    )

    # 27. repair_pfs_l3_flow_tracker_lru (verifier_rejection: map value pointer arithmetic without offset boundary check)
    t27_p_pass1 = binascii.hexlify(make_eth() + make_ipv4(src_ip="10.0.1.1", proto=6) + make_tcp(src_port=10000, dst_port=80)).decode()
    t27_p_pass2 = binascii.hexlify(make_eth() + make_ipv4(src_ip="10.0.1.2", proto=6) + make_tcp(src_port=10001, dst_port=80)).decode()
    t27_p_udp = binascii.hexlify(make_eth() + make_ipv4(proto=17) + make_udp()).decode()
    t27_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()
    t27_p_trunc = binascii.hexlify(make_eth() + make_ipv4()[:12]).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_pfs_l3_flow_tracker_lru",
            application_category="packet_filtering_security",
            difficulty="level_3",
            task_family="xdp_flow_tracker",
            template_family="xdp_lru_map_filter",
            semantic_signature="ipv4+5tuple_flow_tracker+xdp_pass",
            diagnostic_category="verifier_rejection",
            failure_reason="Kernel verifier rejection: writing to map value at unchecked variable offset",
            instruction="Fix the verifier rejection in the LRU flow tracker. Update the 5-tuple flow state entry in the LRU map safely and return XDP_PASS for valid packets.",
            requirements=[
                "Define 5-tuple struct flow_key (saddr, daddr, sport, dport, proto)",
                "Define flow_stats struct with packets (__u64) and bytes (__u64)",
                "Safely lookup and update flow statistics in LRU hash map",
                "Ensure bounds checks before dereferencing headers",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct flow_key {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8 proto;
    __u8 pad[3];
};

struct flow_val {
    __u64 packets;
    __u64 bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct flow_key);
    __type(value, struct flow_val);
    __uint(max_entries, 65536);
} flow_map SEC(".maps");

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
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

    __u32 ip_len = (__u32)ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct flow_key key = {0};
    key.saddr = ip->saddr;
    key.daddr = ip->daddr;
    key.proto = ip->protocol;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + ip_len;
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        key.sport = tcp->source;
        key.dport = tcp->dest;
    }

    struct flow_val *val = bpf_map_lookup_elem(&flow_map, &key);
    if (val) {
        // Verifier fault: variable pointer arithmetic on map value
        __u64 *p = (__u64 *)((void *)val + (key.proto == IPPROTO_TCP ? 0 : 8));
        *p += 1;
    } else {
        struct flow_val init = {.packets = 1, .bytes = (__u64)(data_end - data)};
        bpf_map_update_elem(&flow_map, &key, &init, BPF_ANY);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""0: R1=ctx(off=0,imm=0) R10=fp0
...
32: (85) call bpf_map_lookup_elem#1
33: R0=map_value_or_null(id=1,off=0,r=16,imm=0)
34: (15) if r0 == 0x0 goto pc+8
; *p += 1;
35: (0f) r0 += r4
variable offset access into map_value prohibited
processed 36 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
-- END PROG LOAD LOG --""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct flow_key {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8 proto;
    __u8 pad[3];
};

struct flow_val {
    __u64 packets;
    __u64 bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct flow_key);
    __type(value, struct flow_val);
    __uint(max_entries, 65536);
} flow_map SEC(".maps");

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
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

    __u32 ip_len = (__u32)ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct flow_key key = {0};
    key.saddr = ip->saddr;
    key.daddr = ip->daddr;
    key.proto = ip->protocol;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + ip_len;
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        key.sport = tcp->source;
        key.dport = tcp->dest;
    }

    struct flow_val *val = bpf_map_lookup_elem(&flow_map, &key);
    if (val) {
        val->packets += 1;
        val->bytes += (__u64)(data_end - data);
    } else {
        struct flow_val init = {.packets = 1, .bytes = (__u64)(data_end - data)};
        bpf_map_update_elem(&flow_map, &key, &init, BPF_ANY);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_flow_tcp_1", "description": "Pass and track TCP flow 1", "packet_hex": t27_p_pass1, "expected_action": "XDP_PASS"},
                {"name": "pass_flow_tcp_2", "description": "Pass and track TCP flow 2", "packet_hex": t27_p_pass2, "expected_action": "XDP_PASS"},
                {"name": "pass_flow_udp", "description": "Pass and track UDP flow", "packet_hex": t27_p_udp, "expected_action": "XDP_PASS"},
                {"name": "pass_arp", "description": "Pass ARP frame", "packet_hex": t27_p_arp, "expected_action": "XDP_PASS"},
                {"name": "pass_trunc", "description": "Pass truncated frame safely", "packet_hex": t27_p_trunc, "expected_action": "XDP_PASS"},
            ],
        )
    )

    # 28. repair_pfs_l3_dpi_header_chain (verifier_rejection: variable offset payload read without upper bound proof)
    t28_p_drop = binascii.hexlify(make_eth() + make_ipv4(proto=6) + make_tcp(dst_port=80, payload=b"GET /admin HTTP/1.1\r\n")).decode()
    t28_p_pass = binascii.hexlify(make_eth() + make_ipv4(proto=6) + make_tcp(dst_port=80, payload=b"GET /index HTTP/1.1\r\n")).decode()
    t28_p_udp = binascii.hexlify(make_eth() + make_ipv4(proto=17) + make_udp()).decode()
    t28_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()
    t28_p_trunc = binascii.hexlify(make_eth() + make_ipv4(proto=6)[:16]).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_pfs_l3_dpi_header_chain",
            application_category="packet_filtering_security",
            difficulty="level_3",
            task_family="xdp_dpi_filter",
            template_family="xdp_payload_filter",
            semantic_signature="ipv4+tcp_payload_admin_path+drop",
            diagnostic_category="verifier_rejection",
            failure_reason="Kernel verifier rejection: TCP payload offset pointer read without explicit bounds verification on payload slice",
            instruction="Fix the packet verifier boundary check when reading TCP payload bytes. Drop TCP port 80 packets containing the string '/admin' in their first 10 payload bytes, passing all other traffic.",
            requirements=[
                "Parse Ethernet, IPv4, and TCP headers safely",
                "Calculate TCP payload offset: data + sizeof(eth) + ip->ihl*4 + tcp->doff*4",
                "Verify payload offset + 10 <= data_end before inspecting payload",
                "Drop matching /admin packets; return XDP_PASS for others",
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
int xdp_filter(struct xdp_md *ctx) {
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

    if (tcp->dest != bpf_htons(80))
        return XDP_PASS;

    __u32 tcp_len = (__u32)tcp->doff * 4;
    if (tcp_len < sizeof(struct tcphdr))
        return XDP_PASS;

    char *payload = (void *)tcp + tcp_len;
    // Verifier error: missing check on payload + 10 <= data_end
    if ((void *)payload > data_end)
        return XDP_PASS;

    if (payload[4] == '/' && payload[5] == 'a' && payload[6] == 'd' && payload[7] == 'm' && payload[8] == 'i' && payload[9] == 'n')
        return XDP_DROP;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""0: R1=ctx(off=0,imm=0) R10=fp0
...
27: (2d) if r3 > r1 goto pc+12
; if (payload[4] == '/' && ...
28: (71) r4 = *(u8 *)(r3 +4)
invalid access to packet, id=2, off=4, size=1, R3_w=pkt(off=54,r=54,var_off=(0x0; 0x7c),imm=0)
processed 29 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
-- END PROG LOAD LOG --""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
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

    if (tcp->dest != bpf_htons(80))
        return XDP_PASS;

    __u32 tcp_len = (__u32)tcp->doff * 4;
    if (tcp_len < sizeof(struct tcphdr) || (void *)tcp + tcp_len > data_end)
        return XDP_PASS;

    char *payload = (void *)tcp + tcp_len;
    if ((void *)(payload + 10) > data_end)
        return XDP_PASS;

    if (payload[4] == '/' && payload[5] == 'a' && payload[6] == 'd' && payload[7] == 'm' && payload[8] == 'i' && payload[9] == 'n')
        return XDP_DROP;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "drop_http_admin", "description": "Drop HTTP request to /admin path", "packet_hex": t28_p_drop, "expected_action": "XDP_DROP"},
                {"name": "pass_http_index", "description": "Pass HTTP request to /index path", "packet_hex": t28_p_pass, "expected_action": "XDP_PASS"},
                {"name": "pass_udp", "description": "Pass UDP traffic", "packet_hex": t28_p_udp, "expected_action": "XDP_PASS"},
                {"name": "pass_arp", "description": "Pass ARP frame", "packet_hex": t28_p_arp, "expected_action": "XDP_PASS"},
                {"name": "pass_trunc", "description": "Pass truncated packet safely", "packet_hex": t28_p_trunc, "expected_action": "XDP_PASS"},
            ],
        )
    )

    # 29. repair_pfs_l3_strict_syn_quota (behavioral_logic_bug: inverted quota policy)
    t29_p_syn1 = binascii.hexlify(make_eth() + make_ipv4(src_ip="10.2.2.1", proto=6) + make_tcp(dst_port=443, flags=0x02)).decode()
    t29_p_syn2 = binascii.hexlify(make_eth() + make_ipv4(src_ip="10.2.2.2", proto=6) + make_tcp(dst_port=443, flags=0x02)).decode()
    t29_p_ack = binascii.hexlify(make_eth() + make_ipv4(src_ip="10.2.2.1", proto=6) + make_tcp(dst_port=443, flags=0x10)).decode()
    t29_p_udp = binascii.hexlify(make_eth() + make_ipv4(proto=17) + make_udp()).decode()
    t29_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()
    t29_p_trunc = binascii.hexlify(make_eth() + make_ipv4()[:12]).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_pfs_l3_strict_syn_quota",
            application_category="packet_filtering_security",
            difficulty="level_3",
            task_family="xdp_syn_quota",
            template_family="xdp_hash_map_filter",
            semantic_signature="ipv4+syn_quota_3+pass_then_drop",
            diagnostic_category="behavioral_logic_bug",
            failure_reason="Behavioral bug: inverted quota logic - program drops first 3 SYN packets and passes subsequent packets",
            instruction="Fix the stateful quota policy logic in the XDP filter. Pass the first 3 TCP SYN packets per source IP address, and drop subsequent (4th+) TCP SYN packets from that source. Pass all non-SYN packets.",
            requirements=[
                "Maintain per-source IP SYN counter in a BPF hash map",
                "Pass first 3 SYN packets (*cnt <= 3); drop when *cnt > 3",
                "Do not drop established TCP packets (ACK, FIN, RST) or UDP packets",
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
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1024);
} syn_quota SEC(".maps");

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
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

    if (tcp->syn && !tcp->ack) {
        __u32 src = ip->saddr;
        __u64 *val = bpf_map_lookup_elem(&syn_quota, &src);
        if (!val) {
            __u64 init = 1;
            bpf_map_update_elem(&syn_quota, &src, &init, BPF_ANY);
            // Behavioral bug: dropping first SYN packet
            return XDP_DROP;
        }

        *val += 1;
        if (*val <= 3)
            return XDP_DROP; // Behavioral bug: dropping first 3
        return XDP_PASS;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""FAIL: test_case 'pass_first_syn' failed:
  Expected action: XDP_PASS
  Observed action: XDP_DROP (first SYN packet from new client was dropped)
1 of 6 test cases failed.""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1024);
} syn_quota SEC(".maps");

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
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

    if (tcp->syn && !tcp->ack) {
        __u32 src = ip->saddr;
        __u64 *val = bpf_map_lookup_elem(&syn_quota, &src);
        if (!val) {
            __u64 init = 1;
            bpf_map_update_elem(&syn_quota, &src, &init, BPF_ANY);
            return XDP_PASS;
        }

        *val += 1;
        if (*val <= 3)
            return XDP_PASS;
        return XDP_DROP;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_first_syn", "description": "Pass first SYN packet", "packet_hex": t29_p_syn1, "expected_action": "XDP_PASS"},
                {"name": "pass_other_src_syn", "description": "Pass first SYN from second source", "packet_hex": t29_p_syn2, "expected_action": "XDP_PASS"},
                {"name": "pass_ack_traffic", "description": "Pass TCP ACK established packet", "packet_hex": t29_p_ack, "expected_action": "XDP_PASS"},
                {"name": "pass_udp", "description": "Pass UDP traffic", "packet_hex": t29_p_udp, "expected_action": "XDP_PASS"},
                {"name": "pass_arp", "description": "Pass ARP frame", "packet_hex": t29_p_arp, "expected_action": "XDP_PASS"},
                {"name": "pass_trunc", "description": "Pass truncated safely", "packet_hex": t29_p_trunc, "expected_action": "XDP_PASS"},
            ],
        )
    )

    # 30. repair_pfs_l3_tiered_acl_precedence (behavioral_logic_bug: rule precedence bug allow evaluated after denylist)
    t30_p_admin_pass = binascii.hexlify(make_eth() + make_ipv4(src_ip="10.0.0.1", proto=6) + make_tcp(dst_port=22)).decode() # Whitelisted admin IP
    t30_p_other_drop = binascii.hexlify(make_eth() + make_ipv4(src_ip="10.0.0.5", proto=6) + make_tcp(dst_port=22)).decode() # Other IP targeting port 22
    t30_p_web_pass = binascii.hexlify(make_eth() + make_ipv4(src_ip="10.0.0.5", proto=6) + make_tcp(dst_port=80)).decode()
    t30_p_udp = binascii.hexlify(make_eth() + make_ipv4(proto=17) + make_udp()).decode()
    t30_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()
    t30_p_trunc = binascii.hexlify(make_eth() + make_ipv4()[:12]).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_pfs_l3_tiered_acl_precedence",
            application_category="packet_filtering_security",
            difficulty="level_3",
            task_family="xdp_tiered_acl",
            template_family="xdp_multi_map_filter",
            semantic_signature="ipv4+allowlist_overrides_denylist+acl",
            diagnostic_category="behavioral_logic_bug",
            failure_reason="Rule precedence bug: global port 22 block evaluated before admin IP allowlist lookup, causing admin SSH traffic to be dropped",
            instruction="Fix rule precedence in the tiered ACL filter so that allowlisted source IPs (in allowlist_map) are permitted to access port 22 before applying the general port 22 block rule.",
            requirements=[
                "Check allowlist_map hash map for source IP first",
                "If source IP is in allowlist, return XDP_PASS immediately",
                "If not allowlisted and TCP dport is 22, return XDP_DROP",
                "Pass all other traffic (web port 80, UDP, ARP, etc.)",
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
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, 128);
} allowlist_map SEC(".maps");

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
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

    // Behavioral bug: port 22 block evaluated before allowlist lookup
    if (tcp->dest == bpf_htons(22))
        return XDP_DROP;

    __u32 src = ip->saddr;
    __u8 *allowed = bpf_map_lookup_elem(&allowlist_map, &src);
    if (allowed && *allowed == 1)
        return XDP_PASS;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""FAIL: test_case 'pass_whitelisted_admin_ssh' failed:
  Expected action: XDP_PASS
  Observed action: XDP_DROP (allowlisted admin IP 10.0.0.1 was dropped by port 22 rule)
1 of 6 test cases failed.""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, 128);
} allowlist_map SEC(".maps");

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
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

    __u32 src = ip->saddr;
    __u8 *allowed = bpf_map_lookup_elem(&allowlist_map, &src);
    if (allowed && *allowed == 1)
        return XDP_PASS;

    if (tcp->dest == bpf_htons(22))
        return XDP_DROP;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_whitelisted_admin_ssh", "description": "Pass allowlisted admin on port 22", "packet_hex": t30_p_admin_pass, "expected_action": "XDP_PASS"},
                {"name": "drop_non_whitelisted_ssh", "description": "Drop non-allowlisted client on port 22", "packet_hex": t30_p_other_drop, "expected_action": "XDP_DROP"},
                {"name": "pass_web_traffic", "description": "Pass port 80 traffic", "packet_hex": t30_p_web_pass, "expected_action": "XDP_PASS"},
                {"name": "pass_udp", "description": "Pass UDP traffic", "packet_hex": t30_p_udp, "expected_action": "XDP_PASS"},
                {"name": "pass_arp", "description": "Pass ARP frame", "packet_hex": t30_p_arp, "expected_action": "XDP_PASS"},
                {"name": "pass_trunc", "description": "Pass truncated packet safely", "packet_hex": t30_p_trunc, "expected_action": "XDP_PASS"},
            ],
        )
    )

    return tasks
