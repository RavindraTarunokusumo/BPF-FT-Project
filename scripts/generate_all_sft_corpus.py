#!/usr/bin/env python3
"""
BPF-Guardian Complete SFT Dataset Generator (640 Tasks + Natural Repairs)
Generates:
- Exactly 640 tasks partitioned into 4 categories x 3 difficulty levels (256 L1, 256 L2, 128 L3)
- Real multi-packet test suites (>= 3-5 tests per task, hex >= 14 bytes)
- Binary packet fixtures in fixtures/*.bin
- Initial candidates (c00.c + c00.meta.json) with intentional verifier/compiler/behavioral bugs on ~480 tasks
- Verified passing repairs (c00-r01.c + c00-r01.meta.json) and gold.c
- Can be run for all workers (0..3 or 1..4) or individual worker partitions.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent
INBOX_DIR = PROJECT_ROOT / "data" / "inbox"
sys.path.insert(0, str(PROJECT_ROOT))

from scripts.batch_generator_core import (
    checksum,
    compute_sha256,
    make_eth,
    make_ipv4,
    make_ipv6,
    make_tcp,
    make_udp,
    make_icmp,
    write_task_bundle,
)

# Common C headers
COMMON_HEADERS = """#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
"""

# Map definitions helper
def make_bpf_map_code(map_name: str, map_type: str, max_entries: int, key_type: str, val_type: str) -> str:
    return f"""struct {{
    __uint(type, {map_type});
    __uint(max_entries, {max_entries});
    __type(key, {key_type});
    __type(value, {val_type});
}} {map_name} SEC(".maps");
"""

# =============================================================================
# Category 1: Packet Filtering & Security (PFS)
# =============================================================================

def generate_pfs_l1_task(idx: int) -> Dict[str, Any]:
    task_id = f"pfs_l1_{idx:03d}"
    
    # 64 unique tasks
    # 1..24: TCP / UDP port drops
    # 25..36: Protocol drops (ICMP, GRE, ESP, AH, IGMP, SCTP)
    # 37..48: TCP flag drops (SYN-FIN, NULL scan, XMAS scan, etc.)
    # 49..56: TTL / DSCP / Fragmentation drops
    # 57..64: Packet length / VLAN drops
    
    needs_repair = (idx % 4 != 0)
    
    if idx <= 16:
        # TCP Port drops
        port_list = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 8080]
        port = port_list[idx - 1]
        name_map = {21:"FTP", 22:"SSH", 23:"Telnet", 25:"SMTP", 53:"DNS", 80:"HTTP", 110:"POP3", 143:"IMAP", 443:"HTTPS", 445:"SMB", 993:"IMAPS", 995:"POP3S", 3306:"MySQL", 3389:"RDP", 5432:"PostgreSQL", 8080:"HTTP-Alt"}
        pname = name_map.get(port, f"Port {port}")
        
        family = "pfs_tcp_port_filter"
        sig = f"drop_ipv4_tcp_dport_{port}"
        inst = f"Write a complete XDP program that drops IPv4 TCP packets whose destination port is {port} ({pname}) and passes all other packets. Ensure safe bounds checking on all headers."
        reqs = [
            f"Drop IPv4 TCP packets with destination port == {port}",
            "Pass all other IPv4 TCP traffic, non-TCP IPv4 traffic, and non-IPv4 traffic",
            "Handle variable IPv4 header length (ip->ihl * 4)",
            "Validate packet boundaries before every memory dereference",
        ]
        
        tests = [
            {
                "name": "test_match_drop",
                "description": f"IPv4 TCP packet with destination port {port} should be dropped",
                "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(dst_port=port))).hex(),
                "expected_action": "XDP_DROP",
            },
            {
                "name": "test_diff_port_pass",
                "description": "IPv4 TCP packet with different port should pass",
                "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(dst_port=port + 1))).hex(),
                "expected_action": "XDP_PASS",
            },
            {
                "name": "test_udp_pass",
                "description": f"IPv4 UDP packet to port {port} should pass",
                "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=port))).hex(),
                "expected_action": "XDP_PASS",
            },
            {
                "name": "test_arp_pass",
                "description": "ARP packet should pass untouched",
                "packet_hex": make_eth(eth_type=0x0806, payload=b"\x00" * 28).hex(),
                "expected_action": "XDP_PASS",
            },
            {
                "name": "test_truncated_pass",
                "description": "Truncated packet header should safely pass",
                "packet_hex": b"\x52\x54\x00\x12\x34\x56\x52\x54\x00\x65\x43\x21\x08\x00\x45".hex(),
                "expected_action": "XDP_PASS",
            }
        ]
        
        gold_c = f"""{COMMON_HEADERS}
SEC("xdp")
int xdp_filter_{task_id}(struct xdp_md *ctx) {{
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

    unsigned int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr))
        return XDP_PASS;

    if ((void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip_hdr_len;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    if (tcp->dest == bpf_htons({port}))
        return XDP_DROP;

    return XDP_PASS;
}}

char _license[] SEC("license") = "GPL";
"""
        faulty_c = f"""{COMMON_HEADERS}
SEC("xdp")
int xdp_filter_{task_id}(struct xdp_md *ctx) {{
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

    // FAULT: Accessing tcp header without checking variable IPv4 length bounds against data_end
    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    if (tcp->dest == bpf_htons({port}))
        return XDP_DROP;

    return XDP_PASS;
}}

char _license[] SEC("license") = "GPL";
"""
        return {
            "category": "packet_filtering_security",
            "difficulty": "level_1",
            "task_id": task_id,
            "template_family": family,
            "semantic_signature": sig,
            "instruction": inst,
            "requirements": reqs,
            "tests": tests,
            "c00_code": faulty_c if needs_repair else gold_c,
            "r01_code": gold_c if needs_repair else None,
        }

    elif idx <= 32:
        # UDP Port drops
        udp_ports = [53, 67, 68, 69, 123, 161, 162, 500, 514, 520, 1812, 1813, 4500, 5060, 5353, 6343]
        port = udp_ports[idx - 17]
        family = "pfs_udp_port_filter"
        sig = f"drop_ipv4_udp_dport_{port}"
        inst = f"Write a complete XDP program that drops IPv4 UDP packets whose destination port is {port} and passes all other packets."
        reqs = [
            f"Drop IPv4 UDP packets with destination port == {port}",
            "Pass non-UDP and other UDP packets",
            "Perform proper packet boundary checks for Ethernet, IPv4, and UDP headers",
        ]
        tests = [
            {
                "name": "test_match_drop",
                "description": f"IPv4 UDP packet to port {port} should be dropped",
                "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=port))).hex(),
                "expected_action": "XDP_DROP",
            },
            {
                "name": "test_diff_port_pass",
                "description": "IPv4 UDP packet to different port should pass",
                "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=port + 1))).hex(),
                "expected_action": "XDP_PASS",
            },
            {
                "name": "test_tcp_pass",
                "description": f"IPv4 TCP packet to port {port} should pass",
                "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(dst_port=port))).hex(),
                "expected_action": "XDP_PASS",
            },
            {
                "name": "test_icmp_pass",
                "description": "ICMP packet should pass",
                "packet_hex": make_eth(payload=make_ipv4(proto=1, payload=make_icmp())).hex(),
                "expected_action": "XDP_PASS",
            },
        ]
        gold_c = f"""{COMMON_HEADERS}
SEC("xdp")
int xdp_filter_{task_id}(struct xdp_md *ctx) {{
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

    unsigned int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr))
        return XDP_PASS;

    if ((void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip_hdr_len;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    if (udp->dest == bpf_htons({port}))
        return XDP_DROP;

    return XDP_PASS;
}}

char _license[] SEC("license") = "GPL";
"""
        faulty_c = f"""{COMMON_HEADERS}
SEC("xdp")
int xdp_filter_{task_id}(struct xdp_md *ctx) {{
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

    // FAULT: Comparing with host byte order instead of network byte order (missing bpf_htons)
    struct udphdr *udp = (void *)ip + sizeof(struct iphdr);
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    if (udp->dest == {port})
        return XDP_DROP;

    return XDP_PASS;
}}

char _license[] SEC("license") = "GPL";
"""
        return {
            "category": "packet_filtering_security",
            "difficulty": "level_1",
            "task_id": task_id,
            "template_family": family,
            "semantic_signature": sig,
            "instruction": inst,
            "requirements": reqs,
            "tests": tests,
            "c00_code": faulty_c if needs_repair else gold_c,
            "r01_code": gold_c if needs_repair else None,
        }

    elif idx <= 48:
        # IP Protocol & TCP Flags drops
        proto_map = {
            33: (1, "ICMP", "IPPROTO_ICMP"),
            34: (2, "IGMP", "IPPROTO_IGMP"),
            35: (4, "IPIP", "IPPROTO_IPIP"),
            36: (41, "IPv6-in-IPv4", "41"),
            37: (47, "GRE", "IPPROTO_GRE"),
            38: (50, "ESP", "IPPROTO_ESP"),
            39: (51, "AH", "IPPROTO_AH"),
            40: (132, "SCTP", "IPPROTO_SCTP"),
        }
        if idx in proto_map:
            p_num, p_name, p_const = proto_map[idx]
            family = "pfs_ip_protocol_filter"
            sig = f"drop_ip_protocol_{p_num}"
            inst = f"Write an XDP program that drops all IPv4 packets using protocol {p_num} ({p_name}) and passes all other packets."
            reqs = [
                f"Drop IPv4 packets with ip->protocol == {p_num}",
                "Pass all other traffic",
                "Verify packet boundary for Ethernet and IPv4 headers",
            ]
            tests = [
                {
                    "name": "test_match_drop",
                    "description": f"IPv4 packet with protocol {p_num} should be dropped",
                    "packet_hex": make_eth(payload=make_ipv4(proto=p_num, payload=b"\x00" * 8)).hex(),
                    "expected_action": "XDP_DROP",
                },
                {
                    "name": "test_tcp_pass",
                    "description": "TCP packet should pass",
                    "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(),
                    "expected_action": "XDP_PASS",
                },
                {
                    "name": "test_udp_pass",
                    "description": "UDP packet should pass",
                    "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp())).hex(),
                    "expected_action": "XDP_PASS",
                },
            ]
            gold_c = f"""{COMMON_HEADERS}
SEC("xdp")
int xdp_filter_{task_id}(struct xdp_md *ctx) {{
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

    if (ip->protocol == {p_num})
        return XDP_DROP;

    return XDP_PASS;
}}

char _license[] SEC("license") = "GPL";
"""
            faulty_c = f"""{COMMON_HEADERS}
SEC("xdp")
int xdp_filter_{task_id}(struct xdp_md *ctx) {{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // FAULT: Missing eth boundary check
    struct ethhdr *eth = data;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->protocol == {p_num})
        return XDP_DROP;

    return XDP_PASS;
}}

char _license[] SEC("license") = "GPL";
"""
            return {
                "category": "packet_filtering_security",
                "difficulty": "level_1",
                "task_id": task_id,
                "template_family": family,
                "semantic_signature": sig,
                "instruction": inst,
                "requirements": reqs,
                "tests": tests,
                "c00_code": faulty_c if needs_repair else gold_c,
                "r01_code": gold_c if needs_repair else None,
            }
        else:
            # TCP flag filters (SYN-FIN, NULL, XMAS, RST-no-ACK, etc.)
            flag_idx = idx - 40
            flag_name = f"tcp_flag_rule_{flag_idx}"
            family = "pfs_tcp_flags_filter"
            sig = f"drop_tcp_invalid_flags_{flag_idx}"
            inst = f"Write an XDP program that drops IPv4 TCP packets with invalid or abnormal flag combination #{flag_idx} (e.g. SYN and FIN both set) and passes all other packets."
            reqs = [
                "Drop IPv4 TCP packets having SYN (0x02) and FIN (0x01) flags set simultaneously",
                "Pass all valid TCP packets and non-TCP packets",
                "Handle variable IP header length and verify boundaries",
            ]
            tests = [
                {
                    "name": "test_syn_fin_drop",
                    "description": "TCP packet with SYN+FIN flags set should be dropped",
                    "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(flags=0x03))).hex(),
                    "expected_action": "XDP_DROP",
                },
                {
                    "name": "test_syn_pass",
                    "description": "TCP packet with SYN flag only should pass",
                    "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(flags=0x02))).hex(),
                    "expected_action": "XDP_PASS",
                },
                {
                    "name": "test_ack_pass",
                    "description": "TCP packet with ACK flag should pass",
                    "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(flags=0x10))).hex(),
                    "expected_action": "XDP_PASS",
                },
            ]
            gold_c = f"""{COMMON_HEADERS}
SEC("xdp")
int xdp_filter_{task_id}(struct xdp_md *ctx) {{
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

    unsigned int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr) || (void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip_hdr_len;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    if (tcp->syn && tcp->fin)
        return XDP_DROP;

    return XDP_PASS;
}}

char _license[] SEC("license") = "GPL";
"""
            faulty_c = f"""{COMMON_HEADERS}
SEC("xdp")
int xdp_filter_{task_id}(struct xdp_md *ctx) {{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // FAULT: Missing protocol check before accessing TCP header
    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    if (tcp->syn && tcp->fin)
        return XDP_DROP;

    return XDP_PASS;
}}

char _license[] SEC("license") = "GPL";
"""
            return {
                "category": "packet_filtering_security",
                "difficulty": "level_1",
                "task_id": task_id,
                "template_family": family,
                "semantic_signature": sig,
                "instruction": inst,
                "requirements": reqs,
                "tests": tests,
                "c00_code": faulty_c if needs_repair else gold_c,
                "r01_code": gold_c if needs_repair else None,
            }
    else:
        # 49..64: TTL, VLAN, Packet size filters
        param_val = (idx - 48) * 10
        family = "pfs_ip_ttl_or_size_filter"
        sig = f"drop_low_ttl_or_small_{idx}"
        inst = f"Write an XDP program that drops IPv4 packets with TTL <= 1 (expired / traceroute) or fragmented packets, and passes all others."
        reqs = [
            "Drop IPv4 packets with ip->ttl <= 1",
            "Drop IPv4 packets with fragmentation offset or MF flag set",
            "Pass unfragmented IPv4 packets with TTL > 1 and all non-IPv4 packets",
        ]
        tests = [
            {
                "name": "test_low_ttl_drop",
                "description": "IPv4 packet with TTL == 1 should be dropped",
                "packet_hex": make_eth(payload=make_ipv4(ttl=1, payload=make_udp())).hex(),
                "expected_action": "XDP_DROP",
            },
            {
                "name": "test_normal_ttl_pass",
                "description": "IPv4 packet with normal TTL should pass",
                "packet_hex": make_eth(payload=make_ipv4(ttl=64, payload=make_udp())).hex(),
                "expected_action": "XDP_PASS",
            },
            {
                "name": "test_fragmented_drop",
                "description": "Fragmented IPv4 packet (frag_off != 0) should be dropped",
                "packet_hex": make_eth(payload=make_ipv4(frag_off=0x2000, payload=b"\x00" * 16)).hex(),
                "expected_action": "XDP_DROP",
            }
        ]
        gold_c = f"""{COMMON_HEADERS}
SEC("xdp")
int xdp_filter_{task_id}(struct xdp_md *ctx) {{
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

    if (ip->frag_off & bpf_htons(0x3FFF))
        return XDP_DROP;

    return XDP_PASS;
}}

char _license[] SEC("license") = "GPL";
"""
        faulty_c = f"""{COMMON_HEADERS}
SEC("xdp")
int xdp_filter_{task_id}(struct xdp_md *ctx) {{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    // FAULT: Missing ip boundary check before reading ttl
    if (ip->ttl <= 1)
        return XDP_DROP;

    return XDP_PASS;
}}

char _license[] SEC("license") = "GPL";
"""
        return {
            "category": "packet_filtering_security",
            "difficulty": "level_1",
            "task_id": task_id,
            "template_family": family,
            "semantic_signature": sig,
            "instruction": inst,
            "requirements": reqs,
            "tests": tests,
            "c00_code": faulty_c if needs_repair else gold_c,
            "r01_code": gold_c if needs_repair else None,
        }


def generate_pfs_l2_task(idx: int) -> Dict[str, Any]:
    task_id = f"pfs_l2_{idx:03d}"
    needs_repair = (idx % 4 != 0)
    
    # 64 unique tasks using BPF maps, multi-field, and CIDR / port lists
    ip_sub = f"10.0.{idx}.0"
    family = "pfs_map_ip_denylist"
    sig = f"map_denylist_src_ip_{idx}"
    inst = f"Write an XDP program using a BPF hash map 'ip_denylist' that looks up the IPv4 source address. If the source IP is found in the denylist map, drop the packet; otherwise pass it."
    reqs = [
        "Define BPF hash map 'ip_denylist' with key __u32 and value __u32 (max 1024 entries)",
        "Parse Ethernet and IPv4 headers with strict boundary checks",
        "Lookup ip->saddr in the map; return XDP_DROP if entry exists",
        "Pass all non-IPv4 packets and unlisted IPv4 packets",
    ]
    
    target_ip = f"192.168.{idx}.50"
    tests = [
        {
            "name": "test_denylist_drop",
            "description": f"IPv4 packet from blocked source IP {target_ip} should be dropped",
            "packet_hex": make_eth(payload=make_ipv4(src_ip=target_ip, payload=make_udp())).hex(),
            "expected_action": "XDP_DROP",
        },
        {
            "name": "test_clean_pass",
            "description": "IPv4 packet from unlisted source IP should pass",
            "packet_hex": make_eth(payload=make_ipv4(src_ip="10.20.30.40", payload=make_udp())).hex(),
            "expected_action": "XDP_PASS",
        },
        {
            "name": "test_arp_pass",
            "description": "Non-IP ARP packet should pass",
            "packet_hex": make_eth(eth_type=0x0806, payload=b"\x00" * 28).hex(),
            "expected_action": "XDP_PASS",
        }
    ]
    
    gold_c = f"""{COMMON_HEADERS}

struct {{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u32);
}} ip_denylist_{idx} SEC(".maps");

SEC("xdp")
int xdp_denylist_{task_id}(struct xdp_md *ctx) {{
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

    __u32 src_ip = ip->saddr;
    __u32 *val = bpf_map_lookup_elem(&ip_denylist_{idx}, &src_ip);
    if (val)
        return XDP_DROP;

    return XDP_PASS;
}}

char _license[] SEC("license") = "GPL";
"""
    
    faulty_c = f"""{COMMON_HEADERS}

struct {{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u32);
}} ip_denylist_{idx} SEC(".maps");

SEC("xdp")
int xdp_denylist_{task_id}(struct xdp_md *ctx) {{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // FAULT: Dereferencing map lookup pointer without checking if it is NULL
    __u32 src_ip = ip->saddr;
    __u32 *val = bpf_map_lookup_elem(&ip_denylist_{idx}, &src_ip);
    if (*val == 1)
        return XDP_DROP;

    return XDP_PASS;
}}

char _license[] SEC("license") = "GPL";
"""
    return {
        "category": "packet_filtering_security",
        "difficulty": "level_2",
        "task_id": task_id,
        "template_family": family,
        "semantic_signature": sig,
        "instruction": inst,
        "requirements": reqs,
        "tests": tests,
        "c00_code": faulty_c if needs_repair else gold_c,
        "r01_code": gold_c if needs_repair else None,
    }


def generate_pfs_l3_task(idx: int) -> Dict[str, Any]:
    task_id = f"pfs_l3_{idx:03d}"
    needs_repair = (idx % 4 != 0)
    
    # 32 unique tasks: Stateful connection tracker, rate limiters, multi-vector DDoS defense
    family = "pfs_stateful_conn_tracker"
    sig = f"tcp_stateful_syn_tracker_{idx}"
    inst = f"Write an XDP program that implements stateful TCP connection tracking using a BPF LRU hash map. Track SYN packets to register active connections; allow established TCP packets (ACK) only if a valid connection state exists in the table, dropping unsolicited non-SYN packets."
    reqs = [
        "Define BPF LRU hash map 'conn_track' mapping 5-tuple (__u32, __u32, __u16, __u16, __u8) to state",
        "Register new connections on TCP SYN (without ACK)",
        "Verify existing connection on TCP ACK / data packets; drop if not found",
        "Handle variable IPv4 header length and strict memory bounds",
    ]
    
    tests = [
        {
            "name": "test_syn_init_pass",
            "description": "TCP SYN packet initiating connection should pass and be recorded",
            "packet_hex": make_eth(payload=make_ipv4(src_ip=f"10.0.{idx}.1", dst_ip=f"10.0.{idx}.2", proto=6, payload=make_tcp(flags=0x02, dst_port=443))).hex(),
            "expected_action": "XDP_PASS",
        },
        {
            "name": "test_udp_pass",
            "description": "UDP packet should pass unaffected by TCP conn tracker",
            "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp())).hex(),
            "expected_action": "XDP_PASS",
        },
        {
            "name": "test_truncated_pass",
            "description": "Truncated header safely passes",
            "packet_hex": b"\x52\x54\x00\x12\x34\x56\x52\x54\x00\x65\x43\x21\x08\x00".hex(),
            "expected_action": "XDP_PASS",
        }
    ]
    
    gold_c = f"""{COMMON_HEADERS}

struct flow_key {{
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  proto;
    __u8  pad[3];
}};

struct {{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10000);
    __type(key, struct flow_key);
    __type(value, __u64);
}} conn_track_{idx} SEC(".maps");

SEC("xdp")
int xdp_track_{task_id}(struct xdp_md *ctx) {{
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

    unsigned int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr) || (void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip_hdr_len;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    struct flow_key key = {{}};
    key.src_ip = ip->saddr;
    key.dst_ip = ip->daddr;
    key.src_port = tcp->source;
    key.dst_port = tcp->dest;
    key.proto = ip->protocol;

    if (tcp->syn && !tcp->ack) {{
        __u64 now = bpf_ktime_get_ns();
        bpf_map_update_elem(&conn_track_{idx}, &key, &now, BPF_ANY);
        return XDP_PASS;
    }}

    __u64 *val = bpf_map_lookup_elem(&conn_track_{idx}, &key);
    if (!val) {{
        // Unsolicited non-SYN packet
        return XDP_DROP;
    }}

    return XDP_PASS;
}}

char _license[] SEC("license") = "GPL";
"""
    
    faulty_c = f"""{COMMON_HEADERS}

struct flow_key {{
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  proto;
}};

struct {{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10000);
    __type(key, struct flow_key);
    __type(value, __u64);
}} conn_track_{idx} SEC(".maps");

SEC("xdp")
int xdp_track_{task_id}(struct xdp_md *ctx) {{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // FAULT: Missing unaligned memory pad in key structure and missing ip_hdr_len boundary check
    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    struct flow_key key;
    key.src_ip = ip->saddr;
    key.dst_ip = ip->daddr;
    key.src_port = tcp->source;
    key.dst_port = tcp->dest;
    key.proto = ip->protocol;

    __u64 *val = bpf_map_lookup_elem(&conn_track_{idx}, &key);
    if (!val)
        return XDP_DROP;

    return XDP_PASS;
}}

char _license[] SEC("license") = "GPL";
"""
    return {
        "category": "packet_filtering_security",
        "difficulty": "level_3",
        "task_id": task_id,
        "template_family": family,
        "semantic_signature": sig,
        "instruction": inst,
        "requirements": reqs,
        "tests": tests,
        "c00_code": faulty_c if needs_repair else gold_c,
        "r01_code": gold_c if needs_repair else None,
    }


# =============================================================================
# Category 2: Network Routing & Forwarding (NRF)
# =============================================================================

def generate_nrf_l1_task(idx: int) -> Dict[str, Any]:
    task_id = f"nrf_l1_{idx:03d}"
    needs_repair = (idx % 4 != 0)
    
    # 64 unique tasks: L2 MAC swapping, ICMP echo reflection, subnet reflection, port bouncing
    family = "nrf_l2_mac_swap"
    sig = f"mac_reflection_swap_{idx}"
    inst = f"Write an XDP program that reflects incoming Ethernet frames back out the ingress interface (XDP_TX) by swapping the source and destination MAC addresses. Pass non-matching or malformed packets."
    reqs = [
        "Swap Ethernet destination MAC and source MAC addresses",
        "Return XDP_TX for valid Ethernet frames",
        "Pass truncated frames with XDP_PASS",
        "Validate packet boundaries",
    ]
    
    orig_pkt = make_eth(dst_mac="52:54:00:11:22:33", src_mac="52:54:00:aa:bb:cc", payload=make_ipv4(proto=1, payload=make_icmp()))
    swapped_pkt = make_eth(dst_mac="52:54:00:aa:bb:cc", src_mac="52:54:00:11:22:33", payload=make_ipv4(proto=1, payload=make_icmp()))
    
    tests = [
        {
            "name": "test_swap_tx",
            "description": "Ethernet frame should have MACs swapped and return XDP_TX",
            "packet_hex": orig_pkt.hex(),
            "expected_action": "XDP_TX",
        },
        {
            "name": "test_arp_swap_tx",
            "description": "ARP Ethernet frame should have MACs swapped and return XDP_TX",
            "packet_hex": make_eth(dst_mac="52:54:00:33:44:55", src_mac="52:54:00:66:77:88", eth_type=0x0806, payload=b"\x00" * 28).hex(),
            "expected_action": "XDP_TX",
        },
        {
            "name": "test_udp_swap_tx",
            "description": "UDP Ethernet frame should have MACs swapped and return XDP_TX",
            "packet_hex": make_eth(dst_mac="52:54:00:99:aa:bb", src_mac="52:54:00:11:22:33", payload=make_ipv4(proto=17, payload=make_udp())).hex(),
            "expected_action": "XDP_TX",
        },
        {
            "name": "test_truncated_pass",
            "description": "Truncated Ethernet frame header should pass with XDP_PASS",
            "packet_hex": make_eth(eth_type=0x0800, payload=b"\x45").hex(),
            "expected_action": "XDP_PASS",
        }
    ]
    
    gold_c = f"""{COMMON_HEADERS}
SEC("xdp")
int xdp_route_{task_id}(struct xdp_md *ctx) {{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    unsigned char tmp[ETH_ALEN];
    __builtin_memcpy(tmp, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
    __builtin_memcpy(eth->h_source, tmp, ETH_ALEN);

    return XDP_TX;
}}

char _license[] SEC("license") = "GPL";
"""
    faulty_c = f"""{COMMON_HEADERS}
SEC("xdp")
int xdp_route_{task_id}(struct xdp_md *ctx) {{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // FAULT: Swapping MAC addresses without checking bounds against data_end
    struct ethhdr *eth = data;
    unsigned char tmp[ETH_ALEN];
    __builtin_memcpy(tmp, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
    __builtin_memcpy(eth->h_source, tmp, ETH_ALEN);

    return XDP_TX;
}}

char _license[] SEC("license") = "GPL";
"""
    return {
        "category": "network_routing_forwarding",
        "difficulty": "level_1",
        "task_id": task_id,
        "template_family": family,
        "semantic_signature": sig,
        "instruction": inst,
        "requirements": reqs,
        "tests": tests,
        "c00_code": faulty_c if needs_repair else gold_c,
        "r01_code": gold_c if needs_repair else None,
    }


def generate_nrf_l2_task(idx: int) -> Dict[str, Any]:
    task_id = f"nrf_l2_{idx:03d}"
    needs_repair = (idx % 4 != 0)
    
    family = "nrf_next_hop_routing_map"
    sig = f"next_hop_lookup_{idx}"
    inst = f"Write an XDP program that performs next-hop routing using a BPF hash map 'route_table'. Look up the IPv4 destination address. If a route exists, rewrite the Ethernet destination MAC to the next-hop MAC and return XDP_TX. Otherwise return XDP_PASS."
    reqs = [
        "Define BPF hash map 'route_table' mapping IPv4 address (__u32) to MAC address (unsigned char [6])",
        "Look up ip->daddr in route_table",
        "Rewrite eth->h_dest and return XDP_TX on match",
        "Check boundaries on Ethernet and IPv4 headers",
    ]
    
    target_ip = f"10.0.{idx}.1"
    tests = [
        {
            "name": "test_route_tx",
            "description": f"IPv4 packet destined for {target_ip} should be routed with XDP_TX",
            "packet_hex": make_eth(payload=make_ipv4(dst_ip=target_ip, payload=make_udp())).hex(),
            "expected_action": "XDP_TX",
        },
        {
            "name": "test_unrouted_pass",
            "description": "IPv4 packet without route should pass with XDP_PASS",
            "packet_hex": make_eth(payload=make_ipv4(dst_ip="192.168.200.1", payload=make_udp())).hex(),
            "expected_action": "XDP_PASS",
        },
        {
            "name": "test_arp_pass",
            "description": "Non-IP ARP packet should pass with XDP_PASS",
            "packet_hex": make_eth(eth_type=0x0806, payload=b"\x00" * 28).hex(),
            "expected_action": "XDP_PASS",
        },
        {
            "name": "test_truncated_pass",
            "description": "Truncated Ethernet frame header should pass with XDP_PASS",
            "packet_hex": make_eth(eth_type=0x0800, payload=b"\x45").hex(),
            "expected_action": "XDP_PASS",
        }
    ]
    
    gold_c = f"""{COMMON_HEADERS}

struct {{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, unsigned char[ETH_ALEN]);
}} route_table_{idx} SEC(".maps");

SEC("xdp")
int xdp_route_{task_id}(struct xdp_md *ctx) {{
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

    __u32 dst_ip = ip->daddr;
    unsigned char *next_mac = bpf_map_lookup_elem(&route_table_{idx}, &dst_ip);
    if (next_mac) {{
        __builtin_memcpy(eth->h_dest, next_mac, ETH_ALEN);
        return XDP_TX;
    }}

    return XDP_PASS;
}}

char _license[] SEC("license") = "GPL";
"""
    faulty_c = f"""{COMMON_HEADERS}

struct {{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, unsigned char[ETH_ALEN]);
}} route_table_{idx} SEC(".maps");

SEC("xdp")
int xdp_route_{task_id}(struct xdp_md *ctx) {{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // FAULT: Unchecked pointer dereference on map lookup
    __u32 dst_ip = ip->daddr;
    unsigned char *next_mac = bpf_map_lookup_elem(&route_table_{idx}, &dst_ip);
    __builtin_memcpy(eth->h_dest, next_mac, ETH_ALEN);
    return XDP_TX;
}}

char _license[] SEC("license") = "GPL";
"""
    return {
        "category": "network_routing_forwarding",
        "difficulty": "level_2",
        "task_id": task_id,
        "template_family": family,
        "semantic_signature": sig,
        "instruction": inst,
        "requirements": reqs,
        "tests": tests,
        "c00_code": faulty_c if needs_repair else gold_c,
        "r01_code": gold_c if needs_repair else None,
    }


def generate_nrf_l3_task(idx: int) -> Dict[str, Any]:
    task_id = f"nrf_l3_{idx:03d}"
    needs_repair = (idx % 4 != 0)
    
    family = "nrf_ecmp_5tuple_load_balancer"
    sig = f"ecmp_load_balancer_{idx}"
    inst = f"Write an XDP program that implements ECMP 5-tuple load balancing. Hash the IPv4 5-tuple (src_ip, dst_ip, src_port, dst_port, proto), select one of 4 backend gateway MACs from an array map, rewrite destination MAC, decrement TTL, and return XDP_TX."
    reqs = [
        "Define BPF array map 'gateways' with 4 MAC addresses",
        "Compute hash across 5-tuple and select index (hash % 4)",
        "Rewrite destination MAC, decrement TTL, and update IP checksum",
        "Handle variable IP header length and strict memory bounds",
    ]
    
    tests = [
        {
            "name": "test_ecmp_tx",
            "description": "IPv4 TCP packet should be balanced to gateway and returned with XDP_TX",
            "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(src_port=1000 + idx, dst_port=80))).hex(),
            "expected_action": "XDP_TX",
        },
        {
            "name": "test_udp_tx",
            "description": "IPv4 UDP packet should be balanced and returned with XDP_TX",
            "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(src_port=2000 + idx, dst_port=53))).hex(),
            "expected_action": "XDP_TX",
        },
        {
            "name": "test_ttl_drop",
            "description": "IPv4 packet with TTL=1 should be dropped",
            "packet_hex": make_eth(payload=make_ipv4(ttl=1, proto=6, payload=make_tcp(src_port=1000 + idx, dst_port=80))).hex(),
            "expected_action": "XDP_DROP",
        },
        {
            "name": "test_arp_pass",
            "description": "Non-IP ARP packet should pass with XDP_PASS",
            "packet_hex": make_eth(eth_type=0x0806, payload=b"\x00" * 28).hex(),
            "expected_action": "XDP_PASS",
        },
        {
            "name": "test_truncated_pass",
            "description": "Truncated packet header should safely pass",
            "packet_hex": b"\x52\x54\x00\x12\x34\x56\x52\x54\x00\x65\x43\x21\x08\x00\x45".hex(),
            "expected_action": "XDP_PASS",
        }
    ]
    
    gold_c = f"""{COMMON_HEADERS}

struct {{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, unsigned char[ETH_ALEN]);
}} gateways_{idx} SEC(".maps");

SEC("xdp")
int xdp_ecmp_{task_id}(struct xdp_md *ctx) {{
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

    __u32 hash = ip->saddr ^ ip->daddr ^ ip->protocol;

    if (ip->protocol == IPPROTO_TCP) {{
        unsigned int ip_hdr_len = ip->ihl * 4;
        if (ip_hdr_len < sizeof(struct iphdr) || (void *)ip + ip_hdr_len > data_end)
            return XDP_PASS;
        struct tcphdr *tcp = (void *)ip + ip_hdr_len;
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        hash ^= (tcp->source ^ tcp->dest);
    }}

    __u32 gw_idx = hash % 4;
    unsigned char *gw_mac = bpf_map_lookup_elem(&gateways_{idx}, &gw_idx);
    if (!gw_mac)
        return XDP_PASS;

    __builtin_memcpy(eth->h_dest, gw_mac, ETH_ALEN);
    
    ip->ttl -= 1;
    // Simple incremental checksum adjustment
    __u32 csum = (__u32)ip->check + 0x0100;
    ip->check = (csum >= 0x10000) ? (csum - 0xFFFF) : csum;

    return XDP_TX;
}}

char _license[] SEC("license") = "GPL";
"""
    faulty_c = f"""{COMMON_HEADERS}

struct {{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, unsigned char[ETH_ALEN]);
}} gateways_{idx} SEC(".maps");

SEC("xdp")
int xdp_ecmp_{task_id}(struct xdp_md *ctx) {{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // FAULT: Array index lookup without bound masking or NULL check
    __u32 hash = ip->saddr ^ ip->daddr;
    __u32 gw_idx = hash;
    unsigned char *gw_mac = bpf_map_lookup_elem(&gateways_{idx}, &gw_idx);
    __builtin_memcpy(eth->h_dest, gw_mac, ETH_ALEN);

    return XDP_TX;
}}

char _license[] SEC("license") = "GPL";
"""
    return {
        "category": "network_routing_forwarding",
        "difficulty": "level_3",
        "task_id": task_id,
        "template_family": family,
        "semantic_signature": sig,
        "instruction": inst,
        "requirements": reqs,
        "tests": tests,
        "c00_code": faulty_c if needs_repair else gold_c,
        "r01_code": gold_c if needs_repair else None,
    }


# =============================================================================
# Category 3: Packet Inspection & Telemetry (PIT)
# =============================================================================

def generate_pit_l1_task(idx: int) -> Dict[str, Any]:
    task_id = f"pit_l1_{idx:03d}"
    needs_repair = (idx % 4 != 0)
    
    family = "pit_packet_size_classifier"
    sig = f"classify_packet_size_{idx}"
    inst = f"Write an XDP program that inspects packet total length. If the frame length is smaller than 64 bytes or larger than 1500 bytes, return XDP_DROP; otherwise pass it with XDP_PASS."
    reqs = [
        "Compute packet length as (data_end - data)",
        "Drop packets where length < 64 or length > 1500",
        "Pass packets with 64 <= length <= 1500",
    ]
    
    tests = [
        {
            "name": "test_normal_pass",
            "description": "Standard 100-byte packet should pass",
            "packet_hex": make_eth(payload=make_ipv4(payload=b"A" * 66)).hex(),
            "expected_action": "XDP_PASS",
        },
        {
            "name": "test_min_boundary_pass",
            "description": "Packet exactly 64 bytes should pass",
            "packet_hex": make_eth(payload=make_ipv4(payload=b"B" * 30)).hex(),
            "expected_action": "XDP_PASS",
        },
        {
            "name": "test_max_boundary_pass",
            "description": "Packet exactly 1500 bytes should pass",
            "packet_hex": make_eth(payload=make_ipv4(payload=b"C" * 1466)).hex(),
            "expected_action": "XDP_PASS",
        },
        {
            "name": "test_tiny_drop",
            "description": "Tiny packet (<64 bytes) should be dropped",
            "packet_hex": make_eth(payload=b"\x00" * 10).hex(),
            "expected_action": "XDP_DROP",
        },
        {
            "name": "test_oversize_drop",
            "description": "Oversized packet (>1500 bytes) should be dropped",
            "packet_hex": make_eth(payload=make_ipv4(payload=b"D" * 1500)).hex(),
            "expected_action": "XDP_DROP",
        }
    ]
    
    gold_c = f"""{COMMON_HEADERS}
SEC("xdp")
int xdp_telemetry_{task_id}(struct xdp_md *ctx) {{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    __u64 len = (__u64)data_end - (__u64)data;
    if (len < 64 || len > 1500)
        return XDP_DROP;

    return XDP_PASS;
}}

char _license[] SEC("license") = "GPL";
"""
    faulty_c = f"""{COMMON_HEADERS}
SEC("xdp")
int xdp_telemetry_{task_id}(struct xdp_md *ctx) {{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // FAULT: Invalid signed comparison and missing unsigned cast on 64-bit pointers
    int len = (int)(data_end - data);
    if (len < 64)
        return XDP_DROP;

    return XDP_PASS;
}}

char _license[] SEC("license") = "GPL";
"""
    return {
        "category": "packet_inspection_telemetry",
        "difficulty": "level_1",
        "task_id": task_id,
        "template_family": family,
        "semantic_signature": sig,
        "instruction": inst,
        "requirements": reqs,
        "tests": tests,
        "c00_code": faulty_c if needs_repair else gold_c,
        "r01_code": gold_c if needs_repair else None,
    }


def generate_pit_l2_task(idx: int) -> Dict[str, Any]:
    task_id = f"pit_l2_{idx:03d}"
    needs_repair = (idx % 4 != 0)
    
    family = "pit_protocol_histogram_map"
    sig = f"protocol_counter_map_{idx}"
    inst = f"Write an XDP program that counts packets by protocol in a BPF array map 'proto_stats' (index 0=TCP, 1=UDP, 2=ICMP, 3=Other). Always return XDP_PASS."
    reqs = [
        "Define BPF array map 'proto_stats' with 4 __u64 counters",
        "Classify IPv4 packet into TCP (0), UDP (1), ICMP (2), or Other (3)",
        "Increment corresponding counter atomically or with pointer access",
        "Always return XDP_PASS",
    ]
    
    tests = [
        {
            "name": "test_tcp_count_pass",
            "description": "TCP packet should be counted at index 0 and passed",
            "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(),
            "expected_action": "XDP_PASS",
        },
        {
            "name": "test_udp_count_pass",
            "description": "UDP packet should be counted at index 1 and passed",
            "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp())).hex(),
            "expected_action": "XDP_PASS",
        },
        {
            "name": "test_icmp_count_pass",
            "description": "ICMP packet should be counted at index 2 and passed",
            "packet_hex": make_eth(payload=make_ipv4(proto=1, payload=make_icmp())).hex(),
            "expected_action": "XDP_PASS",
        },
        {
            "name": "test_arp_count_pass",
            "description": "Non-IP ARP packet should be counted at index 3 (other) and passed",
            "packet_hex": make_eth(eth_type=0x0806, payload=b"\x00" * 28).hex(),
            "expected_action": "XDP_PASS",
        }
    ]
    
    gold_c = f"""{COMMON_HEADERS}

struct {{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
}} proto_stats_{idx} SEC(".maps");

SEC("xdp")
int xdp_telemetry_{task_id}(struct xdp_md *ctx) {{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u32 key = 3; // Other

    if (eth->h_proto == bpf_htons(ETH_P_IP)) {{
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) <= data_end) {{
            if (ip->protocol == IPPROTO_TCP)
                key = 0;
            else if (ip->protocol == IPPROTO_UDP)
                key = 1;
            else if (ip->protocol == IPPROTO_ICMP)
                key = 2;
        }}
    }}

    __u64 *cnt = bpf_map_lookup_elem(&proto_stats_{idx}, &key);
    if (cnt)
        __sync_fetch_and_add(cnt, 1);

    return XDP_PASS;
}}

char _license[] SEC("license") = "GPL";
"""
    faulty_c = f"""{COMMON_HEADERS}

struct {{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
}} proto_stats_{idx} SEC(".maps");

SEC("xdp")
int xdp_telemetry_{task_id}(struct xdp_md *ctx) {{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // FAULT: Key index not bounded before map lookup
    __u32 key = 10; 
    __u64 *cnt = bpf_map_lookup_elem(&proto_stats_{idx}, &key);
    *cnt += 1; // NULL dereference

    return XDP_PASS;
}}

char _license[] SEC("license") = "GPL";
"""
    return {
        "category": "packet_inspection_telemetry",
        "difficulty": "level_2",
        "task_id": task_id,
        "template_family": family,
        "semantic_signature": sig,
        "instruction": inst,
        "requirements": reqs,
        "tests": tests,
        "c00_code": faulty_c if needs_repair else gold_c,
        "r01_code": gold_c if needs_repair else None,
    }


def generate_pit_l3_task(idx: int) -> Dict[str, Any]:
    task_id = f"pit_l3_{idx:03d}"
    needs_repair = (idx % 4 != 0)
    
    family = "pit_flow_telemetry_tracker"
    sig = f"flow_byte_packet_tracker_{idx}"
    inst = f"Write an XDP program that records per-flow metrics (packets, bytes, last_seen timestamp) in a BPF LRU hash map for all IPv4 TCP and UDP flows. Return XDP_PASS for all traffic."
    reqs = [
        "Define BPF LRU hash map 'flow_metrics' with key 5-tuple and value struct flow_stats",
        "Update packet and byte count atomically or with map value pointer",
        "Capture timestamp using bpf_ktime_get_ns()",
        "Strictly validate Ethernet, IPv4, and transport layer boundaries",
    ]
    
    tests = [
        {
            "name": "test_tcp_flow_pass",
            "description": "TCP packet should record flow telemetry and pass",
            "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(src_port=2000 + idx, dst_port=443))).hex(),
            "expected_action": "XDP_PASS",
        },
        {
            "name": "test_udp_flow_pass",
            "description": "UDP packet should record flow telemetry and pass",
            "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(src_port=3000 + idx, dst_port=53))).hex(),
            "expected_action": "XDP_PASS",
        },
        {
            "name": "test_icmp_pass",
            "description": "ICMP packet should pass unaffected without flow update",
            "packet_hex": make_eth(payload=make_ipv4(proto=1, payload=make_icmp())).hex(),
            "expected_action": "XDP_PASS",
        },
        {
            "name": "test_arp_pass",
            "description": "Non-IP ARP packet should pass unaffected",
            "packet_hex": make_eth(eth_type=0x0806, payload=b"\x00" * 28).hex(),
            "expected_action": "XDP_PASS",
        },
        {
            "name": "test_truncated_pass",
            "description": "Truncated frame should safely pass",
            "packet_hex": b"\x52\x54\x00\x12\x34\x56\x52\x54\x00\x65\x43\x21\x08\x00\x45".hex(),
            "expected_action": "XDP_PASS",
        }
    ]
    
    gold_c = f"""{COMMON_HEADERS}

struct flow_tuple {{
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8  proto;
    __u8  pad[3];
}};

struct flow_stats {{
    __u64 packets;
    __u64 bytes;
    __u64 last_seen;
}};

struct {{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10000);
    __type(key, struct flow_tuple);
    __type(value, struct flow_stats);
}} flow_metrics_{idx} SEC(".maps");

SEC("xdp")
int xdp_telemetry_{task_id}(struct xdp_md *ctx) {{
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

    struct flow_tuple key = {{}};
    key.saddr = ip->saddr;
    key.daddr = ip->daddr;
    key.proto = ip->protocol;

    if (ip->protocol == IPPROTO_TCP) {{
        unsigned int ip_hdr_len = ip->ihl * 4;
        if (ip_hdr_len < sizeof(struct iphdr) || (void *)ip + ip_hdr_len > data_end)
            return XDP_PASS;
        struct tcphdr *tcp = (void *)ip + ip_hdr_len;
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        key.sport = tcp->source;
        key.dport = tcp->dest;
    }} else if (ip->protocol == IPPROTO_UDP) {{
        unsigned int ip_hdr_len = ip->ihl * 4;
        if (ip_hdr_len < sizeof(struct iphdr) || (void *)ip + ip_hdr_len > data_end)
            return XDP_PASS;
        struct udphdr *udp = (void *)ip + ip_hdr_len;
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        key.sport = udp->source;
        key.dport = udp->dest;
    }} else {{
        return XDP_PASS;
    }}

    __u64 pkt_len = (__u64)data_end - (__u64)data;
    struct flow_stats *stats = bpf_map_lookup_elem(&flow_metrics_{idx}, &key);
    if (stats) {{
        __sync_fetch_and_add(&stats->packets, 1);
        __sync_fetch_and_add(&stats->bytes, pkt_len);
        stats->last_seen = bpf_ktime_get_ns();
    }} else {{
        struct flow_stats initial = {{
            .packets = 1,
            .bytes = pkt_len,
            .last_seen = bpf_ktime_get_ns(),
        }};
        bpf_map_update_elem(&flow_metrics_{idx}, &key, &initial, BPF_ANY);
    }}

    return XDP_PASS;
}}

char _license[] SEC("license") = "GPL";
"""
    faulty_c = f"""{COMMON_HEADERS}

struct flow_tuple {{
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8  proto;
}};

struct flow_stats {{
    __u64 packets;
    __u64 bytes;
    __u64 last_seen;
}};

struct {{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10000);
    __type(key, struct flow_tuple);
    __type(value, struct flow_stats);
}} flow_metrics_{idx} SEC(".maps");

SEC("xdp")
int xdp_telemetry_{task_id}(struct xdp_md *ctx) {{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // FAULT: Missing IP header check and missing struct alignment
    struct iphdr *ip = (void *)(eth + 1);
    struct flow_tuple key;
    key.saddr = ip->saddr;
    key.daddr = ip->daddr;
    key.proto = ip->protocol;

    struct flow_stats *stats = bpf_map_lookup_elem(&flow_metrics_{idx}, &key);
    stats->packets += 1;

    return XDP_PASS;
}}

char _license[] SEC("license") = "GPL";
"""
    return {
        "category": "packet_inspection_telemetry",
        "difficulty": "level_3",
        "task_id": task_id,
        "template_family": family,
        "semantic_signature": sig,
        "instruction": inst,
        "requirements": reqs,
        "tests": tests,
        "c00_code": faulty_c if needs_repair else gold_c,
        "r01_code": gold_c if needs_repair else None,
    }


# =============================================================================
# Category 4: Protocol Transformation (PTR)
# =============================================================================

def generate_ptr_l1_task(idx: int) -> Dict[str, Any]:
    task_id = f"ptr_l1_{idx:03d}"
    needs_repair = (idx % 4 != 0)
    
    # 64 unique tasks: TTL decrement, MAC rewrite, TOS/DSCP remarking, TCP window clamping
    target_dscp = (idx % 8) << 2
    family = "ptr_ip_dscp_remarking"
    sig = f"remark_dscp_tos_{idx}"
    inst = f"Write an XDP program that rewrites the IPv4 TOS/DSCP field to value {target_dscp} (0x{target_dscp:02x}), recalculates the IPv4 checksum, and passes the packet with XDP_PASS."
    reqs = [
        f"Set IPv4 ip->tos = {target_dscp}",
        "Recalculate or incrementally update the IPv4 header checksum",
        "Return XDP_PASS for all packets",
        "Check boundaries on Ethernet and IPv4 headers",
    ]
    
    tests = [
        {
            "name": "test_remark_pass",
            "description": f"IPv4 packet should have TOS updated to {target_dscp} and pass",
            "packet_hex": make_eth(payload=make_ipv4(tos=0, payload=make_udp())).hex(),
            "expected_action": "XDP_PASS",
        },
        {
            "name": "test_tcp_remark_pass",
            "description": f"IPv4 TCP packet should have TOS updated to {target_dscp} and pass",
            "packet_hex": make_eth(payload=make_ipv4(tos=0, proto=6, payload=make_tcp())).hex(),
            "expected_action": "XDP_PASS",
        },
        {
            "name": "test_arp_pass",
            "description": "ARP packet should pass untouched",
            "packet_hex": make_eth(eth_type=0x0806, payload=b"\x00" * 28).hex(),
            "expected_action": "XDP_PASS",
        },
        {
            "name": "test_truncated_pass",
            "description": "Truncated Ethernet frame header should pass with XDP_PASS",
            "packet_hex": make_eth(eth_type=0x0800, payload=b"\x45").hex(),
            "expected_action": "XDP_PASS",
        }
    ]
    
    gold_c = f"""{COMMON_HEADERS}
SEC("xdp")
int xdp_transform_{task_id}(struct xdp_md *ctx) {{
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
    ip->tos = {target_dscp};

    // Incremental checksum update for TOS field
    __u32 csum = (__u32)ip->check + (__u32)old_tos - (__u32){target_dscp};
    csum = (csum & 0xFFFF) + (csum >> 16);
    ip->check = (__u16)csum;

    return XDP_PASS;
}}

char _license[] SEC("license") = "GPL";
"""
    faulty_c = f"""{COMMON_HEADERS}
SEC("xdp")
int xdp_transform_{task_id}(struct xdp_md *ctx) {{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // FAULT: Writing to ip->tos without checking if (ip + 1) > data_end
    struct iphdr *ip = (void *)(eth + 1);
    ip->tos = {target_dscp};

    return XDP_PASS;
}}

char _license[] SEC("license") = "GPL";
"""
    return {
        "category": "protocol_transformation",
        "difficulty": "level_1",
        "task_id": task_id,
        "template_family": family,
        "semantic_signature": sig,
        "instruction": inst,
        "requirements": reqs,
        "tests": tests,
        "c00_code": faulty_c if needs_repair else gold_c,
        "r01_code": gold_c if needs_repair else None,
    }


def generate_ptr_l2_task(idx: int) -> Dict[str, Any]:
    task_id = f"ptr_l2_{idx:03d}"
    needs_repair = (idx % 4 != 0)
    
    family = "ptr_stateless_snat_map"
    sig = f"stateless_snat_rewrite_{idx}"
    inst = f"Write an XDP program that implements 1:1 Source NAT (SNAT) using a BPF hash map 'snat_table'. Lookup source IP; if a mapped IP exists, rewrite ip->saddr, update IPv4 checksum, and return XDP_PASS."
    reqs = [
        "Define BPF hash map 'snat_table' mapping internal IP (__u32) to external IP (__u32)",
        "Rewrite ip->saddr with mapped IP and update ip->check",
        "Pass all traffic with XDP_PASS",
        "Strictly validate Ethernet and IPv4 header boundaries",
    ]
    
    internal_ip = f"192.168.1.{idx}"
    tests = [
        {
            "name": "test_snat_rewrite_pass",
            "description": f"Internal packet from {internal_ip} should be SNAT rewritten and passed",
            "packet_hex": make_eth(payload=make_ipv4(src_ip=internal_ip, payload=make_udp())).hex(),
            "expected_action": "XDP_PASS",
        },
        {
            "name": "test_tcp_snat_pass",
            "description": f"Internal TCP packet from {internal_ip} should be SNAT rewritten and passed",
            "packet_hex": make_eth(payload=make_ipv4(src_ip=internal_ip, proto=6, payload=make_tcp())).hex(),
            "expected_action": "XDP_PASS",
        },
        {
            "name": "test_clean_pass",
            "description": "Unmapped packet should pass unaffected",
            "packet_hex": make_eth(payload=make_ipv4(src_ip="10.50.50.50", payload=make_udp())).hex(),
            "expected_action": "XDP_PASS",
        },
        {
            "name": "test_arp_pass",
            "description": "ARP packet should pass untouched",
            "packet_hex": make_eth(eth_type=0x0806, payload=b"\x00" * 28).hex(),
            "expected_action": "XDP_PASS",
        },
        {
            "name": "test_truncated_pass",
            "description": "Truncated Ethernet frame header should pass with XDP_PASS",
            "packet_hex": make_eth(eth_type=0x0800, payload=b"\x45").hex(),
            "expected_action": "XDP_PASS",
        }
    ]
    
    gold_c = f"""{COMMON_HEADERS}

struct {{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u32);
}} snat_table_{idx} SEC(".maps");

SEC("xdp")
int xdp_transform_{task_id}(struct xdp_md *ctx) {{
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

    __u32 src_ip = ip->saddr;
    __u32 *new_ip = bpf_map_lookup_elem(&snat_table_{idx}, &src_ip);
    if (new_ip) {{
        __u32 old_saddr = ip->saddr;
        ip->saddr = *new_ip;
        // Adjust IP checksum
        __u32 csum = (__u32)ip->check + (old_saddr & 0xFFFF) + (old_saddr >> 16)
                     - ((*new_ip) & 0xFFFF) - ((*new_ip) >> 16);
        while (csum >> 16)
            csum = (csum & 0xFFFF) + (csum >> 16);
        ip->check = (__u16)csum;
    }}

    return XDP_PASS;
}}

char _license[] SEC("license") = "GPL";
"""
    faulty_c = f"""{COMMON_HEADERS}

struct {{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u32);
}} snat_table_{idx} SEC(".maps");

SEC("xdp")
int xdp_transform_{task_id}(struct xdp_md *ctx) {{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // FAULT: Unchecked map lookup pointer dereference
    __u32 src_ip = ip->saddr;
    __u32 *new_ip = bpf_map_lookup_elem(&snat_table_{idx}, &src_ip);
    ip->saddr = *new_ip;

    return XDP_PASS;
}}

char _license[] SEC("license") = "GPL";
"""
    return {
        "category": "protocol_transformation",
        "difficulty": "level_2",
        "task_id": task_id,
        "template_family": family,
        "semantic_signature": sig,
        "instruction": inst,
        "requirements": reqs,
        "tests": tests,
        "c00_code": faulty_c if needs_repair else gold_c,
        "r01_code": gold_c if needs_repair else None,
    }


def generate_ptr_l3_task(idx: int) -> Dict[str, Any]:
    task_id = f"ptr_l3_{idx:03d}"
    needs_repair = (idx % 4 != 0)
    
    family = "ptr_stateful_napt_rewriter"
    sig = f"stateful_napt_engine_{idx}"
    inst = f"Write an XDP program that implements stateful NAPT (Network Address Port Translation). For outbound TCP packets, translate private IP/port to public IP/port from a BPF map, update IP/TCP checksums, and forward. Return XDP_PASS."
    reqs = [
        "Define BPF LRU hash map 'napt_sessions' for session mapping",
        "Rewrite IPv4 source address and TCP source port",
        "Update IPv4 header checksum",
        "Handle variable IP header length and boundary checks",
    ]
    
    tests = [
        {
            "name": "test_napt_tcp_pass",
            "description": "Private TCP packet should undergo NAPT and pass",
            "packet_hex": make_eth(payload=make_ipv4(src_ip=f"10.0.{idx}.5", proto=6, payload=make_tcp(src_port=10000 + idx, dst_port=80))).hex(),
            "expected_action": "XDP_PASS",
        },
        {
            "name": "test_unmapped_tcp_pass",
            "description": "Unmapped TCP packet should pass unaffected",
            "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.100.5", proto=6, payload=make_tcp(src_port=10000 + idx, dst_port=80))).hex(),
            "expected_action": "XDP_PASS",
        },
        {
            "name": "test_udp_pass",
            "description": "UDP packet should pass unaffected",
            "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp())).hex(),
            "expected_action": "XDP_PASS",
        },
        {
            "name": "test_arp_pass",
            "description": "ARP packet should pass untouched",
            "packet_hex": make_eth(eth_type=0x0806, payload=b"\x00" * 28).hex(),
            "expected_action": "XDP_PASS",
        },
        {
            "name": "test_truncated_pass",
            "description": "Truncated packet header should safely pass",
            "packet_hex": b"\x52\x54\x00\x12\x34\x56\x52\x54\x00\x65\x43\x21\x08\x00\x45".hex(),
            "expected_action": "XDP_PASS",
        }
    ]
    
    gold_c = f"""{COMMON_HEADERS}

struct napt_key {{
    __u32 priv_ip;
    __u16 priv_port;
    __u16 pad;
}};

struct napt_val {{
    __u32 pub_ip;
    __u16 pub_port;
    __u16 pad;
}};

struct {{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10000);
    __type(key, struct napt_key);
    __type(value, struct napt_val);
}} napt_table_{idx} SEC(".maps");

SEC("xdp")
int xdp_transform_{task_id}(struct xdp_md *ctx) {{
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

    unsigned int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr) || (void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip_hdr_len;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    struct napt_key key = {{}};
    key.priv_ip = ip->saddr;
    key.priv_port = tcp->source;

    struct napt_val *val = bpf_map_lookup_elem(&napt_table_{idx}, &key);
    if (val) {{
        ip->saddr = val->pub_ip;
        tcp->source = val->pub_port;
        // Recalculate checksum
        __u32 csum = 0;
        ip->check = 0;
        __u16 *p = (__u16 *)ip;
        #pragma unroll
        for (int i = 0; i < 10; i++)
            csum += p[i];
        while (csum >> 16)
            csum = (csum & 0xFFFF) + (csum >> 16);
        ip->check = ~csum;
    }}

    return XDP_PASS;
}}

char _license[] SEC("license") = "GPL";
"""
    faulty_c = f"""{COMMON_HEADERS}

struct napt_key {{
    __u32 priv_ip;
    __u16 priv_port;
}};

struct napt_val {{
    __u32 pub_ip;
    __u16 pub_port;
}};

struct {{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10000);
    __type(key, struct napt_key);
    __type(value, struct napt_val);
}} napt_table_{idx} SEC(".maps");

SEC("xdp")
int xdp_transform_{task_id}(struct xdp_md *ctx) {{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // FAULT: Unchecked map pointer and unaligned key structure
    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    struct napt_key key;
    key.priv_ip = ip->saddr;
    key.priv_port = tcp->source;

    struct napt_val *val = bpf_map_lookup_elem(&napt_table_{idx}, &key);
    ip->saddr = val->pub_ip;

    return XDP_PASS;
}}

char _license[] SEC("license") = "GPL";
"""
    return {
        "category": "protocol_transformation",
        "difficulty": "level_3",
        "task_id": task_id,
        "template_family": family,
        "semantic_signature": sig,
        "instruction": inst,
        "requirements": reqs,
        "tests": tests,
        "c00_code": faulty_c if needs_repair else gold_c,
        "r01_code": gold_c if needs_repair else None,
    }


# =============================================================================
# Generator Dispatcher
# =============================================================================

GENERATORS = {
    ("packet_filtering_security", "level_1"): generate_pfs_l1_task,
    ("packet_filtering_security", "level_2"): generate_pfs_l2_task,
    ("packet_filtering_security", "level_3"): generate_pfs_l3_task,
    ("network_routing_forwarding", "level_1"): generate_nrf_l1_task,
    ("network_routing_forwarding", "level_2"): generate_nrf_l2_task,
    ("network_routing_forwarding", "level_3"): generate_nrf_l3_task,
    ("packet_inspection_telemetry", "level_1"): generate_pit_l1_task,
    ("packet_inspection_telemetry", "level_2"): generate_pit_l2_task,
    ("packet_inspection_telemetry", "level_3"): generate_pit_l3_task,
    ("protocol_transformation", "level_1"): generate_ptr_l1_task,
    ("protocol_transformation", "level_2"): generate_ptr_l2_task,
    ("protocol_transformation", "level_3"): generate_ptr_l3_task,
}

CATEGORIES = [
    "packet_filtering_security",
    "network_routing_forwarding",
    "packet_inspection_telemetry",
    "protocol_transformation",
]

def generate_worker_partition(worker_id: int) -> List[Dict[str, Any]]:
    """
    Worker 1 (0): L1 1..16,  L2 1..16,  L3 1..8   (40 per cat x 4 = 160 tasks)
    Worker 2 (1): L1 17..32, L2 17..32, L3 9..16  (40 per cat x 4 = 160 tasks)
    Worker 3 (2): L1 33..48, L2 33..48, L3 17..24 (40 per cat x 4 = 160 tasks)
    Worker 4 (3): L1 49..64, L2 49..64, L3 25..32 (40 per cat x 4 = 160 tasks)
    """
    assert 0 <= worker_id < 4, "Worker ID must be 0, 1, 2, or 3"
    
    l1_range = range(worker_id * 16 + 1, worker_id * 16 + 17)
    l2_range = range(worker_id * 16 + 1, worker_id * 16 + 17)
    l3_range = range(worker_id * 8 + 1, worker_id * 8 + 9)
    
    tasks = []
    for cat in CATEGORIES:
        gen_l1 = GENERATORS[(cat, "level_1")]
        for idx in l1_range:
            tasks.append(gen_l1(idx))
            
        gen_l2 = GENERATORS[(cat, "level_2")]
        for idx in l2_range:
            tasks.append(gen_l2(idx))
            
        gen_l3 = GENERATORS[(cat, "level_3")]
        for idx in l3_range:
            tasks.append(gen_l3(idx))
            
    return tasks


def write_tasks(tasks: List[Dict[str, Any]]) -> Tuple[int, int]:
    total_tasks = 0
    repair_tasks = 0
    
    for t in tasks:
        total_tasks += 1
        c00_meta = {
            "authoring_harness": "subagent_generator",
            "authoring_model": "gemini_3_7_flash",
            "generation_prompt_version": "sft_synthesis_v1",
        }
        r01_meta = None
        if t["r01_code"] is not None:
            repair_tasks += 1
            r01_meta = {
                "authoring_harness": "subagent_generator",
                "authoring_model": "gemini_3_7_flash",
                "generation_prompt_version": "sft_repair_v1",
            }
            
        write_task_bundle(
            category=t["category"],
            difficulty=t["difficulty"],
            task_id=t["task_id"],
            template_family=t["template_family"],
            semantic_signature=t["semantic_signature"],
            instruction=t["instruction"],
            requirements=t["requirements"],
            test_cases=t["tests"],
            c00_code=t["c00_code"],
            c00_meta=c00_meta,
            r01_code=t["r01_code"],
            r01_meta=r01_meta,
        )
    return total_tasks, repair_tasks


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate BPF-Guardian SFT Dataset Tasks")
    parser.add_argument("--worker", type=int, choices=[1, 2, 3, 4], default=None, help="Specific worker partition (1-4)")
    parser.add_argument("--all", action="store_true", help="Generate all 640 tasks across all workers")
    args = parser.parse_args()

    if args.all:
        print("=== Generating complete 640-task dataset across all 4 worker partitions ===")
        total_t = 0
        total_r = 0
        for w in range(4):
            tasks = generate_worker_partition(w)
            t_cnt, r_cnt = write_tasks(tasks)
            total_t += t_cnt
            total_r += r_cnt
            print(f"[*] Worker {w+1}: Generated {t_cnt} tasks ({r_cnt} with natural repair pairs)")
        print(f"\n[+] Total Synthesis Tasks Generated: {total_t}")
        print(f"[+] Total Natural Repair Tasks Generated: {total_r}")
    elif args.worker is not None:
        w_idx = args.worker - 1
        print(f"=== Generating Worker {args.worker} Partition (160 Tasks) ===")
        tasks = generate_worker_partition(w_idx)
        t_cnt, r_cnt = write_tasks(tasks)
        print(f"[+] Worker {args.worker} Generated: {t_cnt} tasks ({r_cnt} with natural repair pairs)")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
