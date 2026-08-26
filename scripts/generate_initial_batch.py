#!/usr/bin/env python3
"""
Generates Batch-001 for Antigravity inbox with 10 XDP tasks,
initial candidates (c00.c), provenance metadata (c00.meta.json), and task specs (task.json).
"""

from __future__ import annotations

import hashlib
import json
import os
import struct
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
INBOX_DIR = PROJECT_ROOT / "data" / "inbox" / "antigravity" / "batch-001"


def compute_sha256_str(text: str) -> str:
    digest = hashlib.sha256()
    digest.update(text.encode("utf-8"))
    return digest.hexdigest()


# Helper packet generators
def make_eth_packet(eth_type: int = 0x0800, payload: bytes = b"") -> bytes:
    dst_mac = bytes([0x52, 0x54, 0x00, 0x12, 0x34, 0x56])
    src_mac = bytes([0x52, 0x54, 0x00, 0x65, 0x43, 0x21])
    return dst_mac + src_mac + struct.pack("!H", eth_type) + payload


def make_vlan_eth_packet(vlan_id: int = 100, inner_eth_type: int = 0x0800, payload: bytes = b"") -> bytes:
    dst_mac = bytes([0x52, 0x54, 0x00, 0x12, 0x34, 0x56])
    src_mac = bytes([0x52, 0x54, 0x00, 0x65, 0x43, 0x21])
    vlan_hdr = struct.pack("!HH", 0x8100, vlan_id & 0x0FFF)
    return dst_mac + src_mac + vlan_hdr + struct.pack("!H", inner_eth_type) + payload


def make_ipv4_packet(
    src_ip: str = "192.168.1.10",
    dst_ip: str = "192.168.1.20",
    proto: int = 6,
    ttl: int = 64,
    payload: bytes = b"",
) -> bytes:
    src_bytes = bytes(map(int, src_ip.split(".")))
    dst_bytes = bytes(map(int, dst_ip.split(".")))
    tot_len = 20 + len(payload)
    iph = struct.pack("!BBHHHBBH4s4s", 0x45, 0, tot_len, 1234, 0, ttl, proto, 0, src_bytes, dst_bytes)
    return iph + payload


def make_tcp_packet(
    src_port: int = 12345,
    dst_port: int = 80,
    flags: int = 0x02,
    payload: bytes = b"DATA",
) -> bytes:
    data_offset = 5  # 20 bytes header
    tcph = struct.pack("!HHIIHHHH", src_port, dst_port, 1000, 0, (data_offset << 12) | flags, 65535, 0, 0)
    return tcph + payload


def make_udp_packet(
    src_port: int = 12345,
    dst_port: int = 53,
    payload: bytes = b"DNS_QUERY",
    override_length: int | None = None,
) -> bytes:
    udp_len = override_length if override_length is not None else (8 + len(payload))
    udph = struct.pack("!HHHH", src_port, dst_port, udp_len, 0)
    return udph + payload


def make_icmp_packet(icmp_type: int = 8, icmp_code: int = 0, payload: bytes = b"PING") -> bytes:
    icmph = struct.pack("!BBHI", icmp_type, icmp_code, 0, 0)
    return icmph + payload


def build_tasks() -> list[dict]:
    tasks = []

    # =========================================================================
    # Task 1: Drop IPv4 TCP Dport 23 (Telnet)
    # =========================================================================
    t1_id = "xdp_antigravity_b01_t01_drop_tcp_port"
    t1_c00 = """#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int xdp_drop_tcp_23(struct xdp_md *ctx) {
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

    if (tcp->dest == bpf_htons(23))
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    t1_tests = [
        {
            "name": "positive_telnet_drop",
            "description": "IPv4 TCP to port 23 should be dropped",
            "packet_hex": make_eth_packet(0x0800, make_ipv4_packet(proto=6, payload=make_tcp_packet(dst_port=23))).hex(),
            "expected_action": "XDP_DROP",
        },
        {
            "name": "negative_http_pass",
            "description": "IPv4 TCP to port 80 should pass",
            "packet_hex": make_eth_packet(0x0800, make_ipv4_packet(proto=6, payload=make_tcp_packet(dst_port=80))).hex(),
            "expected_action": "XDP_PASS",
        },
        {
            "name": "negative_udp_pass",
            "description": "IPv4 UDP to port 23 should pass",
            "packet_hex": make_eth_packet(0x0800, make_ipv4_packet(proto=17, payload=make_udp_packet(dst_port=23))).hex(),
            "expected_action": "XDP_PASS",
        },
        {
            "name": "negative_arp_pass",
            "description": "Non-IP ARP packet should pass",
            "packet_hex": make_eth_packet(0x0806, b"\x00" * 28).hex(),
            "expected_action": "XDP_PASS",
        },
        {
            "name": "boundary_truncated_pass",
            "description": "Truncated Ethernet packet (<14 bytes) should safely pass",
            "packet_hex": b"\x52\x54\x00\x12".hex(),
            "expected_action": "XDP_PASS",
        },
    ]
    tasks.append({
        "task_id": t1_id,
        "template_family": "ipv4_tcp_destination_filter",
        "semantic_signature": "ipv4+tcp+dport_23+drop",
        "difficulty": "basic",
        "split": "train",
        "instruction": "Write a complete XDP/eBPF C program that drops IPv4 TCP packets whose destination port is 23 (Telnet) and passes every other packet. Handle variable-length IPv4 headers and check all packet bounds.",
        "requirements": [
            "Return complete C source only",
            "Check bounds before every packet-header access",
            "Handle variable IPv4 header length (ip->ihl * 4)",
            "Pass non-IPv4 and non-TCP packets",
        ],
        "gold_candidate_id": None,
        "c00": t1_c00,
        "tests": t1_tests,
    })

    # =========================================================================
    # Task 2: Drop IPv4 UDP Dport 53 (DNS) - Initial candidate with verifier error
    # =========================================================================
    t2_id = "xdp_antigravity_b01_t02_drop_udp_port"
    # Faulty initial candidate: Missing bound check for UDP header after variable IPv4 header length
    t2_c00 = """#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int xdp_drop_udp_dns(struct xdp_md *ctx) {
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

    // FAULT: Missing check on (udphdr + 1) > data_end before dereferencing udp->dest
    struct udphdr *udp = (void *)ip + (ip->ihl * 4);
    if (udp->dest == bpf_htons(53))
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    t2_tests = [
        {
            "name": "positive_dns_drop",
            "description": "IPv4 UDP to port 53 should be dropped",
            "packet_hex": make_eth_packet(0x0800, make_ipv4_packet(proto=17, payload=make_udp_packet(dst_port=53))).hex(),
            "expected_action": "XDP_DROP",
        },
        {
            "name": "negative_ntp_pass",
            "description": "IPv4 UDP to port 123 should pass",
            "packet_hex": make_eth_packet(0x0800, make_ipv4_packet(proto=17, payload=make_udp_packet(dst_port=123))).hex(),
            "expected_action": "XDP_PASS",
        },
        {
            "name": "negative_tcp_pass",
            "description": "IPv4 TCP to port 53 should pass",
            "packet_hex": make_eth_packet(0x0800, make_ipv4_packet(proto=6, payload=make_tcp_packet(dst_port=53))).hex(),
            "expected_action": "XDP_PASS",
        },
        {
            "name": "negative_arp_pass",
            "description": "Non-IP ARP packet should pass",
            "packet_hex": make_eth_packet(0x0806, b"\x00" * 28).hex(),
            "expected_action": "XDP_PASS",
        },
        {
            "name": "boundary_short_pass",
            "description": "Short packet should safely pass",
            "packet_hex": b"\x52\x54\x00\x12\x34\x56\x52\x54\x00".hex(),
            "expected_action": "XDP_PASS",
        },
    ]
    tasks.append({
        "task_id": t2_id,
        "template_family": "ipv4_udp_destination_filter",
        "semantic_signature": "ipv4+udp+dport_53+drop",
        "difficulty": "basic",
        "split": "train",
        "instruction": "Write a complete XDP/eBPF C program that drops IPv4 UDP packets destined for port 53 (DNS) and passes all other packets. Validate all header bounds rigorously.",
        "requirements": [
            "Return complete C source only",
            "Check bounds before every packet-header access",
            "Handle variable IPv4 header length (ip->ihl * 4)",
            "Pass non-IPv4 and non-UDP packets",
        ],
        "gold_candidate_id": None,
        "c00": t2_c00,
        "tests": t2_tests,
    })

    # =========================================================================
    # Task 3: Drop IPv4 ICMP (Protocol 1)
    # =========================================================================
    t3_id = "xdp_antigravity_b01_t03_drop_icmp"
    t3_c00 = """#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int xdp_drop_icmp(struct xdp_md *ctx) {
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

    if (ip->protocol == IPPROTO_ICMP)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    t3_tests = [
        {
            "name": "positive_icmp_drop",
            "description": "IPv4 ICMP ping should be dropped",
            "packet_hex": make_eth_packet(0x0800, make_ipv4_packet(proto=1, payload=make_icmp_packet(8, 0))).hex(),
            "expected_action": "XDP_DROP",
        },
        {
            "name": "negative_tcp_pass",
            "description": "IPv4 TCP packet should pass",
            "packet_hex": make_eth_packet(0x0800, make_ipv4_packet(proto=6, payload=make_tcp_packet(dst_port=80))).hex(),
            "expected_action": "XDP_PASS",
        },
        {
            "name": "negative_udp_pass",
            "description": "IPv4 UDP packet should pass",
            "packet_hex": make_eth_packet(0x0800, make_ipv4_packet(proto=17, payload=make_udp_packet(dst_port=53))).hex(),
            "expected_action": "XDP_PASS",
        },
        {
            "name": "negative_arp_pass",
            "description": "ARP packet should pass",
            "packet_hex": make_eth_packet(0x0806, b"\x00" * 28).hex(),
            "expected_action": "XDP_PASS",
        },
        {
            "name": "boundary_short_pass",
            "description": "Short packet should safely pass",
            "packet_hex": b"\x00\x11\x22\x33\x44\x55".hex(),
            "expected_action": "XDP_PASS",
        },
    ]
    tasks.append({
        "task_id": t3_id,
        "template_family": "ipv4_protocol_filter",
        "semantic_signature": "ipv4+proto_icmp+drop",
        "difficulty": "basic",
        "split": "train",
        "instruction": "Write a complete XDP/eBPF C program that drops all IPv4 ICMP packets (IP protocol 1) and passes every other packet. Ensure safe bounds checking.",
        "requirements": [
            "Return complete C source only",
            "Check bounds for Ethernet and IPv4 headers",
            "Pass non-IPv4 and non-ICMP packets",
        ],
        "gold_candidate_id": None,
        "c00": t3_c00,
        "tests": t3_tests,
    })

    # =========================================================================
    # Task 4: Drop TCP SYN+FIN - Initial candidate with compiler error
    # =========================================================================
    t4_id = "xdp_antigravity_b01_t04_drop_syn_fin"
    # Faulty initial candidate: syntax/compiler error (missing semicolon and undefined macro)
    t4_c00 = """#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int xdp_drop_syn_fin(struct xdp_md *ctx) {
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

    // SYN is bit 1 (0x02) and FIN is bit 0 (0x01) in flags byte
    // FAULT: Syntax error missing semicolon on flags definition and typo in byte offset
    __u8 tcp_flags = ((__u8 *)tcp)[13]
    if ((tcp_flags & 0x03) == 0x03)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    t4_tests = [
        {
            "name": "positive_syn_fin_drop",
            "description": "TCP with SYN and FIN (flags=0x03) should be dropped",
            "packet_hex": make_eth_packet(0x0800, make_ipv4_packet(proto=6, payload=make_tcp_packet(flags=0x03))).hex(),
            "expected_action": "XDP_DROP",
        },
        {
            "name": "positive_syn_fin_ack_drop",
            "description": "TCP with SYN, FIN, and ACK (flags=0x13) should be dropped",
            "packet_hex": make_eth_packet(0x0800, make_ipv4_packet(proto=6, payload=make_tcp_packet(flags=0x13))).hex(),
            "expected_action": "XDP_DROP",
        },
        {
            "name": "negative_syn_pass",
            "description": "Normal TCP SYN packet (flags=0x02) should pass",
            "packet_hex": make_eth_packet(0x0800, make_ipv4_packet(proto=6, payload=make_tcp_packet(flags=0x02))).hex(),
            "expected_action": "XDP_PASS",
        },
        {
            "name": "negative_ack_pass",
            "description": "Normal TCP ACK packet (flags=0x10) should pass",
            "packet_hex": make_eth_packet(0x0800, make_ipv4_packet(proto=6, payload=make_tcp_packet(flags=0x10))).hex(),
            "expected_action": "XDP_PASS",
        },
        {
            "name": "negative_udp_pass",
            "description": "IPv4 UDP packet should pass",
            "packet_hex": make_eth_packet(0x0800, make_ipv4_packet(proto=17, payload=make_udp_packet())).hex(),
            "expected_action": "XDP_PASS",
        },
    ]
    tasks.append({
        "task_id": t4_id,
        "template_family": "ipv4_tcp_flags_filter",
        "semantic_signature": "ipv4+tcp+syn_fin+drop",
        "difficulty": "intermediate",
        "split": "train",
        "instruction": "Write a complete XDP/eBPF C program that drops IPv4 TCP packets with both SYN (0x02) and FIN (0x01) flags set simultaneously, and passes all other packets. Validate Ethernet, IPv4, and TCP header bounds.",
        "requirements": [
            "Return complete C source only",
            "Check bounds for Ethernet, IPv4, and TCP headers",
            "Inspect TCP flags byte (SYN=0x02, FIN=0x01)",
            "Pass all valid TCP packets and non-TCP traffic",
        ],
        "gold_candidate_id": None,
        "c00": t4_c00,
        "tests": t4_tests,
    })

    # =========================================================================
    # Task 5: Drop Oversized Packets (> 1400 bytes)
    # =========================================================================
    t5_id = "xdp_antigravity_b01_t05_drop_oversized"
    t5_c00 = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_drop_oversized(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    unsigned long pkt_len = (unsigned long)((char *)data_end - (char *)data);
    if (pkt_len > 1400)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    t5_tests = [
        {
            "name": "positive_oversized_drop",
            "description": "Packet of 1450 bytes should be dropped",
            "packet_hex": (make_eth_packet(0x0800, make_ipv4_packet(proto=17, payload=b"X" * 1416))).hex(),
            "expected_action": "XDP_DROP",
        },
        {
            "name": "negative_small_pass",
            "description": "Packet of 64 bytes should pass",
            "packet_hex": make_eth_packet(0x0800, make_ipv4_packet(proto=17, payload=b"A" * 30)).hex(),
            "expected_action": "XDP_PASS",
        },
        {
            "name": "boundary_1400_pass",
            "description": "Packet of exactly 1400 bytes should pass",
            "packet_hex": (b"P" * 1400).hex(),
            "expected_action": "XDP_PASS",
        },
        {
            "name": "boundary_1401_drop",
            "description": "Packet of 1401 bytes should be dropped",
            "packet_hex": (b"P" * 1401).hex(),
            "expected_action": "XDP_DROP",
        },
    ]
    tasks.append({
        "task_id": t5_id,
        "template_family": "packet_length_filter",
        "semantic_signature": "wire_len_gt_1400+drop",
        "difficulty": "basic",
        "split": "train",
        "instruction": "Write a complete XDP/eBPF C program that calculates total wire packet length (data_end - data) and drops any packet strictly greater than 1400 bytes, passing all packets of 1400 bytes or less.",
        "requirements": [
            "Return complete C source only",
            "Inspect ctx->data and ctx->data_end",
            "Drop if length > 1400",
            "Pass if length <= 1400",
        ],
        "gold_candidate_id": None,
        "c00": t5_c00,
        "tests": t5_tests,
    })

    # =========================================================================
    # Task 6: VLAN 802.1Q HTTP Dport 8080 Drop - Initial candidate with behavioral bug
    # =========================================================================
    t6_id = "xdp_antigravity_b01_t06_vlan_drop_http"
    # Faulty initial candidate: Endianness bug on TCP destination port comparison (8080 instead of bpf_htons(8080))
    t6_c00 = """#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

SEC("xdp")
int xdp_vlan_filter(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_8021Q))
        return XDP_PASS;

    struct vlan_hdr *vlan = (void *)(eth + 1);
    if ((void *)(vlan + 1) > data_end)
        return XDP_PASS;

    if (vlan->h_vlan_encapsulated_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(vlan + 1);
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

    // FAULT: Comparing network byte order port with host byte order constant without bpf_htons
    if (tcp->dest == 8080)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    t6_tests = [
        {
            "name": "positive_vlan_8080_drop",
            "description": "VLAN tagged IPv4 TCP dport=8080 should be dropped",
            "packet_hex": make_vlan_eth_packet(100, 0x0800, make_ipv4_packet(proto=6, payload=make_tcp_packet(dst_port=8080))).hex(),
            "expected_action": "XDP_DROP",
        },
        {
            "name": "negative_vlan_80_pass",
            "description": "VLAN tagged IPv4 TCP dport=80 should pass",
            "packet_hex": make_vlan_eth_packet(100, 0x0800, make_ipv4_packet(proto=6, payload=make_tcp_packet(dst_port=80))).hex(),
            "expected_action": "XDP_PASS",
        },
        {
            "name": "negative_untagged_8080_pass",
            "description": "Untagged IPv4 TCP dport=8080 should pass",
            "packet_hex": make_eth_packet(0x0800, make_ipv4_packet(proto=6, payload=make_tcp_packet(dst_port=8080))).hex(),
            "expected_action": "XDP_PASS",
        },
        {
            "name": "negative_vlan_udp_pass",
            "description": "VLAN tagged IPv4 UDP packet should pass",
            "packet_hex": make_vlan_eth_packet(100, 0x0800, make_ipv4_packet(proto=17, payload=make_udp_packet(dst_port=8080))).hex(),
            "expected_action": "XDP_PASS",
        },
        {
            "name": "boundary_short_vlan_pass",
            "description": "Truncated VLAN packet (<18 bytes) should safely pass",
            "packet_hex": b"\x52\x54\x00\x12\x34\x56\x52\x54\x00\x65\x43\x21\x81\x00\x00\x64".hex(),
            "expected_action": "XDP_PASS",
        },
    ]
    tasks.append({
        "task_id": t6_id,
        "template_family": "vlan_header_parsing",
        "semantic_signature": "vlan_8021q+ipv4+tcp+dport_8080+drop",
        "difficulty": "intermediate",
        "split": "train",
        "instruction": "Write a complete XDP/eBPF C program that parses 802.1Q VLAN tagged frames (EtherType 0x8100). If the encapsulated packet is IPv4 TCP destined for port 8080, drop it. Untagged packets and non-8080 traffic must be passed.",
        "requirements": [
            "Return complete C source only",
            "Parse 802.1Q header after Ethernet",
            "Check bounds for Ethernet, VLAN, IPv4, and TCP headers",
            "Apply correct byte order conversions using bpf_htons",
            "Pass untagged and non-matching traffic",
        ],
        "gold_candidate_id": None,
        "c00": t6_c00,
        "tests": t6_tests,
    })

    # =========================================================================
    # Task 7: BPF Hash Map IP Denylist
    # =========================================================================
    t7_id = "xdp_antigravity_b01_t07_src_ip_denylist_map"
    t7_c00 = """#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, 1024);
} blocked_ips SEC(".maps");

SEC("xdp")
int xdp_denylist_lookup(struct xdp_md *ctx) {
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
    __u8 *blocked = bpf_map_lookup_elem(&blocked_ips, &src_ip);
    if (blocked && *blocked != 0)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    t7_tests = [
        {
            "name": "negative_ip_not_blocked_pass",
            "description": "Source IP not in denylist should pass",
            "packet_hex": make_eth_packet(0x0800, make_ipv4_packet(src_ip="10.0.0.1", proto=6, payload=make_tcp_packet())).hex(),
            "expected_action": "XDP_PASS",
        },
        {
            "name": "negative_non_ip_pass",
            "description": "Non-IPv4 ARP packet should pass",
            "packet_hex": make_eth_packet(0x0806, b"\x00" * 28).hex(),
            "expected_action": "XDP_PASS",
        },
        {
            "name": "boundary_short_pass",
            "description": "Short packet (<14 bytes) should safely pass",
            "packet_hex": b"\x52\x54\x00\x12".hex(),
            "expected_action": "XDP_PASS",
        },
    ]
    tasks.append({
        "task_id": t7_id,
        "template_family": "bpf_map_denylist",
        "semantic_signature": "bpf_map_hash+ipv4_saddr+drop",
        "difficulty": "intermediate",
        "split": "train",
        "instruction": "Write a complete XDP/eBPF C program defining a BPF_MAP_TYPE_HASH map named 'blocked_ips' (key __u32, value __u8, max_entries 1024). Lookup the IPv4 source address in blocked_ips; if found and non-zero, drop the packet. Pass all other packets.",
        "requirements": [
            "Return complete C source only",
            "Define blocked_ips map in .maps section with BTF map definition",
            "Check bounds for Ethernet and IPv4 headers",
            "Check return pointer from bpf_map_lookup_elem before dereferencing",
            "Pass non-IPv4 and unblocked packets",
        ],
        "gold_candidate_id": None,
        "c00": t7_c00,
        "tests": t7_tests,
    })

    # =========================================================================
    # Task 8: BPF Array Map Packet Counter
    # =========================================================================
    t8_id = "xdp_antigravity_b01_t08_count_packets_map"
    t8_c00 = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} pkt_stats SEC(".maps");

SEC("xdp")
int xdp_count_packets(struct xdp_md *ctx) {
    __u32 key = 0;
    __u64 *count = bpf_map_lookup_elem(&pkt_stats, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    t8_tests = [
        {
            "name": "count_tcp_packet_pass",
            "description": "IPv4 TCP packet counted and passed",
            "packet_hex": make_eth_packet(0x0800, make_ipv4_packet(proto=6, payload=make_tcp_packet())).hex(),
            "expected_action": "XDP_PASS",
        },
        {
            "name": "count_udp_packet_pass",
            "description": "IPv4 UDP packet counted and passed",
            "packet_hex": make_eth_packet(0x0800, make_ipv4_packet(proto=17, payload=make_udp_packet())).hex(),
            "expected_action": "XDP_PASS",
        },
        {
            "name": "count_short_packet_pass",
            "description": "Arbitrary short packet counted and passed",
            "packet_hex": b"\x01\x02\x03\x04".hex(),
            "expected_action": "XDP_PASS",
        },
    ]
    tasks.append({
        "task_id": t8_id,
        "template_family": "bpf_map_counter",
        "semantic_signature": "bpf_map_array+pkt_counter+pass",
        "difficulty": "basic",
        "split": "train",
        "instruction": "Write a complete XDP/eBPF C program defining a BPF_MAP_TYPE_ARRAY map named 'pkt_stats' (key __u32, value __u64, max_entries 1). For every packet, look up key 0, atomically increment the counter, and return XDP_PASS.",
        "requirements": [
            "Return complete C source only",
            "Define pkt_stats map in .maps section",
            "Check null pointer on map lookup result before updating",
            "Return XDP_PASS for all packets",
        ],
        "gold_candidate_id": None,
        "c00": t8_c00,
        "tests": t8_tests,
    })

    # =========================================================================
    # Task 9: Drop UDP DNS Amplification (Port 53 & length > 512) - Initial candidate with verifier error
    # =========================================================================
    t9_id = "xdp_antigravity_b01_t09_drop_udp_dns_amplification"
    # Faulty initial candidate: Missing bounds check on UDP header before dereferencing udp->len
    t9_c00 = """#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int xdp_drop_dns_amp(struct xdp_md *ctx) {
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
    if (ip_hdr_len < sizeof(struct iphdr) || (void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    // FAULT: Missing check on (void *)(udp + 1) > data_end before reading udp->source / udp->dest / udp->len
    struct udphdr *udp = (void *)ip + ip_hdr_len;
    __u16 src = bpf_ntohs(udp->source);
    __u16 dst = bpf_ntohs(udp->dest);
    __u16 ulen = bpf_ntohs(udp->len);

    if ((src == 53 || dst == 53) && ulen > 512)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    t9_tests = [
        {
            "name": "positive_dns_large_src_drop",
            "description": "UDP packet from port 53 with length 600 should be dropped",
            "packet_hex": make_eth_packet(0x0800, make_ipv4_packet(proto=17, payload=make_udp_packet(src_port=53, dst_port=12345, payload=b"A"*592, override_length=600))).hex(),
            "expected_action": "XDP_DROP",
        },
        {
            "name": "positive_dns_large_dst_drop",
            "description": "UDP packet to port 53 with length 600 should be dropped",
            "packet_hex": make_eth_packet(0x0800, make_ipv4_packet(proto=17, payload=make_udp_packet(src_port=12345, dst_port=53, payload=b"A"*592, override_length=600))).hex(),
            "expected_action": "XDP_DROP",
        },
        {
            "name": "negative_dns_small_pass",
            "description": "UDP DNS packet with length 100 should pass",
            "packet_hex": make_eth_packet(0x0800, make_ipv4_packet(proto=17, payload=make_udp_packet(src_port=53, dst_port=12345, payload=b"A"*92, override_length=100))).hex(),
            "expected_action": "XDP_PASS",
        },
        {
            "name": "negative_other_udp_large_pass",
            "description": "Non-DNS UDP packet with length 600 should pass",
            "packet_hex": make_eth_packet(0x0800, make_ipv4_packet(proto=17, payload=make_udp_packet(src_port=8080, dst_port=9090, payload=b"A"*592, override_length=600))).hex(),
            "expected_action": "XDP_PASS",
        },
        {
            "name": "negative_tcp_pass",
            "description": "IPv4 TCP packet should pass",
            "packet_hex": make_eth_packet(0x0800, make_ipv4_packet(proto=6, payload=make_tcp_packet(dst_port=53))).hex(),
            "expected_action": "XDP_PASS",
        },
    ]
    tasks.append({
        "task_id": t9_id,
        "template_family": "multi_condition_combination",
        "semantic_signature": "ipv4+udp+port_53+len_gt_512+drop",
        "difficulty": "intermediate",
        "split": "train",
        "instruction": "Write a complete XDP/eBPF C program that drops IPv4 UDP packets if either source or destination port is 53 (DNS) AND the UDP header length exceeds 512 bytes. Pass all other packets.",
        "requirements": [
            "Return complete C source only",
            "Check bounds for Ethernet, IPv4, and UDP headers",
            "Handle variable IPv4 header length (ip->ihl * 4)",
            "Extract UDP length field and compare with 512",
            "Pass non-DNS UDP and other protocols",
        ],
        "gold_candidate_id": None,
        "c00": t9_c00,
        "tests": t9_tests,
    })

    # =========================================================================
    # Task 10: Allow Only SSH on IPv4 TCP (Firewall)
    # =========================================================================
    t10_id = "xdp_antigravity_b01_t10_allow_only_ssh"
    t10_c00 = """#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int xdp_ssh_only(struct xdp_md *ctx) {
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

    // Drop all IPv4 TCP packets whose destination port is NOT 22
    if (tcp->dest != bpf_htons(22))
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    t10_tests = [
        {
            "name": "ssh_port_22_pass",
            "description": "IPv4 TCP to port 22 should pass",
            "packet_hex": make_eth_packet(0x0800, make_ipv4_packet(proto=6, payload=make_tcp_packet(dst_port=22))).hex(),
            "expected_action": "XDP_PASS",
        },
        {
            "name": "http_port_80_drop",
            "description": "IPv4 TCP to port 80 should be dropped",
            "packet_hex": make_eth_packet(0x0800, make_ipv4_packet(proto=6, payload=make_tcp_packet(dst_port=80))).hex(),
            "expected_action": "XDP_DROP",
        },
        {
            "name": "https_port_443_drop",
            "description": "IPv4 TCP to port 443 should be dropped",
            "packet_hex": make_eth_packet(0x0800, make_ipv4_packet(proto=6, payload=make_tcp_packet(dst_port=443))).hex(),
            "expected_action": "XDP_DROP",
        },
        {
            "name": "udp_dns_pass",
            "description": "IPv4 UDP traffic should pass",
            "packet_hex": make_eth_packet(0x0800, make_ipv4_packet(proto=17, payload=make_udp_packet(dst_port=53))).hex(),
            "expected_action": "XDP_PASS",
        },
        {
            "name": "icmp_pass",
            "description": "IPv4 ICMP traffic should pass",
            "packet_hex": make_eth_packet(0x0800, make_ipv4_packet(proto=1, payload=make_icmp_packet())).hex(),
            "expected_action": "XDP_PASS",
        },
        {
            "name": "arp_pass",
            "description": "Non-IP ARP traffic should pass",
            "packet_hex": make_eth_packet(0x0806, b"\x00" * 28).hex(),
            "expected_action": "XDP_PASS",
        },
    ]
    tasks.append({
        "task_id": t10_id,
        "template_family": "ipv4_tcp_firewall",
        "semantic_signature": "ipv4+tcp+dport_not_22+drop",
        "difficulty": "basic",
        "split": "train",
        "instruction": "Write a complete XDP/eBPF C program that acts as an SSH firewall: if a packet is IPv4 TCP and its destination port is not 22, drop it. Pass port 22 TCP packets, non-TCP IPv4 packets, and non-IPv4 traffic.",
        "requirements": [
            "Return complete C source only",
            "Check bounds for Ethernet, IPv4, and TCP headers",
            "Pass IPv4 TCP destination port 22",
            "Drop all other IPv4 TCP packets",
            "Pass non-TCP IPv4 and non-IPv4 packets",
        ],
        "gold_candidate_id": None,
        "c00": t10_c00,
        "tests": t10_tests,
    })

    return tasks


def main() -> None:
    tasks = build_tasks()
    batch_id = "batch-001"
    batch_dir = INBOX_DIR
    batch_dir.mkdir(parents=True, exist_ok=True)

    print(f"Generating {len(tasks)} tasks in {batch_dir}...")

    for task_info in tasks:
        task_id = task_info["task_id"]
        t_dir = batch_dir / task_id
        t_dir.mkdir(parents=True, exist_ok=True)

        # 1. Write task.json
        task_data = {
            "task_id": task_id,
            "template_family": task_info["template_family"],
            "semantic_signature": task_info["semantic_signature"],
            "difficulty": task_info["difficulty"],
            "split": task_info["split"],
            "instruction": task_info["instruction"],
            "requirements": task_info["requirements"],
            "gold_candidate_id": task_info["gold_candidate_id"],
            "tests": task_info["tests"],
        }
        (t_dir / "task.json").write_text(json.dumps(task_data, indent=2), encoding="utf-8")

        # 2. Write c00.c
        c00_code = task_info["c00"]
        c00_path = t_dir / "c00.c"
        c00_path.write_text(c00_code, encoding="utf-8")
        c00_sha = compute_sha256_str(c00_code)

        # 3. Write c00.meta.json
        c00_meta = {
            "candidate_id": f"{task_id}_c00",
            "task_id": task_id,
            "authoring_harness": "antigravity",
            "authoring_model": "gemini-3.7-flash",
            "generation_prompt_version": "agent-generation-v1",
            "source_path": "c00.c",
            "parent_candidate_id": None,
            "repair_attempt": 0,
            "claimed_status": "unvalidated",
            "source_sha256": c00_sha,
        }
        (t_dir / "c00.meta.json").write_text(json.dumps(c00_meta, indent=2), encoding="utf-8")

        print(f"  [+] Created task: {task_id}")

    print("Batch generation complete.")


if __name__ == "__main__":
    main()
