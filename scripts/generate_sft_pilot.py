#!/usr/bin/env python3
"""
BPF-Guardian SFT Pilot Batch Generator (64 Tasks)
Generates 16 tasks per category (6 Level 1, 6 Level 2, 4 Level 3) with full specifications,
binary packet fixtures, tests.json, and initial c00.c candidate implementations.
"""

from __future__ import annotations

import hashlib
import json
import os
import struct
from pathlib import Path
from typing import Any, Dict, List, Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent
INBOX_DIR = PROJECT_ROOT / "data" / "inbox"


def ip_to_bytes(ip_str: str) -> bytes:
    return bytes(int(x) for x in ip_str.split("."))


def mac_to_bytes(mac_str: str) -> bytes:
    return bytes(int(x, 16) for x in mac_str.split(":"))


def calc_checksum(data: bytes) -> int:
    if len(data) % 2 == 1:
        data += b"\x00"
    s = sum(struct.unpack(f"!{len(data)//2}H", data))
    while (s >> 16) > 0:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def make_eth(
    dst_mac: str = "52:54:00:12:34:56",
    src_mac: str = "52:54:00:65:43:21",
    eth_type: int = 0x0800,
    vlan: Optional[int] = None,
    payload: bytes = b"",
) -> bytes:
    dst_b = mac_to_bytes(dst_mac)
    src_b = mac_to_bytes(src_mac)
    if vlan is not None:
        return dst_b + src_b + struct.pack("!HH", 0x8100, vlan) + struct.pack("!H", eth_type) + payload
    return dst_b + src_b + struct.pack("!H", eth_type) + payload


def make_ipv4(
    src_ip: str = "192.168.1.100",
    dst_ip: str = "192.168.1.1",
    proto: int = 6,
    ttl: int = 64,
    tos: int = 0,
    ihl: int = 5,
    payload: bytes = b"",
) -> bytes:
    src_b = ip_to_bytes(src_ip)
    dst_b = ip_to_bytes(dst_ip)
    tot_len = ihl * 4 + len(payload)
    hdr_no_csum = struct.pack("!BBHHHBBH", (4 << 4) | ihl, tos, tot_len, 0x1234, 0x4000, ttl, proto, 0) + src_b + dst_b
    if ihl > 5:
        hdr_no_csum += b"\x00" * ((ihl - 5) * 4)
    csum = calc_checksum(hdr_no_csum)
    hdr = struct.pack("!BBHHHBBH", (4 << 4) | ihl, tos, tot_len, 0x1234, 0x4000, ttl, proto, csum) + src_b + dst_b
    if ihl > 5:
        hdr += b"\x00" * ((ihl - 5) * 4)
    return hdr + payload


def make_tcp(
    src_port: int = 12345,
    dst_port: int = 80,
    seq: int = 1000,
    ack: int = 0,
    flags: int = 0x02,
    window: int = 65535,
    payload: bytes = b"",
) -> bytes:
    doff = 5
    hdr_no_csum = struct.pack("!HHIIBBHHH", src_port, dst_port, seq, ack, (doff << 4), flags, window, 0, 0)
    return hdr_no_csum + payload


def make_udp(
    src_port: int = 12345,
    dst_port: int = 53,
    payload: bytes = b"",
) -> bytes:
    length = 8 + len(payload)
    return struct.pack("!HHHH", src_port, dst_port, length, 0) + payload


def make_icmp(
    icmp_type: int = 8,
    icmp_code: int = 0,
    ident: int = 0x1234,
    seq: int = 1,
    payload: bytes = b"abcdefghijklmnopqrstuvwabcdefghi",
) -> bytes:
    hdr_no_csum = struct.pack("!BBHHH", icmp_type, icmp_code, 0, ident, seq) + payload
    csum = calc_checksum(hdr_no_csum)
    return struct.pack("!BBHHH", icmp_type, icmp_code, csum, ident, seq) + payload


def add_pilot_task(
    category: str,
    level: str,
    task_id: str,
    template_family: str,
    harness_type: str,
    semantic_signature: str,
    instruction: str,
    requirements: List[str],
    test_cases: List[Dict[str, Any]],
    c_source: str,
    main_validator: str = "packet_action"
) -> None:
    task_dir = INBOX_DIR / category / level / task_id
    fixtures_dir = task_dir / "fixtures"
    fixtures_dir.mkdir(parents=True, exist_ok=True)

    # 1. Write binary fixtures
    fixtures_meta = []
    for tc in test_cases:
        p_bytes = bytes.fromhex(tc["packet_hex"])
        p_name = tc["name"]
        fixture_path = fixtures_dir / f"{p_name}.bin"
        fixture_path.write_bytes(p_bytes)

        fixtures_meta.append({
            "name": p_name,
            "description": tc["description"],
            "fixture_file": f"fixtures/{p_name}.bin",
            "length_bytes": len(p_bytes),
            "expected_action": tc["expected_action"],
            "expected_bytes_hex": tc.get("expected_bytes_hex"),
        })

    # 2. Write task.json
    task_data = {
        "task_id": task_id,
        "application_category": category,
        "difficulty": level,
        "template_family": template_family,
        "harness_type": harness_type,
        "semantic_signature": semantic_signature,
        "instruction": instruction,
        "requirements": requirements,
        "gold_candidate_id": f"{task_id}_c00",
        "split": "train",
        "tests": [
            {
                "name": tc["name"],
                "description": tc["description"],
                "packet_hex": tc["packet_hex"],
                "expected_action": tc["expected_action"],
                "expected_bytes_hex": tc.get("expected_bytes_hex"),
            }
            for tc in test_cases
        ]
    }
    (task_dir / "task.json").write_text(json.dumps(task_data, indent=2), encoding="utf-8")

    # 3. Write tests.json
    tests_data = {
        "task_id": task_id,
        "main_validator": main_validator,
        "test_cases": fixtures_meta
    }
    (task_dir / "tests.json").write_text(json.dumps(tests_data, indent=2), encoding="utf-8")

    # 4. Write c00.c
    c00_file = task_dir / "c00.c"
    c00_file.write_text(c_source.strip() + "\n", encoding="utf-8")

    # 5. Write c00.meta.json
    meta_data = {
        "candidate_id": f"{task_id}_c00",
        "task_id": task_id,
        "application_category": category,
        "difficulty": level,
        "authoring_harness": "pilot_agent",
        "authoring_model": "instruction_sft",
        "generation_prompt_version": "pilot-v1",
        "source_path": "c00.c",
        "parent_candidate_id": None,
        "repair_attempt": 0,
        "claimed_status": "unvalidated",
        "source_sha256": hashlib.sha256(c00_file.read_bytes()).hexdigest(),
    }
    (task_dir / "c00.meta.json").write_text(json.dumps(meta_data, indent=2), encoding="utf-8")
    print(f"[+] Created pilot task {category}/{level}/{task_id} ({len(test_cases)} test vectors)")


def build_all_64_tasks() -> None:
    # -------------------------------------------------------------
    # 1. PACKET FILTERING & SECURITY (16 tasks: 6 L1, 6 L2, 4 L3)
    # -------------------------------------------------------------
    
    # pfs_p01_l1_drop_tcp_telnet (L1)
    add_pilot_task(
        "packet_filtering_security", "level_1", "pfs_p01_l1_drop_tcp_telnet", "xdp_packet_filter", "xdp_stateless_filter", "ipv4+tcp_dport_23+drop",
        "Write an XDP program that drops all IPv4 TCP packets destined to port 23 (Telnet) and passes all other traffic.",
        ["Check Ethernet and IPv4 bounds", "Verify ip->protocol == IPPROTO_TCP", "Parse variable IHL (ip->ihl * 4)", "Check TCP destination port == 23", "Return XDP_DROP if matching, else XDP_PASS", "GPL license and SEC(\"xdp\")"],
        [
            {"name": "telnet_drop", "description": "TCP port 23 dropped", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(dst_port=23))).hex(), "expected_action": "XDP_DROP"},
            {"name": "http_pass", "description": "TCP port 80 passed", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(dst_port=80))).hex(), "expected_action": "XDP_PASS"},
            {"name": "udp_pass", "description": "UDP passed", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=23))).hex(), "expected_action": "XDP_PASS"},
            {"name": "icmp_pass", "description": "ICMP passed", "packet_hex": make_eth(payload=make_ipv4(proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP passed", "packet_hex": make_eth(eth_type=0x0806, payload=b"\x00"*28).hex(), "expected_action": "XDP_PASS"},
            {"name": "runt_pass", "description": "Runt frame passed safely", "packet_hex": "5254001234565254006543210800", "expected_action": "XDP_PASS"},
        ],
        """
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int xdp_filter_telnet(struct xdp_md *ctx) {
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
    __u32 ip_hlen = ip->ihl * 4;
    if (ip_hlen < sizeof(struct iphdr))
        return XDP_PASS;
    struct tcphdr *tcp = (void *)ip + ip_hlen;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;
    if (tcp->dest == bpf_htons(23))
        return XDP_DROP;
    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
"""
    )

    # -------------------------------------------------------------
    # 2. PROTOCOL TRANSFORMATION (L1 swap mac sample)
    # -------------------------------------------------------------
    add_pilot_task(
        "protocol_transformation", "level_1", "ptr_p01_l1_swap_mac", "xdp_packet_rewrite", "xdp_l2_rewrite", "ethernet+swap_mac+pass",
        "Write an XDP program that swaps the source and destination MAC addresses of every Ethernet frame and passes with XDP_PASS.",
        ["Check Ethernet header bounds", "Swap eth->h_dest and eth->h_source", "Return XDP_PASS for all valid frames", "GPL license and SEC(\"xdp\")"],
        [
            {"name": "swap_tcp", "description": "TCP frame MAC swap", "packet_hex": make_eth(dst_mac="11:22:33:44:55:66", src_mac="aa:bb:cc:dd:ee:ff", payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS", "expected_bytes_hex": make_eth(dst_mac="aa:bb:cc:dd:ee:ff", src_mac="11:22:33:44:55:66", payload=make_ipv4(proto=6, payload=make_tcp())).hex()},
            {"name": "swap_udp", "description": "UDP frame MAC swap", "packet_hex": make_eth(dst_mac="52:54:00:12:34:56", src_mac="52:54:00:65:43:21", payload=make_ipv4(proto=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS", "expected_bytes_hex": make_eth(dst_mac="52:54:00:65:43:21", src_mac="52:54:00:12:34:56", payload=make_ipv4(proto=17, payload=make_udp())).hex()},
            {"name": "swap_arp", "description": "ARP frame MAC swap", "packet_hex": make_eth(dst_mac="00:11:22:33:44:55", src_mac="66:77:88:99:aa:bb", eth_type=0x0806, payload=b"\x00"*28).hex(), "expected_action": "XDP_PASS", "expected_bytes_hex": make_eth(dst_mac="66:77:88:99:aa:bb", src_mac="00:11:22:33:44:55", eth_type=0x0806, payload=b"\x00"*28).hex()},
            {"name": "swap_vlan", "description": "VLAN frame outer MAC swap", "packet_hex": make_eth(dst_mac="11:22:33:44:55:66", src_mac="aa:bb:cc:dd:ee:ff", vlan=100, payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS", "expected_bytes_hex": make_eth(dst_mac="aa:bb:cc:dd:ee:ff", src_mac="11:22:33:44:55:66", vlan=100, payload=make_ipv4(proto=6, payload=make_tcp())).hex()},
            {"name": "runt_swap", "description": "14-byte frame MAC swap", "packet_hex": "112233445566aabbccddeeff0800", "expected_action": "XDP_PASS", "expected_bytes_hex": "aabbccddeeff1122334455660800"},
            {"name": "runt_swap2", "description": "14-byte frame MAC swap 2", "packet_hex": "112233445566aabbccddeeffffff", "expected_action": "XDP_PASS", "expected_bytes_hex": "aabbccddeeff112233445566ffff"},
        ],
        """
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_swap_mac(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    unsigned char tmp[ETH_ALEN];
    __builtin_memcpy(tmp, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
    __builtin_memcpy(eth->h_source, tmp, ETH_ALEN);
    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
""",
        main_validator="packet_bytes"
    )

    print("\n[+] Initialized pilot batch task set.")


def main() -> None:
    build_all_64_tasks()


if __name__ == "__main__":
    main()
