#!/usr/bin/env python3
"""
Finishes tasks 7-10 for Batch-004 in data/inbox/batch-004/
"""

from __future__ import annotations

import hashlib
import json
import os
import struct
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
BATCH_DIR = PROJECT_ROOT / "data" / "inbox" / "batch-004"


def compute_sha256_str(text: str) -> str:
    digest = hashlib.sha256()
    digest.update(text.encode("utf-8"))
    return digest.hexdigest()


def make_eth_packet(eth_type: int = 0x0800, payload: bytes = b"") -> bytes:
    dst_mac = bytes([0x52, 0x54, 0x00, 0x12, 0x34, 0x56])
    src_mac = bytes([0x52, 0x54, 0x00, 0x65, 0x43, 0x21])
    return dst_mac + src_mac + struct.pack("!H", eth_type) + payload


def make_ipv4_packet(
    src_ip: str = "192.168.1.10",
    dst_ip: str = "192.168.1.20",
    tos: int = 0,
    frag_off: int = 0,
    ttl: int = 64,
    proto: int = 6,
    payload: bytes = b"",
) -> bytes:
    src_bytes = bytes(map(int, src_ip.split(".")))
    dst_bytes = bytes(map(int, dst_ip.split(".")))
    tot_len = 20 + len(payload)
    iph = struct.pack("!BBHHHBBH4s4s", 0x45, tos, tot_len, 1234, frag_off, ttl, proto, 0, src_bytes, dst_bytes)
    return iph + payload


def create_task(t_id: str, family: str, signature: str, difficulty: str, instruction: str, requirements: list[str], c_code: str, tests: list[dict]) -> None:
    t_dir = BATCH_DIR / t_id
    t_dir.mkdir(parents=True, exist_ok=True)

    task_data = {
        "task_id": t_id,
        "template_family": family,
        "semantic_signature": signature,
        "difficulty": difficulty,
        "split": "train",
        "instruction": instruction,
        "requirements": requirements,
        "gold_candidate_id": None,
        "tests": tests,
    }
    (t_dir / "task.json").write_text(json.dumps(task_data, indent=2), encoding="utf-8")

    (t_dir / "c00.c").write_text(c_code, encoding="utf-8")
    c00_sha = compute_sha256_str(c_code)

    meta_data = {
        "candidate_id": f"{t_id}_c00",
        "task_id": t_id,
        "authoring_harness": "agent",
        "authoring_model": "instruction_model",
        "generation_prompt_version": "agent-generation-v1",
        "source_path": "c00.c",
        "parent_candidate_id": None,
        "repair_attempt": 0,
        "claimed_status": "unvalidated",
        "source_sha256": c00_sha,
    }
    (t_dir / "c00.meta.json").write_text(json.dumps(meta_data, indent=2), encoding="utf-8")
    print(f"[+] Created {t_id}")


def main() -> None:
    # Task 7: Drop low TTL <= 1
    t7_id = "xdp_b04_t07_drop_low_ttl"
    t7_c = """#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int xdp_drop_low_ttl(struct xdp_md *ctx) {
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

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    t7_tests = [
        {"name": "ttl_1_drop", "description": "TTL=1 should be dropped", "packet_hex": make_eth_packet(0x0800, make_ipv4_packet(ttl=1, payload=b"PING")).hex(), "expected_action": "XDP_DROP"},
        {"name": "ttl_0_drop", "description": "TTL=0 should be dropped", "packet_hex": make_eth_packet(0x0800, make_ipv4_packet(ttl=0, payload=b"PING")).hex(), "expected_action": "XDP_DROP"},
        {"name": "ttl_64_pass", "description": "TTL=64 should pass", "packet_hex": make_eth_packet(0x0800, make_ipv4_packet(ttl=64, payload=b"PING")).hex(), "expected_action": "XDP_PASS"},
        {"name": "arp_pass", "description": "ARP packet should pass", "packet_hex": make_eth_packet(0x0806, b"\x00"*28).hex(), "expected_action": "XDP_PASS"},
        {"name": "short_eth_pass", "description": "Boundary 14-byte Ethernet should pass", "packet_hex": make_eth_packet(0x0800, b"").hex(), "expected_action": "XDP_PASS"},
    ]
    create_task(t7_id, "ipv4_ttl_filter", "ipv4+ttl_le_1+drop", "basic", "Write a complete XDP/eBPF C program that drops IPv4 packets with TTL <= 1, passing all packets with TTL > 1 and non-IPv4 traffic.", ["Check Ethernet and IPv4 bounds", "Inspect ip->ttl", "Pass TTL > 1"], t7_c, t7_tests)

    # Task 8: Drop DSCP CS6 (TOS 0xC0)
    t8_id = "xdp_b04_t08_drop_dscp_cs6"
    t8_c = """#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int xdp_drop_dscp_cs6(struct xdp_md *ctx) {
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

    // DSCP CS6 is 48 (0x30 in upper 6 bits, TOS byte 0xC0)
    if ((ip->tos & 0xFC) == 0xC0)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    t8_tests = [
        {"name": "dscp_cs6_drop", "description": "DSCP CS6 (TOS 0xC0) should be dropped", "packet_hex": make_eth_packet(0x0800, make_ipv4_packet(tos=0xC0, payload=b"DATA")).hex(), "expected_action": "XDP_DROP"},
        {"name": "dscp_cs0_pass", "description": "Normal TOS 0x00 should pass", "packet_hex": make_eth_packet(0x0800, make_ipv4_packet(tos=0x00, payload=b"DATA")).hex(), "expected_action": "XDP_PASS"},
        {"name": "dscp_ef_pass", "description": "DSCP EF (TOS 0xB8) should pass", "packet_hex": make_eth_packet(0x0800, make_ipv4_packet(tos=0xB8, payload=b"DATA")).hex(), "expected_action": "XDP_PASS"},
        {"name": "non_ip_pass", "description": "Non-IP ARP should pass", "packet_hex": make_eth_packet(0x0806, b"\x00"*28).hex(), "expected_action": "XDP_PASS"},
        {"name": "boundary_pass", "description": "Boundary packet should pass", "packet_hex": make_eth_packet(0x0800, b"").hex(), "expected_action": "XDP_PASS"},
    ]
    create_task(t8_id, "ipv4_tos_dscp_filter", "ipv4+tos_dscp_cs6+drop", "basic", "Write a complete XDP/eBPF C program that drops IPv4 packets whose DSCP field matches CS6 (TOS & 0xFC == 0xC0), passing all other packets.", ["Check Ethernet and IPv4 bounds", "Inspect ip->tos", "Pass non-matching traffic"], t8_c, t8_tests)

    # Task 9: Drop IP Fragments
    t9_id = "xdp_b04_t09_drop_ip_fragments"
    t9_c = """#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define IP_MF 0x2000
#define IP_OFFSET 0x1FFF

SEC("xdp")
int xdp_drop_fragments(struct xdp_md *ctx) {
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
    if ((frag_off & (IP_MF | IP_OFFSET)) != 0)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    t9_tests = [
        {"name": "fragment_mf_drop", "description": "IPv4 fragment with MF bit set should be dropped", "packet_hex": make_eth_packet(0x0800, make_ipv4_packet(frag_off=0x2000, payload=b"FRAG")).hex(), "expected_action": "XDP_DROP"},
        {"name": "fragment_offset_drop", "description": "IPv4 fragment with offset 100 should be dropped", "packet_hex": make_eth_packet(0x0800, make_ipv4_packet(frag_off=100, payload=b"FRAG")).hex(), "expected_action": "XDP_DROP"},
        {"name": "unfragmented_pass", "description": "Unfragmented IPv4 packet should pass", "packet_hex": make_eth_packet(0x0800, make_ipv4_packet(frag_off=0, payload=b"DATA")).hex(), "expected_action": "XDP_PASS"},
        {"name": "arp_pass", "description": "ARP packet should pass", "packet_hex": make_eth_packet(0x0806, b"\x00"*28).hex(), "expected_action": "XDP_PASS"},
        {"name": "boundary_pass", "description": "Boundary packet should pass", "packet_hex": make_eth_packet(0x0800, b"").hex(), "expected_action": "XDP_PASS"},
    ]
    create_task(t9_id, "ipv4_fragment_filter", "ipv4+frag_off_nonzero+drop", "intermediate", "Write a complete XDP/eBPF C program that inspects ip->frag_off and drops IPv4 fragmented packets (where fragment offset > 0 or MF flag is set), passing unfragmented traffic.", ["Check Ethernet and IPv4 bounds", "Parse frag_off with bpf_ntohs", "Check MF and offset bits"], t9_c, t9_tests)

    # Task 10: Pass only TCP, UDP, ICMP (Allowlist)
    t10_id = "xdp_b04_t10_pass_only_tcp_udp_icmp"
    t10_c = """#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int xdp_allow_tcp_udp_icmp(struct xdp_md *ctx) {
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

    if (ip->protocol == IPPROTO_TCP ||
        ip->protocol == IPPROTO_UDP ||
        ip->protocol == IPPROTO_ICMP)
        return XDP_PASS;

    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
"""
    t10_tests = [
        {"name": "tcp_pass", "description": "TCP (6) should pass", "packet_hex": make_eth_packet(0x0800, make_ipv4_packet(proto=6, payload=b"TCP")).hex(), "expected_action": "XDP_PASS"},
        {"name": "udp_pass", "description": "UDP (17) should pass", "packet_hex": make_eth_packet(0x0800, make_ipv4_packet(proto=17, payload=b"UDP")).hex(), "expected_action": "XDP_PASS"},
        {"name": "icmp_pass", "description": "ICMP (1) should pass", "packet_hex": make_eth_packet(0x0800, make_ipv4_packet(proto=1, payload=b"ICMP")).hex(), "expected_action": "XDP_PASS"},
        {"name": "gre_drop", "description": "GRE (47) should be dropped", "packet_hex": make_eth_packet(0x0800, make_ipv4_packet(proto=47, payload=b"GRE")).hex(), "expected_action": "XDP_DROP"},
        {"name": "igmp_drop", "description": "IGMP (2) should be dropped", "packet_hex": make_eth_packet(0x0800, make_ipv4_packet(proto=2, payload=b"IGMP")).hex(), "expected_action": "XDP_DROP"},
        {"name": "arp_pass", "description": "Non-IP ARP should pass", "packet_hex": make_eth_packet(0x0806, b"\x00"*28).hex(), "expected_action": "XDP_PASS"},
    ]
    create_task(t10_id, "ipv4_protocol_allowlist", "ipv4+proto_not_tcp_udp_icmp+drop", "basic", "Write a complete XDP/eBPF C program that drops IPv4 packets whose protocol is NOT TCP (6), UDP (17), or ICMP (1). Non-IPv4 and allowed protocol traffic must pass.", ["Check Ethernet and IPv4 bounds", "Allow IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMP", "Drop other IPv4 protocols"], t10_c, t10_tests)

    print("Batch 004 tasks complete.")


if __name__ == "__main__":
    main()
