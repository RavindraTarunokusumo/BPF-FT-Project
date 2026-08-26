#!/usr/bin/env python3
"""
Fixes task.json and creates c00-r01 for xdp_b04_t09_drop_ip_fragments
"""

from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
TASK_DIR = PROJECT_ROOT / "data" / "inbox" / "batch-004" / "xdp_b04_t09_drop_ip_fragments"
VAL_DIR = PROJECT_ROOT / "data" / "validation" / "batch-004"


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
    frag_off: int = 0,
    ttl: int = 64,
    proto: int = 17,
    payload: bytes = b"DATA",
) -> bytes:
    src_bytes = bytes(map(int, src_ip.split(".")))
    dst_bytes = bytes(map(int, dst_ip.split(".")))
    tot_len = 20 + len(payload)
    iph = struct.pack("!BBHHHBBH4s4s", 0x45, 0, tot_len, 1234, frag_off, ttl, proto, 0, src_bytes, dst_bytes)
    return iph + payload


def main() -> None:
    # 1. Update task.json with correct test cases
    tests = [
        {"name": "fragment_mf_drop", "description": "IPv4 packet with MF (More Fragments) bit set should be dropped", "packet_hex": make_eth_packet(0x0800, make_ipv4_packet(frag_off=0x2000, payload=b"FRAG")).hex(), "expected_action": "XDP_DROP"},
        {"name": "fragment_offset_drop", "description": "IPv4 packet with fragment offset 100 should be dropped", "packet_hex": make_eth_packet(0x0800, make_ipv4_packet(frag_off=100, payload=b"FRAG")).hex(), "expected_action": "XDP_DROP"},
        {"name": "unfragmented_pass", "description": "Unfragmented IPv4 packet (frag_off=0) should pass", "packet_hex": make_eth_packet(0x0800, make_ipv4_packet(frag_off=0, payload=b"DATA")).hex(), "expected_action": "XDP_PASS"},
        {"name": "arp_pass", "description": "Non-IP ARP packet should pass", "packet_hex": make_eth_packet(0x0806, b"\x00"*28).hex(), "expected_action": "XDP_PASS"},
    ]

    task_json_file = TASK_DIR / "task.json"
    task_data = json.loads(task_json_file.read_text(encoding="utf-8"))
    task_data["template_family"] = "ipv4_fragment_filter"
    task_data["semantic_signature"] = "ipv4+frag_off_nonzero+drop"
    task_data["instruction"] = "Write a complete XDP/eBPF C program that drops IPv4 fragmented packets (where fragment offset > 0 or MF flag is set in ip->frag_off), passing unfragmented traffic."
    task_data["tests"] = tests
    task_json_file.write_text(json.dumps(task_data, indent=2), encoding="utf-8")

    # 2. Write c00-r01.c
    c_code = """#include <linux/bpf.h>
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
    (TASK_DIR / "c00-r01.c").write_text(c_code, encoding="utf-8")

    diag_file = VAL_DIR / "xdp_b04_t09_drop_ip_fragments_c00.json"
    diag = ""
    if diag_file.exists():
        diag = json.loads(diag_file.read_text(encoding="utf-8")).get("diagnostic", "")

    meta = {
        "candidate_id": "xdp_b04_t09_drop_ip_fragments_c00_r01",
        "task_id": "xdp_b04_t09_drop_ip_fragments",
        "authoring_harness": "agent",
        "authoring_model": "instruction_model",
        "generation_prompt_version": "agent-repair-v1",
        "source_path": "c00-r01.c",
        "parent_candidate_id": "xdp_b04_t09_drop_ip_fragments_c00",
        "repair_attempt": 1,
        "failure_diagnostic": diag,
        "claimed_status": "unvalidated",
        "source_sha256": compute_sha256_str(c_code),
    }
    (TASK_DIR / "c00-r01.meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print("[+] Fixed b04 t09 task.json and generated c00-r01")


if __name__ == "__main__":
    main()
