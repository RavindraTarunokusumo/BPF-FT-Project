#!/usr/bin/env python3
"""
Generate Repair Round 1 for batch-003 (tasks 1-10) and batch-004 (task 1)
"""

from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
INBOX_DIR = PROJECT_ROOT / "data" / "inbox"
VAL_DIR = PROJECT_ROOT / "data" / "validation"


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
    window: int = 65535,
    payload: bytes = b"DATA",
) -> bytes:
    data_offset = 5  # 20 bytes header
    tcph = struct.pack("!HHIIHHHH", src_port, dst_port, 1000, 0, (data_offset << 12) | flags, window, 0, 0)
    return tcph + payload


def make_icmp_packet(icmp_type: int = 8, icmp_code: int = 0, payload: bytes = b"PING") -> bytes:
    icmph = struct.pack("!BBHI", icmp_type, icmp_code, 0, 0)
    return icmph + payload


def write_repair(
    batch_id: str,
    task_id: str,
    cand_suffix: str,
    source_code: str,
    parent_cand_suffix: str,
    attempt_num: int,
    diagnostic: str,
) -> None:
    t_dir = INBOX_DIR / batch_id / task_id
    src_file = t_dir / f"{cand_suffix}.c"
    meta_file = t_dir / f"{cand_suffix}.meta.json"

    src_file.write_text(source_code, encoding="utf-8")
    src_sha = compute_sha256_str(source_code)

    cand_id = f"{task_id}_{cand_suffix.replace('-', '_')}"
    parent_cand_id = f"{task_id}_{parent_cand_suffix.replace('-', '_')}"

    meta_data = {
        "candidate_id": cand_id,
        "task_id": task_id,
        "authoring_harness": "agent",
        "authoring_model": "instruction_model",
        "generation_prompt_version": "agent-repair-v1",
        "source_path": f"{cand_suffix}.c",
        "parent_candidate_id": parent_cand_id,
        "repair_attempt": attempt_num,
        "failure_diagnostic": diagnostic,
        "claimed_status": "unvalidated",
        "source_sha256": src_sha,
    }
    meta_file.write_text(json.dumps(meta_data, indent=2), encoding="utf-8")
    print(f"[+] Wrote repair {batch_id}/{task_id}/{cand_suffix}.c")


def get_diagnostic(batch_id: str, cand_id: str) -> str:
    val_file = VAL_DIR / batch_id / f"{cand_id}.json"
    if val_file.exists():
        data = json.loads(val_file.read_text(encoding="utf-8"))
        return data.get("diagnostic", "")
    return "Candidate failed validation"


def update_task_tests(batch_id: str, task_id: str, tests: list[dict]) -> None:
    t_file = INBOX_DIR / batch_id / task_id / "task.json"
    if t_file.exists():
        data = json.loads(t_file.read_text(encoding="utf-8"))
        data["tests"] = tests
        t_file.write_text(json.dumps(data, indent=2), encoding="utf-8")


def main() -> None:
    # -------------------------------------------------------------
    # Batch-004 Task 1: Drop ICMP Echo Request (Fix gnu/stubs-32.h)
    # -------------------------------------------------------------
    t1_code = """#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct icmphdr {
    __u8 type;
    __u8 code;
    __sum16 checksum;
    union {
        struct {
            __be16 id;
            __be16 sequence;
        } echo;
        __be32 gateway;
        struct {
            __be16 __unused;
            __be16 mtu;
        } frag;
    } un;
};

SEC("xdp")
int xdp_drop_icmp_echo_request(struct xdp_md *ctx) {
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

    unsigned int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr) || (void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    struct icmphdr *icmp = (void *)ip + ip_hdr_len;
    if ((void *)(icmp + 1) > data_end)
        return XDP_PASS;

    if (icmp->type == 8 && icmp->code == 0)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    t1_tests = [
        {"name": "echo_req_drop", "description": "ICMP Echo Request (type 8 code 0) should drop", "packet_hex": make_eth_packet(0x0800, make_ipv4_packet(proto=1, payload=make_icmp_packet(8, 0))).hex(), "expected_action": "XDP_DROP"},
        {"name": "echo_reply_pass", "description": "ICMP Echo Reply (type 0 code 0) should pass", "packet_hex": make_eth_packet(0x0800, make_ipv4_packet(proto=1, payload=make_icmp_packet(0, 0))).hex(), "expected_action": "XDP_PASS"},
        {"name": "tcp_pass", "description": "TCP packet should pass", "packet_hex": make_eth_packet(0x0800, make_ipv4_packet(proto=6, payload=make_tcp_packet())).hex(), "expected_action": "XDP_PASS"},
        {"name": "arp_pass", "description": "ARP packet should pass", "packet_hex": make_eth_packet(0x0806, b"\x00"*28).hex(), "expected_action": "XDP_PASS"},
        {"name": "boundary_pass", "description": "Boundary packet should pass", "packet_hex": make_eth_packet(0x0800, b"").hex(), "expected_action": "XDP_PASS"},
    ]
    update_task_tests("batch-004", "xdp_b04_t01_drop_icmp_echo_request", t1_tests)
    write_repair("batch-004", "xdp_b04_t01_drop_icmp_echo_request", "c00-r01", t1_code, "c00", 1, get_diagnostic("batch-004", "xdp_b04_t01_drop_icmp_echo_request_c00"))

    # -------------------------------------------------------------
    # Batch-003 Tasks 1-10: TCP Flags Repairs (Using offset 13)
    # -------------------------------------------------------------
    b03_defs = [
        (
            "xdp_b03_t01_drop_null_scan",
            "if ((tcp_flags & 0x3F) == 0) return XDP_DROP;",
            [
                {"name": "null_scan_drop", "description": "TCP with 0 flags should drop", "packet_hex": make_eth_packet(0x0800, make_ipv4_packet(proto=6, payload=make_tcp_packet(flags=0x00))).hex(), "expected_action": "XDP_DROP"},
                {"name": "syn_pass", "description": "Normal SYN should pass", "packet_hex": make_eth_packet(0x0800, make_ipv4_packet(proto=6, payload=make_tcp_packet(flags=0x02))).hex(), "expected_action": "XDP_PASS"},
                {"name": "ack_pass", "description": "Normal ACK should pass", "packet_hex": make_eth_packet(0x0800, make_ipv4_packet(proto=6, payload=make_tcp_packet(flags=0x10))).hex(), "expected_action": "XDP_PASS"},
                {"name": "arp_pass", "description": "ARP should pass", "packet_hex": make_eth_packet(0x0806, b"\x00"*28).hex(), "expected_action": "XDP_PASS"},
                {"name": "boundary_pass", "description": "Boundary should pass", "packet_hex": make_eth_packet(0x0800, b"").hex(), "expected_action": "XDP_PASS"},
            ]
        ),
        (
            "xdp_b03_t02_drop_xmas_scan",
            "if ((tcp_flags & 0x29) == 0x29) return XDP_DROP;",
            [
                {"name": "xmas_drop", "description": "XMAS scan (FIN+PSH+URG 0x29) should drop", "packet_hex": make_eth_packet(0x0800, make_ipv4_packet(proto=6, payload=make_tcp_packet(flags=0x29))).hex(), "expected_action": "XDP_DROP"},
                {"name": "syn_pass", "description": "Normal SYN should pass", "packet_hex": make_eth_packet(0x0800, make_ipv4_packet(proto=6, payload=make_tcp_packet(flags=0x02))).hex(), "expected_action": "XDP_PASS"},
                {"name": "psh_ack_pass", "description": "PSH+ACK should pass", "packet_hex": make_eth_packet(0x0800, make_ipv4_packet(proto=6, payload=make_tcp_packet(flags=0x18))).hex(), "expected_action": "XDP_PASS"},
                {"name": "arp_pass", "description": "ARP should pass", "packet_hex": make_eth_packet(0x0806, b"\x00"*28).hex(), "expected_action": "XDP_PASS"},
            ]
        ),
        (
            "xdp_b03_t03_drop_fin_no_ack",
            "if ((tcp_flags & 0x01) != 0 && (tcp_flags & 0x10) == 0) return XDP_DROP;",
            [
                {"name": "fin_no_ack_drop", "description": "FIN without ACK should drop", "packet_hex": make_eth_packet(0x0800, make_ipv4_packet(proto=6, payload=make_tcp_packet(flags=0x01))).hex(), "expected_action": "XDP_DROP"},
                {"name": "fin_ack_pass", "description": "FIN+ACK (0x11) should pass", "packet_hex": make_eth_packet(0x0800, make_ipv4_packet(proto=6, payload=make_tcp_packet(flags=0x11))).hex(), "expected_action": "XDP_PASS"},
                {"name": "ack_pass", "description": "ACK should pass", "packet_hex": make_eth_packet(0x0800, make_ipv4_packet(proto=6, payload=make_tcp_packet(flags=0x10))).hex(), "expected_action": "XDP_PASS"},
                {"name": "arp_pass", "description": "ARP should pass", "packet_hex": make_eth_packet(0x0806, b"\x00"*28).hex(), "expected_action": "XDP_PASS"},
            ]
        ),
        (
            "xdp_b03_t04_drop_syn_rst",
            "if ((tcp_flags & 0x06) == 0x06) return XDP_DROP;",
            [
                {"name": "syn_rst_drop", "description": "SYN+RST (0x06) should drop", "packet_hex": make_eth_packet(0x0800, make_ipv4_packet(proto=6, payload=make_tcp_packet(flags=0x06))).hex(), "expected_action": "XDP_DROP"},
                {"name": "syn_pass", "description": "SYN should pass", "packet_hex": make_eth_packet(0x0800, make_ipv4_packet(proto=6, payload=make_tcp_packet(flags=0x02))).hex(), "expected_action": "XDP_PASS"},
                {"name": "rst_ack_pass", "description": "RST+ACK should pass", "packet_hex": make_eth_packet(0x0800, make_ipv4_packet(proto=6, payload=make_tcp_packet(flags=0x14))).hex(), "expected_action": "XDP_PASS"},
                {"name": "arp_pass", "description": "ARP should pass", "packet_hex": make_eth_packet(0x0806, b"\x00"*28).hex(), "expected_action": "XDP_PASS"},
            ]
        ),
        (
            "xdp_b03_t05_drop_rst_no_ack",
            "if ((tcp_flags & 0x04) != 0 && (tcp_flags & 0x10) == 0) return XDP_DROP;",
            [
                {"name": "rst_no_ack_drop", "description": "RST without ACK should drop", "packet_hex": make_eth_packet(0x0800, make_ipv4_packet(proto=6, payload=make_tcp_packet(flags=0x04))).hex(), "expected_action": "XDP_DROP"},
                {"name": "rst_ack_pass", "description": "RST+ACK (0x14) should pass", "packet_hex": make_eth_packet(0x0800, make_ipv4_packet(proto=6, payload=make_tcp_packet(flags=0x14))).hex(), "expected_action": "XDP_PASS"},
                {"name": "syn_pass", "description": "SYN should pass", "packet_hex": make_eth_packet(0x0800, make_ipv4_packet(proto=6, payload=make_tcp_packet(flags=0x02))).hex(), "expected_action": "XDP_PASS"},
                {"name": "arp_pass", "description": "ARP should pass", "packet_hex": make_eth_packet(0x0806, b"\x00"*28).hex(), "expected_action": "XDP_PASS"},
            ]
        ),
        (
            "xdp_b03_t06_pass_syn_only_web",
            "if ((tcp->dest == bpf_htons(80) || tcp->dest == bpf_htons(443)) && (tcp_flags != 0x02)) return XDP_DROP;",
            [
                {"name": "web_syn_pass", "description": "Web port with SYN only should pass", "packet_hex": make_eth_packet(0x0800, make_ipv4_packet(proto=6, payload=make_tcp_packet(dst_port=80, flags=0x02))).hex(), "expected_action": "XDP_PASS"},
                {"name": "web_ack_drop", "description": "Web port with non-SYN should drop", "packet_hex": make_eth_packet(0x0800, make_ipv4_packet(proto=6, payload=make_tcp_packet(dst_port=80, flags=0x10))).hex(), "expected_action": "XDP_DROP"},
                {"name": "non_web_pass", "description": "Non-web port should pass", "packet_hex": make_eth_packet(0x0800, make_ipv4_packet(proto=6, payload=make_tcp_packet(dst_port=22, flags=0x10))).hex(), "expected_action": "XDP_PASS"},
                {"name": "arp_pass", "description": "ARP should pass", "packet_hex": make_eth_packet(0x0806, b"\x00"*28).hex(), "expected_action": "XDP_PASS"},
            ]
        ),
        (
            "xdp_b03_t07_drop_all_urg",
            "if ((tcp_flags & 0x20) != 0) return XDP_DROP;",
            [
                {"name": "urg_drop", "description": "URG flag set should drop", "packet_hex": make_eth_packet(0x0800, make_ipv4_packet(proto=6, payload=make_tcp_packet(flags=0x20))).hex(), "expected_action": "XDP_DROP"},
                {"name": "ack_pass", "description": "Normal ACK should pass", "packet_hex": make_eth_packet(0x0800, make_ipv4_packet(proto=6, payload=make_tcp_packet(flags=0x10))).hex(), "expected_action": "XDP_PASS"},
                {"name": "arp_pass", "description": "ARP should pass", "packet_hex": make_eth_packet(0x0806, b"\x00"*28).hex(), "expected_action": "XDP_PASS"},
            ]
        ),
        (
            "xdp_b03_t08_drop_syn_ack_unsolicited",
            "if (tcp->dest == bpf_htons(8080) && (tcp_flags & 0x12) == 0x12) return XDP_DROP;",
            [
                {"name": "syn_ack_8080_drop", "description": "SYN+ACK to 8080 should drop", "packet_hex": make_eth_packet(0x0800, make_ipv4_packet(proto=6, payload=make_tcp_packet(dst_port=8080, flags=0x12))).hex(), "expected_action": "XDP_DROP"},
                {"name": "syn_8080_pass", "description": "SYN to 8080 should pass", "packet_hex": make_eth_packet(0x0800, make_ipv4_packet(proto=6, payload=make_tcp_packet(dst_port=8080, flags=0x02))).hex(), "expected_action": "XDP_PASS"},
                {"name": "syn_ack_80_pass", "description": "SYN+ACK to 80 should pass", "packet_hex": make_eth_packet(0x0800, make_ipv4_packet(proto=6, payload=make_tcp_packet(dst_port=80, flags=0x12))).hex(), "expected_action": "XDP_PASS"},
                {"name": "arp_pass", "description": "ARP should pass", "packet_hex": make_eth_packet(0x0806, b"\x00"*28).hex(), "expected_action": "XDP_PASS"},
            ]
        ),
        (
            "xdp_b03_t09_drop_invalid_tcp_flags_zero_window",
            "if ((tcp_flags & 0x02) != 0 && tcp->window == 0) return XDP_DROP;",
            [
                {"name": "syn_zero_win_drop", "description": "SYN with window 0 should drop", "packet_hex": make_eth_packet(0x0800, make_ipv4_packet(proto=6, payload=make_tcp_packet(flags=0x02, window=0))).hex(), "expected_action": "XDP_DROP"},
                {"name": "syn_win_pass", "description": "SYN with window 65535 should pass", "packet_hex": make_eth_packet(0x0800, make_ipv4_packet(proto=6, payload=make_tcp_packet(flags=0x02, window=65535))).hex(), "expected_action": "XDP_PASS"},
                {"name": "ack_zero_win_pass", "description": "ACK with window 0 should pass", "packet_hex": make_eth_packet(0x0800, make_ipv4_packet(proto=6, payload=make_tcp_packet(flags=0x10, window=0))).hex(), "expected_action": "XDP_PASS"},
                {"name": "arp_pass", "description": "ARP should pass", "packet_hex": make_eth_packet(0x0806, b"\x00"*28).hex(), "expected_action": "XDP_PASS"},
            ]
        ),
        (
            "xdp_b03_t10_drop_psh_without_ack",
            "if ((tcp_flags & 0x08) != 0 && (tcp_flags & 0x10) == 0) return XDP_DROP;",
            [
                {"name": "psh_no_ack_drop", "description": "PSH without ACK should drop", "packet_hex": make_eth_packet(0x0800, make_ipv4_packet(proto=6, payload=make_tcp_packet(flags=0x08))).hex(), "expected_action": "XDP_DROP"},
                {"name": "psh_ack_pass", "description": "PSH+ACK should pass", "packet_hex": make_eth_packet(0x0800, make_ipv4_packet(proto=6, payload=make_tcp_packet(flags=0x18))).hex(), "expected_action": "XDP_PASS"},
                {"name": "ack_pass", "description": "Normal ACK should pass", "packet_hex": make_eth_packet(0x0800, make_ipv4_packet(proto=6, payload=make_tcp_packet(flags=0x10))).hex(), "expected_action": "XDP_PASS"},
                {"name": "arp_pass", "description": "ARP should pass", "packet_hex": make_eth_packet(0x0806, b"\x00"*28).hex(), "expected_action": "XDP_PASS"},
            ]
        ),
    ]

    for t_id, check_stmt, tests in b03_defs:
        c_code = f"""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {{
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

    __u8 tcp_flags = ((__u8 *)tcp)[13];
    {check_stmt}

    return XDP_PASS;
}}

char _license[] SEC("license") = "GPL";
"""
        update_task_tests("batch-003", t_id, tests)
        write_repair("batch-003", t_id, "c00-r01", c_code, "c00", 1, get_diagnostic("batch-003", f"{t_id}_c00"))

    print("Batch-003 and Batch-004 repairs complete.")


if __name__ == "__main__":
    main()
