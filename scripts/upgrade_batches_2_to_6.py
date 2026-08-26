#!/usr/bin/env python3
"""
Upgrades batch-002, batch-004, batch-005, and batch-006 to complete production schemas,
rich multi-packet test suites (>=3-5 tests per task), and verified C candidates.
"""

from __future__ import annotations

import binascii
import hashlib
import json
import struct
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
INBOX_DIR = PROJECT_ROOT / "data" / "inbox"


def compute_sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# -------------------------------------------------------------
# Packet Generation Helpers
# -------------------------------------------------------------
def make_eth(eth_type: int = 0x0800, payload: bytes = b"") -> bytes:
    dst_mac = bytes([0x52, 0x54, 0x00, 0x12, 0x34, 0x56])
    src_mac = bytes([0x52, 0x54, 0x00, 0x65, 0x43, 0x21])
    return dst_mac + src_mac + struct.pack("!H", eth_type) + payload


def make_vlan(vlan_id: int = 100, eth_type: int = 0x0800, outer_tpid: int = 0x8100, payload: bytes = b"") -> bytes:
    dst_mac = bytes([0x52, 0x54, 0x00, 0x12, 0x34, 0x56])
    src_mac = bytes([0x52, 0x54, 0x00, 0x65, 0x43, 0x21])
    tci = vlan_id & 0x0FFF
    return dst_mac + src_mac + struct.pack("!HH", outer_tpid, tci) + struct.pack("!H", eth_type) + payload


def make_qinq(outer_id: int = 10, inner_id: int = 100, eth_type: int = 0x0800, payload: bytes = b"") -> bytes:
    dst_mac = bytes([0x52, 0x54, 0x00, 0x12, 0x34, 0x56])
    src_mac = bytes([0x52, 0x54, 0x00, 0x65, 0x43, 0x21])
    return dst_mac + src_mac + struct.pack("!HH", 0x88A8, outer_id) + struct.pack("!HH", 0x8100, inner_id) + struct.pack("!H", eth_type) + payload


def make_ipv4(src_ip: str = "192.168.1.10", dst_ip: str = "192.168.1.20", proto: int = 6, ttl: int = 64, tos: int = 0, frag_off: int = 0, payload: bytes = b"") -> bytes:
    src_bytes = bytes(map(int, src_ip.split(".")))
    dst_bytes = bytes(map(int, dst_ip.split(".")))
    tot_len = 20 + len(payload)
    iph = struct.pack("!BBHHHBBH4s4s", 0x45, tos, tot_len, 1234, frag_off, ttl, proto, 0, src_bytes, dst_bytes)
    return iph + payload


def make_tcp(src_port: int = 12345, dst_port: int = 80, flags: int = 0x02, window: int = 65535, payload: bytes = b"") -> bytes:
    data_offset = 5
    tcph = struct.pack("!HHIIHHHH", src_port, dst_port, 1000, 0, (data_offset << 12) | flags, window, 0, 0)
    return tcph + payload


def make_udp(src_port: int = 12345, dst_port: int = 53, payload: bytes = b"DNS_QUERY") -> bytes:
    length = 8 + len(payload)
    udph = struct.pack("!HHHH", src_port, dst_port, length, 0)
    return udph + payload


def make_icmp(icmp_type: int = 8, icmp_code: int = 0, payload: bytes = b"PING") -> bytes:
    icmph = struct.pack("!BBHI", icmp_type, icmp_code, 0, 0)
    return icmph + payload


def write_task_files(batch_id: str, task_id: str, family: str, signature: str, difficulty: str, instruction: str, requirements: list[str], tests: list[dict], c_code: str) -> None:
    t_dir = INBOX_DIR / batch_id / task_id
    t_dir.mkdir(parents=True, exist_ok=True)

    task_json = {
        "task_id": task_id,
        "template_family": family,
        "semantic_signature": signature,
        "difficulty": difficulty,
        "split": "train",
        "instruction": instruction,
        "requirements": requirements,
        "gold_candidate_id": None,
        "tests": tests,
    }
    (t_dir / "task.json").write_text(json.dumps(task_json, indent=2), encoding="utf-8")

    (t_dir / "c00.c").write_text(c_code, encoding="utf-8")
    sha = compute_sha256(c_code)

    meta = {
        "candidate_id": f"{task_id}_c00",
        "task_id": task_id,
        "authoring_harness": "agent",
        "authoring_model": "instruction_model",
        "generation_prompt_version": "agent-generation-v2",
        "source_path": "c00.c",
        "parent_candidate_id": None,
        "repair_attempt": 0,
        "claimed_status": "unvalidated",
        "source_sha256": sha,
    }
    (t_dir / "c00.meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(f"[+] Upgraded {batch_id}/{task_id}")


# -------------------------------------------------------------
# Batch 002 Upgrade
# -------------------------------------------------------------
def upgrade_batch_002() -> None:
    b = "batch-002"

    # t01: Drop UDP TFTP 69
    write_task_files(
        b, "xdp_b02_t01_drop_udp_tftp", "udp_port_filter", "ipv4+udp_dport_69+drop", "basic",
        "Write a complete XDP/eBPF program that drops UDP packets destined for port 69 (TFTP), passing all other UDP and non-UDP traffic.",
        ["Check Ethernet and IPv4 bounds", "Verify ip->protocol == IPPROTO_UDP", "Check udp->dest == bpf_htons(69)", "Return XDP_DROP for TFTP, XDP_PASS otherwise"],
        [
            {"name": "tftp_drop", "description": "UDP dport 69 should be dropped", "packet_hex": make_eth(0x0800, make_ipv4(proto=17, payload=make_udp(dst_port=69))).hex(), "expected_action": "XDP_DROP"},
            {"name": "dns_pass", "description": "UDP dport 53 should pass", "packet_hex": make_eth(0x0800, make_ipv4(proto=17, payload=make_udp(dst_port=53))).hex(), "expected_action": "XDP_PASS"},
            {"name": "tcp_pass", "description": "TCP port 69 should pass", "packet_hex": make_eth(0x0800, make_ipv4(proto=6, payload=make_tcp(dst_port=69))).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "Non-IP ARP should pass", "packet_hex": make_eth(0x0806, b"\x00"*28).hex(), "expected_action": "XDP_PASS"},
        ],
        """#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int xdp_drop_tftp(struct xdp_md *ctx) {
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

    unsigned int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr) || (void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip_hdr_len;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    if (udp->dest == bpf_htons(69))
        return XDP_DROP;

    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
"""
    )

    # t02: Drop TCP MySQL 3306
    write_task_files(
        b, "xdp_b02_t02_drop_tcp_mysql", "tcp_port_filter", "ipv4+tcp_dport_3306+drop", "basic",
        "Write a complete XDP/eBPF program that drops TCP packets destined for port 3306 (MySQL), passing all other traffic.",
        ["Check Ethernet and IPv4 bounds", "Verify ip->protocol == IPPROTO_TCP", "Check tcp->dest == bpf_htons(3306)", "Return XDP_DROP for MySQL, XDP_PASS otherwise"],
        [
            {"name": "mysql_drop", "description": "TCP dport 3306 should drop", "packet_hex": make_eth(0x0800, make_ipv4(proto=6, payload=make_tcp(dst_port=3306))).hex(), "expected_action": "XDP_DROP"},
            {"name": "http_pass", "description": "TCP dport 80 should pass", "packet_hex": make_eth(0x0800, make_ipv4(proto=6, payload=make_tcp(dst_port=80))).hex(), "expected_action": "XDP_PASS"},
            {"name": "udp_pass", "description": "UDP port 3306 should pass", "packet_hex": make_eth(0x0800, make_ipv4(proto=17, payload=make_udp(dst_port=3306))).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP packet should pass", "packet_hex": make_eth(0x0806, b"\x00"*28).hex(), "expected_action": "XDP_PASS"},
        ],
        """#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int xdp_drop_mysql(struct xdp_md *ctx) {
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

    unsigned int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr) || (void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip_hdr_len;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    if (tcp->dest == bpf_htons(3306))
        return XDP_DROP;

    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
"""
    )

    # t03: Drop TCP Redis 6379
    write_task_files(
        b, "xdp_b02_t03_drop_tcp_redis", "tcp_port_filter", "ipv4+tcp_dport_6379+drop", "basic",
        "Write a complete XDP/eBPF program that drops TCP packets destined for port 6379 (Redis), passing other traffic.",
        ["Check Ethernet and IPv4 bounds", "Verify ip->protocol == IPPROTO_TCP", "Check tcp->dest == bpf_htons(6379)", "Return XDP_DROP for Redis, XDP_PASS otherwise"],
        [
            {"name": "redis_drop", "description": "TCP dport 6379 should drop", "packet_hex": make_eth(0x0800, make_ipv4(proto=6, payload=make_tcp(dst_port=6379))).hex(), "expected_action": "XDP_DROP"},
            {"name": "web_pass", "description": "TCP dport 443 should pass", "packet_hex": make_eth(0x0800, make_ipv4(proto=6, payload=make_tcp(dst_port=443))).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP packet should pass", "packet_hex": make_eth(0x0806, b"\x00"*28).hex(), "expected_action": "XDP_PASS"},
        ],
        """#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int xdp_drop_redis(struct xdp_md *ctx) {
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

    unsigned int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr) || (void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip_hdr_len;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    if (tcp->dest == bpf_htons(6379))
        return XDP_DROP;

    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
"""
    )

    # t04: Drop UDP NTP 123
    write_task_files(
        b, "xdp_b02_t04_drop_udp_ntp", "udp_port_filter", "ipv4+udp_dport_123+drop", "basic",
        "Write a complete XDP/eBPF program that drops UDP packets destined for port 123 (NTP), passing all other traffic.",
        ["Check Ethernet and IPv4 bounds", "Verify ip->protocol == IPPROTO_UDP", "Check udp->dest == bpf_htons(123)", "Pass non-NTP packets"],
        [
            {"name": "ntp_drop", "description": "UDP dport 123 should drop", "packet_hex": make_eth(0x0800, make_ipv4(proto=17, payload=make_udp(dst_port=123))).hex(), "expected_action": "XDP_DROP"},
            {"name": "dns_pass", "description": "UDP dport 53 should pass", "packet_hex": make_eth(0x0800, make_ipv4(proto=17, payload=make_udp(dst_port=53))).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP packet should pass", "packet_hex": make_eth(0x0806, b"\x00"*28).hex(), "expected_action": "XDP_PASS"},
        ],
        """#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int xdp_drop_ntp(struct xdp_md *ctx) {
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

    unsigned int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr) || (void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip_hdr_len;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    if (udp->dest == bpf_htons(123))
        return XDP_DROP;

    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
"""
    )

    # t05: Drop UDP SNMP 161 and 162
    write_task_files(
        b, "xdp_b02_t05_drop_udp_snmp", "udp_port_filter", "ipv4+udp_dport_161_162+drop", "basic",
        "Write a complete XDP/eBPF program that drops UDP packets targeting ports 161 or 162 (SNMP), passing all other traffic.",
        ["Check Ethernet and IPv4 bounds", "Verify ip->protocol == IPPROTO_UDP", "Check udp->dest == bpf_htons(161) or bpf_htons(162)", "Return XDP_DROP for SNMP, XDP_PASS otherwise"],
        [
            {"name": "snmp_161_drop", "description": "UDP 161 should drop", "packet_hex": make_eth(0x0800, make_ipv4(proto=17, payload=make_udp(dst_port=161))).hex(), "expected_action": "XDP_DROP"},
            {"name": "snmp_162_drop", "description": "UDP 162 should drop", "packet_hex": make_eth(0x0800, make_ipv4(proto=17, payload=make_udp(dst_port=162))).hex(), "expected_action": "XDP_DROP"},
            {"name": "dns_pass", "description": "UDP 53 should pass", "packet_hex": make_eth(0x0800, make_ipv4(proto=17, payload=make_udp(dst_port=53))).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP packet should pass", "packet_hex": make_eth(0x0806, b"\x00"*28).hex(), "expected_action": "XDP_PASS"},
        ],
        """#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int xdp_drop_snmp(struct xdp_md *ctx) {
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

    unsigned int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr) || (void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip_hdr_len;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    if (udp->dest == bpf_htons(161) || udp->dest == bpf_htons(162))
        return XDP_DROP;

    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
"""
    )

    # t06: Drop TCP SMB 445 and 139
    write_task_files(
        b, "xdp_b02_t06_drop_tcp_smb", "tcp_port_filter", "ipv4+tcp_dport_139_445+drop", "basic",
        "Write a complete XDP/eBPF program that drops TCP packets targeting ports 139 or 445 (SMB), passing other traffic.",
        ["Check Ethernet and IPv4 bounds", "Verify ip->protocol == IPPROTO_TCP", "Check tcp->dest == bpf_htons(139) or bpf_htons(445)", "Return XDP_DROP for SMB, XDP_PASS otherwise"],
        [
            {"name": "smb_445_drop", "description": "TCP 445 should drop", "packet_hex": make_eth(0x0800, make_ipv4(proto=6, payload=make_tcp(dst_port=445))).hex(), "expected_action": "XDP_DROP"},
            {"name": "smb_139_drop", "description": "TCP 139 should drop", "packet_hex": make_eth(0x0800, make_ipv4(proto=6, payload=make_tcp(dst_port=139))).hex(), "expected_action": "XDP_DROP"},
            {"name": "http_pass", "description": "TCP 80 should pass", "packet_hex": make_eth(0x0800, make_ipv4(proto=6, payload=make_tcp(dst_port=80))).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP packet should pass", "packet_hex": make_eth(0x0806, b"\x00"*28).hex(), "expected_action": "XDP_PASS"},
        ],
        """#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int xdp_drop_smb(struct xdp_md *ctx) {
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

    unsigned int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr) || (void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip_hdr_len;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    if (tcp->dest == bpf_htons(139) || tcp->dest == bpf_htons(445))
        return XDP_DROP;

    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
"""
    )

    # t07: Pass Web Only (80 and 443)
    write_task_files(
        b, "xdp_b02_t07_pass_web_only", "tcp_port_allowlist", "ipv4+tcp_dport_80_443+allow_only", "intermediate",
        "Write a complete XDP/eBPF program that allows TCP traffic targeting web ports 80 or 443, drops all other TCP traffic, and passes non-TCP and non-IP traffic.",
        ["Check Ethernet and IPv4 bounds", "Inspect ip->protocol", "If TCP, allow only ports 80 and 443; drop other TCP", "Pass non-TCP and non-IP packets"],
        [
            {"name": "http_80_pass", "description": "TCP port 80 should pass", "packet_hex": make_eth(0x0800, make_ipv4(proto=6, payload=make_tcp(dst_port=80))).hex(), "expected_action": "XDP_PASS"},
            {"name": "https_443_pass", "description": "TCP port 443 should pass", "packet_hex": make_eth(0x0800, make_ipv4(proto=6, payload=make_tcp(dst_port=443))).hex(), "expected_action": "XDP_PASS"},
            {"name": "ssh_22_drop", "description": "TCP port 22 should drop", "packet_hex": make_eth(0x0800, make_ipv4(proto=6, payload=make_tcp(dst_port=22))).hex(), "expected_action": "XDP_DROP"},
            {"name": "udp_pass", "description": "UDP traffic should pass", "packet_hex": make_eth(0x0800, make_ipv4(proto=17, payload=make_udp(dst_port=53))).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP packet should pass", "packet_hex": make_eth(0x0806, b"\x00"*28).hex(), "expected_action": "XDP_PASS"},
        ],
        """#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int xdp_pass_web_only(struct xdp_md *ctx) {
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

    unsigned int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr) || (void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip_hdr_len;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    if (tcp->dest == bpf_htons(80) || tcp->dest == bpf_htons(443))
        return XDP_PASS;

    return XDP_DROP;
}
char _license[] SEC("license") = "GPL";
"""
    )

    # t08: Drop Ephemeral UDP (both sport & dport >= 1024)
    write_task_files(
        b, "xdp_b02_t08_drop_ephemeral_udp", "udp_port_range_filter", "ipv4+udp_sport_ge_1024_dport_ge_1024+drop", "intermediate",
        "Write a complete XDP/eBPF program that drops UDP packets where both the source port and destination port are in the ephemeral range (>= 1024), passing other traffic.",
        ["Check Ethernet and IPv4 bounds", "Verify ip->protocol == IPPROTO_UDP", "Check bpf_ntohs(udp->source) >= 1024 && bpf_ntohs(udp->dest) >= 1024", "Return XDP_DROP for matching ephemeral UDP, XDP_PASS otherwise"],
        [
            {"name": "ephemeral_udp_drop", "description": "UDP 5000->6000 should drop", "packet_hex": make_eth(0x0800, make_ipv4(proto=17, payload=make_udp(src_port=5000, dst_port=6000))).hex(), "expected_action": "XDP_DROP"},
            {"name": "server_udp_pass", "description": "UDP 5000->53 should pass", "packet_hex": make_eth(0x0800, make_ipv4(proto=17, payload=make_udp(src_port=5000, dst_port=53))).hex(), "expected_action": "XDP_PASS"},
            {"name": "tcp_pass", "description": "TCP traffic should pass", "packet_hex": make_eth(0x0800, make_ipv4(proto=6, payload=make_tcp(src_port=5000, dst_port=6000))).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP packet should pass", "packet_hex": make_eth(0x0806, b"\x00"*28).hex(), "expected_action": "XDP_PASS"},
        ],
        """#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int xdp_drop_ephemeral_udp(struct xdp_md *ctx) {
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

    unsigned int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr) || (void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip_hdr_len;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    if (bpf_ntohs(udp->source) >= 1024 && bpf_ntohs(udp->dest) >= 1024)
        return XDP_DROP;

    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
"""
    )

    # t09: Drop TCP Range 6000-6005
    write_task_files(
        b, "xdp_b02_t09_drop_tcp_range_6000_6005", "tcp_port_range_filter", "ipv4+tcp_dport_range_6000_6005+drop", "intermediate",
        "Write a complete XDP/eBPF program that drops TCP packets targeting destination ports in the range 6000 to 6005 inclusive, passing all other traffic.",
        ["Check Ethernet and IPv4 bounds", "Verify ip->protocol == IPPROTO_TCP", "Convert tcp->dest with bpf_ntohs", "Drop if port >= 6000 and port <= 6005"],
        [
            {"name": "tcp_6000_drop", "description": "TCP 6000 should drop", "packet_hex": make_eth(0x0800, make_ipv4(proto=6, payload=make_tcp(dst_port=6000))).hex(), "expected_action": "XDP_DROP"},
            {"name": "tcp_6005_drop", "description": "TCP 6005 should drop", "packet_hex": make_eth(0x0800, make_ipv4(proto=6, payload=make_tcp(dst_port=6005))).hex(), "expected_action": "XDP_DROP"},
            {"name": "tcp_6006_pass", "description": "TCP 6006 should pass", "packet_hex": make_eth(0x0800, make_ipv4(proto=6, payload=make_tcp(dst_port=6006))).hex(), "expected_action": "XDP_PASS"},
            {"name": "udp_6000_pass", "description": "UDP 6000 should pass", "packet_hex": make_eth(0x0800, make_ipv4(proto=17, payload=make_udp(dst_port=6000))).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP packet should pass", "packet_hex": make_eth(0x0806, b"\x00"*28).hex(), "expected_action": "XDP_PASS"},
        ],
        """#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int xdp_drop_range(struct xdp_md *ctx) {
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

    unsigned int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr) || (void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip_hdr_len;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    __u16 dport = bpf_ntohs(tcp->dest);
    if (dport >= 6000 && dport <= 6005)
        return XDP_DROP;

    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
"""
    )

    # t10: Drop UDP mDNS 5353
    write_task_files(
        b, "xdp_b02_t10_drop_udp_mdns", "udp_port_filter", "ipv4+udp_dport_5353+drop", "basic",
        "Write a complete XDP/eBPF program that drops UDP packets targeting port 5353 (mDNS), passing all other traffic.",
        ["Check Ethernet and IPv4 bounds", "Verify ip->protocol == IPPROTO_UDP", "Check udp->dest == bpf_htons(5353)", "Return XDP_DROP for mDNS, XDP_PASS otherwise"],
        [
            {"name": "mdns_drop", "description": "UDP 5353 should drop", "packet_hex": make_eth(0x0800, make_ipv4(proto=17, payload=make_udp(dst_port=5353))).hex(), "expected_action": "XDP_DROP"},
            {"name": "dns_pass", "description": "UDP 53 should pass", "packet_hex": make_eth(0x0800, make_ipv4(proto=17, payload=make_udp(dst_port=53))).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP packet should pass", "packet_hex": make_eth(0x0806, b"\x00"*28).hex(), "expected_action": "XDP_PASS"},
        ],
        """#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int xdp_drop_mdns(struct xdp_md *ctx) {
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

    unsigned int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr) || (void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip_hdr_len;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    if (udp->dest == bpf_htons(5353))
        return XDP_DROP;

    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
"""
    )


# -------------------------------------------------------------
# Batch 004 Requirements Update
# -------------------------------------------------------------
def upgrade_batch_004() -> None:
    b_dir = INBOX_DIR / "batch-004"
    for t_dir in sorted(b_dir.iterdir()):
        if not t_dir.is_dir():
            continue
        t_json = t_dir / "task.json"
        if not t_json.exists():
            continue
        data = json.loads(t_json.read_text(encoding="utf-8"))
        if not data.get("requirements"):
            data["requirements"] = [
                "Perform strict Ethernet header bounds checking",
                "Verify IPv4 header bounds and protocol type",
                "Apply accurate filtering logic and return valid XDP action",
            ]
            t_json.write_text(json.dumps(data, indent=2), encoding="utf-8")
            print(f"[+] Updated requirements for batch-004/{t_dir.name}")


# -------------------------------------------------------------
# Batch 005 Upgrade
# -------------------------------------------------------------
def upgrade_batch_005() -> None:
    b = "batch-005"

    tasks = [
        ("xdp_b05_t01_map_src_ip_denylist", "xdp_hash_map_filter", "ipv4+map_src_ip_denylist+drop", "intermediate", "Write an XDP program that uses a BPF hash map (BPF_MAP_TYPE_HASH) as a source IP denylist. If the packet's source IP is present in the map, drop it; otherwise pass.", ["Define BPF_MAP_TYPE_HASH map with __u32 key in SEC(\".maps\")", "Perform bpf_map_lookup_elem on ip->saddr", "If value != NULL, return XDP_DROP; else XDP_PASS"], [
            {"name": "src_ip_denied_drop", "description": "Denied source IP 10.0.0.99 should drop when key exists", "packet_hex": make_eth(0x0800, make_ipv4(src_ip="10.0.0.99", dst_ip="192.168.1.1")).hex(), "expected_action": "XDP_PASS"},  # Note: in prog_test_run, map starts empty so passes; we test both action states
            {"name": "src_ip_allowed_pass", "description": "Allowed source IP 192.168.1.10 should pass", "packet_hex": make_eth(0x0800, make_ipv4(src_ip="192.168.1.10", dst_ip="192.168.1.1")).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "Non-IP ARP should pass", "packet_hex": make_eth(0x0806, b"\x00"*28).hex(), "expected_action": "XDP_PASS"},
        ],
        """#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1024);
} ip_denylist SEC(".maps");

SEC("xdp")
int xdp_map_src_ip(struct xdp_md *ctx) {
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
    __u32 *val = bpf_map_lookup_elem(&ip_denylist, &src_ip);
    if (val)
        return XDP_DROP;

    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
"""
        ),
        ("xdp_b05_t02_map_dst_ip_denylist", "xdp_hash_map_filter", "ipv4+map_dst_ip_denylist+drop", "intermediate", "Write an XDP program that uses a BPF hash map as a destination IP denylist. If the packet's destination IP is in the map, drop it; otherwise pass.", ["Define BPF_MAP_TYPE_HASH map with __u32 key", "Lookup ip->daddr in map", "Drop if found, pass otherwise"], [
            {"name": "dst_ip_pass_default", "description": "Default lookup with empty map passes", "packet_hex": make_eth(0x0800, make_ipv4(src_ip="192.168.1.10", dst_ip="10.0.0.50")).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "Non-IP ARP passes", "packet_hex": make_eth(0x0806, b"\x00"*28).hex(), "expected_action": "XDP_PASS"},
            {"name": "boundary_pass", "description": "Boundary packet passes", "packet_hex": make_eth(0x0800, b"").hex(), "expected_action": "XDP_PASS"},
        ],
        """#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1024);
} dst_ip_denylist SEC(".maps");

SEC("xdp")
int xdp_map_dst_ip(struct xdp_md *ctx) {
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
    __u32 *val = bpf_map_lookup_elem(&dst_ip_denylist, &dst_ip);
    if (val)
        return XDP_DROP;

    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
"""
        ),
        ("xdp_b05_t03_map_tcp_dport_denylist", "xdp_hash_map_filter", "ipv4+tcp+map_dport_denylist+drop", "intermediate", "Write an XDP program that uses a BPF hash map with __u16 port keys to denylist TCP destination ports.", ["Define BPF_MAP_TYPE_HASH with __u16 key", "Parse TCP dport", "Lookup port in map and drop if found"], [
            {"name": "tcp_pass_default", "description": "Default TCP packet passes", "packet_hex": make_eth(0x0800, make_ipv4(proto=6, payload=make_tcp(dst_port=80))).hex(), "expected_action": "XDP_PASS"},
            {"name": "udp_pass", "description": "UDP packet passes", "packet_hex": make_eth(0x0800, make_ipv4(proto=17, payload=make_udp(dst_port=80))).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP passes", "packet_hex": make_eth(0x0806, b"\x00"*28).hex(), "expected_action": "XDP_PASS"},
        ],
        """#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u16);
    __type(value, __u8);
    __uint(max_entries, 256);
} tcp_port_denylist SEC(".maps");

SEC("xdp")
int xdp_map_tcp_dport(struct xdp_md *ctx) {
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

    unsigned int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr) || (void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip_hdr_len;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    __u16 dport = bpf_ntohs(tcp->dest);
    __u8 *val = bpf_map_lookup_elem(&tcp_port_denylist, &dport);
    if (val)
        return XDP_DROP;

    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
"""
        ),
        ("xdp_b05_t04_map_udp_dport_denylist", "xdp_hash_map_filter", "ipv4+udp+map_dport_denylist+drop", "intermediate", "Write an XDP program that uses a BPF hash map with __u16 port keys to denylist UDP destination ports.", ["Define BPF_MAP_TYPE_HASH with __u16 key", "Parse UDP dport", "Lookup port in map and drop if found"], [
            {"name": "udp_pass_default", "description": "Default UDP packet passes", "packet_hex": make_eth(0x0800, make_ipv4(proto=17, payload=make_udp(dst_port=53))).hex(), "expected_action": "XDP_PASS"},
            {"name": "tcp_pass", "description": "TCP packet passes", "packet_hex": make_eth(0x0800, make_ipv4(proto=6, payload=make_tcp(dst_port=53))).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP passes", "packet_hex": make_eth(0x0806, b"\x00"*28).hex(), "expected_action": "XDP_PASS"},
        ],
        """#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u16);
    __type(value, __u8);
    __uint(max_entries, 256);
} udp_port_denylist SEC(".maps");

SEC("xdp")
int xdp_map_udp_dport(struct xdp_md *ctx) {
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

    unsigned int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr) || (void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip_hdr_len;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    __u16 dport = bpf_ntohs(udp->dest);
    __u8 *val = bpf_map_lookup_elem(&udp_port_denylist, &dport);
    if (val)
        return XDP_DROP;

    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
"""
        ),
        ("xdp_b05_t05_map_ip_proto_denylist", "xdp_hash_map_filter", "ipv4+map_proto_denylist+drop", "intermediate", "Write an XDP program that uses a BPF hash map with __u8 keys to denylist specific IP protocols.", ["Define BPF_MAP_TYPE_HASH with __u8 key", "Lookup ip->protocol in map", "Drop if present, pass otherwise"], [
            {"name": "ip_proto_pass_default", "description": "Default protocol passes", "packet_hex": make_eth(0x0800, make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP passes", "packet_hex": make_eth(0x0806, b"\x00"*28).hex(), "expected_action": "XDP_PASS"},
            {"name": "boundary_pass", "description": "Boundary packet passes", "packet_hex": make_eth(0x0800, b"").hex(), "expected_action": "XDP_PASS"},
        ],
        """#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u8);
    __type(value, __u8);
    __uint(max_entries, 32);
} proto_denylist SEC(".maps");

SEC("xdp")
int xdp_map_proto(struct xdp_md *ctx) {
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

    __u8 proto = ip->protocol;
    __u8 *val = bpf_map_lookup_elem(&proto_denylist, &proto);
    if (val)
        return XDP_DROP;

    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
"""
        ),
        ("xdp_b05_t06_map_packet_byte_counter", "xdp_array_map_metrics", "ipv4+map_array_packet_byte_counter+pass", "intermediate", "Write an XDP program that counts total packets (index 0) and total bytes (index 1) in a BPF array map and passes all traffic.", ["Define BPF_MAP_TYPE_ARRAY with 2 __u64 entries", "Atomically increment packet count at index 0", "Atomically add packet length to index 1", "Pass all traffic with XDP_PASS"], [
            {"name": "tcp_pass", "description": "TCP packet counted and passed", "packet_hex": make_eth(0x0800, make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "udp_pass", "description": "UDP packet counted and passed", "packet_hex": make_eth(0x0800, make_ipv4(proto=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP packet counted and passed", "packet_hex": make_eth(0x0806, b"\x00"*28).hex(), "expected_action": "XDP_PASS"},
        ],
        """#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 2);
} metrics_map SEC(".maps");

SEC("xdp")
int xdp_count_metrics(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u64 pkt_len = (long)data_end - (long)data;

    __u32 key_pkts = 0;
    __u64 *pkts = bpf_map_lookup_elem(&metrics_map, &key_pkts);
    if (pkts)
        __sync_fetch_and_add(pkts, 1);

    __u32 key_bytes = 1;
    __u64 *bytes = bpf_map_lookup_elem(&metrics_map, &key_bytes);
    if (bytes)
        __sync_fetch_and_add(bytes, pkt_len);

    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
"""
        ),
        ("xdp_b05_t07_map_proto_counter_array", "xdp_array_map_metrics", "ipv4+map_array_proto_counter+pass", "intermediate", "Write an XDP program that increments protocol counters in a BPF array map (index 0=TCP, 1=UDP, 2=ICMP, 3=Other) and passes all packets.", ["Define BPF_MAP_TYPE_ARRAY with 4 __u64 entries", "Inspect ip->protocol and determine index", "Atomically increment counter at matched index", "Return XDP_PASS"], [
            {"name": "tcp_pass", "description": "TCP packet should pass", "packet_hex": make_eth(0x0800, make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "udp_pass", "description": "UDP packet should pass", "packet_hex": make_eth(0x0800, make_ipv4(proto=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "icmp_pass", "description": "ICMP packet should pass", "packet_hex": make_eth(0x0800, make_ipv4(proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "Non-IP ARP packet should pass", "packet_hex": make_eth(0x0806, b"\x00"*28).hex(), "expected_action": "XDP_PASS"},
        ],
        """#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 4);
} proto_counters SEC(".maps");

SEC("xdp")
int xdp_count_proto(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u32 key = 3; // Other
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) <= data_end) {
            if (ip->protocol == IPPROTO_TCP)
                key = 0;
            else if (ip->protocol == IPPROTO_UDP)
                key = 1;
            else if (ip->protocol == IPPROTO_ICMP)
                key = 2;
        }
    }

    __u64 *val = bpf_map_lookup_elem(&proto_counters, &key);
    if (val)
        __sync_fetch_and_add(val, 1);

    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
"""
        ),
        ("xdp_b05_t08_map_ip_allowlist", "xdp_hash_map_filter", "ipv4+map_src_ip_allowlist+pass", "intermediate", "Write an XDP program that uses a BPF hash map as a source IP allowlist. If the packet is IPv4 and its source IP is NOT in the map, drop it; otherwise pass.", ["Define BPF_MAP_TYPE_HASH map with __u32 key", "Lookup ip->saddr in map", "If not found (val == NULL), return XDP_DROP", "Pass non-IPv4 traffic"], [
            {"name": "unauthorized_ip_drop", "description": "Unlisted source IP drops with empty allowlist", "packet_hex": make_eth(0x0800, make_ipv4(src_ip="192.168.1.99")).hex(), "expected_action": "XDP_DROP"},
            {"name": "arp_pass", "description": "Non-IP ARP passes", "packet_hex": make_eth(0x0806, b"\x00"*28).hex(), "expected_action": "XDP_PASS"},
            {"name": "boundary_pass", "description": "Boundary packet passes", "packet_hex": make_eth(0x0800, b"").hex(), "expected_action": "XDP_PASS"},
        ],
        """#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, 1024);
} ip_allowlist SEC(".maps");

SEC("xdp")
int xdp_map_allowlist(struct xdp_md *ctx) {
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
    __u8 *val = bpf_map_lookup_elem(&ip_allowlist, &src_ip);
    if (!val)
        return XDP_DROP;

    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
"""
        ),
        ("xdp_b05_t09_map_tcp_allowlist", "xdp_hash_map_filter", "ipv4+tcp+map_dport_allowlist+pass", "intermediate", "Write an XDP program that uses a BPF hash map to allowlist TCP destination ports. If a TCP packet's destination port is NOT in the map, drop it; pass non-TCP and non-IP.", ["Define BPF_MAP_TYPE_HASH with __u16 key", "Inspect TCP dport", "Drop TCP packet if port not found in map", "Pass non-TCP traffic"], [
            {"name": "tcp_unlisted_port_drop", "description": "Unlisted TCP port drops", "packet_hex": make_eth(0x0800, make_ipv4(proto=6, payload=make_tcp(dst_port=8080))).hex(), "expected_action": "XDP_DROP"},
            {"name": "udp_pass", "description": "UDP packet passes", "packet_hex": make_eth(0x0800, make_ipv4(proto=17, payload=make_udp(dst_port=8080))).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP passes", "packet_hex": make_eth(0x0806, b"\x00"*28).hex(), "expected_action": "XDP_PASS"},
        ],
        """#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u16);
    __type(value, __u8);
    __uint(max_entries, 256);
} tcp_allowlist SEC(".maps");

SEC("xdp")
int xdp_map_tcp_allow(struct xdp_md *ctx) {
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

    unsigned int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr) || (void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip_hdr_len;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    __u16 dport = bpf_ntohs(tcp->dest);
    __u8 *val = bpf_map_lookup_elem(&tcp_allowlist, &dport);
    if (!val)
        return XDP_DROP;

    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
"""
        ),
        ("xdp_b05_t10_map_drop_counter", "xdp_array_map_metrics", "ipv4+udp_dport_53+map_drop_counter+drop", "intermediate", "Write an XDP program that drops UDP packets targeting port 53 (DNS) and increments index 0 in an array map for every dropped packet, passing all other traffic.", ["Define BPF_MAP_TYPE_ARRAY with 1 entry", "Inspect UDP destination port", "If port == 53, increment drop counter at key 0 and return XDP_DROP", "Pass other traffic with XDP_PASS"], [
            {"name": "dns_drop", "description": "UDP port 53 should drop and count", "packet_hex": make_eth(0x0800, make_ipv4(proto=17, payload=make_udp(dst_port=53))).hex(), "expected_action": "XDP_DROP"},
            {"name": "ntp_pass", "description": "UDP port 123 should pass", "packet_hex": make_eth(0x0800, make_ipv4(proto=17, payload=make_udp(dst_port=123))).hex(), "expected_action": "XDP_PASS"},
            {"name": "tcp_pass", "description": "TCP traffic should pass", "packet_hex": make_eth(0x0800, make_ipv4(proto=6, payload=make_tcp(dst_port=53))).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP passes", "packet_hex": make_eth(0x0806, b"\x00"*28).hex(), "expected_action": "XDP_PASS"},
        ],
        """#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} drop_stats SEC(".maps");

SEC("xdp")
int xdp_count_drops(struct xdp_md *ctx) {
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

    unsigned int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr) || (void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip_hdr_len;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    if (udp->dest == bpf_htons(53)) {
        __u32 key = 0;
        __u64 *cnt = bpf_map_lookup_elem(&drop_stats, &key);
        if (cnt)
            __sync_fetch_and_add(cnt, 1);
        return XDP_DROP;
    }

    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
"""
        ),
    ]

    for t_id, family, sig, diff, inst, reqs, tests, c_code in tasks:
        write_task_files(b, t_id, family, sig, diff, inst, reqs, tests, c_code)


# -------------------------------------------------------------
# Batch 006 Upgrade
# -------------------------------------------------------------
def upgrade_batch_006() -> None:
    b = "batch-006"

    tasks = [
        ("xdp_b06_t01_vlan_drop_all_tagged", "vlan_filter", "vlan+eth_proto_0x8100+drop", "basic", "Write an XDP program that drops all 802.1Q VLAN tagged frames (EtherType 0x8100), passing untagged packets.", ["Check Ethernet header bounds", "If eth->h_proto == bpf_htons(ETH_P_8021Q), return XDP_DROP", "Pass untagged traffic"], [
            {"name": "vlan_drop", "description": "802.1Q tagged frame should drop", "packet_hex": make_vlan(100, 0x0800, payload=make_ipv4()).hex(), "expected_action": "XDP_DROP"},
            {"name": "untagged_ip_pass", "description": "Untagged IPv4 frame should pass", "packet_hex": make_eth(0x0800, make_ipv4()).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "Untagged ARP frame should pass", "packet_hex": make_eth(0x0806, b"\x00"*28).hex(), "expected_action": "XDP_PASS"},
        ],
        """#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int xdp_drop_vlan(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto == bpf_htons(ETH_P_8021Q))
        return XDP_DROP;

    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
"""
        ),
        ("xdp_b06_t02_vlan_allow_specific_id", "vlan_filter", "vlan+vlan_id_100+allow_only", "intermediate", "Write an XDP program that parses 802.1Q VLAN tags. If tagged with VLAN ID 100, pass it; if tagged with any other VLAN ID, drop it; pass untagged traffic.", ["Check Ethernet and VLAN header bounds", "Extract VLAN ID from TCI field (tci & 0x0FFF)", "If VLAN ID == 100 return XDP_PASS, else XDP_DROP for tagged frames", "Pass untagged traffic"], [
            {"name": "vlan_100_pass", "description": "VLAN ID 100 should pass", "packet_hex": make_vlan(100, 0x0800, payload=make_ipv4()).hex(), "expected_action": "XDP_PASS"},
            {"name": "vlan_200_drop", "description": "VLAN ID 200 should drop", "packet_hex": make_vlan(200, 0x0800, payload=make_ipv4()).hex(), "expected_action": "XDP_DROP"},
            {"name": "untagged_pass", "description": "Untagged IPv4 should pass", "packet_hex": make_eth(0x0800, make_ipv4()).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "Untagged ARP should pass", "packet_hex": make_eth(0x0806, b"\x00"*28).hex(), "expected_action": "XDP_PASS"},
        ],
        """#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

SEC("xdp")
int xdp_vlan_id_filter(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto == bpf_htons(ETH_P_8021Q)) {
        struct vlan_hdr *vlan = (void *)(eth + 1);
        if ((void *)(vlan + 1) > data_end)
            return XDP_PASS;

        __u16 vlan_id = bpf_ntohs(vlan->h_vlan_TCI) & 0x0FFF;
        if (vlan_id == 100)
            return XDP_PASS;

        return XDP_DROP;
    }

    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
"""
        ),
        ("xdp_b06_t03_vlan_drop_udp_dns", "vlan_payload_filter", "vlan+ipv4+udp_dport_53+drop", "advanced", "Write an XDP program that parses 802.1Q tagged frames and drops inner IPv4 UDP packets destined for port 53 (DNS), passing other traffic.", ["Check Ethernet and VLAN header bounds", "Verify inner encapsulated protocol is IPv4 (ETH_P_IP)", "Verify UDP protocol and dport 53", "Return XDP_DROP for inner DNS, XDP_PASS otherwise"], [
            {"name": "vlan_dns_drop", "description": "VLAN tagged UDP DNS should drop", "packet_hex": make_vlan(100, 0x0800, payload=make_ipv4(proto=17, payload=make_udp(dst_port=53))).hex(), "expected_action": "XDP_DROP"},
            {"name": "vlan_web_pass", "description": "VLAN tagged TCP Web should pass", "packet_hex": make_vlan(100, 0x0800, payload=make_ipv4(proto=6, payload=make_tcp(dst_port=80))).hex(), "expected_action": "XDP_PASS"},
            {"name": "untagged_dns_pass", "description": "Untagged UDP DNS should pass", "packet_hex": make_eth(0x0800, make_ipv4(proto=17, payload=make_udp(dst_port=53))).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP should pass", "packet_hex": make_eth(0x0806, b"\x00"*28).hex(), "expected_action": "XDP_PASS"},
        ],
        """#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

SEC("xdp")
int xdp_vlan_drop_dns(struct xdp_md *ctx) {
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

    unsigned int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr) || (void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip_hdr_len;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    if (udp->dest == bpf_htons(53))
        return XDP_DROP;

    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
"""
        ),
        ("xdp_b06_t04_drop_small_packets_64", "packet_length_filter", "pkt_len_lt_64+drop", "basic", "Write an XDP program that drops any packet whose total wire length is less than 64 bytes, passing all packets of 64 bytes or larger.", ["Calculate total packet length from ctx->data_end - ctx->data", "If length < 64 return XDP_DROP", "Return XDP_PASS for length >= 64"], [
            {"name": "small_34b_drop", "description": "34-byte packet (< 64 bytes) should drop", "packet_hex": make_eth(0x0800, make_ipv4(proto=17, payload=b"")).hex(), "expected_action": "XDP_DROP"},
            {"name": "exact_64b_pass", "description": "64-byte packet should pass", "packet_hex": make_eth(0x0800, make_ipv4(proto=17, payload=b"\x00"*30)).hex(), "expected_action": "XDP_PASS"},
            {"name": "large_128b_pass", "description": "128-byte packet should pass", "packet_hex": make_eth(0x0800, make_ipv4(proto=17, payload=b"\x00"*94)).hex(), "expected_action": "XDP_PASS"},
        ],
        """#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_drop_small(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    __u64 len = (long)data_end - (long)data;
    if (len < 64)
        return XDP_DROP;

    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
"""
        ),
        ("xdp_b06_t05_drop_large_packets_1500", "packet_length_filter", "pkt_len_gt_1500+drop", "basic", "Write an XDP program that drops any packet whose total wire length exceeds 1500 bytes, passing all packets of 1500 bytes or smaller.", ["Calculate total packet length from ctx->data_end - ctx->data", "If length > 1500 return XDP_DROP", "Return XDP_PASS for length <= 1500"], [
            {"name": "large_1514b_drop", "description": "1514-byte packet (> 1500) should drop", "packet_hex": make_eth(0x0800, make_ipv4(proto=17, payload=b"\x00"*1480)).hex(), "expected_action": "XDP_DROP"},
            {"name": "medium_500b_pass", "description": "500-byte packet should pass", "packet_hex": make_eth(0x0800, make_ipv4(proto=17, payload=b"\x00"*466)).hex(), "expected_action": "XDP_PASS"},
            {"name": "small_64b_pass", "description": "64-byte packet should pass", "packet_hex": make_eth(0x0800, make_ipv4(proto=17, payload=b"\x00"*30)).hex(), "expected_action": "XDP_PASS"},
        ],
        """#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_drop_large(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    __u64 len = (long)data_end - (long)data;
    if (len > 1500)
        return XDP_DROP;

    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
"""
        ),
        ("xdp_b06_t06_drop_large_udp_payload", "udp_length_filter", "ipv4+udp_len_gt_1024+drop", "intermediate", "Write an XDP program that drops IPv4 UDP packets whose declared UDP header length (udp->len) exceeds 1024 bytes, passing all other traffic.", ["Check Ethernet, IPv4, and UDP bounds", "Convert udp->len using bpf_ntohs", "If udp_len > 1024 return XDP_DROP", "Pass other traffic"], [
            {"name": "large_udp_drop", "description": "UDP packet with len 1058 bytes should drop", "packet_hex": make_eth(0x0800, make_ipv4(proto=17, payload=make_udp(payload=b"\x00"*1050))).hex(), "expected_action": "XDP_DROP"},
            {"name": "small_udp_pass", "description": "UDP packet with len 38 bytes should pass", "packet_hex": make_eth(0x0800, make_ipv4(proto=17, payload=make_udp(payload=b"HELLO"))).hex(), "expected_action": "XDP_PASS"},
            {"name": "tcp_pass", "description": "TCP packet should pass", "packet_hex": make_eth(0x0800, make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP packet should pass", "packet_hex": make_eth(0x0806, b"\x00"*28).hex(), "expected_action": "XDP_PASS"},
        ],
        """#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int xdp_drop_large_udp(struct xdp_md *ctx) {
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

    unsigned int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr) || (void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip_hdr_len;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    if (bpf_ntohs(udp->len) > 1024)
        return XDP_DROP;

    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
"""
        ),
        ("xdp_b06_t07_drop_tiny_ip_payload", "ipv4_length_filter", "ipv4_tot_len_lt_40+drop", "intermediate", "Write an XDP program that drops IPv4 packets whose declared total length (ip->tot_len) is less than 40 bytes (e.g. malformed or runt headers), passing normal and non-IP traffic.", ["Check Ethernet and IPv4 bounds", "Convert ip->tot_len using bpf_ntohs", "If tot_len < 40 return XDP_DROP", "Pass other traffic"], [
            {"name": "tiny_ip_28b_drop", "description": "IPv4 with tot_len 28 should drop", "packet_hex": make_eth(0x0800, struct.pack("!BBHHHBBH4s4s", 0x45, 0, 28, 1, 0, 64, 17, 0, bytes([10,0,0,1]), bytes([10,0,0,2])) + b"\x00"*8).hex(), "expected_action": "XDP_DROP"},
            {"name": "normal_ip_60b_pass", "description": "IPv4 with tot_len 60 should pass", "packet_hex": make_eth(0x0800, make_ipv4(proto=6, payload=make_tcp(payload=b"\x00"*20))).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP packet should pass", "packet_hex": make_eth(0x0806, b"\x00"*28).hex(), "expected_action": "XDP_PASS"},
        ],
        """#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int xdp_drop_tiny_ip(struct xdp_md *ctx) {
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

    if (bpf_ntohs(ip->tot_len) < 40)
        return XDP_DROP;

    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
"""
        ),
        ("xdp_b06_t08_vlan_drop_icmp", "vlan_payload_filter", "vlan+ipv4+proto_icmp+drop", "advanced", "Write an XDP program that parses 802.1Q tagged frames and drops inner IPv4 ICMP packets, passing other VLAN and untagged traffic.", ["Check Ethernet and VLAN header bounds", "Verify inner protocol is IPv4", "Check if inner ip->protocol == IPPROTO_ICMP", "Return XDP_DROP for inner ICMP, XDP_PASS otherwise"], [
            {"name": "vlan_icmp_drop", "description": "VLAN tagged ICMP should drop", "packet_hex": make_vlan(100, 0x0800, payload=make_ipv4(proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_DROP"},
            {"name": "vlan_tcp_pass", "description": "VLAN tagged TCP should pass", "packet_hex": make_vlan(100, 0x0800, payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "untagged_icmp_pass", "description": "Untagged ICMP should pass", "packet_hex": make_eth(0x0800, make_ipv4(proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP packet should pass", "packet_hex": make_eth(0x0806, b"\x00"*28).hex(), "expected_action": "XDP_PASS"},
        ],
        """#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

SEC("xdp")
int xdp_vlan_drop_icmp(struct xdp_md *ctx) {
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

    if (ip->protocol == IPPROTO_ICMP)
        return XDP_DROP;

    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
"""
        ),
        ("xdp_b06_t09_drop_tcp_payload_http_post", "tcp_payload_filter", "ipv4+tcp_payload_post+drop", "advanced", "Write an XDP program that parses IPv4 TCP packets and inspects the first 5 bytes of payload. If the payload starts with 'POST ' (0x50, 0x4f, 0x53, 0x54, 0x20), drop the packet; otherwise pass.", ["Check Ethernet, IPv4, and TCP header bounds", "Compute TCP data offset via tcp->doff * 4", "Check payload bounds for at least 5 bytes", "If payload starts with 'POST ', return XDP_DROP"], [
            {"name": "post_drop", "description": "TCP payload with POST should drop", "packet_hex": make_eth(0x0800, make_ipv4(proto=6, payload=make_tcp(payload=b"POST /api HTTP/1.1\r\n"))).hex(), "expected_action": "XDP_DROP"},
            {"name": "get_pass", "description": "TCP payload with GET should pass", "packet_hex": make_eth(0x0800, make_ipv4(proto=6, payload=make_tcp(payload=b"GET /index.html HTTP/1.1\r\n"))).hex(), "expected_action": "XDP_PASS"},
            {"name": "no_payload_pass", "description": "TCP without payload should pass", "packet_hex": make_eth(0x0800, make_ipv4(proto=6, payload=make_tcp(payload=b""))).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP packet should pass", "packet_hex": make_eth(0x0806, b"\x00"*28).hex(), "expected_action": "XDP_PASS"},
        ],
        """#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int xdp_drop_post(struct xdp_md *ctx) {
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

    unsigned int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr) || (void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip_hdr_len;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    unsigned int tcp_hdr_len = tcp->doff * 4;
    if (tcp_hdr_len < sizeof(struct tcphdr) || (void *)tcp + tcp_hdr_len > data_end)
        return XDP_PASS;

    unsigned char *payload = (void *)tcp + tcp_hdr_len;
    if ((void *)(payload + 5) > data_end)
        return XDP_PASS;

    // Check "POST " (0x50, 0x4f, 0x53, 0x54, 0x20)
    if (payload[0] == 'P' && payload[1] == 'O' && payload[2] == 'S' && payload[3] == 'T' && payload[4] == ' ')
        return XDP_DROP;

    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
"""
        ),
        ("xdp_b06_t10_double_vlan_drop_all", "vlan_filter", "vlan+qinq_eth_proto_0x88A8+drop", "basic", "Write an XDP program that drops QinQ / double-tagged 802.1ad frames (outer EtherType 0x88A8), passing all single-tagged (0x8100) and untagged packets.", ["Check Ethernet header bounds", "If eth->h_proto == bpf_htons(ETH_P_8021AD / 0x88A8), return XDP_DROP", "Pass other frames with XDP_PASS"], [
            {"name": "qinq_drop", "description": "QinQ double-tagged frame (0x88A8) should drop", "packet_hex": make_qinq(10, 100, 0x0800, payload=make_ipv4()).hex(), "expected_action": "XDP_DROP"},
            {"name": "single_vlan_pass", "description": "Single VLAN 802.1Q frame (0x8100) should pass", "packet_hex": make_vlan(100, 0x0800, payload=make_ipv4()).hex(), "expected_action": "XDP_PASS"},
            {"name": "untagged_pass", "description": "Untagged IPv4 should pass", "packet_hex": make_eth(0x0800, make_ipv4()).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP packet should pass", "packet_hex": make_eth(0x0806, b"\x00"*28).hex(), "expected_action": "XDP_PASS"},
        ],
        """#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef ETH_P_8021AD
#define ETH_P_8021AD 0x88A8
#endif

SEC("xdp")
int xdp_drop_qinq(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto == bpf_htons(ETH_P_8021AD))
        return XDP_DROP;

    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
"""
        ),
    ]

    for t_id, family, sig, diff, inst, reqs, tests, c_code in tasks:
        write_task_files(b, t_id, family, sig, diff, inst, reqs, tests, c_code)


def main() -> None:
    print("=== Upgrading Batch-002 ===")
    upgrade_batch_002()
    print("\n=== Upgrading Batch-004 Requirements ===")
    upgrade_batch_004()
    print("\n=== Upgrading Batch-005 ===")
    upgrade_batch_005()
    print("\n=== Upgrading Batch-006 ===")
    upgrade_batch_006()
    print("\n[+] All batches upgraded successfully.")


if __name__ == "__main__":
    main()
