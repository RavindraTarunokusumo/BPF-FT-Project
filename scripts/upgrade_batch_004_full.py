#!/usr/bin/env python3
"""
Upgrades batch-004 tasks 2-8 and 10 with rich multi-packet test suites (3-5 tests each).
"""

from __future__ import annotations

import json
import struct
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
B04_DIR = PROJECT_ROOT / "data" / "inbox" / "batch-004"


def make_eth(eth_type: int = 0x0800, payload: bytes = b"") -> bytes:
    dst_mac = bytes([0x52, 0x54, 0x00, 0x12, 0x34, 0x56])
    src_mac = bytes([0x52, 0x54, 0x00, 0x65, 0x43, 0x21])
    return dst_mac + src_mac + struct.pack("!H", eth_type) + payload


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


def update_task(task_id: str, family: str, sig: str, diff: str, inst: str, reqs: list[str], tests: list[dict], c_code: str) -> None:
    t_dir = B04_DIR / task_id
    t_dir.mkdir(parents=True, exist_ok=True)

    task_json = {
        "task_id": task_id,
        "template_family": family,
        "semantic_signature": sig,
        "difficulty": diff,
        "split": "train",
        "instruction": inst,
        "requirements": reqs,
        "gold_candidate_id": None,
        "tests": tests,
    }
    (t_dir / "task.json").write_text(json.dumps(task_json, indent=2), encoding="utf-8")
    (t_dir / "c00.c").write_text(c_code, encoding="utf-8")
    print(f"[+] Upgraded {task_id}")


def main() -> None:
    # t02: Drop ICMP Destination Unreachable (Type 3)
    update_task(
        "xdp_b04_t02_drop_icmp_unreachable", "icmp_type_filter", "ipv4+icmp_type_3+drop", "basic",
        "Write a complete XDP/eBPF program that drops ICMP Destination Unreachable packets (type 3), passing all other ICMP and non-ICMP traffic.",
        ["Check Ethernet and IPv4 bounds", "Verify ip->protocol == IPPROTO_ICMP", "Inspect ICMP type byte at offset after IPv4 header", "If type == 3 return XDP_DROP; else XDP_PASS"],
        [
            {"name": "unreachable_drop", "description": "ICMP Destination Unreachable (type 3) should drop", "packet_hex": make_eth(0x0800, make_ipv4(proto=1, payload=make_icmp(icmp_type=3, icmp_code=1))).hex(), "expected_action": "XDP_DROP"},
            {"name": "echo_reply_pass", "description": "ICMP Echo Reply (type 0) should pass", "packet_hex": make_eth(0x0800, make_ipv4(proto=1, payload=make_icmp(icmp_type=0, icmp_code=0))).hex(), "expected_action": "XDP_PASS"},
            {"name": "tcp_pass", "description": "TCP traffic should pass", "packet_hex": make_eth(0x0800, make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP packet should pass", "packet_hex": make_eth(0x0806, b"\x00"*28).hex(), "expected_action": "XDP_PASS"},
        ],
        """#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int xdp_drop_unreachable(struct xdp_md *ctx) {
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

    if (ip->protocol != IPPROTO_ICMP)
        return XDP_PASS;

    unsigned char *icmp = (void *)ip + ip_hdr_len;
    if ((void *)(icmp + 1) > data_end)
        return XDP_PASS;

    if (icmp[0] == 3)
        return XDP_DROP;

    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
"""
    )

    # t03: Drop GRE Protocol 47
    update_task(
        "xdp_b04_t03_drop_gre_protocol", "ip_protocol_filter", "ipv4+proto_gre_47+drop", "basic",
        "Write a complete XDP/eBPF program that drops GRE (Generic Routing Encapsulation) packets (IP protocol 47), passing all other traffic.",
        ["Check Ethernet and IPv4 bounds", "Inspect ip->protocol", "If protocol == 47 return XDP_DROP; else XDP_PASS", "Pass non-IP packets"],
        [
            {"name": "gre_drop", "description": "GRE protocol 47 should drop", "packet_hex": make_eth(0x0800, make_ipv4(proto=47, payload=b"\x00"*10)).hex(), "expected_action": "XDP_DROP"},
            {"name": "tcp_pass", "description": "TCP protocol 6 should pass", "packet_hex": make_eth(0x0800, make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "udp_pass", "description": "UDP protocol 17 should pass", "packet_hex": make_eth(0x0800, make_ipv4(proto=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP packet should pass", "packet_hex": make_eth(0x0806, b"\x00"*28).hex(), "expected_action": "XDP_PASS"},
        ],
        """#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int xdp_drop_gre(struct xdp_md *ctx) {
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

    if (ip->protocol == 47)
        return XDP_DROP;

    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
"""
    )

    # t04: Drop IPsec ESP 50
    update_task(
        "xdp_b04_t04_drop_ipsec_esp", "ip_protocol_filter", "ipv4+proto_esp_50+drop", "basic",
        "Write a complete XDP/eBPF program that drops IPsec ESP packets (IP protocol 50), passing all other traffic.",
        ["Check Ethernet and IPv4 bounds", "Inspect ip->protocol", "If protocol == 50 (IPPROTO_ESP) return XDP_DROP", "Pass non-IP and other protocol packets"],
        [
            {"name": "esp_drop", "description": "ESP protocol 50 should drop", "packet_hex": make_eth(0x0800, make_ipv4(proto=50, payload=b"\x00"*16)).hex(), "expected_action": "XDP_DROP"},
            {"name": "tcp_pass", "description": "TCP protocol 6 should pass", "packet_hex": make_eth(0x0800, make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "udp_pass", "description": "UDP protocol 17 should pass", "packet_hex": make_eth(0x0800, make_ipv4(proto=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP packet should pass", "packet_hex": make_eth(0x0806, b"\x00"*28).hex(), "expected_action": "XDP_PASS"},
        ],
        """#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int xdp_drop_esp(struct xdp_md *ctx) {
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

    if (ip->protocol == 50)
        return XDP_DROP;

    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
"""
    )

    # t05: Drop IPsec AH 51
    update_task(
        "xdp_b04_t05_drop_ipsec_ah", "ip_protocol_filter", "ipv4+proto_ah_51+drop", "basic",
        "Write a complete XDP/eBPF program that drops IPsec AH packets (IP protocol 51), passing all other traffic.",
        ["Check Ethernet and IPv4 bounds", "Inspect ip->protocol", "If protocol == 51 (IPPROTO_AH) return XDP_DROP", "Pass non-IP and other protocol packets"],
        [
            {"name": "ah_drop", "description": "AH protocol 51 should drop", "packet_hex": make_eth(0x0800, make_ipv4(proto=51, payload=b"\x00"*16)).hex(), "expected_action": "XDP_DROP"},
            {"name": "tcp_pass", "description": "TCP protocol 6 should pass", "packet_hex": make_eth(0x0800, make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "udp_pass", "description": "UDP protocol 17 should pass", "packet_hex": make_eth(0x0800, make_ipv4(proto=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP packet should pass", "packet_hex": make_eth(0x0806, b"\x00"*28).hex(), "expected_action": "XDP_PASS"},
        ],
        """#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int xdp_drop_ah(struct xdp_md *ctx) {
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

    if (ip->protocol == 51)
        return XDP_DROP;

    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
"""
    )

    # t06: Drop IGMP Protocol 2
    update_task(
        "xdp_b04_t06_drop_igmp", "ip_protocol_filter", "ipv4+proto_igmp_2+drop", "basic",
        "Write a complete XDP/eBPF program that drops IGMP packets (IP protocol 2), passing all other traffic.",
        ["Check Ethernet and IPv4 bounds", "Inspect ip->protocol", "If protocol == 2 (IPPROTO_IGMP) return XDP_DROP", "Pass other traffic"],
        [
            {"name": "igmp_drop", "description": "IGMP protocol 2 should drop", "packet_hex": make_eth(0x0800, make_ipv4(proto=2, payload=b"\x00"*8)).hex(), "expected_action": "XDP_DROP"},
            {"name": "tcp_pass", "description": "TCP protocol 6 should pass", "packet_hex": make_eth(0x0800, make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "udp_pass", "description": "UDP protocol 17 should pass", "packet_hex": make_eth(0x0800, make_ipv4(proto=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP packet should pass", "packet_hex": make_eth(0x0806, b"\x00"*28).hex(), "expected_action": "XDP_PASS"},
        ],
        """#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int xdp_drop_igmp(struct xdp_md *ctx) {
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

    if (ip->protocol == 2)
        return XDP_DROP;

    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
"""
    )

    # t07: Drop low TTL <= 1
    update_task(
        "xdp_b04_t07_drop_low_ttl", "ipv4_ttl_filter", "ipv4+ttl_le_1+drop", "basic",
        "Write a complete XDP/eBPF program that drops IPv4 packets with TTL <= 1, passing packets with TTL > 1 and non-IPv4 traffic.",
        ["Check Ethernet and IPv4 bounds", "Inspect ip->ttl", "If ttl <= 1 return XDP_DROP; else XDP_PASS", "Pass non-IPv4 traffic"],
        [
            {"name": "ttl_1_drop", "description": "TTL=1 should drop", "packet_hex": make_eth(0x0800, make_ipv4(ttl=1, payload=b"DATA")).hex(), "expected_action": "XDP_DROP"},
            {"name": "ttl_0_drop", "description": "TTL=0 should drop", "packet_hex": make_eth(0x0800, make_ipv4(ttl=0, payload=b"DATA")).hex(), "expected_action": "XDP_DROP"},
            {"name": "ttl_64_pass", "description": "TTL=64 should pass", "packet_hex": make_eth(0x0800, make_ipv4(ttl=64, payload=b"DATA")).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP packet should pass", "packet_hex": make_eth(0x0806, b"\x00"*28).hex(), "expected_action": "XDP_PASS"},
        ],
        """#include <linux/bpf.h>
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
    )

    # t08: Drop DSCP CS6 (TOS 0xC0)
    update_task(
        "xdp_b04_t08_drop_dscp_cs6", "ipv4_tos_dscp_filter", "ipv4+tos_dscp_cs6+drop", "basic",
        "Write a complete XDP/eBPF program that drops IPv4 packets whose DSCP field matches CS6 (TOS & 0xFC == 0xC0), passing all other traffic.",
        ["Check Ethernet and IPv4 bounds", "Inspect ip->tos", "If (ip->tos & 0xFC) == 0xC0 return XDP_DROP", "Pass other traffic with XDP_PASS"],
        [
            {"name": "dscp_cs6_drop", "description": "DSCP CS6 (TOS 0xC0) should drop", "packet_hex": make_eth(0x0800, make_ipv4(tos=0xC0, payload=b"DATA")).hex(), "expected_action": "XDP_DROP"},
            {"name": "dscp_cs0_pass", "description": "Normal TOS 0x00 should pass", "packet_hex": make_eth(0x0800, make_ipv4(tos=0x00, payload=b"DATA")).hex(), "expected_action": "XDP_PASS"},
            {"name": "dscp_ef_pass", "description": "DSCP EF (TOS 0xB8) should pass", "packet_hex": make_eth(0x0800, make_ipv4(tos=0xB8, payload=b"DATA")).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP packet should pass", "packet_hex": make_eth(0x0806, b"\x00"*28).hex(), "expected_action": "XDP_PASS"},
        ],
        """#include <linux/bpf.h>
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

    if ((ip->tos & 0xFC) == 0xC0)
        return XDP_DROP;

    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
"""
    )

    # t10: Pass Only TCP, UDP, ICMP
    update_task(
        "xdp_b04_t10_pass_only_tcp_udp_icmp", "ipv4_protocol_allowlist", "ipv4+proto_not_tcp_udp_icmp+drop", "basic",
        "Write a complete XDP/eBPF program that drops IPv4 packets whose protocol is NOT TCP (6), UDP (17), or ICMP (1). Non-IPv4 traffic and allowed protocols must pass.",
        ["Check Ethernet and IPv4 bounds", "Check if ip->protocol matches IPPROTO_TCP, IPPROTO_UDP, or IPPROTO_ICMP", "Return XDP_PASS for allowed protocols", "Return XDP_DROP for other IPv4 protocols", "Pass non-IPv4 traffic"],
        [
            {"name": "tcp_pass", "description": "TCP (6) should pass", "packet_hex": make_eth(0x0800, make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "udp_pass", "description": "UDP (17) should pass", "packet_hex": make_eth(0x0800, make_ipv4(proto=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "icmp_pass", "description": "ICMP (1) should pass", "packet_hex": make_eth(0x0800, make_ipv4(proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "gre_drop", "description": "GRE (47) should drop", "packet_hex": make_eth(0x0800, make_ipv4(proto=47, payload=b"GRE")).hex(), "expected_action": "XDP_DROP"},
            {"name": "igmp_drop", "description": "IGMP (2) should drop", "packet_hex": make_eth(0x0800, make_ipv4(proto=2, payload=b"IGMP")).hex(), "expected_action": "XDP_DROP"},
            {"name": "arp_pass", "description": "ARP packet should pass", "packet_hex": make_eth(0x0806, b"\x00"*28).hex(), "expected_action": "XDP_PASS"},
        ],
        """#include <linux/bpf.h>
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
    )


if __name__ == "__main__":
    main()
