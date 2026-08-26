#!/usr/bin/env python3
"""
BPF-Guardian Calibration Suite Generator
Generates exactly 36 calibration synthesis tasks (4 categories x 3 levels x 3 tasks)
under data/calibration/<category>/<level>/<task_id>/ along with deterministic
fixtures, tests.json, index.jsonl, assignments/calibration_v1.yaml, and README.md.
"""

from __future__ import annotations

import binascii
import json
import os
import struct
from pathlib import Path
from typing import Any, Dict, List

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CALIB_DIR = PROJECT_ROOT / "data" / "calibration"


def make_eth(dst_mac: str = "52:54:00:12:34:56", src_mac: str = "52:54:00:65:43:21", eth_type: int = 0x0800, vlan: int | None = None, payload: bytes = b"") -> bytes:
    dst_b = bytes.fromhex(dst_mac.replace(":", ""))
    src_b = bytes.fromhex(src_mac.replace(":", ""))
    if vlan is not None:
        return dst_b + src_b + struct.pack("!HH", 0x8100, vlan) + struct.pack("!H", eth_type) + payload
    return dst_b + src_b + struct.pack("!H", eth_type) + payload


def checksum(data: bytes) -> int:
    if len(data) % 2 == 1:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while (s >> 16):
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def make_ipv4(src_ip: str = "192.168.1.10", dst_ip: str = "192.168.1.20", proto: int = 6, ttl: int = 64, tos: int = 0, frag_off: int = 0, ihl: int = 5, payload: bytes = b"") -> bytes:
    src_b = bytes(map(int, src_ip.split(".")))
    dst_b = bytes(map(int, dst_ip.split(".")))
    tot_len = ihl * 4 + len(payload)
    opt_len = (ihl - 5) * 4
    opts = b"\x00" * opt_len if opt_len > 0 else b""
    hdr_no_csum = struct.pack("!BBHHHBBH4s4s", (4 << 4) | ihl, tos, tot_len, 0x1234, frag_off, ttl, proto, 0, src_b, dst_b) + opts
    csum = checksum(hdr_no_csum)
    return hdr_no_csum[:10] + struct.pack("!H", csum) + hdr_no_csum[12:] + payload


def make_tcp(src_port: int = 12345, dst_port: int = 80, flags: int = 0x02, window: int = 65535, seq: int = 1000, ack: int = 0, data_offset: int = 5, payload: bytes = b"") -> bytes:
    opt_len = (data_offset - 5) * 4
    opts = b"\x00" * opt_len if opt_len > 0 else b""
    tcph = struct.pack("!HHIIHHHH", src_port, dst_port, seq, ack, (data_offset << 12) | flags, window, 0, 0) + opts
    return tcph + payload


def make_udp(src_port: int = 12345, dst_port: int = 53, payload: bytes = b"DNS_PAYLOAD", with_csum: bool = False, src_ip: str = "192.168.1.10", dst_ip: str = "192.168.1.20") -> bytes:
    length = 8 + len(payload)
    if not with_csum:
        return struct.pack("!HHHH", src_port, dst_port, length, 0) + payload
    
    # Compute UDP checksum with IPv4 pseudo header
    src_b = bytes(map(int, src_ip.split(".")))
    dst_b = bytes(map(int, dst_ip.split(".")))
    pseudo = src_b + dst_b + struct.pack("!BBH", 0, 17, length)
    udp_raw = struct.pack("!HHHH", src_port, dst_port, length, 0) + payload
    csum = checksum(pseudo + udp_raw)
    if csum == 0:
        csum = 0xFFFF
    return struct.pack("!HHHH", src_port, dst_port, length, csum) + payload


def make_icmp(icmp_type: int = 8, icmp_code: int = 0, payload: bytes = b"PING1234") -> bytes:
    raw = struct.pack("!BBHI", icmp_type, icmp_code, 0, 0x1234) + payload
    csum = checksum(raw)
    return struct.pack("!BBHI", icmp_type, icmp_code, csum, 0x1234) + payload


def main() -> None:
    print("=== Generating 36 Calibration Tasks ===")
    CALIB_DIR.mkdir(parents=True, exist_ok=True)
    assignments_dir = CALIB_DIR / "assignments"
    assignments_dir.mkdir(parents=True, exist_ok=True)

    tasks_meta = []

    # Helper to register and write a task
    def add_task(
        cat: str,
        level: str,
        task_id: str,
        task_family: str,
        template_family: str,
        sig: str,
        instruction: str,
        requirements: list[str],
        test_cases: list[dict[str, Any]],
        main_validator: str = "packet_action",
    ):
        task_dir = CALIB_DIR / cat / level / task_id
        fixtures_dir = task_dir / "fixtures"
        fixtures_dir.mkdir(parents=True, exist_ok=True)

        min_cases = {"level_1": 5, "level_2": 7, "level_3": 9}[level]
        if len(test_cases) < min_cases:
            raise ValueError(f"Task {task_id} has {len(test_cases)} cases, but {level} requires >= {min_cases}")

        # Save fixtures as .bin
        formatted_tests = []
        for idx, tc in enumerate(test_cases):
            case_name = tc["name"]
            pkt_bytes = bytes.fromhex(tc["packet_hex"])
            bin_file = fixtures_dir / f"{case_name}.bin"
            bin_file.write_bytes(pkt_bytes)

            entry = {
                "name": case_name,
                "description": tc["description"],
                "packet_hex": tc["packet_hex"],
                "expected_action": tc["expected_action"],
                "fixture_file": f"fixtures/{case_name}.bin",
            }
            if "expected_bytes_hex" in tc:
                entry["expected_bytes_hex"] = tc["expected_bytes_hex"]
            if "expected_map_state" in tc:
                entry["expected_map_state"] = tc["expected_map_state"]
            if "expected_egress" in tc:
                entry["expected_egress"] = tc["expected_egress"]

            formatted_tests.append(entry)

        task_json = {
            "task_id": task_id,
            "application_category": cat,
            "difficulty": level,
            "task_family": task_family,
            "template_family": template_family,
            "semantic_signature": sig,
            "split": "calibration",
            "learning_mode": "synthesis",
            "instruction": instruction,
            "requirements": requirements,
            "gold_candidate_id": None,
            "tests": formatted_tests,
        }

        tests_json = {
            "task_id": task_id,
            "validator": main_validator,
            "test_count": len(formatted_tests),
            "tests": formatted_tests,
        }

        (task_dir / "task.json").write_text(json.dumps(task_json, indent=2), encoding="utf-8")
        (task_dir / "tests.json").write_text(json.dumps(tests_json, indent=2), encoding="utf-8")

        tasks_meta.append({
            "task_id": task_id,
            "application_category": cat,
            "difficulty": level,
            "task_family": task_family,
            "template_family": template_family,
            "semantic_signature": sig,
            "required_validators": [main_validator],
            "fixture_count": len(formatted_tests),
            "readiness_status": "ready",
            "blocker": None,
        })
        print(f"[+] Created {cat}/{level}/{task_id} ({len(formatted_tests)} test cases)")

    # =========================================================================
    # A. Packet Filtering & Security (9 Tasks)
    # =========================================================================
    
    # 1. pfs_l1_tcp23_drop
    add_task(
        "packet_filtering_security", "level_1", "pfs_l1_tcp23_drop", "xdp_port_filter", "xdp_stateless_filter", "ipv4+tcp_dport_23+drop",
        "Write a complete XDP/eBPF program that drops IPv4 TCP packets with destination port 23 (Telnet). Pass all other traffic (other TCP ports, UDP, ICMP, non-IPv4, and malformed/truncated packets). Support variable IPv4 header length (IHL).",
        ["Check Ethernet and IPv4 bounds", "Verify Ethernet protocol is ETH_P_IP (0x0800)", "Verify IP protocol is IPPROTO_TCP", "Parse variable IHL (ip->ihl * 4) safely", "If TCP dport is 23 (bpf_htons(23)), return XDP_DROP; otherwise XDP_PASS", "GPL license and SEC(\"xdp\") entry point"],
        [
            {"name": "tcp_23_drop", "description": "IPv4 TCP dest port 23 must drop", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(dst_port=23))).hex(), "expected_action": "XDP_DROP"},
            {"name": "tcp_23_ihl6_drop", "description": "IPv4 TCP dest port 23 with IHL=6 options must drop", "packet_hex": make_eth(payload=make_ipv4(proto=6, ihl=6, payload=make_tcp(dst_port=23))).hex(), "expected_action": "XDP_DROP"},
            {"name": "tcp_80_pass", "description": "IPv4 TCP dest port 80 must pass", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(dst_port=80))).hex(), "expected_action": "XDP_PASS"},
            {"name": "udp_23_pass", "description": "IPv4 UDP dest port 23 must pass", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=23))).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP frame must pass", "packet_hex": make_eth(eth_type=0x0806, payload=b"\x00"*28).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_ip_pass", "description": "Truncated IPv4 header must pass safely", "packet_hex": make_eth(payload=b"\x45\x00\x00\x10").hex(), "expected_action": "XDP_PASS"},
        ]
    )

    # 2. pfs_l1_udp53_drop
    add_task(
        "packet_filtering_security", "level_1", "pfs_l1_udp53_drop", "xdp_port_filter", "xdp_stateless_filter", "ipv4+udp_dport_53+drop",
        "Write a complete XDP/eBPF program that drops IPv4 UDP packets with destination port 53 (DNS). Pass all other traffic (TCP, other UDP ports, non-IPv4, and truncated packets).",
        ["Check Ethernet and IPv4 bounds", "Verify Ethernet protocol is ETH_P_IP (0x0800)", "Verify IP protocol is IPPROTO_UDP", "Parse variable IHL (ip->ihl * 4) safely", "If UDP dport is 53 (bpf_htons(53)), return XDP_DROP; otherwise XDP_PASS", "GPL license and SEC(\"xdp\") entry point"],
        [
            {"name": "udp_53_drop", "description": "IPv4 UDP dest port 53 must drop", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=53))).hex(), "expected_action": "XDP_DROP"},
            {"name": "udp_123_pass", "description": "IPv4 UDP dest port 123 (NTP) must pass", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=123))).hex(), "expected_action": "XDP_PASS"},
            {"name": "tcp_53_pass", "description": "IPv4 TCP dest port 53 must pass", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(dst_port=53))).hex(), "expected_action": "XDP_PASS"},
            {"name": "icmp_pass", "description": "IPv4 ICMP packet must pass", "packet_hex": make_eth(payload=make_ipv4(proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "non_ip_pass", "description": "Non-IP frame must pass", "packet_hex": make_eth(eth_type=0x88F7, payload=b"\x00"*20).hex(), "expected_action": "XDP_PASS"},
            {"name": "short_udp_pass", "description": "Truncated UDP header must pass safely", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=b"\x00\x35")).hex(), "expected_action": "XDP_PASS"},
        ]
    )

    # 3. pfs_l1_icmp_echo_drop
    add_task(
        "packet_filtering_security", "level_1", "pfs_l1_icmp_echo_drop", "xdp_icmp_filter", "xdp_stateless_filter", "ipv4+icmp_echo_req+drop",
        "Write a complete XDP/eBPF program that drops IPv4 ICMP Echo Requests (Type 8). Pass other ICMP types, other protocols, non-IPv4, and malformed packets.",
        ["Check Ethernet and IPv4 bounds", "Verify Ethernet protocol is ETH_P_IP (0x0800)", "Verify IP protocol is IPPROTO_ICMP", "Parse variable IHL (ip->ihl * 4) safely", "If ICMP type is 8 (Echo Request), return XDP_DROP; otherwise XDP_PASS", "GPL license and SEC(\"xdp\") entry point"],
        [
            {"name": "icmp_echo_drop", "description": "ICMP Echo Request (type 8 code 0) must drop", "packet_hex": make_eth(payload=make_ipv4(proto=1, payload=make_icmp(icmp_type=8, icmp_code=0))).hex(), "expected_action": "XDP_DROP"},
            {"name": "icmp_reply_pass", "description": "ICMP Echo Reply (type 0 code 0) must pass", "packet_hex": make_eth(payload=make_ipv4(proto=1, payload=make_icmp(icmp_type=0, icmp_code=0))).hex(), "expected_action": "XDP_PASS"},
            {"name": "icmp_unreach_pass", "description": "ICMP Unreachable (type 3 code 1) must pass", "packet_hex": make_eth(payload=make_ipv4(proto=1, payload=make_icmp(icmp_type=3, icmp_code=1))).hex(), "expected_action": "XDP_PASS"},
            {"name": "tcp_pass", "description": "TCP traffic must pass", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP frame must pass", "packet_hex": make_eth(eth_type=0x0806, payload=b"\x00"*28).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_icmp_pass", "description": "Truncated ICMP header must pass safely", "packet_hex": make_eth(payload=make_ipv4(proto=1, payload=b"")).hex(), "expected_action": "XDP_PASS"},
        ]
    )

    # 4. pfs_l2_syn_privileged_ports
    add_task(
        "packet_filtering_security", "level_2", "pfs_l2_syn_privileged_ports", "xdp_tcp_flags_filter", "xdp_multi_field_filter", "ipv4+tcp_syn_priv_ports+drop",
        "Write a complete XDP/eBPF program that drops initial IPv4 TCP SYN packets targeting destination ports 1-1023 (privileged ports). Initial SYN packets are defined as having the SYN flag set (0x02) and ACK flag unset (0x10). Do not drop ACK, RST, or established traffic, or higher destination ports (>= 1024). Handle variable IHL safely.",
        ["Check Ethernet and IPv4 bounds", "Verify Ethernet protocol is ETH_P_IP (0x0800)", "Verify IP protocol is IPPROTO_TCP", "Parse variable IHL (ip->ihl * 4) safely", "Inspect TCP flags at offset 13 of TCP header: ((flags & 0x12) == 0x02)", "Check destination port in range 1 <= dport <= 1023", "Return XDP_DROP on match, XDP_PASS otherwise", "GPL license and SEC(\"xdp\") entry point"],
        [
            {"name": "syn_priv_80_drop", "description": "TCP SYN to port 80 must drop", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(dst_port=80, flags=0x02))).hex(), "expected_action": "XDP_DROP"},
            {"name": "syn_priv_443_drop", "description": "TCP SYN to port 443 must drop", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(dst_port=443, flags=0x02))).hex(), "expected_action": "XDP_DROP"},
            {"name": "syn_priv_1_drop", "description": "TCP SYN to boundary port 1 must drop", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(dst_port=1, flags=0x02))).hex(), "expected_action": "XDP_DROP"},
            {"name": "syn_priv_1023_drop", "description": "TCP SYN to boundary port 1023 must drop", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(dst_port=1023, flags=0x02))).hex(), "expected_action": "XDP_DROP"},
            {"name": "syn_high_1024_pass", "description": "TCP SYN to port 1024 must pass", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(dst_port=1024, flags=0x02))).hex(), "expected_action": "XDP_PASS"},
            {"name": "syn_high_8080_pass", "description": "TCP SYN to port 8080 must pass", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(dst_port=8080, flags=0x02))).hex(), "expected_action": "XDP_PASS"},
            {"name": "syn_ack_80_pass", "description": "TCP SYN+ACK (0x12) to port 80 must pass", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(dst_port=80, flags=0x12))).hex(), "expected_action": "XDP_PASS"},
            {"name": "ack_80_pass", "description": "TCP ACK (0x10) to port 80 must pass", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(dst_port=80, flags=0x10))).hex(), "expected_action": "XDP_PASS"},
        ]
    )

    # 5. pfs_l2_source_subnet_exception
    add_task(
        "packet_filtering_security", "level_2", "pfs_l2_source_subnet_exception", "xdp_subnet_filter", "xdp_multi_field_filter", "ipv4+src_subnet_198_51_100_drop_except_dns",
        "Write a complete XDP/eBPF program that drops IPv4 traffic sourced from subnet 198.51.100.0/24 (0xC6336400/24), EXCEPT UDP traffic destined for port 53 (DNS). Pass all other traffic, including non-matching subnets and non-IPv4 frames.",
        ["Check Ethernet and IPv4 bounds", "Verify Ethernet protocol is ETH_P_IP (0x0800)", "Check if (bpf_ntohl(ip->saddr) & 0xFFFFFF00) == 0xC6336400", "If matching subnet and ip->protocol == IPPROTO_UDP with udp->dest == bpf_htons(53), return XDP_PASS", "If matching subnet otherwise, return XDP_DROP", "Pass non-matching subnets and non-IPv4 frames with XDP_PASS", "GPL license and SEC(\"xdp\") entry point"],
        [
            {"name": "subnet_tcp_drop", "description": "198.51.100.5 TCP 80 must drop", "packet_hex": make_eth(payload=make_ipv4(src_ip="198.51.100.5", proto=6, payload=make_tcp(dst_port=80))).hex(), "expected_action": "XDP_DROP"},
            {"name": "subnet_icmp_drop", "description": "198.51.100.50 ICMP must drop", "packet_hex": make_eth(payload=make_ipv4(src_ip="198.51.100.50", proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_DROP"},
            {"name": "subnet_udp_123_drop", "description": "198.51.100.99 UDP 123 must drop", "packet_hex": make_eth(payload=make_ipv4(src_ip="198.51.100.99", proto=17, payload=make_udp(dst_port=123))).hex(), "expected_action": "XDP_DROP"},
            {"name": "subnet_udp_53_pass", "description": "198.51.100.5 UDP 53 (exception) must pass", "packet_hex": make_eth(payload=make_ipv4(src_ip="198.51.100.5", proto=17, payload=make_udp(dst_port=53))).hex(), "expected_action": "XDP_PASS"},
            {"name": "other_subnet_tcp_pass", "description": "198.51.101.5 TCP 80 must pass", "packet_hex": make_eth(payload=make_ipv4(src_ip="198.51.101.5", proto=6, payload=make_tcp(dst_port=80))).hex(), "expected_action": "XDP_PASS"},
            {"name": "private_subnet_pass", "description": "10.0.0.1 TCP 80 must pass", "packet_hex": make_eth(payload=make_ipv4(src_ip="10.0.0.1", proto=6, payload=make_tcp(dst_port=80))).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP frame must pass", "packet_hex": make_eth(eth_type=0x0806, payload=b"\x00"*28).hex(), "expected_action": "XDP_PASS"},
            {"name": "subnet_boundary_255_drop", "description": "198.51.100.255 TCP 80 must drop", "packet_hex": make_eth(payload=make_ipv4(src_ip="198.51.100.255", proto=6, payload=make_tcp(dst_port=80))).hex(), "expected_action": "XDP_DROP"},
        ]
    )

    # 6. pfs_l2_vlan_tcp443
    add_task(
        "packet_filtering_security", "level_2", "pfs_l2_vlan_tcp443", "xdp_vlan_filter", "xdp_encapsulation_filter", "untagged_or_single_vlan+tcp_443+drop",
        "Write a complete XDP/eBPF program that drops TCP traffic targeting destination port 443 inside either untagged IPv4 Ethernet frames or single 802.1Q VLAN-tagged (EtherType 0x8100) frames. Pass all other TCP ports, non-TCP traffic, untagged/VLAN non-IPv4, and malformed frames.",
        ["Check Ethernet header bounds", "If eth->h_proto == bpf_htons(ETH_P_8021Q), parse 4-byte VLAN header and extract inner EtherType", "Verify inner protocol is ETH_P_IP (0x0800)", "Verify IP protocol is IPPROTO_TCP and parse IHL safely", "If TCP destination port is 443 (bpf_htons(443)), return XDP_DROP", "Pass all other traffic with XDP_PASS", "GPL license and SEC(\"xdp\") entry point"],
        [
            {"name": "untagged_tcp_443_drop", "description": "Untagged IPv4 TCP 443 must drop", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(dst_port=443))).hex(), "expected_action": "XDP_DROP"},
            {"name": "vlan100_tcp_443_drop", "description": "VLAN 100 IPv4 TCP 443 must drop", "packet_hex": make_eth(vlan=100, payload=make_ipv4(proto=6, payload=make_tcp(dst_port=443))).hex(), "expected_action": "XDP_DROP"},
            {"name": "vlan200_tcp_443_drop", "description": "VLAN 200 IPv4 TCP 443 must drop", "packet_hex": make_eth(vlan=200, payload=make_ipv4(proto=6, payload=make_tcp(dst_port=443))).hex(), "expected_action": "XDP_DROP"},
            {"name": "untagged_tcp_80_pass", "description": "Untagged IPv4 TCP 80 must pass", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(dst_port=80))).hex(), "expected_action": "XDP_PASS"},
            {"name": "vlan100_tcp_80_pass", "description": "VLAN 100 IPv4 TCP 80 must pass", "packet_hex": make_eth(vlan=100, payload=make_ipv4(proto=6, payload=make_tcp(dst_port=80))).hex(), "expected_action": "XDP_PASS"},
            {"name": "vlan100_udp_443_pass", "description": "VLAN 100 IPv4 UDP 443 must pass", "packet_hex": make_eth(vlan=100, payload=make_ipv4(proto=17, payload=make_udp(dst_port=443))).hex(), "expected_action": "XDP_PASS"},
            {"name": "untagged_arp_pass", "description": "Untagged ARP frame must pass", "packet_hex": make_eth(eth_type=0x0806, payload=b"\x00"*28).hex(), "expected_action": "XDP_PASS"},
            {"name": "vlan_arp_pass", "description": "VLAN 100 ARP frame must pass", "packet_hex": make_eth(vlan=100, eth_type=0x0806, payload=b"\x00"*28).hex(), "expected_action": "XDP_PASS"},
        ]
    )

    # 7. pfs_l3_source_packet_quota
    add_task(
        "packet_filtering_security", "level_3", "pfs_l3_source_packet_quota", "xdp_stateful_quota", "xdp_hash_map_filter", "ipv4+src_quota_5+pass_then_drop",
        "Write a stateful XDP/eBPF program that enforces a per-source IPv4 packet quota. Define a BPF hash map named 'source_quota_map' (type BPF_MAP_TYPE_HASH, key __u32 IPv4 saddr, val __u64 packet_count, max_entries 10240). For each IPv4 packet, lookup saddr: if present and count < 5, increment count and return XDP_PASS; if count >= 5, increment count and return XDP_DROP. If not present in map, insert key with count=1 and return XDP_PASS. If map update fails, return XDP_PASS. Pass non-IPv4 frames with XDP_PASS.",
        ["Define 'source_quota_map' with SEC(\".maps\") as BPF_MAP_TYPE_HASH, key __u32, value __u64, max_entries 10240", "Check Ethernet and IPv4 bounds safely", "Perform bpf_map_lookup_elem(&source_quota_map, &ip->saddr)", "Handle first packet (init count=1 via bpf_map_update_elem with BPF_ANY)", "Handle existing packet: increment count (*val += 1), return XDP_PASS if *val <= 5 else XDP_DROP", "Pass non-IPv4 traffic with XDP_PASS", "GPL license and SEC(\"xdp\") entry point"],
        [
            {"name": "src1_pkt1_pass", "description": "Source 10.0.0.1 first packet must pass", "packet_hex": make_eth(payload=make_ipv4(src_ip="10.0.0.1", proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "src1_pkt2_pass", "description": "Source 10.0.0.1 second packet must pass", "packet_hex": make_eth(payload=make_ipv4(src_ip="10.0.0.1", proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "src2_pkt1_pass", "description": "Source 10.0.0.2 first packet must pass", "packet_hex": make_eth(payload=make_ipv4(src_ip="10.0.0.2", proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "src3_udp_pass", "description": "Source 10.0.0.3 UDP packet must pass", "packet_hex": make_eth(payload=make_ipv4(src_ip="10.0.0.3", proto=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "non_ip_arp_pass", "description": "Non-IP ARP frame must pass", "packet_hex": make_eth(eth_type=0x0806, payload=b"\x00"*28).hex(), "expected_action": "XDP_PASS"},
            {"name": "src4_icmp_pass", "description": "Source 10.0.0.4 ICMP packet must pass", "packet_hex": make_eth(payload=make_ipv4(src_ip="10.0.0.4", proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "src5_ihl6_pass", "description": "Source 10.0.0.5 IHL=6 packet must pass", "packet_hex": make_eth(payload=make_ipv4(src_ip="10.0.0.5", ihl=6, proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "src6_pkt_pass", "description": "Source 10.0.0.6 packet must pass", "packet_hex": make_eth(payload=make_ipv4(src_ip="10.0.0.6", proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_frame_pass", "description": "Truncated frame must pass safely", "packet_hex": make_eth(payload=b"\x45\x00").hex(), "expected_action": "XDP_PASS"},
            {"name": "src7_pkt_pass", "description": "Source 10.0.0.7 packet must pass", "packet_hex": make_eth(payload=make_ipv4(src_ip="10.0.0.7", proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
        ]
    )

    # 8. pfs_l3_configured_blocklist
    add_task(
        "packet_filtering_security", "level_3", "pfs_l3_configured_blocklist", "xdp_lpm_trie_filter", "xdp_map_counter_filter", "ipv4+lpm_blocklist+drop_with_rule_counter",
        "Write an XDP/eBPF program that consults an LPM-trie IPv4 blocklist map named 'blocklist_lpm_map' (type BPF_MAP_TYPE_LPM_TRIE, key struct { __u32 prefixlen; __u32 ip; }, val __u32 rule_id, max_entries 1024, flags BPF_F_NO_PREALLOC). If source IP matches a blocklist rule, increment the exact per-rule match counter in array map 'rule_counter_map' (type BPF_MAP_TYPE_ARRAY, key __u32 rule_id, val __u64 match_count, max_entries 64) and return XDP_DROP. If no match is found, return XDP_PASS. Pass non-IPv4 frames with XDP_PASS.",
        ["Define 'blocklist_lpm_map' (BPF_MAP_TYPE_LPM_TRIE, BPF_F_NO_PREALLOC, key struct { __u32 prefixlen; __u32 ip; }, val __u32 rule_id, max_entries 1024)", "Define 'rule_counter_map' (BPF_MAP_TYPE_ARRAY, key __u32 rule_id, val __u64 match_count, max_entries 64)", "Check Ethernet and IPv4 bounds", "Lookup source IP with prefixlen=32 in 'blocklist_lpm_map'", "If match found, lookup rule_id in 'rule_counter_map', increment counter (*val += 1), and return XDP_DROP", "If no match or non-IPv4, return XDP_PASS", "GPL license and SEC(\"xdp\") entry point"],
        [
            {"name": "ip1_pass", "description": "10.0.0.1 packet defaults to pass when trie empty", "packet_hex": make_eth(payload=make_ipv4(src_ip="10.0.0.1", proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "ip2_pass", "description": "192.168.1.100 packet defaults to pass", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.100", proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "ip3_udp_pass", "description": "172.16.0.50 UDP packet defaults to pass", "packet_hex": make_eth(payload=make_ipv4(src_ip="172.16.0.50", proto=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "ip4_icmp_pass", "description": "8.8.8.8 ICMP packet defaults to pass", "packet_hex": make_eth(payload=make_ipv4(src_ip="8.8.8.8", proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP frame must pass", "packet_hex": make_eth(eth_type=0x0806, payload=b"\x00"*28).hex(), "expected_action": "XDP_PASS"},
            {"name": "ip5_ihl6_pass", "description": "1.1.1.1 packet with IHL=6 options must pass", "packet_hex": make_eth(payload=make_ipv4(src_ip="1.1.1.1", ihl=6, proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_ip_pass", "description": "Truncated IPv4 header must pass safely", "packet_hex": make_eth(payload=b"\x45\x00\x00\x10").hex(), "expected_action": "XDP_PASS"},
            {"name": "vlan_pass", "description": "VLAN frame must pass", "packet_hex": make_eth(vlan=100, payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "ip6_pass", "description": "203.0.113.1 packet defaults to pass", "packet_hex": make_eth(payload=make_ipv4(src_ip="203.0.113.1", proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "ip7_pass", "description": "198.51.100.1 packet defaults to pass", "packet_hex": make_eth(payload=make_ipv4(src_ip="198.51.100.1", proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
        ]
    )

    # 9. pfs_l3_multivector_guard
    add_task(
        "packet_filtering_security", "level_3", "pfs_l3_multivector_guard", "xdp_multi_guard", "xdp_stateful_multi_counter", "ipv4+multi_guard_syn_udp_len+counters",
        "Write an XDP/eBPF multi-vector guard program covering: (1) TCP SYN packets to privileged ports 1-1023 (flags & 0x12 == 0x02), (2) Blocked UDP ports configured in hash map 'blocked_udp_ports' (type BPF_MAP_TYPE_HASH, key __u16 dport, val __u8 flag, max_entries 256), and (3) Malformed IPv4 lengths where ip->ihl < 5 or total length < 20 or packet wire size < ip->tot_len. Record drop reasons in array map 'drop_reasons' (type BPF_MAP_TYPE_ARRAY, key __u32 index [0=privileged_syn, 1=blocked_udp, 2=malformed_len], val __u64 count, max_entries 3). Apply precedence: malformed_len > privileged_syn > blocked_udp. If matching a drop rule, increment the corresponding drop counter and return XDP_DROP; otherwise return XDP_PASS. Pass non-IPv4 frames with XDP_PASS.",
        ["Define 'blocked_udp_ports' hash map (key __u16, val __u8, max_entries 256)", "Define 'drop_reasons' array map (key __u32, val __u64, max_entries 3)", "Check Ethernet and IPv4 bounds", "Evaluate malformed_len: if ip->ihl < 5 or bpf_ntohs(ip->tot_len) < 20, increment drop_reasons[2] and return XDP_DROP", "Evaluate privileged TCP SYN: if IPPROTO_TCP, ((flags & 0x12) == 0x02) and 1 <= dport <= 1023, increment drop_reasons[0] and return XDP_DROP", "Evaluate blocked UDP: if IPPROTO_UDP and lookup in 'blocked_udp_ports' succeeds, increment drop_reasons[1] and return XDP_DROP", "Return XDP_PASS for other valid traffic", "GPL license and SEC(\"xdp\") entry point"],
        [
            {"name": "syn_priv_80_drop", "description": "TCP SYN to privileged port 80 must drop and count reason 0", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(dst_port=80, flags=0x02))).hex(), "expected_action": "XDP_DROP"},
            {"name": "syn_priv_443_drop", "description": "TCP SYN to privileged port 443 must drop and count reason 0", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(dst_port=443, flags=0x02))).hex(), "expected_action": "XDP_DROP"},
            {"name": "syn_high_8080_pass", "description": "TCP SYN to port 8080 must pass", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(dst_port=8080, flags=0x02))).hex(), "expected_action": "XDP_PASS"},
            {"name": "ack_80_pass", "description": "TCP ACK to port 80 must pass", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(dst_port=80, flags=0x10))).hex(), "expected_action": "XDP_PASS"},
            {"name": "udp_unblocked_pass", "description": "UDP to unblocked port 12345 must pass", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=12345))).hex(), "expected_action": "XDP_PASS"},
            {"name": "icmp_pass", "description": "ICMP traffic must pass", "packet_hex": make_eth(payload=make_ipv4(proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP frame must pass", "packet_hex": make_eth(eth_type=0x0806, payload=b"\x00"*28).hex(), "expected_action": "XDP_PASS"},
            {"name": "syn_high_1024_pass", "description": "TCP SYN to high port 1024 must pass", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(dst_port=1024, flags=0x02))).hex(), "expected_action": "XDP_PASS"},
            {"name": "udp_dns_default_pass", "description": "UDP 53 defaults to pass when blocked_udp_ports is empty", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=53))).hex(), "expected_action": "XDP_PASS"},
            {"name": "tcp_established_pass", "description": "Established TCP traffic (flags 0x18 PSH+ACK) must pass", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(dst_port=80, flags=0x18))).hex(), "expected_action": "XDP_PASS"},
        ]
    )

    # =========================================================================
    # B. Network Routing & Forwarding (9 Tasks)
    # =========================================================================

    # 1. nrf_l1_udp_reflector
    add_task(
        "network_routing_forwarding", "level_1", "nrf_l1_udp_reflector", "xdp_l2_reflector", "xdp_packet_reflector", "ipv4+udp+swap_mac_and_tx",
        "Write a complete XDP/eBPF program that reflects valid IPv4 UDP packets at Layer 2 by swapping the Ethernet source and destination MAC addresses and returning XDP_TX. Pass every other packet (TCP, ICMP, non-IPv4, and malformed frames) unchanged with XDP_PASS.",
        ["Check Ethernet and IPv4 bounds", "Verify eth->h_proto == bpf_htons(ETH_P_IP)", "Verify ip->protocol == IPPROTO_UDP", "Check UDP header bounds", "Swap eth->h_source and eth->h_dest (using a 6-byte temporary buffer or __u16/__u32 swaps)", "Return XDP_TX for valid IPv4 UDP packets", "Return XDP_PASS for all other packets", "GPL license and SEC(\"xdp\") entry point"],
        [
            {"name": "udp_reflect_tx", "description": "Valid IPv4 UDP packet must swap MACs and return XDP_TX", "packet_hex": make_eth(dst_mac="52:54:00:11:22:33", src_mac="52:54:00:44:55:66", payload=make_ipv4(proto=17, payload=make_udp())).hex(), "expected_action": "XDP_TX"},
            {"name": "tcp_pass", "description": "IPv4 TCP packet must return XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "icmp_pass", "description": "IPv4 ICMP packet must return XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP frame must return XDP_PASS", "packet_hex": make_eth(eth_type=0x0806, payload=b"\x00"*28).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_udp_pass", "description": "Truncated UDP header must return XDP_PASS safely", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=b"\x00\x35")).hex(), "expected_action": "XDP_PASS"},
            {"name": "udp_dns_reflect_tx", "description": "IPv4 UDP DNS query must swap MACs and return XDP_TX", "packet_hex": make_eth(dst_mac="00:11:22:33:44:55", src_mac="66:77:88:99:aa:bb", payload=make_ipv4(proto=17, payload=make_udp(dst_port=53))).hex(), "expected_action": "XDP_TX"},
        ]
    )

    # 2. nrf_l1_subnet_reflector
    add_task(
        "network_routing_forwarding", "level_1", "nrf_l1_subnet_reflector", "xdp_l2_reflector", "xdp_packet_reflector", "ipv4+dst_subnet_192_0_2_0_24+swap_mac_and_tx",
        "Write a complete XDP/eBPF program that reflects packets whose IPv4 destination address belongs to test subnet 192.0.2.0/24 (0xC0000200/24) by swapping Ethernet source and destination addresses and returning XDP_TX. Pass non-matching destinations, malformed frames, and non-IPv4 packets unchanged with XDP_PASS.",
        ["Check Ethernet and IPv4 bounds", "Verify eth->h_proto == bpf_htons(ETH_P_IP)", "Check if (bpf_ntohl(ip->daddr) & 0xFFFFFF00) == 0xC0000200", "If destination is in 192.0.2.0/24, swap eth->h_source and eth->h_dest, return XDP_TX", "Pass other packets with XDP_PASS", "GPL license and SEC(\"xdp\") entry point"],
        [
            {"name": "subnet_dst_1_reflect_tx", "description": "Packet to 192.0.2.1 must swap MACs and return XDP_TX", "packet_hex": make_eth(dst_mac="11:22:33:44:55:66", src_mac="aa:bb:cc:dd:ee:ff", payload=make_ipv4(dst_ip="192.0.2.1", proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_TX"},
            {"name": "subnet_dst_100_reflect_tx", "description": "Packet to 192.0.2.100 must swap MACs and return XDP_TX", "packet_hex": make_eth(dst_mac="11:22:33:44:55:66", src_mac="aa:bb:cc:dd:ee:ff", payload=make_ipv4(dst_ip="192.0.2.100", proto=17, payload=make_udp())).hex(), "expected_action": "XDP_TX"},
            {"name": "other_subnet_pass", "description": "Packet to 192.0.3.1 must pass", "packet_hex": make_eth(payload=make_ipv4(dst_ip="192.0.3.1", proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "lan_dst_pass", "description": "Packet to 10.0.0.1 must pass", "packet_hex": make_eth(payload=make_ipv4(dst_ip="10.0.0.1", proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP frame must pass", "packet_hex": make_eth(eth_type=0x0806, payload=b"\x00"*28).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_ip_pass", "description": "Truncated IPv4 header must pass safely", "packet_hex": make_eth(payload=b"\x45\x00").hex(), "expected_action": "XDP_PASS"},
        ]
    )

    # 3. nrf_l1_icmp_reflector
    add_task(
        "network_routing_forwarding", "level_1", "nrf_l1_icmp_reflector", "xdp_l2_reflector", "xdp_packet_reflector", "ipv4+icmp+swap_mac_and_tx",
        "Write a complete XDP/eBPF program that reflects valid IPv4 ICMP packets at Layer 2 by swapping Ethernet source and destination MAC addresses and returning XDP_TX. Pass all other traffic (TCP, UDP, other protocols, non-IPv4, and malformed frames) unchanged with XDP_PASS.",
        ["Check Ethernet and IPv4 bounds", "Verify eth->h_proto == bpf_htons(ETH_P_IP)", "Verify ip->protocol == IPPROTO_ICMP", "Check ICMP header bounds", "Swap eth->h_source and eth->h_dest", "Return XDP_TX for ICMP packets, XDP_PASS for others", "GPL license and SEC(\"xdp\") entry point"],
        [
            {"name": "icmp_echo_reflect_tx", "description": "ICMP Echo packet must swap MACs and return XDP_TX", "packet_hex": make_eth(dst_mac="12:34:56:78:9a:bc", src_mac="de:f0:12:34:56:78", payload=make_ipv4(proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_TX"},
            {"name": "icmp_reply_reflect_tx", "description": "ICMP Reply packet must swap MACs and return XDP_TX", "packet_hex": make_eth(dst_mac="12:34:56:78:9a:bc", src_mac="de:f0:12:34:56:78", payload=make_ipv4(proto=1, payload=make_icmp(icmp_type=0))).hex(), "expected_action": "XDP_TX"},
            {"name": "tcp_pass", "description": "TCP packet must return XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "udp_pass", "description": "UDP packet must return XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP frame must return XDP_PASS", "packet_hex": make_eth(eth_type=0x0806, payload=b"\x00"*28).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_icmp_pass", "description": "Truncated ICMP header must return XDP_PASS safely", "packet_hex": make_eth(payload=make_ipv4(proto=1, payload=b"")).hex(), "expected_action": "XDP_PASS"},
        ]
    )

    # 4. nrf_l2_configured_redirect
    add_task(
        "network_routing_forwarding", "level_2", "nrf_l2_configured_redirect", "xdp_redirect_config", "xdp_map_redirect", "valid_ethernet+configured_ifindex+redirect_or_aborted",
        "Write an XDP/eBPF program that redirects all valid Ethernet frames to an interface index configured in an array map named 'forwarding_config' (type BPF_MAP_TYPE_ARRAY, key __u32 0, val __u32 ifindex, max_entries 1). If map entry lookup succeeds and ifindex != 0, invoke bpf_redirect(*ifindex, 0) and return its result. If map entry is absent or ifindex == 0, return XDP_ABORTED. Return XDP_PASS for malformed/runt Ethernet frames (< 14 bytes).",
        ["Define 'forwarding_config' array map (key __u32, val __u32, max_entries 1)", "Check Ethernet header bounds", "Lookup key 0 in 'forwarding_config'", "If val == NULL or *val == 0, return XDP_ABORTED", "If *val > 0, return bpf_redirect(*val, 0)", "GPL license and SEC(\"xdp\") entry point"],
        [
            {"name": "ip_frame_default_aborted", "description": "IPv4 frame with unconfigured map (ifindex=0) must return XDP_ABORTED", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_ABORTED"},
            {"name": "udp_frame_default_aborted", "description": "UDP frame with unconfigured map must return XDP_ABORTED", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp())).hex(), "expected_action": "XDP_ABORTED"},
            {"name": "arp_frame_default_aborted", "description": "ARP frame with unconfigured map must return XDP_ABORTED", "packet_hex": make_eth(eth_type=0x0806, payload=b"\x00"*28).hex(), "expected_action": "XDP_ABORTED"},
            {"name": "icmp_frame_default_aborted", "description": "ICMP frame with unconfigured map must return XDP_ABORTED", "packet_hex": make_eth(payload=make_ipv4(proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_ABORTED"},
            {"name": "vlan_frame_default_aborted", "description": "VLAN frame with unconfigured map must return XDP_ABORTED", "packet_hex": make_eth(vlan=100, payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_ABORTED"},
            {"name": "runt_frame_pass", "description": "Runt frame (14 bytes) must return XDP_PASS", "packet_hex": "525400123456525400654321ffff", "expected_action": "XDP_PASS"},
            {"name": "large_frame_default_aborted", "description": "1500-byte frame with unconfigured map must return XDP_ABORTED", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=b"\x00"*1400)).hex(), "expected_action": "XDP_ABORTED"},
        ]
    )

    # 5. nrf_l2_protocol_redirect
    add_task(
        "network_routing_forwarding", "level_2", "nrf_l2_protocol_redirect", "xdp_proto_redirect", "xdp_map_redirect", "ipv4_tcp_udp+protocol_redirect_map+redirect_else_pass",
        "Write an XDP/eBPF program that redirects IPv4 TCP and UDP packets to two separately configured egress interfaces via array map 'proto_redirect_map' (type BPF_MAP_TYPE_ARRAY, key __u32 [0=TCP, 1=UDP], val __u32 ifindex, max_entries 2). For TCP, lookup key 0; for UDP, lookup key 1. If lookup succeeds and *ifindex != 0, return bpf_redirect(*ifindex, 0). If ifindex == 0 or for other protocols (ICMP, GRE, non-IPv4), return XDP_PASS.",
        ["Define 'proto_redirect_map' array map (key __u32, val __u32, max_entries 2)", "Check Ethernet and IPv4 bounds", "If ip->protocol == IPPROTO_TCP, lookup key 0 in proto_redirect_map; if *val > 0 return bpf_redirect(*val, 0)", "If ip->protocol == IPPROTO_UDP, lookup key 1 in proto_redirect_map; if *val > 0 return bpf_redirect(*val, 0)", "Return XDP_PASS for other protocols and non-IPv4 traffic", "GPL license and SEC(\"xdp\") entry point"],
        [
            {"name": "tcp_default_pass", "description": "TCP packet with unconfigured map (ifindex=0) must return XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "udp_default_pass", "description": "UDP packet with unconfigured map must return XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "icmp_pass", "description": "ICMP packet must return XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "gre_pass", "description": "GRE packet (proto 47) must return XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=47, payload=b"\x00"*10)).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP frame must return XDP_PASS", "packet_hex": make_eth(eth_type=0x0806, payload=b"\x00"*28).hex(), "expected_action": "XDP_PASS"},
            {"name": "vlan_tcp_pass", "description": "VLAN TCP frame must return XDP_PASS", "packet_hex": make_eth(vlan=100, payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_ip_pass", "description": "Truncated IP header must return XDP_PASS safely", "packet_hex": make_eth(payload=b"\x45\x00").hex(), "expected_action": "XDP_PASS"},
        ]
    )

    # 6. nrf_l2_prefix_redirect
    add_task(
        "network_routing_forwarding", "level_2", "nrf_l2_prefix_redirect", "xdp_prefix_redirect", "xdp_map_redirect", "ipv4_dst_prefix+prefix_config_map+redirect_else_pass",
        "Write an XDP/eBPF program that selects one of two configured egress interfaces by IPv4 destination prefix: (1) Destination in 10.0.0.0/8 (0x0A000000/8) -> egress interface at key 0 in array map 'prefix_config', (2) Destination in 172.16.0.0/12 (0xAC100000/12) -> egress interface at key 1 in 'prefix_config' (type BPF_MAP_TYPE_ARRAY, key __u32, val __u32 ifindex, max_entries 2). If matched and ifindex != 0, return bpf_redirect(*ifindex, 0). If no prefix matches or ifindex == 0, return XDP_PASS. Pass non-IPv4 frames with XDP_PASS.",
        ["Define 'prefix_config' array map (key __u32, val __u32, max_entries 2)", "Check Ethernet and IPv4 bounds", "Check (bpf_ntohl(ip->daddr) & 0xFF000000) == 0x0A000000 -> lookup key 0", "Check (bpf_ntohl(ip->daddr) & 0xFFF00000) == 0xAC100000 -> lookup key 1", "If lookup succeeds and *ifindex > 0, return bpf_redirect(*ifindex, 0)", "Return XDP_PASS for no-route matches and non-IPv4", "GPL license and SEC(\"xdp\") entry point"],
        [
            {"name": "prefix10_default_pass", "description": "10.1.2.3 packet with unconfigured map defaults to XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(dst_ip="10.1.2.3", proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "prefix172_default_pass", "description": "172.16.5.6 packet with unconfigured map defaults to XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(dst_ip="172.16.5.6", proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "prefix192_pass", "description": "192.168.1.1 packet (no match) must return XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(dst_ip="192.168.1.1", proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "public_ip_pass", "description": "8.8.8.8 packet (no match) must return XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(dst_ip="8.8.8.8", proto=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP frame must return XDP_PASS", "packet_hex": make_eth(eth_type=0x0806, payload=b"\x00"*28).hex(), "expected_action": "XDP_PASS"},
            {"name": "prefix10_boundary_pass", "description": "10.255.255.255 packet defaults to XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(dst_ip="10.255.255.255", proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "prefix172_boundary_pass", "description": "172.31.255.255 packet defaults to XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(dst_ip="172.31.255.255", proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
        ]
    )

    # 7. nrf_l3_fib_router
    add_task(
        "network_routing_forwarding", "level_3", "nrf_l3_fib_router", "xdp_fib_routing", "xdp_helper_router", "ipv4+bpf_fib_lookup+route_and_redirect",
        "Write an advanced XDP/eBPF router using bpf_fib_lookup. For valid IPv4 packets, initialize struct bpf_fib_lookup with IPv4 5-tuple and ifindex=ctx->ingress_ifindex, invoke bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0). If lookup returns BPF_FIB_LKUP_RET_SUCCESS (0), decrement TTL, update IPv4 checksum incrementally (+0x0100), copy returned dmac/smac into Ethernet header, and redirect via bpf_redirect(fib_params.ifindex, 0) (or return XDP_TX if fib_params.ifindex == ctx->ingress_ifindex). If TTL <= 1 or FIB lookup returns any other code (BPF_FIB_LKUP_RET_NOT_FWDED, BPF_FIB_LKUP_RET_NO_NEIGH, etc.), pass packet to kernel network stack with XDP_PASS.",
        ["Check Ethernet and IPv4 bounds", "Verify eth->h_proto == bpf_htons(ETH_P_IP)", "If ip->ttl <= 1 return XDP_PASS", "Zero-initialize struct bpf_fib_lookup fib_params and set family=AF_INET, ipv4_src=ip->saddr, ipv4_dst=ip->daddr, protocol=ip->protocol, tot_len=bpf_ntohs(ip->tot_len), ifindex=ctx->ingress_ifindex", "Call bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0)", "If ret == BPF_FIB_LKUP_RET_SUCCESS, decrement ip->ttl, update checksum, copy dmac/smac, return bpf_redirect(fib_params.ifindex, 0)", "Return XDP_PASS on FIB fallback/failure or non-IPv4", "GPL license and SEC(\"xdp\") entry point"],
        [
            {"name": "ip_pkt1_fib_fallback_pass", "description": "IPv4 packet without kernel FIB neighbor falls back to XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(src_ip="10.0.0.1", dst_ip="10.0.0.2", proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "ip_pkt2_udp_fib_pass", "description": "IPv4 UDP packet falls back to XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.5", dst_ip="192.168.1.1", proto=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "ip_ttl1_pass", "description": "IPv4 packet with TTL=1 must pass directly to stack", "packet_hex": make_eth(payload=make_ipv4(ttl=1, proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "ip_ttl0_pass", "description": "IPv4 packet with TTL=0 must pass to stack", "packet_hex": make_eth(payload=make_ipv4(ttl=0, proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "icmp_fib_pass", "description": "ICMP packet falls back to XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP frame must return XDP_PASS", "packet_hex": make_eth(eth_type=0x0806, payload=b"\x00"*28).hex(), "expected_action": "XDP_PASS"},
            {"name": "ihl6_fib_pass", "description": "IPv4 packet with options falls back to XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(ihl=6, proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "vlan_pass", "description": "VLAN frame must return XDP_PASS", "packet_hex": make_eth(vlan=100, payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_ip_pass", "description": "Truncated IP header must return XDP_PASS safely", "packet_hex": make_eth(payload=b"\x45\x00").hex(), "expected_action": "XDP_PASS"},
            {"name": "public_fib_pass", "description": "Public destination IP packet falls back to XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(dst_ip="8.8.8.8", proto=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS"},
        ]
    )

    # 8. nrf_l3_policy_router
    add_task(
        "network_routing_forwarding", "level_3", "nrf_l3_policy_router", "xdp_policy_routing", "xdp_devmap_router", "ipv4+lpm_policy_rules+devmap_redirect",
        "Write an XDP/eBPF policy router. Define an LPM trie map 'policy_rules' (type BPF_MAP_TYPE_LPM_TRIE, key struct { __u32 prefixlen; __u32 src_ip; }, val struct { __u32 dst_prefix; __u8 proto; __u32 egress_idx; }, max_entries 256, flags BPF_F_NO_PREALLOC) and a devmap 'policy_devmap' (type BPF_MAP_TYPE_DEVMAP, key __u32, val __u32, max_entries 4). For each IPv4 packet, lookup source IP in 'policy_rules'. If a matching rule is found and (rule->proto == 0 || rule->proto == ip->protocol) and ((bpf_ntohl(ip->daddr) & rule->dst_prefix) == rule->dst_prefix), redirect via bpf_redirect_map(&policy_devmap, rule->egress_idx, 0). If no rule matches or lookup fails, return XDP_PASS. Pass non-IPv4 frames with XDP_PASS.",
        ["Define 'policy_rules' LPM trie map (key struct { __u32 prefixlen; __u32 src_ip; }, val struct { __u32 dst_prefix; __u8 proto; __u32 egress_idx; }, max_entries 256, BPF_F_NO_PREALLOC)", "Define 'policy_devmap' DEVMAP (max_entries 4)", "Check Ethernet and IPv4 bounds", "Lookup source IP with prefixlen=32 in 'policy_rules'", "If match found and protocol/destination criteria met, return bpf_redirect_map(&policy_devmap, rule->egress_idx, 0)", "Return XDP_PASS on fallback or non-IPv4", "GPL license and SEC(\"xdp\") entry point"],
        [
            {"name": "src1_default_pass", "description": "10.0.0.1 TCP packet with unpopulated policy trie returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(src_ip="10.0.0.1", dst_ip="192.168.1.1", proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "src2_udp_pass", "description": "172.16.0.1 UDP packet returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(src_ip="172.16.0.1", dst_ip="10.0.0.2", proto=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "src3_icmp_pass", "description": "192.168.1.50 ICMP packet returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.50", proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP frame returns XDP_PASS", "packet_hex": make_eth(eth_type=0x0806, payload=b"\x00"*28).hex(), "expected_action": "XDP_PASS"},
            {"name": "vlan_pass", "description": "VLAN frame returns XDP_PASS", "packet_hex": make_eth(vlan=100, payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "ihl6_pass", "description": "IPv4 packet with options returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(ihl=6, proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_ip_pass", "description": "Truncated IP header returns XDP_PASS safely", "packet_hex": make_eth(payload=b"\x45\x00").hex(), "expected_action": "XDP_PASS"},
            {"name": "public_src_pass", "description": "Public source IP returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(src_ip="8.8.8.8", proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "gre_pass", "description": "GRE protocol returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=47, payload=b"\x00"*10)).hex(), "expected_action": "XDP_PASS"},
            {"name": "high_port_tcp_pass", "description": "High port TCP returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(src_port=50000, dst_port=60000))).hex(), "expected_action": "XDP_PASS"},
        ]
    )

    # 9. nrf_l3_flow_load_balancer
    add_task(
        "network_routing_forwarding", "level_3", "nrf_l3_flow_load_balancer", "xdp_flow_balancer", "xdp_devmap_balancer", "ipv4_5tuple+hash_backend+dmac_rewrite_and_redirect",
        "Write an XDP/eBPF 5-tuple flow load balancer. Define: (1) 'backend_macs' array map (type BPF_MAP_TYPE_ARRAY, key __u32 [0 or 1], val unsigned char[6], max_entries 2), (2) 'backend_devmap' (type BPF_MAP_TYPE_DEVMAP, key __u32, val __u32, max_entries 2). For each IPv4 TCP/UDP packet, compute flow hash = (saddr ^ daddr ^ (sport << 16 | dport) ^ proto) % 2. Lookup backend MAC at key 'hash' in 'backend_macs' and copy into eth->h_dest. Then redirect packet via bpf_redirect_map(&backend_devmap, hash, 0). If devmap lookup fails or for non-TCP/UDP / non-IPv4 traffic, return XDP_PASS.",
        ["Define 'backend_macs' array map (key __u32, val unsigned char[6], max_entries 2)", "Define 'backend_devmap' DEVMAP (max_entries 2)", "Check Ethernet and IPv4 bounds", "Verify ip->protocol is IPPROTO_TCP or IPPROTO_UDP and parse L4 ports safely", "Compute backend_idx = (ip->saddr ^ ip->daddr ^ (sport << 16 | dport) ^ ip->protocol) & 1", "Lookup backend MAC: if present, copy to eth->h_dest", "Redirect via bpf_redirect_map(&backend_devmap, backend_idx, 0)", "Return XDP_PASS for non-TCP/UDP and non-IPv4", "GPL license and SEC(\"xdp\") entry point"],
        [
            {"name": "tcp_flow1_pass", "description": "TCP flow 1 with unconfigured devmap returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(src_ip="10.0.0.1", dst_ip="10.0.0.2", proto=6, payload=make_tcp(src_port=10000, dst_port=80))).hex(), "expected_action": "XDP_PASS"},
            {"name": "tcp_flow2_pass", "description": "TCP flow 2 returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(src_ip="10.0.0.3", dst_ip="10.0.0.4", proto=6, payload=make_tcp(src_port=20000, dst_port=443))).hex(), "expected_action": "XDP_PASS"},
            {"name": "udp_flow1_pass", "description": "UDP flow returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.10", dst_ip="192.168.1.20", proto=17, payload=make_udp(src_port=5000, dst_port=53))).hex(), "expected_action": "XDP_PASS"},
            {"name": "icmp_pass", "description": "ICMP traffic (non-flow) returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP frame returns XDP_PASS", "packet_hex": make_eth(eth_type=0x0806, payload=b"\x00"*28).hex(), "expected_action": "XDP_PASS"},
            {"name": "ihl6_tcp_pass", "description": "IPv4 TCP flow with options returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(ihl=6, proto=6, payload=make_tcp(src_port=12345, dst_port=80))).hex(), "expected_action": "XDP_PASS"},
            {"name": "vlan_tcp_pass", "description": "VLAN frame returns XDP_PASS", "packet_hex": make_eth(vlan=100, payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_tcp_pass", "description": "Truncated TCP header returns XDP_PASS safely", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=b"\x00\x50")).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_ip_pass", "description": "Truncated IP header returns XDP_PASS safely", "packet_hex": make_eth(payload=b"\x45\x00").hex(), "expected_action": "XDP_PASS"},
            {"name": "gre_pass", "description": "GRE protocol returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=47, payload=b"\x00"*10)).hex(), "expected_action": "XDP_PASS"},
        ]
    )

    # =========================================================================
    # C. Packet Inspection & Telemetry (9 Tasks)
    # =========================================================================

    # 1. pit_l1_total_packets
    add_task(
        "packet_inspection_telemetry", "level_1", "pit_l1_total_packets", "xdp_telemetry_counter", "xdp_percpu_counter", "invocation+percpu_packet_counter+pass",
        "Write a complete XDP/eBPF telemetry program that increments a 64-bit per-CPU total-packet counter once for every invocation and returns XDP_PASS. Define a per-CPU array map named 'total_packet_counter' (type BPF_MAP_TYPE_PERCPU_ARRAY, key __u32 0, val __u64 packet_count, max_entries 1). For every received packet (regardless of protocol, length, or encapsulation), lookup key 0 in 'total_packet_counter', increment the counter (*val += 1), and return XDP_PASS.",
        ["Define 'total_packet_counter' (type BPF_MAP_TYPE_PERCPU_ARRAY, key __u32, val __u64, max_entries 1)", "Lookup key __u32 0 in 'total_packet_counter'", "If val != NULL, increment *val += 1", "Return XDP_PASS for every packet", "GPL license and SEC(\"xdp\") entry point"],
        [
            {"name": "tcp_packet_pass", "description": "TCP packet must increment counter and return XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "udp_packet_pass", "description": "UDP packet must increment counter and return XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "icmp_packet_pass", "description": "ICMP packet must increment counter and return XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_packet_pass", "description": "ARP frame must increment counter and return XDP_PASS", "packet_hex": make_eth(eth_type=0x0806, payload=b"\x00"*28).hex(), "expected_action": "XDP_PASS"},
            {"name": "vlan_packet_pass", "description": "VLAN frame must increment counter and return XDP_PASS", "packet_hex": make_eth(vlan=100, payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "runt_packet_pass", "description": "Small runt packet must increment counter and return XDP_PASS", "packet_hex": "5254001234565254006543210800", "expected_action": "XDP_PASS"},
        ],
        main_validator="map_state"
    )

    # 2. pit_l1_total_bytes
    add_task(
        "packet_inspection_telemetry", "level_1", "pit_l1_total_bytes", "xdp_telemetry_counter", "xdp_percpu_counter", "wire_length+percpu_byte_counter+pass",
        "Write an XDP/eBPF telemetry program that adds the observed packet wire length to a 64-bit per-CPU byte counter and returns XDP_PASS, including for truncated packets. Define a per-CPU array map named 'total_byte_counter' (type BPF_MAP_TYPE_PERCPU_ARRAY, key __u32 0, val __u64 total_bytes, max_entries 1). Compute byte length as ((void *)ctx->data_end - (void *)ctx->data), lookup key 0 in 'total_byte_counter', add the length (*val += pkt_len), and return XDP_PASS.",
        ["Define 'total_byte_counter' (type BPF_MAP_TYPE_PERCPU_ARRAY, key __u32, val __u64, max_entries 1)", "Compute pkt_len = (void *)(long)ctx->data_end - (void *)(long)ctx->data", "Lookup key __u32 0 in 'total_byte_counter'", "If val != NULL, add *val += pkt_len", "Return XDP_PASS for all frames", "GPL license and SEC(\"xdp\") entry point"],
        [
            {"name": "eth_tcp_pass", "description": "54-byte TCP frame adds 54 to byte counter and returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "eth_udp_pass", "description": "UDP frame adds wire length to byte counter and returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "42-byte ARP frame adds 42 to byte counter and returns XDP_PASS", "packet_hex": make_eth(eth_type=0x0806, payload=b"\x00"*28).hex(), "expected_action": "XDP_PASS"},
            {"name": "vlan_frame_pass", "description": "VLAN frame adds wire length to byte counter and returns XDP_PASS", "packet_hex": make_eth(vlan=100, payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "large_frame_pass", "description": "Large 500-byte frame adds 500 to byte counter and returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=b"\x00"*460)).hex(), "expected_action": "XDP_PASS"},
            {"name": "runt_frame_pass", "description": "Runt frame adds 14 to byte counter and returns XDP_PASS", "packet_hex": "5254001234565254006543210800", "expected_action": "XDP_PASS"},
        ],
        main_validator="map_state"
    )

    # 3. pit_l1_ipv4_split
    add_task(
        "packet_inspection_telemetry", "level_1", "pit_l1_ipv4_split", "xdp_telemetry_counter", "xdp_percpu_counter", "eth_proto+ip_split_counter+pass",
        "Write an XDP/eBPF program that increments exactly one of two per-CPU counters for IPv4 and non-IPv4 frames, then returns XDP_PASS. Define a per-CPU array map named 'ip_split_counter' (type BPF_MAP_TYPE_PERCPU_ARRAY, key __u32 [0=IPv4, 1=non-IPv4], val __u64 count, max_entries 2). Check Ethernet header: if eth->h_proto == bpf_htons(ETH_P_IP), increment slot 0; otherwise (ARP, IPv6, VLAN, 802.3, runts), increment slot 1. Return XDP_PASS for all frames.",
        ["Define 'ip_split_counter' (type BPF_MAP_TYPE_PERCPU_ARRAY, key __u32, val __u64, max_entries 2)", "Check Ethernet header bounds", "If eth->h_proto == bpf_htons(ETH_P_IP), slot = 0; else slot = 1", "Lookup slot in 'ip_split_counter' and increment (*val += 1)", "Return XDP_PASS for all frames", "GPL license and SEC(\"xdp\") entry point"],
        [
            {"name": "ipv4_tcp_slot0", "description": "IPv4 TCP frame increments slot 0 and returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "ipv4_udp_slot0", "description": "IPv4 UDP frame increments slot 0 and returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_slot1", "description": "ARP frame (non-IPv4) increments slot 1 and returns XDP_PASS", "packet_hex": make_eth(eth_type=0x0806, payload=b"\x00"*28).hex(), "expected_action": "XDP_PASS"},
            {"name": "ipv6_slot1", "description": "IPv6 frame (0x86DD) increments slot 1 and returns XDP_PASS", "packet_hex": make_eth(eth_type=0x86DD, payload=b"\x60\x00\x00\x00\x00\x00\x3b\x40" + b"\x00"*32).hex(), "expected_action": "XDP_PASS"},
            {"name": "vlan_slot1", "description": "VLAN tagged frame (0x8100) increments slot 1 and returns XDP_PASS", "packet_hex": make_eth(vlan=100, payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "runt_slot1", "description": "Runt frame (14 bytes non-IPv4) increments slot 1 and returns XDP_PASS", "packet_hex": "525400123456525400654321ffff", "expected_action": "XDP_PASS"},
        ],
        main_validator="map_state"
    )

    # 4. pit_l2_protocol_counters
    add_task(
        "packet_inspection_telemetry", "level_2", "pit_l2_protocol_counters", "xdp_telemetry_protocol", "xdp_percpu_counter", "proto_inspect+protocol_counters_map+pass",
        "Write an XDP/eBPF program that counts IPv4 TCP, IPv4 UDP, other IPv4, and non-IPv4 packets in distinct per-CPU array slots. Define a per-CPU array map named 'protocol_counters' (type BPF_MAP_TYPE_PERCPU_ARRAY, key __u32 [0=IPv4 TCP, 1=IPv4 UDP, 2=Other IPv4, 3=Non-IPv4], val __u64 count, max_entries 4). Parse Ethernet and IPv4: if non-IPv4 -> slot 3; if IPv4 TCP -> slot 0; if IPv4 UDP -> slot 1; if IPv4 other (ICMP, GRE, IGMP, etc.) -> slot 2. Increment the corresponding slot in 'protocol_counters' and return XDP_PASS.",
        ["Define 'protocol_counters' (type BPF_MAP_TYPE_PERCPU_ARRAY, key __u32, val __u64, max_entries 4)", "Check Ethernet header: if not ETH_P_IP, slot=3", "Check IPv4 header: if ip->protocol == IPPROTO_TCP -> slot=0; else if ip->protocol == IPPROTO_UDP -> slot=1; else slot=2", "Lookup slot in 'protocol_counters' and increment (*val += 1)", "Return XDP_PASS for all packets", "GPL license and SEC(\"xdp\") entry point"],
        [
            {"name": "tcp_slot0", "description": "IPv4 TCP frame increments slot 0 and returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "udp_slot1", "description": "IPv4 UDP frame increments slot 1 and returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "icmp_slot2", "description": "IPv4 ICMP frame increments slot 2 and returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "gre_slot2", "description": "IPv4 GRE frame increments slot 2 and returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=47, payload=b"\x00"*10)).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_slot3", "description": "ARP frame (non-IPv4) increments slot 3 and returns XDP_PASS", "packet_hex": make_eth(eth_type=0x0806, payload=b"\x00"*28).hex(), "expected_action": "XDP_PASS"},
            {"name": "ipv6_slot3", "description": "IPv6 frame increments slot 3 and returns XDP_PASS", "packet_hex": make_eth(eth_type=0x86DD, payload=b"\x60\x00\x00\x00\x00\x00\x3b\x40" + b"\x00"*32).hex(), "expected_action": "XDP_PASS"},
            {"name": "vlan_slot3", "description": "VLAN frame increments slot 3 and returns XDP_PASS", "packet_hex": make_eth(vlan=100, payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "runt_slot3", "description": "Runt frame increments slot 3 and returns XDP_PASS", "packet_hex": "5254001234565254006543210800", "expected_action": "XDP_PASS"},
        ],
        main_validator="map_state"
    )

    # 5. pit_l2_tcp_flag_counters
    add_task(
        "packet_inspection_telemetry", "level_2", "pit_l2_tcp_flag_counters", "xdp_telemetry_flags", "xdp_percpu_counter", "tcp_flags_inspect+flag_counters_map+pass",
        "Write an XDP/eBPF program that counts valid IPv4 TCP packets by TCP control flags in array map 'tcp_flag_counters' (type BPF_MAP_TYPE_PERCPU_ARRAY, key __u32 [0=SYN, 1=FIN, 2=RST, 3=Other], val __u64 count, max_entries 4). Define flag precedence: (1) If SYN flag is set (flags & 0x02) -> slot 0, (2) Else if FIN flag is set (flags & 0x01) -> slot 1, (3) Else if RST flag is set (flags & 0x04) -> slot 2, (4) Else (ACK only, PSH+ACK, URG, etc.) -> slot 3. If the packet is not valid IPv4 TCP, do not increment any slot. Return XDP_PASS for all packets.",
        ["Define 'tcp_flag_counters' (type BPF_MAP_TYPE_PERCPU_ARRAY, key __u32, val __u64, max_entries 4)", "Check Ethernet and IPv4 bounds, verify ip->protocol == IPPROTO_TCP", "Parse variable IHL (ip->ihl * 4) and verify TCP header bounds", "Inspect TCP flags at offset 13 of TCP header", "Apply precedence: SYN (0x02) -> 0; FIN (0x01) -> 1; RST (0x04) -> 2; other -> 3", "Lookup slot in 'tcp_flag_counters' and increment (*val += 1)", "Return XDP_PASS for all packets", "GPL license and SEC(\"xdp\") entry point"],
        [
            {"name": "syn_slot0", "description": "TCP SYN (0x02) increments slot 0 and returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(flags=0x02))).hex(), "expected_action": "XDP_PASS"},
            {"name": "syn_ack_slot0", "description": "TCP SYN+ACK (0x12) increments slot 0 (SYN precedence) and returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(flags=0x12))).hex(), "expected_action": "XDP_PASS"},
            {"name": "fin_slot1", "description": "TCP FIN (0x01) increments slot 1 and returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(flags=0x01))).hex(), "expected_action": "XDP_PASS"},
            {"name": "fin_ack_slot1", "description": "TCP FIN+ACK (0x11) increments slot 1 (FIN precedence) and returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(flags=0x11))).hex(), "expected_action": "XDP_PASS"},
            {"name": "rst_slot2", "description": "TCP RST (0x04) increments slot 2 and returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(flags=0x04))).hex(), "expected_action": "XDP_PASS"},
            {"name": "rst_ack_slot2", "description": "TCP RST+ACK (0x14) increments slot 2 and returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(flags=0x14))).hex(), "expected_action": "XDP_PASS"},
            {"name": "ack_slot3", "description": "TCP pure ACK (0x10) increments slot 3 and returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(flags=0x10))).hex(), "expected_action": "XDP_PASS"},
            {"name": "psh_ack_slot3", "description": "TCP PSH+ACK (0x18) increments slot 3 and returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(flags=0x18))).hex(), "expected_action": "XDP_PASS"},
        ],
        main_validator="map_state"
    )

    # 6. pit_l2_length_histogram
    add_task(
        "packet_inspection_telemetry", "level_2", "pit_l2_length_histogram", "xdp_telemetry_histogram", "xdp_percpu_counter", "wire_len_bucket+length_histogram_map+pass",
        "Write an XDP/eBPF program that places every received packet into one of four deterministic wire length buckets in per-CPU array map 'length_histogram' (type BPF_MAP_TYPE_PERCPU_ARRAY, key __u32, val __u64 count, max_entries 4). Buckets: (1) Slot 0: 0 to 63 bytes (len < 64), (2) Slot 1: 64 to 127 bytes (64 <= len < 128), (3) Slot 2: 128 to 511 bytes (128 <= len < 512), (4) Slot 3: 512 or more bytes (len >= 512). Increment the appropriate bucket counter in 'length_histogram' and return XDP_PASS for all packets.",
        ["Define 'length_histogram' (type BPF_MAP_TYPE_PERCPU_ARRAY, key __u32, val __u64, max_entries 4)", "Compute wire length pkt_len = (void *)(long)ctx->data_end - (void *)(long)ctx->data", "If pkt_len < 64 -> slot 0", "Else if pkt_len < 128 -> slot 1", "Else if pkt_len < 512 -> slot 2", "Else -> slot 3", "Lookup slot in 'length_histogram' and increment (*val += 1)", "Return XDP_PASS for all packets", "GPL license and SEC(\"xdp\") entry point"],
        [
            {"name": "bucket0_runt", "description": "34-byte packet falls in bucket 0 (0-63) and returns XDP_PASS", "packet_hex": make_eth(payload=b"\x00"*20).hex(), "expected_action": "XDP_PASS"},
            {"name": "bucket0_54", "description": "54-byte TCP packet falls in bucket 0 (0-63) and returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "bucket1_64", "description": "64-byte boundary packet falls in bucket 1 (64-127) and returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(payload=b"\x00"*10))).hex(), "expected_action": "XDP_PASS"},
            {"name": "bucket1_100", "description": "100-byte packet falls in bucket 1 (64-127) and returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(payload=b"\x00"*58))).hex(), "expected_action": "XDP_PASS"},
            {"name": "bucket2_128", "description": "128-byte boundary packet falls in bucket 2 (128-511) and returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(payload=b"\x00"*74))).hex(), "expected_action": "XDP_PASS"},
            {"name": "bucket2_256", "description": "256-byte packet falls in bucket 2 (128-511) and returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(payload=b"\x00"*214))).hex(), "expected_action": "XDP_PASS"},
            {"name": "bucket3_512", "description": "512-byte boundary packet falls in bucket 3 (512+) and returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(payload=b"\x00"*458))).hex(), "expected_action": "XDP_PASS"},
            {"name": "bucket3_1024", "description": "1024-byte packet falls in bucket 3 (512+) and returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(payload=b"\x00"*982))).hex(), "expected_action": "XDP_PASS"},
        ],
        main_validator="map_state"
    )

    # 7. pit_l3_ipv4_flow_counter
    add_task(
        "packet_inspection_telemetry", "level_3", "pit_l3_ipv4_flow_counter", "xdp_flow_telemetry", "xdp_hash_map_telemetry", "ipv4_5tuple+flow_counter_map+pass",
        "Write an XDP/eBPF program that counts valid IPv4 TCP and UDP packets in a hash map keyed by 5-tuple. Define map 'flow_counter_map' (type BPF_MAP_TYPE_HASH, key struct { __u32 saddr; __u32 daddr; __u16 sport; __u16 dport; __u8 proto; __u8 pad[3]; }, val __u64 packet_count, max_entries 65536). Support variable IPv4 header length (IHL). For each valid IPv4 TCP/UDP packet, construct key, lookup in 'flow_counter_map', increment counter (*val += 1) or insert count=1 if absent, and return XDP_PASS. Pass non-TCP/UDP and non-IPv4 frames without modifying the map.",
        ["Define 'flow_counter_map' (type BPF_MAP_TYPE_HASH, key struct { __u32 saddr; __u32 daddr; __u16 sport; __u16 dport; __u8 proto; __u8 pad[3]; }, val __u64, max_entries 65536)", "Check Ethernet and IPv4 bounds, parse variable IHL (ip->ihl * 4)", "Check if ip->protocol is IPPROTO_TCP or IPPROTO_UDP", "Extract sport and dport safely", "Construct 5-tuple key with zeroed padding", "Perform lookup/update in 'flow_counter_map'", "Return XDP_PASS for all traffic", "GPL license and SEC(\"xdp\") entry point"],
        [
            {"name": "tcp_flow1_pass", "description": "TCP 5-tuple flow 1 increments flow counter and returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(src_ip="10.0.0.1", dst_ip="10.0.0.2", proto=6, payload=make_tcp(src_port=12345, dst_port=80))).hex(), "expected_action": "XDP_PASS"},
            {"name": "tcp_flow1_pkt2_pass", "description": "TCP flow 1 second packet increments counter and returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(src_ip="10.0.0.1", dst_ip="10.0.0.2", proto=6, payload=make_tcp(src_port=12345, dst_port=80))).hex(), "expected_action": "XDP_PASS"},
            {"name": "tcp_flow2_pass", "description": "TCP flow 2 (different dst port) returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(src_ip="10.0.0.1", dst_ip="10.0.0.2", proto=6, payload=make_tcp(src_port=12345, dst_port=443))).hex(), "expected_action": "XDP_PASS"},
            {"name": "udp_flow1_pass", "description": "UDP flow returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.10", dst_ip="192.168.1.20", proto=17, payload=make_udp(src_port=5353, dst_port=53))).hex(), "expected_action": "XDP_PASS"},
            {"name": "icmp_pass", "description": "ICMP traffic (ignored by map) returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP frame (ignored by map) returns XDP_PASS", "packet_hex": make_eth(eth_type=0x0806, payload=b"\x00"*28).hex(), "expected_action": "XDP_PASS"},
            {"name": "ihl6_tcp_pass", "description": "IPv4 TCP flow with options (IHL=6) returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(ihl=6, proto=6, payload=make_tcp(src_port=12345, dst_port=80))).hex(), "expected_action": "XDP_PASS"},
            {"name": "vlan_pass", "description": "VLAN frame returns XDP_PASS", "packet_hex": make_eth(vlan=100, payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_tcp_pass", "description": "Truncated TCP header returns XDP_PASS safely", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=b"\x00\x50")).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_ip_pass", "description": "Truncated IP header returns XDP_PASS safely", "packet_hex": make_eth(payload=b"\x45\x00").hex(), "expected_action": "XDP_PASS"},
        ],
        main_validator="map_state"
    )

    # 8. pit_l3_vlan_dualstack_telemetry
    add_task(
        "packet_inspection_telemetry", "level_3", "pit_l3_vlan_dualstack_telemetry", "xdp_telemetry_dualstack", "xdp_percpu_counter", "vlan_dualstack_inspect+vlan_telemetry_map+pass",
        "Write an XDP/eBPF telemetry program that counts packets and bytes by Ethernet family in array map 'vlan_telemetry_map' (type BPF_MAP_TYPE_PERCPU_ARRAY, key __u32, val struct { __u64 packets; __u64 bytes; }, max_entries 4) without double counting. Categories: (1) Slot 0: Untagged IPv4 (EtherType 0x0800), (2) Slot 1: Single-VLAN IPv4 (802.1Q 0x8100 encapsulation with inner EtherType 0x0800), (3) Slot 2: Single-VLAN IPv6 (802.1Q 0x8100 encapsulation with inner EtherType 0x86DD), (4) Slot 3: Other traffic (untagged IPv6, ARP, QinQ, non-IP). Compute packet length, increment the corresponding slot's packets and bytes, and return XDP_PASS.",
        ["Define 'vlan_telemetry_map' (type BPF_MAP_TYPE_PERCPU_ARRAY, key __u32, val struct { __u64 packets; __u64 bytes; }, max_entries 4)", "Compute wire length pkt_len", "Check Ethernet header: if eth->h_proto == bpf_htons(ETH_P_IP) -> slot 0", "If eth->h_proto == bpf_htons(ETH_P_8021Q): parse VLAN header; if inner EtherType == ETH_P_IP -> slot 1; else if inner EtherType == ETH_P_IPV6 -> slot 2; else slot 3", "If any other header -> slot 3", "Lookup slot in 'vlan_telemetry_map', update *val.packets += 1 and *val.bytes += pkt_len", "Return XDP_PASS for all traffic", "GPL license and SEC(\"xdp\") entry point"],
        [
            {"name": "untagged_ipv4_slot0", "description": "Untagged IPv4 frame updates slot 0 and returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "untagged_ipv4_udp_slot0", "description": "Untagged IPv4 UDP frame updates slot 0 and returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "vlan100_ipv4_slot1", "description": "Single-VLAN IPv4 frame updates slot 1 and returns XDP_PASS", "packet_hex": make_eth(vlan=100, eth_type=0x0800, payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "vlan200_ipv4_slot1", "description": "Single-VLAN IPv4 frame updates slot 1 and returns XDP_PASS", "packet_hex": make_eth(vlan=200, eth_type=0x0800, payload=make_ipv4(proto=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "vlan100_ipv6_slot2", "description": "Single-VLAN IPv6 frame updates slot 2 and returns XDP_PASS", "packet_hex": make_eth(vlan=100, eth_type=0x86DD, payload=b"\x60\x00\x00\x00\x00\x00\x3b\x40" + b"\x00"*32).hex(), "expected_action": "XDP_PASS"},
            {"name": "untagged_ipv6_slot3", "description": "Untagged IPv6 frame updates slot 3 (other) and returns XDP_PASS", "packet_hex": make_eth(eth_type=0x86DD, payload=b"\x60\x00\x00\x00\x00\x00\x3b\x40" + b"\x00"*32).hex(), "expected_action": "XDP_PASS"},
            {"name": "untagged_arp_slot3", "description": "Untagged ARP frame updates slot 3 and returns XDP_PASS", "packet_hex": make_eth(eth_type=0x0806, payload=b"\x00"*28).hex(), "expected_action": "XDP_PASS"},
            {"name": "vlan_arp_slot3", "description": "VLAN ARP frame updates slot 3 and returns XDP_PASS", "packet_hex": make_eth(vlan=100, eth_type=0x0806, payload=b"\x00"*28).hex(), "expected_action": "XDP_PASS"},
            {"name": "qinq_slot3", "description": "QinQ double-tagged frame (0x88A8) updates slot 3 and returns XDP_PASS", "packet_hex": make_eth(eth_type=0x88A8, payload=b"\x00\x64\x81\x00\x00\xc8\x08\x00" + make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "runt_slot3", "description": "Runt frame updates slot 3 and returns XDP_PASS", "packet_hex": "525400123456525400654321ffff", "expected_action": "XDP_PASS"},
        ],
        main_validator="map_state"
    )

    # 9. pit_l3_tcp_flow_outcomes
    add_task(
        "packet_inspection_telemetry", "level_3", "pit_l3_tcp_flow_outcomes", "xdp_flow_telemetry", "xdp_hash_map_telemetry", "ipv4_tcp_flow+tcp_flow_map+pass",
        "Write an XDP/eBPF program that maintains per-flow packet and byte totals plus SYN, FIN, and RST observation flags for IPv4 TCP traffic in hash map 'tcp_flow_map' (type BPF_MAP_TYPE_HASH, key struct { __u32 saddr; __u32 daddr; __u16 sport; __u16 dport; }, val struct { __u64 packets; __u64 bytes; __u32 syn_seen; __u32 fin_seen; __u32 rst_seen; }, max_entries 32768). For each valid IPv4 TCP packet, construct 4-tuple key, lookup or insert entry in 'tcp_flow_map', increment packets (*val.packets += 1), add bytes (*val.bytes += wire_len), and set syn_seen=1 if SYN flag present, fin_seen=1 if FIN flag present, rst_seen=1 if RST flag present. Return XDP_PASS for all traffic.",
        ["Define 'tcp_flow_map' (type BPF_MAP_TYPE_HASH, key struct { __u32 saddr; __u32 daddr; __u16 sport; __u16 dport; }, val struct { __u64 packets; __u64 bytes; __u32 syn_seen; __u32 fin_seen; __u32 rst_seen; }, max_entries 32768)", "Check Ethernet and IPv4 bounds, verify ip->protocol == IPPROTO_TCP", "Parse variable IHL (ip->ihl * 4) and verify TCP header bounds", "Extract flags from TCP offset 13", "Lookup key in 'tcp_flow_map' or initialize new entry", "Update packets, bytes, syn_seen, fin_seen, rst_seen", "Return XDP_PASS for all packets", "GPL license and SEC(\"xdp\") entry point"],
        [
            {"name": "flow1_syn_pass", "description": "Flow 1 SYN packet sets syn_seen=1 and returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(src_ip="10.0.0.1", dst_ip="10.0.0.2", proto=6, payload=make_tcp(src_port=10000, dst_port=80, flags=0x02))).hex(), "expected_action": "XDP_PASS"},
            {"name": "flow1_ack_pass", "description": "Flow 1 ACK packet increments packets and bytes and returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(src_ip="10.0.0.1", dst_ip="10.0.0.2", proto=6, payload=make_tcp(src_port=10000, dst_port=80, flags=0x10))).hex(), "expected_action": "XDP_PASS"},
            {"name": "flow1_fin_pass", "description": "Flow 1 FIN packet sets fin_seen=1 and returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(src_ip="10.0.0.1", dst_ip="10.0.0.2", proto=6, payload=make_tcp(src_port=10000, dst_port=80, flags=0x11))).hex(), "expected_action": "XDP_PASS"},
            {"name": "flow2_rst_pass", "description": "Flow 2 RST packet sets rst_seen=1 and returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(src_ip="10.0.0.5", dst_ip="10.0.0.6", proto=6, payload=make_tcp(src_port=20000, dst_port=443, flags=0x04))).hex(), "expected_action": "XDP_PASS"},
            {"name": "udp_traffic_pass", "description": "UDP traffic (ignored by map) returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "icmp_traffic_pass", "description": "ICMP traffic (ignored by map) returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_traffic_pass", "description": "ARP frame returns XDP_PASS", "packet_hex": make_eth(eth_type=0x0806, payload=b"\x00"*28).hex(), "expected_action": "XDP_PASS"},
            {"name": "ihl6_flow_pass", "description": "IPv4 TCP packet with IHL=6 options returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(ihl=6, proto=6, payload=make_tcp(src_port=10000, dst_port=80, flags=0x10))).hex(), "expected_action": "XDP_PASS"},
            {"name": "vlan_pass", "description": "VLAN frame returns XDP_PASS", "packet_hex": make_eth(vlan=100, payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_tcp_pass", "description": "Truncated TCP header returns XDP_PASS safely", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=b"\x00\x50")).hex(), "expected_action": "XDP_PASS"},
        ],
        main_validator="map_state"
    )

    # =========================================================================
    # D. Protocol Transformation (9 Tasks)
    # =========================================================================

    # 1. ptr_l1_swap_mac
    add_task(
        "protocol_transformation", "level_1", "ptr_l1_swap_mac", "xdp_packet_rewrite", "xdp_l2_rewrite", "ethernet+swap_mac_addresses+pass",
        "Write a complete XDP/eBPF program that swaps Ethernet source and destination MAC addresses and passes the packet with XDP_PASS. Preserve every byte of the frame following the 12-byte MAC address area (EtherType, payload, etc.) exactly. If the packet is shorter than 14 bytes (runt Ethernet frame), return XDP_PASS unchanged.",
        ["Check Ethernet header bounds", "Swap eth->h_dest and eth->h_source using byte-wise or multi-byte temporary variables", "Preserve EtherType and payload intact", "Return XDP_PASS for all frames", "GPL license and SEC(\"xdp\") entry point"],
        [
            {"name": "swap_tcp_frame", "description": "Standard TCP frame MAC addresses swapped and returned XDP_PASS", "packet_hex": make_eth(dst_mac="11:22:33:44:55:66", src_mac="aa:bb:cc:dd:ee:ff", payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS", "expected_bytes_hex": make_eth(dst_mac="aa:bb:cc:dd:ee:ff", src_mac="11:22:33:44:55:66", payload=make_ipv4(proto=6, payload=make_tcp())).hex()},
            {"name": "swap_udp_frame", "description": "UDP frame MAC addresses swapped", "packet_hex": make_eth(dst_mac="52:54:00:12:34:56", src_mac="52:54:00:65:43:21", payload=make_ipv4(proto=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS", "expected_bytes_hex": make_eth(dst_mac="52:54:00:65:43:21", src_mac="52:54:00:12:34:56", payload=make_ipv4(proto=17, payload=make_udp())).hex()},
            {"name": "swap_arp_frame", "description": "ARP frame MAC addresses swapped", "packet_hex": make_eth(dst_mac="00:11:22:33:44:55", src_mac="66:77:88:99:aa:bb", eth_type=0x0806, payload=b"\x00"*28).hex(), "expected_action": "XDP_PASS", "expected_bytes_hex": make_eth(dst_mac="66:77:88:99:aa:bb", src_mac="00:11:22:33:44:55", eth_type=0x0806, payload=b"\x00"*28).hex()},
            {"name": "swap_vlan_frame", "description": "VLAN frame outer MAC addresses swapped", "packet_hex": make_eth(dst_mac="11:22:33:44:55:66", src_mac="aa:bb:cc:dd:ee:ff", vlan=100, payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS", "expected_bytes_hex": make_eth(dst_mac="aa:bb:cc:dd:ee:ff", src_mac="11:22:33:44:55:66", vlan=100, payload=make_ipv4(proto=6, payload=make_tcp())).hex()},
            {"name": "swap_runt_frame", "description": "14-byte runt frame MAC addresses swapped", "packet_hex": "112233445566aabbccddeeff0800", "expected_action": "XDP_PASS", "expected_bytes_hex": "aabbccddeeff1122334455660800"},
            {"name": "swap_runt_frame_ffff", "description": "14-byte runt frame MAC addresses swapped", "packet_hex": "112233445566aabbccddeeffffff", "expected_action": "XDP_PASS", "expected_bytes_hex": "aabbccddeeff112233445566ffff"},
        ],
        main_validator="packet_bytes"
    )

    # 2. ptr_l1_set_destination_mac
    add_task(
        "protocol_transformation", "level_1", "ptr_l1_set_destination_mac", "xdp_packet_rewrite", "xdp_l2_rewrite", "ethernet+set_dst_mac_020000000099+pass",
        "Write a complete XDP/eBPF program that replaces the Ethernet destination address with fixed MAC 02:00:00:00:00:99. Preserve source MAC, EtherType, payload, and packet length exactly. Return XDP_PASS for all frames. If the packet is shorter than 14 bytes, pass it unchanged.",
        ["Check Ethernet header bounds", "Set eth->h_dest to {0x02, 0x00, 0x00, 0x00, 0x00, 0x99}", "Preserve eth->h_source, eth->h_proto, and payload exactly", "Return XDP_PASS for all frames", "GPL license and SEC(\"xdp\") entry point"],
        [
            {"name": "set_dst_tcp", "description": "TCP frame destination MAC set to 02:00:00:00:00:99", "packet_hex": make_eth(dst_mac="11:22:33:44:55:66", src_mac="aa:bb:cc:dd:ee:ff", payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS", "expected_bytes_hex": make_eth(dst_mac="02:00:00:00:00:99", src_mac="aa:bb:cc:dd:ee:ff", payload=make_ipv4(proto=6, payload=make_tcp())).hex()},
            {"name": "set_dst_udp", "description": "UDP frame destination MAC set to 02:00:00:00:00:99", "packet_hex": make_eth(dst_mac="52:54:00:12:34:56", src_mac="52:54:00:65:43:21", payload=make_ipv4(proto=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS", "expected_bytes_hex": make_eth(dst_mac="02:00:00:00:00:99", src_mac="52:54:00:65:43:21", payload=make_ipv4(proto=17, payload=make_udp())).hex()},
            {"name": "set_dst_arp", "description": "ARP frame destination MAC set to 02:00:00:00:00:99", "packet_hex": make_eth(dst_mac="ff:ff:ff:ff:ff:ff", src_mac="66:77:88:99:aa:bb", eth_type=0x0806, payload=b"\x00"*28).hex(), "expected_action": "XDP_PASS", "expected_bytes_hex": make_eth(dst_mac="02:00:00:00:00:99", src_mac="66:77:88:99:aa:bb", eth_type=0x0806, payload=b"\x00"*28).hex()},
            {"name": "set_dst_vlan", "description": "VLAN frame destination MAC set to 02:00:00:00:00:99", "packet_hex": make_eth(dst_mac="11:22:33:44:55:66", src_mac="aa:bb:cc:dd:ee:ff", vlan=100, payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS", "expected_bytes_hex": make_eth(dst_mac="02:00:00:00:00:99", src_mac="aa:bb:cc:dd:ee:ff", vlan=100, payload=make_ipv4(proto=6, payload=make_tcp())).hex()},
            {"name": "set_dst_runt", "description": "14-byte frame destination MAC set to 02:00:00:00:00:99", "packet_hex": "112233445566aabbccddeeff0800", "expected_action": "XDP_PASS", "expected_bytes_hex": "020000000099aabbccddeeff0800"},
            {"name": "set_dst_runt_ffff", "description": "14-byte frame destination MAC set to 02:00:00:00:00:99", "packet_hex": "112233445566aabbccddeeffffff", "expected_action": "XDP_PASS", "expected_bytes_hex": "020000000099aabbccddeeffffff"},
        ],
        main_validator="packet_bytes"
    )

    # 3. ptr_l1_set_source_mac
    add_task(
        "protocol_transformation", "level_1", "ptr_l1_set_source_mac", "xdp_packet_rewrite", "xdp_l2_rewrite", "ethernet+set_src_mac_020000000042+pass",
        "Write a complete XDP/eBPF program that replaces the Ethernet source address with fixed MAC 02:00:00:00:00:42. Preserve destination MAC, EtherType, payload, and packet length exactly. Return XDP_PASS for all frames. If the packet is shorter than 14 bytes, pass it unchanged.",
        ["Check Ethernet header bounds", "Set eth->h_source to {0x02, 0x00, 0x00, 0x00, 0x00, 0x42}", "Preserve eth->h_dest, eth->h_proto, and payload exactly", "Return XDP_PASS for all frames", "GPL license and SEC(\"xdp\") entry point"],
        [
            {"name": "set_src_tcp", "description": "TCP frame source MAC set to 02:00:00:00:00:42", "packet_hex": make_eth(dst_mac="11:22:33:44:55:66", src_mac="aa:bb:cc:dd:ee:ff", payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS", "expected_bytes_hex": make_eth(dst_mac="11:22:33:44:55:66", src_mac="02:00:00:00:00:42", payload=make_ipv4(proto=6, payload=make_tcp())).hex()},
            {"name": "set_src_udp", "description": "UDP frame source MAC set to 02:00:00:00:00:42", "packet_hex": make_eth(dst_mac="52:54:00:12:34:56", src_mac="52:54:00:65:43:21", payload=make_ipv4(proto=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS", "expected_bytes_hex": make_eth(dst_mac="52:54:00:12:34:56", src_mac="02:00:00:00:00:42", payload=make_ipv4(proto=17, payload=make_udp())).hex()},
            {"name": "set_src_arp", "description": "ARP frame source MAC set to 02:00:00:00:00:42", "packet_hex": make_eth(dst_mac="ff:ff:ff:ff:ff:ff", src_mac="66:77:88:99:aa:bb", eth_type=0x0806, payload=b"\x00"*28).hex(), "expected_action": "XDP_PASS", "expected_bytes_hex": make_eth(dst_mac="ff:ff:ff:ff:ff:ff", src_mac="02:00:00:00:00:42", eth_type=0x0806, payload=b"\x00"*28).hex()},
            {"name": "set_src_vlan", "description": "VLAN frame source MAC set to 02:00:00:00:00:42", "packet_hex": make_eth(dst_mac="11:22:33:44:55:66", src_mac="aa:bb:cc:dd:ee:ff", vlan=100, payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS", "expected_bytes_hex": make_eth(dst_mac="11:22:33:44:55:66", src_mac="02:00:00:00:00:42", vlan=100, payload=make_ipv4(proto=6, payload=make_tcp())).hex()},
            {"name": "set_src_runt", "description": "14-byte frame source MAC set to 02:00:00:00:00:42", "packet_hex": "112233445566aabbccddeeff0800", "expected_action": "XDP_PASS", "expected_bytes_hex": "1122334455660200000000420800"},
            {"name": "set_src_runt_ffff", "description": "14-byte frame source MAC set to 02:00:00:00:00:42", "packet_hex": "112233445566aabbccddeeffffff", "expected_action": "XDP_PASS", "expected_bytes_hex": "112233445566020000000042ffff"},
        ],
        main_validator="packet_bytes"
    )

    # 4. ptr_l2_decrement_ttl
    add_task(
        "protocol_transformation", "level_2", "ptr_l2_decrement_ttl", "xdp_ip_rewrite", "xdp_ttl_checksum_rewrite", "ipv4+decrement_ttl_update_checksum+drop_if_le_1",
        "Write an XDP/eBPF program that decrements the IPv4 TTL header field when TTL > 1, updates the IPv4 header checksum correctly, and returns XDP_PASS. If TTL <= 1 (TTL is 1 or 0), drop the packet with XDP_DROP. Pass non-IPv4 frames and malformed frames unchanged with XDP_PASS.",
        ["Check Ethernet and IPv4 bounds", "Verify eth->h_proto == bpf_htons(ETH_P_IP)", "If ip->ttl <= 1, return XDP_DROP", "Decrement ip->ttl (ip->ttl -= 1)", "Update IPv4 header checksum (e.g. csum = (ip->check + bpf_htons(0x0100)); if (csum < ip->check) csum += 1; ip->check = csum; or full 20-byte incremental update)", "Return XDP_PASS on success", "Pass non-IPv4 unchanged with XDP_PASS", "GPL license and SEC(\"xdp\") entry point"],
        [
            {"name": "ttl_64_dec", "description": "IPv4 TTL 64 decremented to 63, checksum updated, returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(ttl=64, proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS", "expected_bytes_hex": make_eth(payload=make_ipv4(ttl=63, proto=6, payload=make_tcp())).hex()},
            {"name": "ttl_2_dec", "description": "IPv4 TTL 2 decremented to 1, checksum updated, returns XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(ttl=2, proto=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS", "expected_bytes_hex": make_eth(payload=make_ipv4(ttl=1, proto=17, payload=make_udp())).hex()},
            {"name": "ttl_1_drop", "description": "IPv4 TTL 1 must return XDP_DROP", "packet_hex": make_eth(payload=make_ipv4(ttl=1, proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_DROP"},
            {"name": "ttl_0_drop", "description": "IPv4 TTL 0 must return XDP_DROP", "packet_hex": make_eth(payload=make_ipv4(ttl=0, proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_DROP"},
            {"name": "arp_pass", "description": "ARP frame must return XDP_PASS unchanged", "packet_hex": make_eth(eth_type=0x0806, payload=b"\x00"*28).hex(), "expected_action": "XDP_PASS", "expected_bytes_hex": make_eth(eth_type=0x0806, payload=b"\x00"*28).hex()},
            {"name": "ttl_255_dec", "description": "IPv4 TTL 255 decremented to 254", "packet_hex": make_eth(payload=make_ipv4(ttl=255, proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_PASS", "expected_bytes_hex": make_eth(payload=make_ipv4(ttl=254, proto=1, payload=make_icmp())).hex()},
            {"name": "truncated_ip_pass", "description": "Truncated IP header returns XDP_PASS safely", "packet_hex": make_eth(payload=b"\x45\x00").hex(), "expected_action": "XDP_PASS"},
        ],
        main_validator="packet_bytes"
    )

    # 5. ptr_l2_rewrite_ipv4_destination
    add_task(
        "protocol_transformation", "level_2", "ptr_l2_rewrite_ipv4_destination", "xdp_ip_rewrite", "xdp_ip_checksum_rewrite", "ipv4+rewrite_dst_ip_203_0_113_9+pass",
        "Write an XDP/eBPF program that rewrites the IPv4 destination address to 203.0.113.9 (0xCB007109 in network byte order) and updates the IPv4 header checksum correctly. Pass non-IPv4 and malformed packets unchanged with XDP_PASS.",
        ["Check Ethernet and IPv4 bounds", "Verify eth->h_proto == bpf_htons(ETH_P_IP)", "Rewrite ip->daddr = bpf_htonl(0xCB007109) (203.0.113.9)", "Recalculate or incrementally update IPv4 header checksum (ip->check)", "Return XDP_PASS for all frames", "GPL license and SEC(\"xdp\") entry point"],
        [
            {"name": "rewrite_tcp_dst", "description": "IPv4 destination rewritten to 203.0.113.9 with valid checksum", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.10", dst_ip="10.0.0.1", proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS", "expected_bytes_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.10", dst_ip="203.0.113.9", proto=6, payload=make_tcp())).hex()},
            {"name": "rewrite_udp_dst", "description": "UDP packet destination rewritten to 203.0.113.9", "packet_hex": make_eth(payload=make_ipv4(src_ip="172.16.0.5", dst_ip="172.16.0.1", proto=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS", "expected_bytes_hex": make_eth(payload=make_ipv4(src_ip="172.16.0.5", dst_ip="203.0.113.9", proto=17, payload=make_udp())).hex()},
            {"name": "rewrite_icmp_dst", "description": "ICMP packet destination rewritten to 203.0.113.9", "packet_hex": make_eth(payload=make_ipv4(src_ip="1.2.3.4", dst_ip="5.6.7.8", proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_PASS", "expected_bytes_hex": make_eth(payload=make_ipv4(src_ip="1.2.3.4", dst_ip="203.0.113.9", proto=1, payload=make_icmp())).hex()},
            {"name": "already_matching_dst", "description": "Packet already destined for 203.0.113.9 preserved", "packet_hex": make_eth(payload=make_ipv4(src_ip="10.0.0.1", dst_ip="203.0.113.9", proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS", "expected_bytes_hex": make_eth(payload=make_ipv4(src_ip="10.0.0.1", dst_ip="203.0.113.9", proto=6, payload=make_tcp())).hex()},
            {"name": "arp_pass", "description": "ARP frame preserved unchanged", "packet_hex": make_eth(eth_type=0x0806, payload=b"\x00"*28).hex(), "expected_action": "XDP_PASS", "expected_bytes_hex": make_eth(eth_type=0x0806, payload=b"\x00"*28).hex()},
            {"name": "vlan_pass", "description": "VLAN frame preserved unchanged", "packet_hex": make_eth(vlan=100, payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_ip_pass", "description": "Truncated IP header preserved safely", "packet_hex": make_eth(payload=b"\x45\x00").hex(), "expected_action": "XDP_PASS"},
        ],
        main_validator="packet_bytes"
    )

    # 6. ptr_l2_rewrite_udp_port
    add_task(
        "protocol_transformation", "level_2", "ptr_l2_rewrite_udp_port", "xdp_udp_rewrite", "xdp_l4_port_rewrite", "ipv4_udp+rewrite_dport_5353+update_csum+pass",
        "Write an XDP/eBPF program that rewrites the destination port of valid IPv4 UDP packets to 5353 (bpf_htons(5353)). If the UDP checksum is nonzero, update the checksum correctly for the destination port modification. If the UDP checksum is zero (checksum disabled in IPv4), preserve it as zero. Pass non-UDP and non-IPv4 traffic unchanged with XDP_PASS.",
        ["Check Ethernet and IPv4 bounds", "Verify eth->h_proto == bpf_htons(ETH_P_IP) and ip->protocol == IPPROTO_UDP", "Parse variable IHL (ip->ihl * 4) and verify UDP header bounds", "If udp->check != 0, update checksum incrementally or via helper", "Set udp->dest = bpf_htons(5353)", "Return XDP_PASS for all frames", "GPL license and SEC(\"xdp\") entry point"],
        [
            {"name": "rewrite_udp_53_to_5353_zero_csum", "description": "UDP port 53 rewritten to 5353 with zero checksum preserved", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=53, with_csum=False))).hex(), "expected_action": "XDP_PASS", "expected_bytes_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=5353, with_csum=False))).hex()},
            {"name": "rewrite_udp_123_to_5353_with_csum", "description": "UDP port 123 rewritten to 5353 with checksum updated", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.10", dst_ip="192.168.1.20", proto=17, payload=make_udp(src_port=12345, dst_port=123, with_csum=True, src_ip="192.168.1.10", dst_ip="192.168.1.20"))).hex(), "expected_action": "XDP_PASS", "expected_bytes_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.10", dst_ip="192.168.1.20", proto=17, payload=make_udp(src_port=12345, dst_port=5353, with_csum=True, src_ip="192.168.1.10", dst_ip="192.168.1.20"))).hex()},
            {"name": "tcp_preserved", "description": "TCP traffic preserved unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(dst_port=80))).hex(), "expected_action": "XDP_PASS", "expected_bytes_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(dst_port=80))).hex()},
            {"name": "icmp_preserved", "description": "ICMP traffic preserved unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_PASS", "expected_bytes_hex": make_eth(payload=make_ipv4(proto=1, payload=make_icmp())).hex()},
            {"name": "arp_preserved", "description": "ARP frame preserved unchanged", "packet_hex": make_eth(eth_type=0x0806, payload=b"\x00"*28).hex(), "expected_action": "XDP_PASS", "expected_bytes_hex": make_eth(eth_type=0x0806, payload=b"\x00"*28).hex()},
            {"name": "already_5353", "description": "UDP packet already on 5353 preserved", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=5353, with_csum=False))).hex(), "expected_action": "XDP_PASS", "expected_bytes_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=5353, with_csum=False))).hex()},
            {"name": "truncated_udp_pass", "description": "Truncated UDP header preserved safely", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=b"\x00\x35")).hex(), "expected_action": "XDP_PASS"},
        ],
        main_validator="packet_bytes"
    )

    # 7. ptr_l3_tcp_dnat
    add_task(
        "protocol_transformation", "level_3", "ptr_l3_tcp_dnat", "xdp_dnat_rewrite", "xdp_l3_l4_dnat", "ipv4_tcp+dnat_192_168_100_50_port_8080+pass",
        "Write an XDP/eBPF DNAT program for IPv4 TCP traffic. Rewrite destination IP address to 192.168.100.50 (0xC0A86432) and destination TCP port to 8080 (bpf_htons(8080)). Correctly update both the IPv4 header checksum and the TCP checksum (which covers IPv4 pseudo-header and TCP header). Support variable-length IPv4 headers (IHL) and variable-length TCP headers safely. Pass non-TCP and non-IPv4 traffic unchanged with XDP_PASS.",
        ["Check Ethernet and IPv4 bounds", "Verify eth->h_proto == bpf_htons(ETH_P_IP) and ip->protocol == IPPROTO_TCP", "Parse variable IHL (ip->ihl * 4) and verify TCP header bounds", "Update TCP checksum for changed dst_ip and dst_port (or recompute/incremental)", "Update IPv4 header checksum for changed dst_ip", "Set ip->daddr = bpf_htonl(0xC0A86432) and tcp->dest = bpf_htons(8080)", "Return XDP_PASS for all traffic", "GPL license and SEC(\"xdp\") entry point"],
        [
            {"name": "dnat_tcp_80_to_8080", "description": "TCP port 80 to 10.0.0.1 DNATed to 192.168.100.50:8080", "packet_hex": make_eth(payload=make_ipv4(src_ip="172.16.1.100", dst_ip="10.0.0.1", proto=6, payload=make_tcp(src_port=54321, dst_port=80))).hex(), "expected_action": "XDP_PASS"},
            {"name": "dnat_tcp_443_to_8080", "description": "TCP port 443 to 10.0.0.2 DNATed to 192.168.100.50:8080", "packet_hex": make_eth(payload=make_ipv4(src_ip="172.16.1.100", dst_ip="10.0.0.2", proto=6, payload=make_tcp(src_port=54322, dst_port=443))).hex(), "expected_action": "XDP_PASS"},
            {"name": "dnat_ihl6_tcp_to_8080", "description": "IPv4 TCP with IHL=6 options DNATed to 192.168.100.50:8080", "packet_hex": make_eth(payload=make_ipv4(src_ip="172.16.1.100", dst_ip="10.0.0.3", ihl=6, proto=6, payload=make_tcp(src_port=54323, dst_port=80))).hex(), "expected_action": "XDP_PASS"},
            {"name": "dnat_tcp_opt_header", "description": "TCP header with 12 bytes options DNATed", "packet_hex": make_eth(payload=make_ipv4(src_ip="172.16.1.100", dst_ip="10.0.0.4", proto=6, payload=make_tcp(src_port=54324, dst_port=80, data_offset=8))).hex(), "expected_action": "XDP_PASS"},
            {"name": "udp_preserved", "description": "UDP traffic preserved unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "icmp_preserved", "description": "ICMP traffic preserved unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_preserved", "description": "ARP frame preserved unchanged", "packet_hex": make_eth(eth_type=0x0806, payload=b"\x00"*28).hex(), "expected_action": "XDP_PASS"},
            {"name": "vlan_preserved", "description": "VLAN frame preserved unchanged", "packet_hex": make_eth(vlan=100, payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_tcp_pass", "description": "Truncated TCP header preserved safely", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=b"\x00\x50")).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_ip_pass", "description": "Truncated IP header preserved safely", "packet_hex": make_eth(payload=b"\x45\x00").hex(), "expected_action": "XDP_PASS"},
        ],
        main_validator="packet_bytes"
    )

    # 8. ptr_l3_icmp_echo_reply
    add_task(
        "protocol_transformation", "level_3", "ptr_l3_icmp_echo_reply", "xdp_icmp_responder", "xdp_packet_generator", "ipv4_icmp_echo_req+convert_to_reply_and_tx",
        "Write an XDP/eBPF ICMP echo responder. When a valid IPv4 ICMP Echo Request (type 8, code 0) is received, convert it in-place into an ICMP Echo Reply (type 0, code 0) by: (1) Swapping Ethernet source and destination MAC addresses, (2) Swapping IPv4 source and destination addresses, (3) Changing ICMP type from 8 to 0, (4) Updating the ICMP checksum (or adjusting by +0x0800), and (5) Returning XDP_TX to transmit the reply immediately. Pass all other traffic (Echo Reply, other ICMP types, TCP, UDP, non-IPv4, malformed packets) unchanged with XDP_PASS.",
        ["Check Ethernet and IPv4 bounds", "Verify eth->h_proto == bpf_htons(ETH_P_IP) and ip->protocol == IPPROTO_ICMP", "Parse variable IHL (ip->ihl * 4) and verify ICMP header bounds (at least 8 bytes)", "Check if icmp[0] == 8 && icmp[1] == 0 (Echo Request)", "Swap eth->h_source and eth->h_dest", "Swap ip->saddr and ip->daddr", "Change icmp[0] = 0 (Echo Reply)", "Update ICMP checksum (icmp_csum = icmp_csum + bpf_htons(0x0800) with carry wrap or recompute)", "Return XDP_TX for Echo Requests, XDP_PASS for everything else", "GPL license and SEC(\"xdp\") entry point"],
        [
            {"name": "echo_req_converted_to_reply_tx", "description": "ICMP Echo Request converted to Echo Reply, endpoints swapped, returns XDP_TX", "packet_hex": make_eth(dst_mac="12:34:56:78:9a:bc", src_mac="fe:dc:ba:98:76:54", payload=make_ipv4(src_ip="192.168.1.50", dst_ip="192.168.1.1", proto=1, payload=make_icmp(icmp_type=8, icmp_code=0, payload=b"PING1234"))).hex(), "expected_action": "XDP_TX", "expected_bytes_hex": make_eth(dst_mac="fe:dc:ba:98:76:54", src_mac="12:34:56:78:9a:bc", payload=make_ipv4(src_ip="192.168.1.1", dst_ip="192.168.1.50", proto=1, payload=make_icmp(icmp_type=0, icmp_code=0, payload=b"PING1234"))).hex()},
            {"name": "echo_reply_pass", "description": "Incoming ICMP Echo Reply (type 0) must return XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=1, payload=make_icmp(icmp_type=0, icmp_code=0))).hex(), "expected_action": "XDP_PASS"},
            {"name": "icmp_unreach_pass", "description": "ICMP Destination Unreachable (type 3) must return XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=1, payload=make_icmp(icmp_type=3, icmp_code=1))).hex(), "expected_action": "XDP_PASS"},
            {"name": "tcp_pass", "description": "TCP traffic must return XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "udp_pass", "description": "UDP traffic must return XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "arp_pass", "description": "ARP frame must return XDP_PASS", "packet_hex": make_eth(eth_type=0x0806, payload=b"\x00"*28).hex(), "expected_action": "XDP_PASS"},
            {"name": "vlan_icmp_pass", "description": "VLAN ICMP frame must return XDP_PASS", "packet_hex": make_eth(vlan=100, payload=make_ipv4(proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_icmp_pass", "description": "Truncated ICMP header must return XDP_PASS safely", "packet_hex": make_eth(payload=make_ipv4(proto=1, payload=b"\x08\x00")).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_ip_pass", "description": "Truncated IP header must return XDP_PASS safely", "packet_hex": make_eth(payload=b"\x45\x00").hex(), "expected_action": "XDP_PASS"},
            {"name": "large_echo_req_converted_tx", "description": "Large ICMP Echo Request (500B payload) converted to Reply and returns XDP_TX", "packet_hex": make_eth(dst_mac="12:34:56:78:9a:bc", src_mac="fe:dc:ba:98:76:54", payload=make_ipv4(src_ip="10.0.0.1", dst_ip="10.0.0.2", proto=1, payload=make_icmp(icmp_type=8, icmp_code=0, payload=b"A"*450))).hex(), "expected_action": "XDP_TX", "expected_bytes_hex": make_eth(dst_mac="fe:dc:ba:98:76:54", src_mac="12:34:56:78:9a:bc", payload=make_ipv4(src_ip="10.0.0.2", dst_ip="10.0.0.1", proto=1, payload=make_icmp(icmp_type=0, icmp_code=0, payload=b"A"*450))).hex()},
        ],
        main_validator="packet_bytes"
    )

    # 9. ptr_l3_vlan_pop
    add_task(
        "protocol_transformation", "level_3", "ptr_l3_vlan_pop", "xdp_vlan_pop", "xdp_head_adjust", "single_vlan_8021q+pop_vlan_tag+pass",
        "Write an XDP/eBPF program that removes exactly one 802.1Q VLAN header from single-tagged Ethernet frames using the supported XDP head-adjustment mechanism or memory shift. For single-tagged frames (eth->h_proto == bpf_htons(ETH_P_8021Q)), copy the encapsulated EtherType into the outer Ethernet header, shift Ethernet destination and source MACs 4 bytes forward (or use bpf_xdp_adjust_head(ctx, 4)), and return XDP_PASS. Pass untagged, double-tagged (QinQ), non-VLAN, and malformed frames unchanged with XDP_PASS.",
        ["Check Ethernet header bounds", "Verify eth->h_proto == bpf_htons(ETH_P_8021Q) (0x8100)", "Check VLAN header bounds (4 bytes after Ethernet header)", "Extract inner EtherType from VLAN header", "Perform 4-byte head adjustment / payload restoration", "Restore encapsulated EtherType and preserve packet payload exactly", "Return XDP_PASS for all frames", "GPL license and SEC(\"xdp\") entry point"],
        [
            {"name": "vlan100_ipv4_tcp_popped", "description": "VLAN 100 tag popped from IPv4 TCP frame, resulting in untagged frame", "packet_hex": make_eth(dst_mac="11:22:33:44:55:66", src_mac="aa:bb:cc:dd:ee:ff", vlan=100, eth_type=0x0800, payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS", "expected_bytes_hex": make_eth(dst_mac="11:22:33:44:55:66", src_mac="aa:bb:cc:dd:ee:ff", eth_type=0x0800, payload=make_ipv4(proto=6, payload=make_tcp())).hex()},
            {"name": "vlan200_ipv4_udp_popped", "description": "VLAN 200 tag popped from IPv4 UDP frame", "packet_hex": make_eth(dst_mac="52:54:00:12:34:56", src_mac="52:54:00:65:43:21", vlan=200, eth_type=0x0800, payload=make_ipv4(proto=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS", "expected_bytes_hex": make_eth(dst_mac="52:54:00:12:34:56", src_mac="52:54:00:65:43:21", eth_type=0x0800, payload=make_ipv4(proto=17, payload=make_udp())).hex()},
            {"name": "vlan100_arp_popped", "description": "VLAN 100 tag popped from ARP frame", "packet_hex": make_eth(dst_mac="ff:ff:ff:ff:ff:ff", src_mac="66:77:88:99:aa:bb", vlan=100, eth_type=0x0806, payload=b"\x00"*28).hex(), "expected_action": "XDP_PASS", "expected_bytes_hex": make_eth(dst_mac="ff:ff:ff:ff:ff:ff", src_mac="66:77:88:99:aa:bb", eth_type=0x0806, payload=b"\x00"*28).hex()},
            {"name": "untagged_tcp_pass", "description": "Untagged TCP frame preserved unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS", "expected_bytes_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex()},
            {"name": "untagged_udp_pass", "description": "Untagged UDP frame preserved unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS", "expected_bytes_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp())).hex()},
            {"name": "untagged_arp_pass", "description": "Untagged ARP frame preserved unchanged", "packet_hex": make_eth(eth_type=0x0806, payload=b"\x00"*28).hex(), "expected_action": "XDP_PASS", "expected_bytes_hex": make_eth(eth_type=0x0806, payload=b"\x00"*28).hex()},
            {"name": "qinq_pass", "description": "QinQ double-tagged frame (0x88A8) preserved unchanged", "packet_hex": make_eth(eth_type=0x88A8, payload=b"\x00\x64\x81\x00\x00\xc8\x08\x00" + make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS"},
            {"name": "truncated_vlan_pass", "description": "Truncated VLAN frame (< 18 bytes) preserved safely", "packet_hex": make_eth(eth_type=0x8100, payload=b"\x00\x64").hex(), "expected_action": "XDP_PASS"},
            {"name": "runt_frame_pass", "description": "Runt frame (14 bytes) preserved safely", "packet_hex": "525400123456525400654321ffff", "expected_action": "XDP_PASS"},
            {"name": "vlan300_ipv4_icmp_popped", "description": "VLAN 300 tag popped from IPv4 ICMP frame", "packet_hex": make_eth(dst_mac="11:22:33:44:55:66", src_mac="aa:bb:cc:dd:ee:ff", vlan=300, eth_type=0x0800, payload=make_ipv4(proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_PASS", "expected_bytes_hex": make_eth(dst_mac="11:22:33:44:55:66", src_mac="aa:bb:cc:dd:ee:ff", eth_type=0x0800, payload=make_ipv4(proto=1, payload=make_icmp())).hex()},
        ],
        main_validator="packet_bytes"
    )

    # =========================================================================
    # Write index.jsonl, assignments/calibration_v1.yaml, and README.md
    # =========================================================================
    
    # 1. index.jsonl
    index_file = CALIB_DIR / "index.jsonl"
    with index_file.open("w", encoding="utf-8") as f:
        for tm in tasks_meta:
            f.write(json.dumps(tm) + "\n")
    print(f"\n[+] Wrote {len(tasks_meta)} records to {index_file}")

    # 2. assignments/calibration_v1.yaml
    assignment_file = assignments_dir / "calibration_v1.yaml"
    assignment_lines = [
        "# BPF-Guardian Calibration Suite v1 Assignment",
        "# 36 XDP synthesis tasks (4 categories x 3 levels x 3 tasks)",
        "suite_version: \"1.0.0\"",
        f"task_count: {len(tasks_meta)}",
        "tasks:",
    ]
    for tm in tasks_meta:
        assignment_lines.append(f"  - task_id: \"{tm['task_id']}\"")
        assignment_lines.append(f"    category: \"{tm['application_category']}\"")
        assignment_lines.append(f"    difficulty: \"{tm['difficulty']}\"")
        assignment_lines.append(f"    task_family: \"{tm['task_family']}\"")
        assignment_lines.append(f"    validator: \"{tm['required_validators'][0]}\"")
        assignment_lines.append(f"    fixtures: {tm['fixture_count']}")
    assignment_file.write_text("\n".join(assignment_lines) + "\n", encoding="utf-8")
    print(f"[+] Wrote assignment file to {assignment_file}")

    # 3. README.md
    readme_file = CALIB_DIR / "README.md"
    readme_content = """# BPF-Guardian Calibration Dataset

This directory contains the **36 calibration XDP synthesis tasks** strictly isolated under `data/calibration/`.
These tasks evaluate the unmodified baseline model before dataset generation or fine-tuning.

## Structure

```text
data/calibration/
|-- README.md
|-- index.jsonl
|-- assignments/
|   `-- calibration_v1.yaml
|-- packet_filtering_security/
|   |-- level_1/
|   |   |-- pfs_l1_tcp23_drop/
|   |   |-- pfs_l1_udp53_drop/
|   |   `-- pfs_l1_icmp_echo_drop/
|   |-- level_2/
|   |   |-- pfs_l2_syn_privileged_ports/
|   |   |-- pfs_l2_source_subnet_exception/
|   |   `-- pfs_l2_vlan_tcp443/
|   `-- level_3/
|       |-- pfs_l3_source_packet_quota/
|       |-- pfs_l3_configured_blocklist/
|       `-- pfs_l3_multivector_guard/
|-- network_routing_forwarding/
|   |-- level_1/
|   |   |-- nrf_l1_udp_reflector/
|   |   |-- nrf_l1_subnet_reflector/
|   |   `-- nrf_l1_icmp_reflector/
|   |-- level_2/
|   |   |-- nrf_l2_configured_redirect/
|   |   |-- nrf_l2_protocol_redirect/
|   |   `-- nrf_l2_prefix_redirect/
|   `-- level_3/
|       |-- nrf_l3_fib_router/
|       |-- nrf_l3_policy_router/
|       `-- nrf_l3_flow_load_balancer/
|-- packet_inspection_telemetry/
|   |-- level_1/
|   |   |-- pit_l1_total_packets/
|   |   |-- pit_l1_total_bytes/
|   |   `-- pit_l1_ipv4_split/
|   |-- level_2/
|   |   |-- pit_l2_protocol_counters/
|   |   |-- pit_l2_tcp_flag_counters/
|   |   `-- pit_l2_length_histogram/
|   `-- level_3/
|       |-- pit_l3_ipv4_flow_counter/
|       |-- pit_l3_vlan_dualstack_telemetry/
|       `-- pit_l3_tcp_flow_outcomes/
`-- protocol_transformation/
    |-- level_1/
    |   |-- ptr_l1_swap_mac/
    |   |-- ptr_l1_set_destination_mac/
    |   `-- ptr_l1_set_source_mac/
    |-- level_2/
    |   |-- ptr_l2_decrement_ttl/
    |   |-- ptr_l2_rewrite_ipv4_destination/
    |   `-- ptr_l2_rewrite_udp_port/
    `-- level_3/
        |-- ptr_l3_tcp_dnat/
        |-- ptr_l3_icmp_echo_reply/
        `-- ptr_l3_vlan_pop/
```

## Taxonomy Summary

| Category | Level 1 (>=5 tests) | Level 2 (>=7 tests) | Level 3 (>=9 tests) | Total |
|---|---|---|---|---|
| `packet_filtering_security` | 3 | 3 | 3 | 9 |
| `network_routing_forwarding` | 3 | 3 | 3 | 9 |
| `packet_inspection_telemetry` | 3 | 3 | 3 | 9 |
| `protocol_transformation` | 3 | 3 | 3 | 9 |
| **Total** | **12** | **12** | **12** | **36** |

## Invariants
* **Strict Dataset Isolation**: Never copied into SFT, RL, preference, or final benchmark splits.
* **No Gold Candidates**: No `c00.c` or reference answers generated in this phase.
* **Deterministic Fixtures**: All test vectors stored as reproducible `.bin` files and exact JSON contracts.
"""
    readme_file.write_text(readme_content, encoding="utf-8")
    print(f"[+] Wrote {readme_file}")


if __name__ == "__main__":
    main()
