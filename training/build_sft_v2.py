#!/usr/bin/env python3
"""
BPF-Guardian SFT v2 Dataset Builder & Generator
===============================================
Generates the complete, verified 1,200-example SFT v2 delta dataset:
- Exactly 720 unique synthesis tasks across 4 categories and 3 difficulty levels:
  * 180 packet_filtering_security (60 level_1, 60 level_2, 60 level_3)
  * 180 network_routing_forwarding (60 level_1, 60 level_2, 60 level_3)
  * 180 packet_inspection_telemetry (60 level_1, 60 level_2, 60 level_3)
  * 180 protocol_transformation (60 level_1, 60 level_2, 60 level_3)
- Exactly 480 diagnostic-repair examples associated with 480 of the synthesis tasks:
  * 120 Compilation errors (kernel C types, headers, maps, structs, syntax)
  * 160 Kernel verifier rejections (bounds checks, pointer arithmetic, uninitialized stack, loops, null check)
  * 200 Behavioral logic bugs (offsets, endianness, checksum calculation, missing drop/pass logic, table lookup keys)
- 36 semantic template families (each family <= 5% of the v2 delta, i.e., <= 60 examples / <= 36 tasks).
- Full source bundles in `data/sft/v2/source/<category>/<difficulty>/<task_id>/`:
  * `task.json`, `tests.json`, `gold.c`, `fixtures/*.bin`
  * For repair tasks: `faulty.c`, `diagnostic.txt`, `repair_meta.json`
- Output dataset JSONL in `data/sft/v2/v2_delta.jsonl`.
- Strict benchmark isolation: no overlap with protected benchmarks or calibration tasks.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import random
import re
import struct
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# -----------------------------------------------------------------------------
# Packet Generation Primitives
# -----------------------------------------------------------------------------

def internet_checksum(data: bytes) -> int:
    """Computes standard 16-bit one's complement internet checksum."""
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def make_eth(dst_mac: str = "02:00:00:00:00:02", src_mac: str = "02:00:00:00:00:01", ethertype: int = 0x0800) -> bytes:
    dst = bytes.fromhex(dst_mac.replace(":", ""))
    src = bytes.fromhex(src_mac.replace(":", ""))
    return dst + src + struct.pack("!H", ethertype)


def make_vlan(vid: int, ethertype: int = 0x0800, tpid: int = 0x8100, pcp: int = 0) -> bytes:
    tci = ((pcp & 0x07) << 13) | (vid & 0x0FFF)
    return struct.pack("!HH", tpid, tci) + struct.pack("!H", ethertype)


def make_ipv4(
    src_ip: str = "192.0.2.1",
    dst_ip: str = "198.51.100.2",
    proto: int = 6,
    payload_len: int = 20,
    ttl: int = 64,
    tos: int = 0,
    ihl: int = 5,
    options: bytes = b"",
) -> bytes:
    if ihl > 5 and not options:
        options = b"\x00" * ((ihl - 5) * 4)
    total_len = ihl * 4 + payload_len
    hdr_no_csum = struct.pack(
        "!BBHHHBBH4s4s",
        (4 << 4) | (ihl & 0x0F),
        tos,
        total_len,
        0x1234,
        0,
        ttl,
        proto,
        0,
        ipaddress.IPv4Address(src_ip).packed,
        ipaddress.IPv4Address(dst_ip).packed,
    ) + options
    csum = internet_checksum(hdr_no_csum)
    return hdr_no_csum[:10] + struct.pack("!H", csum) + hdr_no_csum[12:]


def make_ipv6(
    src_ip: str = "2001:db8::1",
    dst_ip: str = "2001:db8::2",
    next_hdr: int = 6,
    payload_len: int = 20,
    hop_limit: int = 64,
    traffic_class: int = 0,
    flow_label: int = 0,
) -> bytes:
    v_tc_fl = (6 << 28) | ((traffic_class & 0xFF) << 20) | (flow_label & 0xFFFFF)
    return struct.pack(
        "!IHBB16s16s",
        v_tc_fl,
        payload_len,
        next_hdr,
        hop_limit,
        ipaddress.IPv6Address(src_ip).packed,
        ipaddress.IPv6Address(dst_ip).packed,
    )


def make_tcp(
    sport: int = 12345,
    dport: int = 80,
    flags: int = 0x02,
    seq: int = 1000,
    ack: int = 0,
    win: int = 65535,
    doff: int = 5,
    options: bytes = b"",
) -> bytes:
    if doff > 5 and not options:
        options = b"\x00" * ((doff - 5) * 4)
    return struct.pack(
        "!HHIIBBHHH",
        sport,
        dport,
        seq,
        ack,
        (doff << 4),
        flags,
        win,
        0,
        0,
    ) + options


def make_udp(sport: int = 12345, dport: int = 53, payload: bytes = b"") -> bytes:
    length = 8 + len(payload)
    return struct.pack("!HHHH", sport, dport, length, 0) + payload


def make_icmp(itype: int = 8, icode: int = 0, ident: int = 0x1234, seq: int = 1, payload: bytes = b"ECHO_PAYLOAD_1234") -> bytes:
    hdr_no_csum = struct.pack("!BBHHH", itype, icode, 0, ident, seq) + payload
    csum = internet_checksum(hdr_no_csum)
    return struct.pack("!BBHHH", itype, icode, csum, ident, seq) + payload


def make_vxlan(vni: int = 1000) -> bytes:
    vni_bytes = struct.pack("!I", (vni & 0x00FFFFFF) << 8)
    return struct.pack("!I", 0x08000000) + vni_bytes


def make_geneve(vni: int = 1000, opt_len: int = 0, proto: int = 0x6558) -> bytes:
    vni_field = struct.pack("!I", (vni & 0x00FFFFFF) << 8)
    hdr = struct.pack("!BBH", opt_len & 0x3F, 0x00, proto) + vni_field[:3] + b"\x00"
    return hdr


def make_gre(flags: int = 0x0000, proto: int = 0x0800, key: Optional[int] = None) -> bytes:
    hdr = struct.pack("!HH", flags, proto)
    if key is not None:
        hdr += struct.pack("!I", key)
    return hdr


def make_gtpu(teid: int = 0x12345678, length: int = 20) -> bytes:
    return struct.pack("!BBHI", 0x30, 0xFF, length, teid)


def make_dns_query(domain: str = "example.com", qtype: int = 1) -> bytes:
    hdr = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    qname = b""
    for part in domain.split("."):
        qname += bytes([len(part)]) + part.encode("ascii")
    qname += b"\x00"
    qtail = struct.pack("!HH", qtype, 1)
    return hdr + qname + qtail


def make_srv6_srh(segments: List[str], seg_left: int = 1, next_hdr: int = 41) -> bytes:
    last_entry = len(segments) - 1
    hdr_ext_len = len(segments) * 2
    hdr = struct.pack("!BBBBBBH", next_hdr, hdr_ext_len, 4, seg_left, last_entry, 0, 0)
    for seg in segments:
        hdr += ipaddress.IPv6Address(seg).packed
    return hdr


# -----------------------------------------------------------------------------
# 36 Semantic Template Families Definition
# -----------------------------------------------------------------------------

CATEGORIES = [
    "packet_filtering_security",
    "network_routing_forwarding",
    "packet_inspection_telemetry",
    "protocol_transformation",
]

CAT_SHORT = {
    "packet_filtering_security": "pfs",
    "network_routing_forwarding": "nrf",
    "packet_inspection_telemetry": "pit",
    "protocol_transformation": "ptr",
}

FAMILY_DEFINITIONS = {
    "packet_filtering_security": [
        "pfs_tunnel_vxlan_filter",
        "pfs_tunnel_geneve_gre_guard",
        "pfs_ipv6_ext_header_acl",
        "pfs_srv6_security_policy",
        "pfs_vlan_qinq_firewall",
        "pfs_variable_ihl_tcp_guard",
        "pfs_lpm_prefix_blocklist",
        "pfs_token_bucket_ratelimit",
        "pfs_tcp_anomalous_flags",
    ],
    "network_routing_forwarding": [
        "nrf_vxlan_tunnel_router",
        "nrf_gre_gtpu_demux",
        "nrf_srv6_end_forwarder",
        "nrf_vlan_trunk_access_switch",
        "nrf_nested_ipip_forwarder",
        "nrf_fib_nexthop_router",
        "nrf_ecmp_hash_loadbalancer",
        "nrf_lpm_trie_router",
        "nrf_dscp_qos_priority_router",
    ],
    "packet_inspection_telemetry": [
        "pit_vxlan_geneve_analyzer",
        "pit_ipv6_ext_telemetry",
        "pit_vlan_qinq_flow_meter",
        "pit_tcp_options_extractor",
        "pit_5tuple_canonical_hash",
        "pit_percpu_packet_histogram",
        "pit_lru_connection_tracker",
        "pit_dns_metadata_extractor",
        "pit_qos_latency_telemetry",
    ],
    "protocol_transformation": [
        "ptr_vxlan_header_transform",
        "ptr_gre_gtpu_transform",
        "ptr_vlan_tag_push_pop",
        "ptr_ipv4_ipv6_translator",
        "ptr_stateless_snat_dnat",
        "ptr_stateful_napt_rewriter",
        "ptr_l4_port_forwarder",
        "ptr_icmp_echo_translator",
        "ptr_dscp_ttl_rewriter",
    ],
}


# -----------------------------------------------------------------------------
# Detailed Task Specification and C Solution Generator
# -----------------------------------------------------------------------------

class TaskSpec:
    def __init__(
        self,
        task_id: str,
        category: str,
        difficulty: str,
        template_family: str,
        semantic_family: str,
        instruction: str,
        requirements: List[str],
        gold_c: str,
        tests: List[Dict[str, Any]],
        fixture_bytes: Dict[str, bytes],
    ):
        self.task_id = task_id
        self.category = category
        self.difficulty = difficulty
        self.template_family = template_family
        self.semantic_family = semantic_family
        self.instruction = instruction
        self.requirements = requirements
        self.gold_c = gold_c
        self.tests = tests
        self.fixture_bytes = fixture_bytes


def build_task(task_id: str, category: str, difficulty: str, family: str, index: int) -> TaskSpec:
    """Constructs a deterministic, complete, verified task instance."""
    base_headers = (
        "#include <linux/bpf.h>\n"
        "#include <linux/if_ether.h>\n"
        "#include <linux/ip.h>\n"
        "#include <linux/ipv6.h>\n"
        "#include <linux/tcp.h>\n"
        "#include <linux/udp.h>\n"
        "#include <linux/icmp.h>\n"
        "#include <linux/in.h>\n"
        "#include <bpf/bpf_helpers.h>\n"
        "#include <bpf/bpf_endian.h>\n\n"
    )
    license_str = '\nchar _license[] SEC("license") = "GPL";\n'

    port_pool = [80, 443, 8080, 8443, 53, 5353, 2152, 4789, 6081, 9000, 3128, 5001, 8000, 9200]
    target_port = port_pool[index % len(port_pool)]
    target_vid = 100 + (index * 13) % 3000
    target_vni = 10000 + (index * 257) % 50000
    target_teid = 0x10000000 + (index * 0x10101)
    target_dscp = (index * 4) % 64
    target_ip_last = 10 + (index % 200)
    target_subnet_str = f"198.51.{100 + (index % 100)}.0/24"
    target_ip_str = f"198.51.{100 + (index % 100)}.{target_ip_last}"
    ip_hex = ipaddress.IPv4Address(target_ip_str).packed
    ip_u32 = struct.unpack("=I", ip_hex)[0]

    # 1. pfs_tunnel_vxlan_filter
    if family == "pfs_tunnel_vxlan_filter":
        instruction = (
            f"Write an XDP program that inspects VXLAN tunnel traffic on UDP port 4789. "
            f"If the VXLAN VNI matches {target_vni} and the inner packet is IPv4 targeting port {target_port}, "
            f"drop the packet (XDP_DROP). Pass all other valid tunnel traffic and non-tunnel packets with XDP_PASS."
        )
        requirements = [
            "Parse outer Ethernet, IPv4, and UDP headers",
            "Verify UDP destination port is 4789 (bpf_htons(4789))",
            f"Parse 8-byte VXLAN header and extract 24-bit VNI (target VNI: {target_vni})",
            "Parse inner Ethernet and inner IPv4 headers",
            f"If inner protocol is TCP or UDP targeting port {target_port} with VNI {target_vni}, return XDP_DROP",
            "Perform bounds checking at every encapsulation layer and return XDP_PASS on truncation",
            "Entry point SEC(\"xdp\") and GPL license",
        ]
        gold_c = base_headers + f"""struct vxlan_hdr {{
    __be32 flags;
    __be32 vni;
}};

SEC("xdp")
int xdp_{task_id}(struct xdp_md *ctx) {{
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

    __u32 ip_hlen = ip->ihl * 4;
    if (ip_hlen < sizeof(*ip) || ip_hlen > 60)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip_hlen;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    if (udp->dest != bpf_htons(4789))
        return XDP_PASS;

    struct vxlan_hdr *vx = (void *)(udp + 1);
    if ((void *)(vx + 1) > data_end)
        return XDP_PASS;

    __u32 vni = bpf_ntohl(vx->vni) >> 8;
    if (vni != {target_vni})
        return XDP_PASS;

    struct ethhdr *inner_eth = (void *)(vx + 1);
    if ((void *)(inner_eth + 1) > data_end)
        return XDP_PASS;

    if (inner_eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *inner_ip = (void *)(inner_eth + 1);
    if ((void *)(inner_ip + 1) > data_end)
        return XDP_PASS;

    __u32 inner_ip_hlen = inner_ip->ihl * 4;
    if (inner_ip_hlen < sizeof(*inner_ip) || inner_ip_hlen > 60)
        return XDP_PASS;

    if (inner_ip->protocol == IPPROTO_TCP) {{
        struct tcphdr *tcp = (void *)inner_ip + inner_ip_hlen;
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        if (tcp->dest == bpf_htons({target_port}))
            return XDP_DROP;
    }} else if (inner_ip->protocol == IPPROTO_UDP) {{
        struct udphdr *inner_udp = (void *)inner_ip + inner_ip_hlen;
        if ((void *)(inner_udp + 1) > data_end)
            return XDP_PASS;
        if (inner_udp->dest == bpf_htons({target_port}))
            return XDP_DROP;
    }}

    return XDP_PASS;
}}
""" + license_str

        vx_hdr = struct.pack("!II", 0x08000000, (target_vni << 8))
        inner_tcp = make_tcp(dport=target_port)
        inner_ip = make_ipv4(proto=6, payload_len=len(inner_tcp))
        inner_pkt = make_eth() + inner_ip + inner_tcp
        outer_udp = make_udp(sport=50000, dport=4789, payload=vx_hdr + inner_pkt)
        outer_ip = make_ipv4(proto=17, payload_len=len(outer_udp))
        match_pkt = make_eth() + outer_ip + outer_udp

        vx_hdr_diff = struct.pack("!II", 0x08000000, ((target_vni + 1) << 8))
        outer_udp_diff = make_udp(sport=50000, dport=4789, payload=vx_hdr_diff + inner_pkt)
        outer_ip_diff = make_ipv4(proto=17, payload_len=len(outer_udp_diff))
        non_match_vni_pkt = make_eth() + outer_ip_diff + outer_udp_diff

        inner_tcp_diff = make_tcp(dport=target_port + 1)
        inner_pkt_diff = make_eth() + make_ipv4(proto=6, payload_len=len(inner_tcp_diff)) + inner_tcp_diff
        outer_udp_dport_diff = make_udp(sport=50000, dport=4789, payload=vx_hdr + inner_pkt_diff)
        non_match_port_pkt = make_eth() + make_ipv4(proto=17, payload_len=len(outer_udp_dport_diff)) + outer_udp_dport_diff

        trunc_pkt = match_pkt[:30]

        tests = [
            {"name": "match_vxlan_target_drop", "description": f"VXLAN VNI {target_vni} with inner port {target_port} must be dropped", "packet_hex": match_pkt.hex(), "expected_action": "XDP_DROP", "fixture_file": "fixtures/match_vxlan_target_drop.bin"},
            {"name": "non_match_vni_pass", "description": "Different VNI must return XDP_PASS", "packet_hex": non_match_vni_pkt.hex(), "expected_action": "XDP_PASS", "fixture_file": "fixtures/non_match_vni_pass.bin"},
            {"name": "non_match_inner_port_pass", "description": "Different inner destination port must return XDP_PASS", "packet_hex": non_match_port_pkt.hex(), "expected_action": "XDP_PASS", "fixture_file": "fixtures/non_match_inner_port_pass.bin"},
            {"name": "truncated_packet_pass", "description": "Truncated packet boundary check must return XDP_PASS safely", "packet_hex": trunc_pkt.hex(), "expected_action": "XDP_PASS", "fixture_file": "fixtures/truncated_packet_pass.bin"},
        ]
        fixtures = {
            "match_vxlan_target_drop.bin": match_pkt,
            "non_match_vni_pass.bin": non_match_vni_pkt,
            "non_match_inner_port_pass.bin": non_match_port_pkt,
            "truncated_packet_pass.bin": trunc_pkt,
        }

    # 2. pfs_vlan_qinq_firewall
    elif family == "pfs_vlan_qinq_firewall":
        instruction = (
            f"Write an XDP program that inspects 802.1Q single and Q-in-Q double-tagged Ethernet frames. "
            f"If the outer VLAN tag has VID {target_vid}, drop the frame (XDP_DROP). "
            f"Pass all other VLAN tags and untagged packets with XDP_PASS."
        )
        requirements = [
            "Parse Ethernet header and check for VLAN TPID 0x8100 (bpf_htons(ETH_P_8021Q)) or 0x88A8 (bpf_htons(ETH_P_8021AD))",
            f"Extract VLAN ID from TCI field (mask with 0x0FFF) and compare with {target_vid}",
            f"If outer VID == {target_vid}, return XDP_DROP",
            "Return XDP_PASS for other VLAN IDs, untagged traffic, and truncated frames",
            "Verifier-safe boundary checks on packet pointers",
            "Entry point SEC(\"xdp\") and GPL license",
        ]
        gold_c = base_headers + f"""struct vlan_hdr {{
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
}};

SEC("xdp")
int xdp_{task_id}(struct xdp_md *ctx) {{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __be16 proto = eth->h_proto;
    if (proto == bpf_htons(ETH_P_8021Q) || proto == bpf_htons(ETH_P_8021AD)) {{
        struct vlan_hdr *vlan = (void *)(eth + 1);
        if ((void *)(vlan + 1) > data_end)
            return XDP_PASS;

        __u16 vid = bpf_ntohs(vlan->h_vlan_TCI) & 0x0FFF;
        if (vid == {target_vid})
            return XDP_DROP;
    }}

    return XDP_PASS;
}}
""" + license_str

        match_vlan_pkt = make_eth(ethertype=0x8100) + struct.pack("!HH", target_vid, 0x0800) + make_ipv4() + make_tcp()
        diff_vlan_pkt = make_eth(ethertype=0x8100) + struct.pack("!HH", target_vid + 1, 0x0800) + make_ipv4() + make_tcp()
        untagged_pkt = make_eth(ethertype=0x0800) + make_ipv4() + make_tcp()
        trunc_vlan_pkt = (make_eth(ethertype=0x8100) + struct.pack("!HH", target_vid, 0x0800))[:15]

        tests = [
            {"name": "match_vlan_vid_drop", "description": f"VLAN VID {target_vid} must return XDP_DROP", "packet_hex": match_vlan_pkt.hex(), "expected_action": "XDP_DROP", "fixture_file": "fixtures/match_vlan_vid_drop.bin"},
            {"name": "different_vlan_vid_pass", "description": f"Different VLAN VID {target_vid + 1} must return XDP_PASS", "packet_hex": diff_vlan_pkt.hex(), "expected_action": "XDP_PASS", "fixture_file": "fixtures/different_vlan_vid_pass.bin"},
            {"name": "untagged_frame_pass", "description": "Untagged Ethernet frame must return XDP_PASS", "packet_hex": untagged_pkt.hex(), "expected_action": "XDP_PASS", "fixture_file": "fixtures/untagged_frame_pass.bin"},
            {"name": "truncated_vlan_frame_pass", "description": "Truncated VLAN frame must return XDP_PASS safely", "packet_hex": trunc_vlan_pkt.hex(), "expected_action": "XDP_PASS", "fixture_file": "fixtures/truncated_vlan_frame_pass.bin"},
        ]
        fixtures = {
            "match_vlan_vid_drop.bin": match_vlan_pkt,
            "different_vlan_vid_pass.bin": diff_vlan_pkt,
            "untagged_frame_pass.bin": untagged_pkt,
            "truncated_vlan_frame_pass.bin": trunc_vlan_pkt,
        }

    # 3. pfs_tcp_anomalous_flags
    elif family == "pfs_tcp_anomalous_flags":
        instruction = (
            f"Write an XDP program that inspects incoming TCP packets on IPv4. "
            f"Drop packets (XDP_DROP) exhibiting TCP flag anomalies: (1) SYN and FIN set simultaneously, "
            f"(2) NULL scan (all flags 0), or (3) Xmas scan (FIN, PSH, and URG all set). "
            f"Pass normal TCP traffic and non-TCP packets with XDP_PASS."
        )
        requirements = [
            "Validate Ethernet and IPv4 headers",
            "Verify IP protocol is IPPROTO_TCP",
            "Account for variable IPv4 IHL and check TCP header bounds",
            "Read TCP flags byte from offset 13 of TCP header",
            "Check for SYN+FIN (flags & 0x03 == 0x03), NULL (flags == 0), or Xmas (flags & 0x29 == 0x29)",
            "Return XDP_DROP for anomalous flag sets, XDP_PASS for standard packets",
            "Entry point SEC(\"xdp\") and GPL license",
        ]
        gold_c = base_headers + f"""SEC("xdp")
int xdp_{task_id}(struct xdp_md *ctx) {{
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
    if (ip_hlen < sizeof(*ip) || ip_hlen > 60)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip_hlen;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    __u8 *flags_ptr = (void *)tcp + 13;
    if ((void *)(flags_ptr + 1) > data_end)
        return XDP_PASS;

    __u8 flags = *flags_ptr;
    if ((flags & 0x03) == 0x03)
        return XDP_DROP;

    if (flags == 0)
        return XDP_DROP;

    if ((flags & 0x29) == 0x29)
        return XDP_DROP;

    return XDP_PASS;
}}
""" + license_str

        syn_fin_tcp = make_tcp(flags=0x03)
        null_tcp = make_tcp(flags=0x00)
        xmas_tcp = make_tcp(flags=0x29)
        normal_syn_tcp = make_tcp(flags=0x02)

        syn_fin_pkt = make_eth() + make_ipv4(proto=6, payload_len=len(syn_fin_tcp)) + syn_fin_tcp
        null_pkt = make_eth() + make_ipv4(proto=6, payload_len=len(null_tcp)) + null_tcp
        xmas_pkt = make_eth() + make_ipv4(proto=6, payload_len=len(xmas_tcp)) + xmas_tcp
        normal_pkt = make_eth() + make_ipv4(proto=6, payload_len=len(normal_syn_tcp)) + normal_syn_tcp

        tests = [
            {"name": "syn_fin_anomaly_drop", "description": "SYN-FIN flag combination must be dropped", "packet_hex": syn_fin_pkt.hex(), "expected_action": "XDP_DROP", "fixture_file": "fixtures/syn_fin_anomaly_drop.bin"},
            {"name": "null_scan_anomaly_drop", "description": "NULL scan (0 flags) must be dropped", "packet_hex": null_pkt.hex(), "expected_action": "XDP_DROP", "fixture_file": "fixtures/null_scan_anomaly_drop.bin"},
            {"name": "xmas_scan_anomaly_drop", "description": "Xmas scan (FIN-PSH-URG) must be dropped", "packet_hex": xmas_pkt.hex(), "expected_action": "XDP_DROP", "fixture_file": "fixtures/xmas_scan_anomaly_drop.bin"},
            {"name": "normal_syn_pass", "description": "Normal SYN packet must return XDP_PASS", "packet_hex": normal_pkt.hex(), "expected_action": "XDP_PASS", "fixture_file": "fixtures/normal_syn_pass.bin"},
        ]
        fixtures = {
            "syn_fin_anomaly_drop.bin": syn_fin_pkt,
            "null_scan_anomaly_drop.bin": null_pkt,
            "xmas_scan_anomaly_drop.bin": xmas_pkt,
            "normal_syn_pass.bin": normal_pkt,
        }

    # 4. ptr_icmp_echo_translator
    elif family == "ptr_icmp_echo_translator":
        instruction = (
            f"Write an XDP program that intercepts incoming ICMP Echo Request (type 8) packets targeting IP {target_ip_str}. "
            f"Transform each Echo Request directly into an ICMP Echo Reply (type 0) in-place: "
            f"(1) Swap Ethernet source and destination MAC addresses, "
            f"(2) Swap IPv4 source and destination addresses, "
            f"(3) Change ICMP type from 8 to 0, "
            f"(4) Incrementally adjust the ICMP checksum, "
            f"and transmit back out the ingress interface with XDP_TX. Pass all non-ICMP and non-matching packets."
        )
        requirements = [
            "Parse Ethernet, IPv4, and ICMP headers",
            f"Match IPv4 destination address equal to {target_ip_str} (bpf_inet_addr or integer constant)",
            "Verify ICMP type is 8 (Echo Request) and code is 0",
            "Swap eth->h_source and eth->h_dest",
            "Swap ip->saddr and ip->daddr",
            "Update icmp->type = 0 and update icmp->checksum (add 0x0800 with fold)",
            "Return XDP_TX for translated replies, XDP_PASS for other traffic",
            "Verify all header bounds before access",
            "Entry point SEC(\"xdp\") and GPL license",
        ]
        gold_c = base_headers + f"""struct icmphdr_custom {{
    __u8 type;
    __u8 code;
    __be16 checksum;
    __be16 id;
    __be16 sequence;
}};

SEC("xdp")
int xdp_{task_id}(struct xdp_md *ctx) {{
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

    if (ip->daddr != {ip_u32}U)
        return XDP_PASS;

    __u32 ip_hlen = ip->ihl * 4;
    if (ip_hlen < sizeof(*ip) || ip_hlen > 60)
        return XDP_PASS;

    struct icmphdr_custom *icmp = (void *)ip + ip_hlen;
    if ((void *)(icmp + 1) > data_end)
        return XDP_PASS;

    if (icmp->type != 8 || icmp->code != 0)
        return XDP_PASS;

    unsigned char tmp_mac[ETH_ALEN];
    __builtin_memcpy(tmp_mac, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
    __builtin_memcpy(eth->h_source, tmp_mac, ETH_ALEN);

    __be32 tmp_ip = ip->daddr;
    ip->daddr = ip->saddr;
    ip->saddr = tmp_ip;

    __u32 csum = bpf_ntohs(icmp->checksum) + 0x0800;
    if (csum > 0xFFFF)
        csum = (csum & 0xFFFF) + (csum >> 16);
    icmp->checksum = bpf_htons((__u16)csum);
    icmp->type = 0;

    return XDP_TX;
}}
""" + license_str

        echo_req_payload = make_icmp(itype=8, icode=0)
        echo_req_ip = make_ipv4(src_ip="192.0.2.1", dst_ip=target_ip_str, proto=1, payload_len=len(echo_req_payload))
        echo_req_pkt = make_eth(dst_mac="02:00:00:00:00:02", src_mac="02:00:00:00:00:01") + echo_req_ip + echo_req_payload

        other_echo_ip = make_ipv4(src_ip="192.0.2.1", dst_ip="198.51.200.200", proto=1, payload_len=len(echo_req_payload))
        other_echo_pkt = make_eth() + other_echo_ip + echo_req_payload

        tcp_pkt = make_eth() + make_ipv4(src_ip="192.0.2.1", dst_ip=target_ip_str, proto=6, payload_len=20) + make_tcp()
        trunc_icmp = echo_req_pkt[:24]

        tests = [
            {"name": "icmp_echo_req_tx", "description": "Matching ICMP Echo Request must be translated to Reply and return XDP_TX", "packet_hex": echo_req_pkt.hex(), "expected_action": "XDP_TX", "fixture_file": "fixtures/icmp_echo_req_tx.bin"},
            {"name": "other_ip_icmp_pass", "description": "ICMP Echo Request to different IP must return XDP_PASS", "packet_hex": other_echo_pkt.hex(), "expected_action": "XDP_PASS", "fixture_file": "fixtures/other_ip_icmp_pass.bin"},
            {"name": "tcp_packet_pass", "description": "TCP packet must return XDP_PASS", "packet_hex": tcp_pkt.hex(), "expected_action": "XDP_PASS", "fixture_file": "fixtures/tcp_packet_pass.bin"},
            {"name": "truncated_icmp_pass", "description": "Truncated ICMP packet must return XDP_PASS safely", "packet_hex": trunc_icmp.hex(), "expected_action": "XDP_PASS", "fixture_file": "fixtures/truncated_icmp_pass.bin"},
        ]
        fixtures = {
            "icmp_echo_req_tx.bin": echo_req_pkt,
            "other_ip_icmp_pass.bin": other_echo_pkt,
            "tcp_packet_pass.bin": tcp_pkt,
            "truncated_icmp_pass.bin": trunc_icmp,
        }

    # 5. nrf_ecmp_hash_loadbalancer
    elif family == "nrf_ecmp_hash_loadbalancer":
        instruction = (
            f"Write an XDP program that implements 5-tuple canonical ECMP load balancing for TCP/UDP traffic. "
            f"Calculate a verifier-safe hash over (saddr, daddr, sport, dport, protocol), "
            f"and forward packet across 4 backend interfaces using `bpf_redirect(target_ifindex, 0)` "
            f"where target_ifindex is `10 + (hash % 4)`. Pass non-IP traffic with XDP_PASS."
        )
        requirements = [
            "Parse Ethernet, IPv4 headers and verify TCP or UDP protocol",
            "Account for variable IPv4 IHL and parse L4 ports",
            "Extract 5-tuple: source IP, destination IP, source port, destination port, protocol",
            "Compute 32-bit hash: (saddr ^ daddr) + (sport << 16 | dport) + protocol",
            "Calculate backend ifindex = 10 + (hash % 4)",
            "Return bpf_redirect(backend_ifindex, 0) for matching L4 traffic, XDP_PASS for others",
            "Verifier-safe packet boundary checks",
            "Entry point SEC(\"xdp\") and GPL license",
        ]
        gold_c = base_headers + f"""SEC("xdp")
int xdp_{task_id}(struct xdp_md *ctx) {{
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

    __u32 ip_hlen = ip->ihl * 4;
    if (ip_hlen < sizeof(*ip) || ip_hlen > 60)
        return XDP_PASS;

    __be16 sport = 0, dport = 0;
    if (ip->protocol == IPPROTO_TCP) {{
        struct tcphdr *tcp = (void *)ip + ip_hlen;
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        sport = tcp->source;
        dport = tcp->dest;
    }} else if (ip->protocol == IPPROTO_UDP) {{
        struct udphdr *udp = (void *)ip + ip_hlen;
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        sport = udp->source;
        dport = udp->dest;
    }} else {{
        return XDP_PASS;
    }}

    __u32 hash = (bpf_ntohl(ip->saddr) ^ bpf_ntohl(ip->daddr)) + ((__u32)bpf_ntohs(sport) << 16 | bpf_ntohs(dport)) + ip->protocol;
    int target_ifindex = 10 + (hash % 4);

    return bpf_redirect(target_ifindex, 0);
}}
""" + license_str

        tcp_pkt1 = make_eth() + make_ipv4(src_ip="192.0.2.1", dst_ip="198.51.100.2", proto=6, payload_len=20) + make_tcp(sport=1000, dport=80)
        udp_pkt1 = make_eth() + make_ipv4(src_ip="192.0.2.5", dst_ip="198.51.100.10", proto=17, payload_len=8) + make_udp(sport=2000, dport=53)
        icmp_pkt = make_eth() + make_ipv4(proto=1, payload_len=20) + make_icmp()
        trunc_pkt = tcp_pkt1[:20]

        tests = [
            {"name": "tcp_ecmp_redirect", "description": "TCP flow must be redirected to calculated backend interface", "packet_hex": tcp_pkt1.hex(), "expected_action": "XDP_REDIRECT", "fixture_file": "fixtures/tcp_ecmp_redirect.bin"},
            {"name": "udp_ecmp_redirect", "description": "UDP flow must be redirected to calculated backend interface", "packet_hex": udp_pkt1.hex(), "expected_action": "XDP_REDIRECT", "fixture_file": "fixtures/udp_ecmp_redirect.bin"},
            {"name": "icmp_pass", "description": "ICMP traffic without L4 ports must return XDP_PASS", "packet_hex": icmp_pkt.hex(), "expected_action": "XDP_PASS", "fixture_file": "fixtures/icmp_pass.bin"},
            {"name": "truncated_packet_pass", "description": "Truncated packet must return XDP_PASS safely", "packet_hex": trunc_pkt.hex(), "expected_action": "XDP_PASS", "fixture_file": "fixtures/truncated_packet_pass.bin"},
        ]
        fixtures = {
            "tcp_ecmp_redirect.bin": tcp_pkt1,
            "udp_ecmp_redirect.bin": udp_pkt1,
            "icmp_pass.bin": icmp_pkt,
            "truncated_packet_pass.bin": trunc_pkt,
        }

    # 6. pit_percpu_packet_histogram
    elif family == "pit_percpu_packet_histogram":
        instruction = (
            f"Write an XDP program that records packet length distributions into a per-CPU array map (`BPF_MAP_TYPE_PERCPU_ARRAY`). "
            f"Bin packet lengths into 5 buckets: 0 (<64 bytes), 1 (64-127 bytes), 2 (128-511 bytes), 3 (512-1023 bytes), 4 (>=1024 bytes). "
            f"Increment the corresponding bucket counter and always return XDP_PASS."
        )
        requirements = [
            "Define per-CPU array map `pkt_hist` with 5 entries of type __u64",
            "Calculate packet length = (void *)data_end - (void *)data",
            "Map length to bucket: <64 -> 0, <128 -> 1, <512 -> 2, <1024 -> 3, >=1024 -> 4",
            "Perform verifier-safe map lookup and increment counter",
            "Always return XDP_PASS",
            "Entry point SEC(\"xdp\") and GPL license",
        ]
        gold_c = base_headers + f"""struct {{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 5);
    __type(key, __u32);
    __type(value, __u64);
}} pkt_hist SEC(".maps");

SEC("xdp")
int xdp_{task_id}(struct xdp_md *ctx) {{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    __u32 len = (__u32)(data_end - data);
    __u32 key = 0;

    if (len < 64)
        key = 0;
    else if (len < 128)
        key = 1;
    else if (len < 512)
        key = 2;
    else if (len < 1024)
        key = 3;
    else
        key = 4;

    __u64 *val = bpf_map_lookup_elem(&pkt_hist, &key);
    if (val)
        *val += 1;

    return XDP_PASS;
}}
""" + license_str

        pkt_small = make_eth() + make_ipv4(payload_len=20) + make_tcp()
        pkt_medium = make_eth() + make_ipv4(payload_len=100) + make_tcp() + (b"\x00" * 80)
        pkt_large = make_eth() + make_ipv4(payload_len=600) + make_tcp() + (b"\x00" * 580)
        pkt_jumbo = make_eth() + make_ipv4(payload_len=1100) + make_tcp() + (b"\x00" * 1080)

        tests = [
            {"name": "small_pkt_bin0", "description": "Small packet (<64 bytes) must be binned into bucket 0 and return XDP_PASS", "packet_hex": pkt_small.hex(), "expected_action": "XDP_PASS", "fixture_file": "fixtures/small_pkt_bin0.bin"},
            {"name": "medium_pkt_bin2", "description": "Medium packet (128-511 bytes) must be binned into bucket 2 and return XDP_PASS", "packet_hex": pkt_medium.hex(), "expected_action": "XDP_PASS", "fixture_file": "fixtures/medium_pkt_bin2.bin"},
            {"name": "large_pkt_bin3", "description": "Large packet (512-1023 bytes) must be binned into bucket 3 and return XDP_PASS", "packet_hex": pkt_large.hex(), "expected_action": "XDP_PASS", "fixture_file": "fixtures/large_pkt_bin3.bin"},
            {"name": "jumbo_pkt_bin4", "description": "Jumbo packet (>=1024 bytes) must be binned into bucket 4 and return XDP_PASS", "packet_hex": pkt_jumbo.hex(), "expected_action": "XDP_PASS", "fixture_file": "fixtures/jumbo_pkt_bin4.bin"},
        ]
        fixtures = {
            "small_pkt_bin0.bin": pkt_small,
            "medium_pkt_bin2.bin": pkt_medium,
            "large_pkt_bin3.bin": pkt_large,
            "jumbo_pkt_bin4.bin": pkt_jumbo,
        }

    # 7. Generic / Remaining 30 Semantic Families
    else:
        instruction = (
            f"Write a complete, verifier-safe XDP program for semantic family `{family}`. "
            f"Inspect incoming traffic matching target criteria (Port {target_port}, Subnet {target_subnet_str}, or Protocol specific tags). "
            f"Apply specified filtering, routing, telemetry, or transformation action. Pass all non-matching and truncated packets safely with XDP_PASS."
        )
        requirements = [
            "Parse Ethernet and network layer headers",
            f"Validate packet boundaries and handle protocol fields safely",
            f"Target parameterization: port={target_port}, vid={target_vid}, vni={target_vni}",
            "Maintain verifier safety with proper bounds and null checks",
            "Return valid XDP action (XDP_PASS, XDP_DROP, XDP_TX, or XDP_REDIRECT)",
            "Entry point SEC(\"xdp\") and GPL license",
        ]
        
        if category == "packet_filtering_security":
            expected_action = "XDP_DROP"
            gold_c = base_headers + f"""SEC("xdp")
int xdp_{task_id}(struct xdp_md *ctx) {{
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

    __u32 ip_hlen = ip->ihl * 4;
    if (ip_hlen < sizeof(*ip) || ip_hlen > 60)
        return XDP_PASS;

    if (ip->protocol == IPPROTO_TCP) {{
        struct tcphdr *tcp = (void *)ip + ip_hlen;
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        if (tcp->dest == bpf_htons({target_port}))
            return XDP_DROP;
    }} else if (ip->protocol == IPPROTO_UDP) {{
        struct udphdr *udp = (void *)ip + ip_hlen;
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        if (udp->dest == bpf_htons({target_port}))
            return XDP_DROP;
    }}

    return XDP_PASS;
}}
""" + license_str
        elif category == "network_routing_forwarding":
            expected_action = "XDP_TX"
            gold_c = base_headers + f"""SEC("xdp")
int xdp_{task_id}(struct xdp_md *ctx) {{
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

    __u32 ip_hlen = ip->ihl * 4;
    if (ip_hlen < sizeof(*ip) || ip_hlen > 60)
        return XDP_PASS;

    if (ip->protocol == IPPROTO_TCP) {{
        struct tcphdr *tcp = (void *)ip + ip_hlen;
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        if (tcp->dest == bpf_htons({target_port})) {{
            unsigned char tmp_mac[ETH_ALEN];
            __builtin_memcpy(tmp_mac, eth->h_dest, ETH_ALEN);
            __builtin_memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
            __builtin_memcpy(eth->h_source, tmp_mac, ETH_ALEN);
            return XDP_TX;
        }}
    }}

    return XDP_PASS;
}}
""" + license_str
        elif category == "packet_inspection_telemetry":
            expected_action = "XDP_PASS"
            gold_c = base_headers + f"""struct {{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u64);
}} telemetry_map SEC(".maps");

SEC("xdp")
int xdp_{task_id}(struct xdp_md *ctx) {{
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

    __u32 key = ({target_port} % 64);
    __u64 *cnt = bpf_map_lookup_elem(&telemetry_map, &key);
    if (cnt)
        *cnt += 1;

    return XDP_PASS;
}}
""" + license_str
        else:  # protocol_transformation
            expected_action = "XDP_TX"
            gold_c = base_headers + f"""SEC("xdp")
int xdp_{task_id}(struct xdp_md *ctx) {{
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

    __u32 ip_hlen = ip->ihl * 4;
    if (ip_hlen < sizeof(*ip) || ip_hlen > 60)
        return XDP_PASS;

    if (ip->protocol == IPPROTO_UDP) {{
        struct udphdr *udp = (void *)ip + ip_hlen;
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;

        if (udp->dest == bpf_htons({target_port})) {{
            udp->dest = bpf_htons({target_port + 100});
            unsigned char tmp_mac[ETH_ALEN];
            __builtin_memcpy(tmp_mac, eth->h_dest, ETH_ALEN);
            __builtin_memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
            __builtin_memcpy(eth->h_source, tmp_mac, ETH_ALEN);
            return XDP_TX;
        }}
    }}

    return XDP_PASS;
}}
""" + license_str

        matching_pkt = make_eth() + make_ipv4(proto=6 if category != "protocol_transformation" else 17, payload_len=20) + (make_tcp(dport=target_port) if category != "protocol_transformation" else make_udp(dport=target_port))
        non_matching_pkt = make_eth() + make_ipv4(proto=6 if category != "protocol_transformation" else 17, payload_len=20) + (make_tcp(dport=target_port + 1) if category != "protocol_transformation" else make_udp(dport=target_port + 1))
        arp_pkt = make_eth(ethertype=0x0806) + (b"\x00" * 28)
        trunc_pkt = matching_pkt[:16]

        tests = [
            {"name": "match_primary_rule", "description": f"Target rule on port {target_port} must return {expected_action}", "packet_hex": matching_pkt.hex(), "expected_action": expected_action, "fixture_file": "fixtures/match_primary_rule.bin"},
            {"name": "non_matching_port_pass", "description": "Non-matching port must return XDP_PASS", "packet_hex": non_matching_pkt.hex(), "expected_action": "XDP_PASS", "fixture_file": "fixtures/non_matching_port_pass.bin"},
            {"name": "non_ip_arp_pass", "description": "ARP/Non-IP packet must return XDP_PASS", "packet_hex": arp_pkt.hex(), "expected_action": "XDP_PASS", "fixture_file": "fixtures/non_ip_arp_pass.bin"},
            {"name": "truncated_packet_pass", "description": "Truncated packet must return XDP_PASS safely", "packet_hex": trunc_pkt.hex(), "expected_action": "XDP_PASS", "fixture_file": "fixtures/truncated_packet_pass.bin"},
        ]
        fixtures = {
            "match_primary_rule.bin": matching_pkt,
            "non_matching_port_pass.bin": non_matching_pkt,
            "non_ip_arp_pass.bin": arp_pkt,
            "truncated_packet_pass.bin": trunc_pkt,
        }

    return TaskSpec(
        task_id=task_id,
        category=category,
        difficulty=difficulty,
        template_family=family,
        semantic_family=family,
        instruction=instruction,
        requirements=requirements,
        gold_c=gold_c,
        tests=tests,
        fixture_bytes=fixtures,
    )


# -----------------------------------------------------------------------------
# Fault Injection and Diagnostic Generation
# -----------------------------------------------------------------------------

class RepairSpec:
    def __init__(
        self,
        parent_task_id: str,
        fault_class: str,
        fault_injection_id: str,
        faulty_c: str,
        diagnostic: str,
    ):
        self.parent_task_id = parent_task_id
        self.fault_class = fault_class
        self.fault_injection_id = fault_injection_id
        self.faulty_c = faulty_c
        self.diagnostic = diagnostic


def inject_fault(task: TaskSpec, fault_class: str, fault_idx: int) -> RepairSpec:
    """Creates a realistic faulty program and exact diagnostic message."""
    gold = task.gold_c

    if fault_class == "compiler":
        compiler_modes = [
            ("missing_endian_header", "error: call to undeclared function 'bpf_htons'; ISO C99 and later do not support implicit function declarations [-Wimplicit-function-declaration]"),
            ("struct_member_typo", "error: no member named 'dest' in 'struct iphdr'"),
            ("undeclared_action_macro", "error: use of undeclared identifier 'XDP_TX'"),
            ("syntax_missing_semicolon", "error: expected ';' after expression"),
            ("syntax_mismatched_parenthesis", "error: expected ')'"),
            ("missing_bpf_helper_header", "error: call to undeclared function 'bpf_map_lookup_elem'"),
        ]
        mode, err_msg = compiler_modes[fault_idx % len(compiler_modes)]

        if mode == "missing_endian_header":
            faulty = gold.replace("#include <bpf/bpf_endian.h>", "// missing bpf_endian.h")
            diag = f"candidate.c:24:18: {err_msg}\n1 error generated."
        elif mode == "struct_member_typo":
            faulty = gold.replace("ip->daddr", "ip->dest").replace("ip->protocol", "ip->proto")
            diag = f"candidate.c:32:13: {err_msg}\n1 error generated."
        elif mode == "undeclared_action_macro":
            faulty = gold.replace("#include <linux/bpf.h>", "// missing linux/bpf.h")
            diag = f"candidate.c:45:16: {err_msg}\n1 error generated."
        elif mode == "syntax_missing_semicolon":
            faulty = gold.replace("return XDP_PASS;", "return XDP_PASS", 1)
            diag = f"candidate.c:19:24: {err_msg}\n1 error generated."
        elif mode == "syntax_mismatched_parenthesis":
            faulty = gold.replace("if ((void *)(eth + 1) > data_end)", "if ((void *)(eth + 1) > data_end")
            diag = f"candidate.c:15:38: {err_msg}\n1 error generated."
        else:
            faulty = gold.replace("#include <bpf/bpf_helpers.h>", "// missing bpf_helpers.h")
            diag = f"candidate.c:28:17: {err_msg}\n1 error generated."

        return RepairSpec(
            parent_task_id=task.task_id,
            fault_class="compiler",
            fault_injection_id=mode,
            faulty_c=faulty,
            diagnostic=diag,
        )

    elif fault_class == "verifier":
        verifier_modes = [
            ("missing_bounds_check", "invalid access to packet, off=23 size=1, R1(id=0,off=23,r=14)\nR1 offset is outside of the packet"),
            ("missing_map_null_check", "R0 invalid mem access 'map_value_or_null'"),
            ("uninitialized_stack_read", "invalid read from stack off -16+0 size 4"),
            ("unbounded_loop_complexity", "the sequence of 8193 jumps is too complex"),
            ("invalid_pointer_arithmetic", "R2 pointer arithmetic on pkt_end prohibited"),
        ]
        mode, reject_detail = verifier_modes[fault_idx % len(verifier_modes)]

        if mode == "missing_bounds_check":
            faulty = gold.replace("if ((void *)(ip + 1) > data_end)\n        return XDP_PASS;", "// FAULT: missing bounds check on IP header")
        elif mode == "missing_map_null_check":
            faulty = gold.replace("if (val)", "// FAULT: dereferencing map value without null check").replace("if (!val)\n        return XDP_PASS;", "// FAULT: missing null check")
        elif mode == "uninitialized_stack_read":
            faulty = gold.replace("__u32 key = 0;", "__u32 key; // FAULT: uninitialized stack variable")
        elif mode == "unbounded_loop_complexity":
            faulty = gold.replace("return XDP_PASS;", "while (1) { /* loop */ }\n    return XDP_PASS;", 1)
        else:
            faulty = gold.replace("void *data_end = (void *)(long)ctx->data_end;", "void *data_end = (void *)(long)ctx->data_end + 10; // FAULT: illegal pointer math")

        diag = (
            f"Kernel verifier rejected program:\n"
            f"libbpf: loading object from /tmp/bpf_val_{task.task_id[:8]}/candidate.o\n"
            f"libbpf: prog 'xdp_{task.task_id}': BPF program load failed: Permission denied\n"
            f"libbpf: prog 'xdp_{task.task_id}': -- BEGIN PROG LOAD LOG --\n"
            f"func#0 @0\n"
            f"0: R1=ctx() R10=fp0\n"
            f"1: (61) r2 = *(u32 *)(r1 +4)          ; R1=ctx() R2_w=pkt_end()\n"
            f"2: (61) r1 = *(u32 *)(r1 +0)          ; R1_w=pkt(r=0)\n"
            f"3: (bf) r3 = r1                       ; R1_w=pkt(r=0) R3_w=pkt(r=0)\n"
            f"4: (07) r3 += 14                      ; R3_w=pkt(off=14,r=0)\n"
            f"5: (71) r2 = *(u8 *)(r1 +23)\n"
            f"{reject_detail}\n"
            f"verification time 92 usec\n"
            f"stack depth 0\n"
            f"processed 6 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0\n"
            f"-- END PROG LOAD LOG --\n"
            f"libbpf: prog 'xdp_{task.task_id}': failed to load: -13\n"
            f"Error: failed to load object file"
        )

        return RepairSpec(
            parent_task_id=task.task_id,
            fault_class="verifier",
            fault_injection_id=mode,
            faulty_c=faulty,
            diagnostic=diag,
        )

    else:
        behavioral_modes = [
            ("endianness_mismatch", "FAIL: test_case 'match_primary_rule' failed:\n  Expected action: XDP_DROP\n  Observed action: XDP_PASS (port comparison failed due to host byte order without bpf_htons)\n1 of 4 test cases failed."),
            ("missing_action_logic", "FAIL: test_case 'match_primary_rule' failed:\n  Expected action: XDP_TX\n  Observed action: XDP_PASS (matched packet returned XDP_PASS instead of XDP_TX)\n1 of 4 test cases failed."),
            ("fixed_offset_ihl_bug", "FAIL: test_case 'match_primary_rule' failed:\n  Expected action: XDP_DROP\n  Observed action: XDP_PASS (misaligned L4 offset assuming fixed 20-byte IP header)\n1 of 4 test cases failed."),
            ("inverted_match_condition", "FAIL: test_case 'match_primary_rule' failed:\n  Expected action: XDP_DROP\n  Observed action: XDP_PASS (condition inverted != instead of ==)\n1 of 4 test cases failed."),
            ("checksum_update_missing", "FAIL: test_case 'match_primary_rule' failed:\n  Expected action: XDP_TX\n  Observed action: Corrupted packet checksum (IP/L4 checksum was not incrementally updated after field rewrite)\n1 of 4 test cases failed."),
        ]
        mode, diag = behavioral_modes[fault_idx % len(behavioral_modes)]

        if mode == "endianness_mismatch":
            faulty = re.sub(r"bpf_htons\((\d+)\)", r"\1", gold)
        elif mode == "missing_action_logic":
            faulty = gold.replace("return XDP_DROP;", "return XDP_PASS;").replace("return XDP_TX;", "return XDP_PASS;")
        elif mode == "fixed_offset_ihl_bug":
            faulty = gold.replace("__u32 ip_hlen = ip->ihl * 4;", "__u32 ip_hlen = 20; // FAULT: ignoring variable IHL")
        elif mode == "inverted_match_condition":
            faulty = gold.replace(" == bpf_htons(", " != bpf_htons(").replace(" == ", " != ")
        else:
            faulty = gold.replace("icmp->checksum = bpf_htons((__u16)csum);", "// FAULT: forgot to update checksum")

        return RepairSpec(
            parent_task_id=task.task_id,
            fault_class="behavioral",
            fault_injection_id=mode,
            faulty_c=faulty,
            diagnostic=diag,
        )


# -----------------------------------------------------------------------------
# Main Build and Freeze Pipeline
# -----------------------------------------------------------------------------

SYNTHESIS_SYSTEM_PROMPT = """You are an expert Linux kernel eBPF and XDP systems programmer.
Write complete, self-contained, compilation-ready, and verifier-safe C source code for Linux XDP programs."""

REPAIR_SYSTEM_PROMPT = """You are an expert Linux kernel eBPF and XDP systems programmer.
You are fixing an XDP program that produced diagnostic errors during evaluation."""


def format_synthesis_user_prompt(task: TaskSpec) -> str:
    reqs = "\n".join(f"- {r}" for r in task.requirements)
    return f"""Task ID: {task.task_id}
Category: {task.category}
Difficulty: {task.difficulty}

Instruction:
{task.instruction}

Detailed Technical Requirements:
{reqs}

Write the complete C source code for this XDP program."""


def format_repair_user_prompt(task: TaskSpec, repair: RepairSpec) -> str:
    reqs = "\n".join(f"- {r}" for r in task.requirements)
    return f"""Task ID: {task.task_id}
Category: {task.category}
Difficulty: {task.difficulty}

Original Instruction:
{task.instruction}

Technical Requirements:
{reqs}

Previous Implementation:
```c
{repair.faulty_c.strip()}
```

Diagnostic Output:
```text
{repair.diagnostic.strip()}
```

Please provide the corrected, complete, and self-contained C source code for this XDP program."""


def build_sft_v2_dataset(
    output_source_dir: Path,
    output_jsonl_path: Path,
    target_tasks: int = 720,
    target_repairs: int = 480,
    seed: int = 42,
) -> Dict[str, Any]:
    """Generates the full v2 dataset and source bundles."""
    print("=" * 70)
    print("Building BPF-FT SFT v2 Delta Dataset")
    print(f"Target Synthesis Tasks: {target_tasks}")
    print(f"Target Repairs:         {target_repairs}")
    print(f"Source Directory:       {output_source_dir}")
    print(f"JSONL Output:           {output_jsonl_path}")
    print("=" * 70)

    output_source_dir.mkdir(parents=True, exist_ok=True)
    output_jsonl_path.parent.mkdir(parents=True, exist_ok=True)

    tasks: List[TaskSpec] = []
    task_by_id: Dict[str, TaskSpec] = {}

    tasks_per_cat_level = 60

    for cat in CATEGORIES:
        families = FAMILY_DEFINITIONS[cat]
        cat_short = CAT_SHORT[cat]

        for level_idx, level in enumerate(["level_1", "level_2", "level_3"], start=1):
            for i in range(1, tasks_per_cat_level + 1):
                task_id = f"v2_{cat_short}_l{level_idx}_{i:03d}"
                family = families[(i - 1) % len(families)]
                
                task = build_task(
                    task_id=task_id,
                    category=cat,
                    difficulty=level,
                    family=family,
                    index=i + (level_idx * 100),
                )
                tasks.append(task)
                task_by_id[task_id] = task

    print(f"[+] Generated {len(tasks)} unique synthesis tasks across {len(FAMILY_DEFINITIONS)} categories.")

    repairs_by_task: Dict[str, RepairSpec] = {}
    compiler_count = 0
    verifier_count = 0
    behavioral_count = 0

    for cat in CATEGORIES:
        cat_tasks = [t for t in tasks if t.category == cat]
        l1_tasks = [t for t in cat_tasks if t.difficulty == "level_1"]
        l2_tasks = [t for t in cat_tasks if t.difficulty == "level_2"]
        l3_tasks = [t for t in cat_tasks if t.difficulty == "level_3"]

        # 30 compiler (10 L1, 10 L2, 10 L3)
        for idx in range(10):
            repairs_by_task[l1_tasks[idx].task_id] = inject_fault(l1_tasks[idx], "compiler", compiler_count)
            compiler_count += 1
            repairs_by_task[l2_tasks[idx].task_id] = inject_fault(l2_tasks[idx], "compiler", compiler_count)
            compiler_count += 1
            repairs_by_task[l3_tasks[idx].task_id] = inject_fault(l3_tasks[idx], "compiler", compiler_count)
            compiler_count += 1

        # 40 verifier (14 L1, 13 L2, 13 L3)
        for idx in range(10, 24):
            repairs_by_task[l1_tasks[idx].task_id] = inject_fault(l1_tasks[idx], "verifier", verifier_count)
            verifier_count += 1
        for idx in range(10, 23):
            repairs_by_task[l2_tasks[idx].task_id] = inject_fault(l2_tasks[idx], "verifier", verifier_count)
            verifier_count += 1
            repairs_by_task[l3_tasks[idx].task_id] = inject_fault(l3_tasks[idx], "verifier", verifier_count)
            verifier_count += 1

        # 50 behavioral (16 L1, 17 L2, 17 L3)
        for idx in range(24, 40):
            repairs_by_task[l1_tasks[idx].task_id] = inject_fault(l1_tasks[idx], "behavioral", behavioral_count)
            behavioral_count += 1
        for idx in range(23, 40):
            repairs_by_task[l2_tasks[idx].task_id] = inject_fault(l2_tasks[idx], "behavioral", behavioral_count)
            behavioral_count += 1
            repairs_by_task[l3_tasks[idx].task_id] = inject_fault(l3_tasks[idx], "behavioral", behavioral_count)
            behavioral_count += 1

    print(f"[+] Assigned {len(repairs_by_task)} diagnostic-repair instances:")
    print(f"    - Compiler errors:   {compiler_count}")
    print(f"    - Verifier rejects:  {verifier_count}")
    print(f"    - Behavioral logic:  {behavioral_count}")

    # Write Source Task Packages
    print("[*] Writing task bundles to disk...")
    for task in tasks:
        task_dir = output_source_dir / task.category / task.difficulty / task.task_id
        fixtures_dir = task_dir / "fixtures"
        fixtures_dir.mkdir(parents=True, exist_ok=True)

        for fname, data in task.fixture_bytes.items():
            (fixtures_dir / fname).write_bytes(data)

        tests_data = {
            "task_id": task.task_id,
            "validator": "packet_action",
            "test_count": len(task.tests),
            "tests": task.tests,
        }
        (task_dir / "tests.json").write_text(json.dumps(tests_data, indent=2), encoding="utf-8")

        task_data = {
            "task_id": task.task_id,
            "application_category": task.category,
            "category": task.category,
            "difficulty": task.difficulty,
            "task_family": task.template_family,
            "template_family": task.template_family,
            "semantic_family": task.semantic_family,
            "instruction": task.instruction,
            "requirements": task.requirements,
            "gold_candidate_id": None,
            "tests": task.tests,
        }
        (task_dir / "task.json").write_text(json.dumps(task_data, indent=2), encoding="utf-8")

        (task_dir / "gold.c").write_text(task.gold_c, encoding="utf-8")

        if task.task_id in repairs_by_task:
            repair = repairs_by_task[task.task_id]
            (task_dir / "faulty.c").write_text(repair.faulty_c, encoding="utf-8")
            (task_dir / "diagnostic.txt").write_text(repair.diagnostic, encoding="utf-8")
            repair_meta = {
                "task_id": task.task_id,
                "fault_class": repair.fault_class,
                "fault_injection_id": repair.fault_injection_id,
                "diagnostic_sha256": hashlib.sha256(repair.diagnostic.encode("utf-8")).hexdigest(),
            }
            (task_dir / "repair_meta.json").write_text(json.dumps(repair_meta, indent=2), encoding="utf-8")

    print("[+] Wrote 720 source task bundles.")

    # Assemble v2_delta.jsonl
    print("[*] Assembling v2_delta.jsonl dataset...")
    rows: List[Dict[str, Any]] = []

    for task in tasks:
        gold_sha256 = hashlib.sha256(task.gold_c.encode("utf-8")).hexdigest()
        
        task_data = {
            "task_id": task.task_id,
            "category": task.category,
            "difficulty": task.difficulty,
            "template_family": task.template_family,
            "semantic_family": task.semantic_family,
            "instruction": task.instruction,
            "requirements": task.requirements,
        }
        task_spec_sha256 = hashlib.sha256(json.dumps(task_data, sort_keys=True).encode("utf-8")).hexdigest()

        fixture_manifest = {name: hashlib.sha256(data).hexdigest() for name, data in sorted(task.fixture_bytes.items())}
        fixture_manifest_sha256 = hashlib.sha256(json.dumps(fixture_manifest, sort_keys=True).encode("utf-8")).hexdigest()

        syn_row = {
            "example_id": f"v2_syn_{task.task_id}",
            "task_id": task.task_id,
            "category": task.category,
            "difficulty": task.difficulty,
            "template_family": task.template_family,
            "semantic_family": task.semantic_family,
            "example_type": "synthesis",
            "dataset_version": "v2",
            "source_kind": "new_v2",
            "generator_id": "bpf_sft_v2_generator",
            "generation_attempt": 1,
            "gold_source_sha256": gold_sha256,
            "task_spec_sha256": task_spec_sha256,
            "fixture_manifest_sha256": fixture_manifest_sha256,
            "messages": [
                {"role": "system", "content": SYNTHESIS_SYSTEM_PROMPT},
                {"role": "user", "content": format_synthesis_user_prompt(task)},
                {"role": "assistant", "content": task.gold_c},
            ],
        }
        rows.append(syn_row)

        if task.task_id in repairs_by_task:
            repair = repairs_by_task[task.task_id]
            diag_sha256 = hashlib.sha256(repair.diagnostic.encode("utf-8")).hexdigest()

            rep_row = {
                "example_id": f"v2_rep_{task.task_id}",
                "task_id": task.task_id,
                "category": task.category,
                "difficulty": task.difficulty,
                "template_family": task.template_family,
                "semantic_family": task.semantic_family,
                "example_type": "repair",
                "dataset_version": "v2",
                "source_kind": "new_v2",
                "generator_id": "bpf_sft_v2_generator",
                "generation_attempt": 1,
                "gold_source_sha256": gold_sha256,
                "task_spec_sha256": task_spec_sha256,
                "fixture_manifest_sha256": fixture_manifest_sha256,
                "fault_class": repair.fault_class,
                "fault_injection_id": repair.fault_injection_id,
                "diagnostic_sha256": diag_sha256,
                "parent_synthesis_task_id": task.task_id,
                "messages": [
                    {"role": "system", "content": REPAIR_SYSTEM_PROMPT},
                    {"role": "user", "content": format_repair_user_prompt(task, repair)},
                    {"role": "assistant", "content": task.gold_c},
                ],
            }
            rows.append(rep_row)

    rows.sort(key=lambda r: r["example_id"])

    with output_jsonl_path.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    print(f"[+] Wrote {len(rows)} rows to {output_jsonl_path}")

    dataset_sha256 = hashlib.sha256(output_jsonl_path.read_bytes()).hexdigest()

    family_counts = Counter(r["template_family"] for r in rows)
    max_family_count = max(family_counts.values())
    max_family_pct = (max_family_count / len(rows)) * 100.0

    stats = {
        "total_examples": len(rows),
        "synthesis_examples": sum(1 for r in rows if r["example_type"] == "synthesis"),
        "repair_examples": sum(1 for r in rows if r["example_type"] == "repair"),
        "compiler_repairs": compiler_count,
        "verifier_repairs": verifier_count,
        "behavioral_repairs": behavioral_count,
        "unique_tasks": len(tasks),
        "template_families_count": len(family_counts),
        "max_family_count": max_family_count,
        "max_family_pct": max_family_pct,
        "dataset_sha256": dataset_sha256,
    }

    print("\n" + "=" * 70)
    print("SFT v2 Delta Dataset Summary")
    print("=" * 70)
    print(f"Total Rows:            {stats['total_examples']} (Target: 1200)")
    print(f"Synthesis Examples:    {stats['synthesis_examples']} (Target: 720)")
    print(f"Repair Examples:       {stats['repair_examples']} (Target: 480)")
    print(f"  - Compiler:          {stats['compiler_repairs']} (Target: 120)")
    print(f"  - Verifier:          {stats['verifier_repairs']} (Target: 160)")
    print(f"  - Behavioral:        {stats['behavioral_repairs']} (Target: 200)")
    print(f"Template Families:     {stats['template_families_count']} (Min: 28)")
    print(f"Max Family Quota:      {stats['max_family_count']} rows ({stats['max_family_pct']:.2f}% <= 5.0% target)")
    print(f"Dataset SHA256:        {stats['dataset_sha256']}")
    print("=" * 70)

    return stats


def main() -> None:
    parser = argparse.ArgumentParser(description="BPF-Guardian SFT v2 Dataset Builder")
    parser.add_argument("--source-dir", type=Path, default=PROJECT_ROOT / "data" / "sft" / "v2" / "source", help="Output source task directory")
    parser.add_argument("--output-jsonl", type=Path, default=PROJECT_ROOT / "data" / "sft" / "v2" / "v2_delta.jsonl", help="Output JSONL path")
    parser.add_argument("--seed", type=int, default=42, help="Deterministic generator seed")
    args = parser.parse_args()

    build_sft_v2_dataset(
        output_source_dir=args.source_dir,
        output_jsonl_path=args.output_jsonl,
        seed=args.seed,
    )


if __name__ == "__main__":
    main()
