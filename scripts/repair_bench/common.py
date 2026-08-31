#!/usr/bin/env python3
"""
Common utilities and packet builders for BPF-Guardian Repair Benchmark.
"""

from __future__ import annotations

import binascii
import hashlib
import json
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


def compute_sha256_str(content: str | bytes) -> str:
    if isinstance(content, str):
        content = content.encode("utf-8")
    return hashlib.sha256(content).hexdigest()


def checksum(data: bytes) -> int:
    if len(data) % 2 == 1:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def make_eth(
    dst_mac: str = "52:54:00:12:34:56",
    src_mac: str = "52:54:00:65:43:21",
    eth_type: int = 0x0800,
    vlan: Optional[int] = None,
    vlan_inner: Optional[int] = None,
    payload: bytes = b"",
) -> bytes:
    dst_b = bytes.fromhex(dst_mac.replace(":", ""))
    src_b = bytes.fromhex(src_mac.replace(":", ""))
    if vlan is not None and vlan_inner is not None:
        return (
            dst_b
            + src_b
            + struct.pack("!HH", 0x88A8, vlan)
            + struct.pack("!HH", 0x8100, vlan_inner)
            + struct.pack("!H", eth_type)
            + payload
        )
    if vlan is not None:
        return (
            dst_b
            + src_b
            + struct.pack("!HH", 0x8100, vlan)
            + struct.pack("!H", eth_type)
            + payload
        )
    return dst_b + src_b + struct.pack("!H", eth_type) + payload


def make_ipv4(
    src_ip: str = "192.168.1.10",
    dst_ip: str = "192.168.1.20",
    proto: int = 6,
    ttl: int = 64,
    tos: int = 0,
    frag_off: int = 0,
    ihl: int = 5,
    payload: bytes = b"",
) -> bytes:
    src_b = bytes(map(int, src_ip.split(".")))
    dst_b = bytes(map(int, dst_ip.split(".")))
    tot_len = ihl * 4 + len(payload)
    opt_len = (ihl - 5) * 4
    opts = b"\x00" * opt_len if opt_len > 0 else b""
    hdr_no_csum = (
        struct.pack(
            "!BBHHHBBH4s4s",
            (4 << 4) | ihl,
            tos,
            tot_len,
            0x1234,
            frag_off,
            ttl,
            proto,
            0,
            src_b,
            dst_b,
        )
        + opts
    )
    csum = checksum(hdr_no_csum)
    return hdr_no_csum[:10] + struct.pack("!H", csum) + hdr_no_csum[12:] + payload


def make_tcp(
    src_port: int = 12345,
    dst_port: int = 80,
    flags: int = 0x02,
    window: int = 65535,
    seq: int = 1000,
    ack: int = 0,
    data_offset: int = 5,
    payload: bytes = b"",
) -> bytes:
    opt_len = (data_offset - 5) * 4
    opts = b"\x00" * opt_len if opt_len > 0 else b""
    tcph = (
        struct.pack(
            "!HHIIHHHH",
            src_port,
            dst_port,
            seq,
            ack,
            (data_offset << 12) | flags,
            window,
            0,
            0,
        )
        + opts
    )
    return tcph + payload


def make_udp(
    src_port: int = 12345,
    dst_port: int = 53,
    payload: bytes = b"DNS_PAYLOAD",
    with_csum: bool = False,
    src_ip: str = "192.168.1.10",
    dst_ip: str = "192.168.1.20",
) -> bytes:
    length = 8 + len(payload)
    if not with_csum:
        return struct.pack("!HHHH", src_port, dst_port, length, 0) + payload

    src_b = bytes(map(int, src_ip.split(".")))
    dst_b = bytes(map(int, dst_ip.split(".")))
    pseudo = src_b + dst_b + struct.pack("!BBH", 0, 17, length)
    udp_raw = struct.pack("!HHHH", src_port, dst_port, length, 0) + payload
    csum = checksum(pseudo + udp_raw)
    if csum == 0:
        csum = 0xFFFF
    return struct.pack("!HHHH", src_port, dst_port, length, csum) + payload


def make_icmp(
    icmp_type: int = 8,
    icmp_code: int = 0,
    payload: bytes = b"PING1234",
) -> bytes:
    raw = struct.pack("!BBHI", icmp_type, icmp_code, 0, 0x1234) + payload
    csum = checksum(raw)
    return struct.pack("!BBHI", icmp_type, icmp_code, csum, 0x1234) + payload


def make_arp(
    op: int = 1,
    sha: str = "52:54:00:65:43:21",
    spa: str = "192.168.1.10",
    tha: str = "00:00:00:00:00:00",
    tpa: str = "192.168.1.20",
) -> bytes:
    sha_b = bytes.fromhex(sha.replace(":", ""))
    tha_b = bytes.fromhex(tha.replace(":", ""))
    spa_b = bytes(map(int, spa.split(".")))
    tpa_b = bytes(map(int, tpa.split(".")))
    return struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, op, sha_b, spa_b, tha_b, tpa_b)


@dataclass
class RepairTaskSpec:
    task_id: str
    application_category: str
    difficulty: str
    task_family: str
    template_family: str
    semantic_signature: str
    diagnostic_category: str  # "compilation_error" | "verifier_rejection" | "behavioral_logic_bug"
    failure_reason: str
    instruction: str
    requirements: List[str]
    faulty_c: str
    diagnostic_txt: str
    solution_c: str
    test_cases: List[Dict[str, Any]]
    validator_type: str = "packet_action"
