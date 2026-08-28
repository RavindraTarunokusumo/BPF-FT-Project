#!/usr/bin/env python3
"""
BPF-Guardian SFT Task & Candidate Generator Engine
Generates complete task specifications, multi-packet test suites, binary fixtures,
initial candidates (c00.c), provenance metadata (c00.meta.json), repair candidates (c00-r01.c),
and gold verified code (gold.c).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent
INBOX_DIR = PROJECT_ROOT / "data" / "inbox"

# -----------------------------------------------------------------------------
# Packet Generation Helpers
# -----------------------------------------------------------------------------

def checksum(data: bytes) -> int:
    if len(data) % 2 == 1:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while (s >> 16):
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def make_eth(
    dst_mac: str = "52:54:00:12:34:56",
    src_mac: str = "52:54:00:65:43:21",
    eth_type: int = 0x0800,
    vlan: Optional[int] = None,
    qinq_outer: Optional[int] = None,
    payload: bytes = b"",
) -> bytes:
    dst_b = bytes.fromhex(dst_mac.replace(":", ""))
    src_b = bytes.fromhex(src_mac.replace(":", ""))
    if qinq_outer is not None and vlan is not None:
        return (
            dst_b + src_b +
            struct.pack("!HH", 0x88A8, qinq_outer & 0x0FFF) +
            struct.pack("!HH", 0x8100, vlan & 0x0FFF) +
            struct.pack("!H", eth_type) + payload
        )
    if vlan is not None:
        return dst_b + src_b + struct.pack("!HH", 0x8100, vlan & 0x0FFF) + struct.pack("!H", eth_type) + payload
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
    hdr_no_csum = struct.pack("!BBHHHBBH4s4s", (4 << 4) | ihl, tos, tot_len, 0x1234, frag_off, ttl, proto, 0, src_b, dst_b) + opts
    csum = checksum(hdr_no_csum)
    return hdr_no_csum[:10] + struct.pack("!H", csum) + hdr_no_csum[12:] + payload


def make_ipv6(
    src_ip: str = "2001:db8::1",
    dst_ip: str = "2001:db8::2",
    next_hdr: int = 6,
    hop_limit: int = 64,
    payload: bytes = b"",
) -> bytes:
    import ipaddress
    src_b = ipaddress.IPv6Address(src_ip).packed
    dst_b = ipaddress.IPv6Address(dst_ip).packed
    payload_len = len(payload)
    hdr = struct.pack("!IHBB16s16s", 0x60000000, payload_len, next_hdr, hop_limit, src_b, dst_b)
    return hdr + payload


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
    tcph = struct.pack("!HHIIHHHH", src_port, dst_port, seq, ack, (data_offset << 12) | flags, window, 0, 0) + opts
    return tcph + payload


def make_udp(
    src_port: int = 12345,
    dst_port: int = 53,
    payload: bytes = b"DNS_QUERY_DATA",
) -> bytes:
    length = 8 + len(payload)
    return struct.pack("!HHHH", src_port, dst_port, length, 0) + payload


def make_icmp(
    icmp_type: int = 8,
    icmp_code: int = 0,
    payload: bytes = b"PING1234",
) -> bytes:
    raw = struct.pack("!BBHI", icmp_type, icmp_code, 0, 0x1234) + payload
    csum = checksum(raw)
    return struct.pack("!BBHI", icmp_type, icmp_code, csum, 0x1234) + payload


def compute_sha256(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.replace("\r\n", "\n").encode("utf-8")
    return hashlib.sha256(data).hexdigest()


# -----------------------------------------------------------------------------
# Task Writer Utility
# -----------------------------------------------------------------------------

def write_task_bundle(
    category: str,
    difficulty: str,
    task_id: str,
    template_family: str,
    semantic_signature: str,
    instruction: str,
    requirements: List[str],
    test_cases: List[Dict[str, Any]],
    c00_code: str,
    c00_meta: Dict[str, Any],
    r01_code: Optional[str] = None,
    r01_meta: Optional[Dict[str, Any]] = None,
    main_validator: str = "packet_action",
) -> None:
    task_dir = INBOX_DIR / category / difficulty / task_id
    fixtures_dir = task_dir / "fixtures"
    fixtures_dir.mkdir(parents=True, exist_ok=True)

    # Format test cases and write .bin fixtures
    formatted_tests = []
    for tc in test_cases:
        t_name = tc["name"]
        pkt_bytes = bytes.fromhex(tc["packet_hex"])
        bin_path = fixtures_dir / f"{t_name}.bin"
        bin_path.write_bytes(pkt_bytes)

        entry = {
            "name": t_name,
            "description": tc.get("description", ""),
            "packet_hex": tc["packet_hex"],
            "expected_action": tc["expected_action"],
            "fixture_file": f"fixtures/{t_name}.bin",
        }
        if "expected_bytes_hex" in tc:
            entry["expected_bytes_hex"] = tc["expected_bytes_hex"]
        if "expected_map_state" in tc:
            entry["expected_map_state"] = tc["expected_map_state"]
        formatted_tests.append(entry)

    # Determine gold candidate
    gold_candidate_id = f"{task_id}_c00_r01" if r01_code is not None else f"{task_id}_c00"
    gold_code = r01_code if r01_code is not None else c00_code

    task_json = {
        "task_id": task_id,
        "application_category": category,
        "difficulty": difficulty,
        "template_family": template_family,
        "semantic_signature": semantic_signature,
        "split": "train",
        "instruction": instruction,
        "requirements": requirements,
        "gold_candidate_id": gold_candidate_id,
        "tests": formatted_tests,
    }
    (task_dir / "task.json").write_text(json.dumps(task_json, indent=2) + "\n", encoding="utf-8", newline="\n")

    tests_json = {
        "task_id": task_id,
        "validator": main_validator,
        "test_count": len(formatted_tests),
        "test_cases": formatted_tests,
    }
    (task_dir / "tests.json").write_text(json.dumps(tests_json, indent=2) + "\n", encoding="utf-8", newline="\n")

    # c00.c
    c00_norm = c00_code.replace("\r\n", "\n")
    (task_dir / "c00.c").write_text(c00_norm, encoding="utf-8", newline="\n")
    c00_meta["candidate_id"] = f"{task_id}_c00"
    c00_meta["task_id"] = task_id
    c00_meta["source_path"] = "c00.c"
    c00_meta["source_sha256"] = compute_sha256(c00_norm)
    c00_meta["repair_attempt"] = 0
    c00_meta["claimed_status"] = "unvalidated"
    (task_dir / "c00.meta.json").write_text(json.dumps(c00_meta, indent=2) + "\n", encoding="utf-8", newline="\n")

    # r01 if present
    if r01_code is not None:
        r01_norm = r01_code.replace("\r\n", "\n")
        (task_dir / "c00-r01.c").write_text(r01_norm, encoding="utf-8", newline="\n")
        if r01_meta is None:
            r01_meta = {}
        r01_meta["candidate_id"] = f"{task_id}_c00_r01"
        r01_meta["task_id"] = task_id
        r01_meta["source_path"] = "c00-r01.c"
        r01_meta["parent_candidate_id"] = f"{task_id}_c00"
        r01_meta["source_sha256"] = compute_sha256(r01_norm)
        r01_meta["repair_attempt"] = 1
        r01_meta["claimed_status"] = "unvalidated"
        (task_dir / "c00-r01.meta.json").write_text(json.dumps(r01_meta, indent=2) + "\n", encoding="utf-8", newline="\n")
    else:
        stale_r01_c = task_dir / "c00-r01.c"
        if stale_r01_c.exists():
            stale_r01_c.unlink()
        stale_r01_m = task_dir / "c00-r01.meta.json"
        if stale_r01_m.exists():
            stale_r01_m.unlink()

    # gold.c
    gold_norm = gold_code.replace("\r\n", "\n")
    (task_dir / "gold.c").write_text(gold_norm, encoding="utf-8", newline="\n")
