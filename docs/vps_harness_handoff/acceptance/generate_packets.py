#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ipaddress
import struct
from pathlib import Path


def internet_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ethernet_header(
    destination: bytes,
    source: bytes,
    ethertype: int = 0x0800,
) -> bytes:
    return destination + source + struct.pack("!H", ethertype)


def ipv4_header(
    source: str,
    destination: str,
    protocol: int,
    payload_length: int,
    ttl: int = 64,
) -> bytes:
    version_ihl = 0x45
    total_length = 20 + payload_length
    header_without_checksum = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        0,
        total_length,
        0x1234,
        0,
        ttl,
        protocol,
        0,
        ipaddress.IPv4Address(source).packed,
        ipaddress.IPv4Address(destination).packed,
    )
    checksum = internet_checksum(header_without_checksum)
    return header_without_checksum[:10] + struct.pack("!H", checksum) + header_without_checksum[12:]


def tcp_header(source_port: int, destination_port: int, flags: int = 0x02) -> bytes:
    return struct.pack(
        "!HHIIBBHHH",
        source_port,
        destination_port,
        0,
        0,
        5 << 4,
        flags,
        65535,
        0,
        0,
    )


def udp_header(source_port: int, destination_port: int, payload_length: int = 0) -> bytes:
    return struct.pack("!HHHH", source_port, destination_port, 8 + payload_length, 0)


def ipv4_tcp_packet(destination_port: int) -> bytes:
    tcp = tcp_header(40000, destination_port)
    ip = ipv4_header("192.0.2.1", "198.51.100.2", 6, len(tcp))
    return ethernet_header(
        bytes.fromhex("020000000002"),
        bytes.fromhex("020000000001"),
    ) + ip + tcp


def ipv4_udp_packet(destination_port: int) -> bytes:
    udp = udp_header(40000, destination_port)
    ip = ipv4_header("192.0.2.1", "198.51.100.2", 17, len(udp))
    return ethernet_header(
        bytes.fromhex("020000000002"),
        bytes.fromhex("020000000001"),
    ) + ip + udp


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("output_dir", type=Path)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)

    tcp23 = ipv4_tcp_packet(23)
    tcp80 = ipv4_tcp_packet(80)
    udp53 = ipv4_udp_packet(53)
    non_ipv4 = ethernet_header(
        bytes.fromhex("ffffffffffff"),
        bytes.fromhex("020000000001"),
        0x0806,
    ) + bytes(28)
    truncated = bytes.fromhex("02000000000202000000000108004500")

    packets = {
        "tcp23.bin": tcp23,
        "tcp80.bin": tcp80,
        "udp53.bin": udp53,
        "non_ipv4.bin": non_ipv4,
        "truncated.bin": truncated,
        "swap_input.bin": tcp80,
        "swap_expected.bin": tcp80[6:12] + tcp80[0:6] + tcp80[12:],
        "forward.bin": tcp80,
    }

    for filename, packet in packets.items():
        (args.output_dir / filename).write_bytes(packet)


if __name__ == "__main__":
    main()
