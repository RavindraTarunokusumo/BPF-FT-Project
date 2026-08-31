"""
Packet creation and checksumming utilities for BPF-Guardian Private Synthesis Benchmark.
Supports standard L2-L7 protocols and advanced tunnel/encapsulation headers:
Ethernet, 802.1Q VLAN, 802.1ad QinQ, IPv4, IPv6, TCP with Options, UDP, ICMPv4, ICMPv6,
ARP, VXLAN, GENEVE, GRE, GTP-U, SRv6, MPLS, CoAP, WireGuard, QUIC, DNS, DHCP, NTP, SCTP.
"""

from __future__ import annotations

import binascii
import struct
from typing import Any, List, Optional, Tuple, Union


def checksum(data: bytes) -> int:
    """Calculates standard 16-bit Internet Checksum."""
    if len(data) % 2 == 1:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def parse_mac(mac_str: str) -> bytes:
    return bytes.fromhex(mac_str.replace(":", "").replace("-", ""))


def parse_ipv4(ip_str: str) -> bytes:
    return bytes(map(int, ip_str.split(".")))


def parse_ipv6(ip_str: str) -> bytes:
    import ipaddress
    return ipaddress.IPv6Address(ip_str).packed


def make_eth(
    dst_mac: str = "52:54:00:12:34:56",
    src_mac: str = "52:54:00:65:43:21",
    eth_type: int = 0x0800,
    vlan: Optional[int] = None,
    qinq_outer: Optional[int] = None,
    payload: bytes = b"",
) -> bytes:
    """Builds Ethernet II frame with optional single or dual (QinQ) 802.1Q VLAN tags."""
    dst_b = parse_mac(dst_mac)
    src_b = parse_mac(src_mac)
    if qinq_outer is not None:
        inner_vlan = vlan if vlan is not None else 100
        tag = struct.pack("!HH", 0x88A8, qinq_outer) + struct.pack("!HH", 0x8100, inner_vlan)
        return dst_b + src_b + tag + struct.pack("!H", eth_type) + payload
    elif vlan is not None:
        tag = struct.pack("!HH", 0x8100, vlan)
        return dst_b + src_b + tag + struct.pack("!H", eth_type) + payload
    else:
        return dst_b + src_b + struct.pack("!H", eth_type) + payload


def make_ipv4(
    src_ip: str = "192.168.1.10",
    dst_ip: str = "192.168.1.20",
    proto: int = 6,
    ttl: int = 64,
    tos: int = 0,
    frag_off: int = 0,
    ihl: int = 5,
    options: bytes = b"",
    payload: bytes = b"",
) -> bytes:
    """Builds IPv4 packet with calculated header checksum."""
    src_b = parse_ipv4(src_ip)
    dst_b = parse_ipv4(dst_ip)
    ihl_calc = max(ihl, 5 + (len(options) + 3) // 4)
    padded_opts = options.ljust((ihl_calc - 5) * 4, b"\x00")
    tot_len = ihl_calc * 4 + len(payload)
    hdr_no_csum = (
        struct.pack(
            "!BBHHHBBH4s4s",
            (4 << 4) | ihl_calc,
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
        + padded_opts
    )
    csum = checksum(hdr_no_csum)
    return hdr_no_csum[:10] + struct.pack("!H", csum) + hdr_no_csum[12:] + payload


def make_ipv6(
    src_ip: str = "2001:db8::1",
    dst_ip: str = "2001:db8::2",
    next_hdr: int = 6,
    hop_limit: int = 64,
    traffic_class: int = 0,
    flow_label: int = 0,
    payload: bytes = b"",
) -> bytes:
    """Builds IPv6 base header (40 bytes)."""
    src_b = parse_ipv6(src_ip)
    dst_b = parse_ipv6(dst_ip)
    payload_len = len(payload)
    vcf = (6 << 28) | (traffic_class << 20) | (flow_label & 0xFFFFF)
    return struct.pack("!IHBB16s16s", vcf, payload_len, next_hdr, hop_limit, src_b, dst_b) + payload


def make_tcp(
    src_port: int = 12345,
    dst_port: int = 80,
    flags: int = 0x02,  # SYN
    seq: int = 1000,
    ack: int = 0,
    window: int = 65535,
    options: bytes = b"",
    payload: bytes = b"",
    src_ip: str = "192.168.1.10",
    dst_ip: str = "192.168.1.20",
    with_csum: bool = True,
) -> bytes:
    """Builds TCP segment with optional options and pseudo-header checksum."""
    data_offset = 5 + (len(options) + 3) // 4
    padded_opts = options.ljust((data_offset - 5) * 4, b"\x00")
    tcph_no_csum = (
        struct.pack(
            "!HHIIHHHH",
            src_port,
            dst_port,
            seq,
            ack,
            (data_offset << 12) | (flags & 0xFFF),
            window,
            0,
            0,
        )
        + padded_opts
        + payload
    )
    if not with_csum:
        return tcph_no_csum

    # Pseudo-header checksum
    if ":" in src_ip:
        src_b = parse_ipv6(src_ip)
        dst_b = parse_ipv6(dst_ip)
        pseudo = src_b + dst_b + struct.pack("!II", len(tcph_no_csum), 6)
    else:
        src_b = parse_ipv4(src_ip)
        dst_b = parse_ipv4(dst_ip)
        pseudo = src_b + dst_b + struct.pack("!BBH", 0, 6, len(tcph_no_csum))

    csum = checksum(pseudo + tcph_no_csum)
    if csum == 0:
        csum = 0xFFFF
    return tcph_no_csum[:16] + struct.pack("!H", csum) + tcph_no_csum[18:]


def make_udp(
    src_port: int = 12345,
    dst_port: int = 53,
    payload: bytes = b"",
    src_ip: str = "192.168.1.10",
    dst_ip: str = "192.168.1.20",
    with_csum: bool = False,
) -> bytes:
    """Builds UDP packet with optional pseudo-header checksum."""
    length = 8 + len(payload)
    if not with_csum:
        return struct.pack("!HHHH", src_port, dst_port, length, 0) + payload

    if ":" in src_ip:
        src_b = parse_ipv6(src_ip)
        dst_b = parse_ipv6(dst_ip)
        pseudo = src_b + dst_b + struct.pack("!II", length, 17)
    else:
        src_b = parse_ipv4(src_ip)
        dst_b = parse_ipv4(dst_ip)
        pseudo = src_b + dst_b + struct.pack("!BBH", 0, 17, length)

    raw_udp = struct.pack("!HHHH", src_port, dst_port, length, 0) + payload
    csum = checksum(pseudo + raw_udp)
    if csum == 0:
        csum = 0xFFFF
    return struct.pack("!HHHH", src_port, dst_port, length, csum) + payload


def make_icmp(
    icmp_type: int = 8,
    icmp_code: int = 0,
    ident: int = 0x1234,
    seq: int = 1,
    payload: bytes = b"TESTPING",
) -> bytes:
    """Builds ICMPv4 packet with checksum."""
    raw = struct.pack("!BBHHH", icmp_type, icmp_code, 0, ident, seq) + payload
    csum = checksum(raw)
    return struct.pack("!BBHHH", icmp_type, icmp_code, csum, ident, seq) + payload


def make_icmpv6(
    icmp_type: int = 128,  # Echo Request
    icmp_code: int = 0,
    ident: int = 0x1234,
    seq: int = 1,
    payload: bytes = b"TESTPING6",
    src_ip: str = "2001:db8::1",
    dst_ip: str = "2001:db8::2",
) -> bytes:
    """Builds ICMPv6 packet with IPv6 pseudo-header checksum."""
    raw_body = struct.pack("!BBHHH", icmp_type, icmp_code, 0, ident, seq) + payload
    src_b = parse_ipv6(src_ip)
    dst_b = parse_ipv6(dst_ip)
    pseudo = src_b + dst_b + struct.pack("!II", len(raw_body), 58)
    csum = checksum(pseudo + raw_body)
    if csum == 0:
        csum = 0xFFFF
    return struct.pack("!BBHHH", icmp_type, icmp_code, csum, ident, seq) + payload


def make_arp(
    hw_type: int = 1,
    proto_type: int = 0x0800,
    hw_len: int = 6,
    proto_len: int = 4,
    opcode: int = 1,  # 1 = Request, 2 = Reply
    sender_mac: str = "52:54:00:12:34:56",
    sender_ip: str = "192.168.1.10",
    target_mac: str = "00:00:00:00:00:00",
    target_ip: str = "192.168.1.20",
) -> bytes:
    """Builds 28-byte Ethernet ARP packet."""
    smac = parse_mac(sender_mac)
    sip = parse_ipv4(sender_ip)
    tmac = parse_mac(target_mac)
    tip = parse_ipv4(target_ip)
    return struct.pack("!HHBBH6s4s6s4s", hw_type, proto_type, hw_len, proto_len, opcode, smac, sip, tmac, tip)


def make_vxlan(
    vni: int = 100,
    flags: int = 0x08,  # I flag (VNI valid)
    inner_frame: bytes = b"",
) -> bytes:
    """Builds 8-byte VXLAN header + inner Ethernet frame."""
    vx_flags = flags << 24
    vx_vni = (vni & 0xFFFFFF) << 8
    hdr = struct.pack("!II", vx_flags, vx_vni)
    return hdr + inner_frame


def make_geneve(
    vni: int = 100,
    proto_type: int = 0x0800,
    critical: bool = False,
    options: bytes = b"",
    inner_frame: bytes = b"",
) -> bytes:
    """Builds GENEVE header (8 bytes + variable TLV options) + inner frame."""
    opt_len_4b = len(options) // 4
    ver = 0
    oam = 0
    crit = 1 if critical else 0
    rsvd1 = 0
    b0 = (ver << 6) | (opt_len_4b & 0x3F)
    b1 = (oam << 7) | (crit << 6) | (rsvd1 & 0x3F)
    vni_bytes = struct.pack("!I", vni)[1:]  # 3 bytes
    hdr = struct.pack("!BBH", b0, b1, proto_type) + vni_bytes + b"\x00" + options
    return hdr + inner_frame


def make_gre(
    proto: int = 0x0800,
    c_bit: bool = False,
    k_bit: bool = False,
    s_bit: bool = False,
    key: Optional[int] = None,
    seq: Optional[int] = None,
    inner_pkt: bytes = b"",
) -> bytes:
    """Builds GRE header (RFC 2784/2890) with optional checksum, key, and seq fields."""
    flags_val = 0
    if c_bit:
        flags_val |= 0x8000
    if k_bit or key is not None:
        flags_val |= 0x2000
    if s_bit or seq is not None:
        flags_val |= 0x1000

    hdr_fixed = struct.pack("!HH", flags_val, proto)
    extra = b""
    if c_bit:
        # Checksum (2 bytes) + Reserved (2 bytes)
        extra += struct.pack("!HH", 0, 0)
    if k_bit or key is not None:
        extra += struct.pack("!I", key if key is not None else 0x12345678)
    if s_bit or seq is not None:
        extra += struct.pack("!I", seq if seq is not None else 1)

    full_gre = hdr_fixed + extra
    if c_bit:
        csum = checksum(full_gre + inner_pkt)
        full_gre = full_gre[:4] + struct.pack("!H", csum) + full_gre[6:]
    return full_gre + inner_pkt


def make_gtpu(
    msg_type: int = 0xFF,  # 0xFF = G-PDU (User plane data), 0x01 = Echo Request, 0x02 = Echo Reply
    teid: int = 0x12345678,
    flags: int = 0x30,  # Version 1 (001), PT=1 (GTP)
    inner_pkt: bytes = b"",
) -> bytes:
    """Builds GTP-U header (8 bytes) + inner IP payload."""
    length = len(inner_pkt)
    hdr = struct.pack("!BBHI", flags, msg_type, length, teid)
    return hdr + inner_pkt


def make_srv6(
    segments_left: int = 1,
    segments: Optional[List[str]] = None,
    next_hdr: int = 4,  # IPv4
    inner_pkt: bytes = b"",
) -> bytes:
    """Builds IPv6 Routing Header Type 4 (Segment Routing Header - SRH)."""
    seg_list = segments or ["2001:db8::10", "2001:db8::20"]
    last_entry = len(seg_list) - 1
    hdr_ext_len = (8 + len(seg_list) * 16) // 8 - 1
    flags = 0
    tag = 0
    srh_hdr = struct.pack("!BBBBBBH", next_hdr, hdr_ext_len, 4, segments_left, last_entry, flags, tag)
    for s in seg_list:
        srh_hdr += parse_ipv6(s)
    return srh_hdr + inner_pkt


def make_mpls(
    labels: List[Tuple[int, int, bool, int]],  # (label: 20-bit, exp/tc: 3-bit, bos: bool, ttl: 8-bit)
    inner_pkt: bytes = b"",
) -> bytes:
    """Builds MPLS shim header stack (4 bytes per label)."""
    stack = b""
    for label, exp, bos, ttl in labels:
        bos_bit = 1 if bos else 0
        entry = (label << 12) | ((exp & 0x7) << 9) | (bos_bit << 8) | (ttl & 0xFF)
        stack += struct.pack("!I", entry)
    return stack + inner_pkt


def make_coap(
    ver: int = 1,
    type_: int = 0,  # 0=CON, 1=NON, 2=ACK, 3=RST
    code: int = 1,  # 1=GET, 2=POST, 3=PUT, 4=DELETE, 69=2.05 Content
    msg_id: int = 0x1234,
    token: bytes = b"",
    payload: bytes = b"",
) -> bytes:
    """Builds CoAP message (RFC 7252)."""
    tkl = len(token) & 0x0F
    b0 = (ver << 6) | (type_ << 4) | tkl
    hdr = struct.pack("!BBH", b0, code, msg_id) + token
    if payload:
        hdr += b"\xFF" + payload
    return hdr


def make_wireguard(
    msg_type: int = 1,  # 1=Initiation, 2=Response, 3=Cookie, 4=Data
    sender_idx: int = 0x11223344,
    receiver_idx: int = 0x55667788,
    payload: bytes = b"",
) -> bytes:
    """Builds WireGuard packet header (UDP 51820)."""
    if msg_type == 1:
        hdr = struct.pack("!IBBB", msg_type, 0, 0, 0) + struct.pack("<I", sender_idx)
        return hdr + payload.ljust(140, b"\xaa")
    elif msg_type == 2:
        hdr = struct.pack("!IBBB", msg_type, 0, 0, 0) + struct.pack("<II", sender_idx, receiver_idx)
        return hdr + payload.ljust(80, b"\xbb")
    else:
        hdr = struct.pack("!IBBB", msg_type, 0, 0, 0) + struct.pack("<I", receiver_idx) + struct.pack("<Q", 1)
        return hdr + payload


def make_quic(
    long_hdr: bool = True,
    pkt_type: int = 0x00,  # 0x00 = Initial
    dcid: bytes = b"\x01\x02\x03\x04\x05\x06\x07\x08",
    scid: bytes = b"\x11\x12\x13\x14\x15\x16\x17\x18",
    token: bytes = b"",
    payload: bytes = b"QUIC_FRAME_DATA",
) -> bytes:
    """Builds QUIC packet header (RFC 9000)."""
    if long_hdr:
        b0 = 0xC0 | (pkt_type << 4)
        version = 0x00000001
        dcid_len = len(dcid)
        scid_len = len(scid)
        hdr = struct.pack("!BI", b0, version) + bytes([dcid_len]) + dcid + bytes([scid_len]) + scid
        if pkt_type == 0:
            token_len = len(token)
            hdr += bytes([token_len]) + token
        length = len(payload) + 4
        hdr += struct.pack("!H", length) + struct.pack("!I", 1)
        return hdr + payload
    else:
        b0 = 0x40
        return struct.pack("!B", b0) + dcid + struct.pack("!I", 1) + payload


def make_dns(
    txid: int = 0x1234,
    qr: int = 0,  # 0=Query, 1=Response
    opcode: int = 0,
    rcode: int = 0,
    qname: str = "example.com",
    qtype: int = 1,  # 1=A, 28=AAAA, 16=TXT, 10=NULL
    qclass: int = 1,  # IN
) -> bytes:
    """Builds DNS query/response payload."""
    flags = (qr << 15) | (opcode << 11) | (rcode & 0x0F)
    hdr = struct.pack("!HHHHHH", txid, flags, 1, 0, 0, 0)
    qname_parts = qname.strip(".").split(".")
    qname_b = b""
    for p in qname_parts:
        pb = p.encode("ascii")
        qname_b += bytes([len(pb)]) + pb
    qname_b += b"\x00"
    question = qname_b + struct.pack("!HH", qtype, qclass)
    return hdr + question


def make_dhcp(
    op: int = 1,  # 1=BOOTREQUEST, 2=BOOTREPLY
    xid: int = 0x3903F326,
    chaddr: str = "52:54:00:12:34:56",
    msg_type: int = 1,  # 1=Discover, 2=Offer, 3=Request, 5=Ack
    server_ip: str = "192.168.1.1",
) -> bytes:
    """Builds DHCP packet payload (RFC 2131)."""
    ch_b = parse_mac(chaddr).ljust(16, b"\x00")
    hdr = struct.pack("!BBBBIHH4s4s4s4s16s64s128s", op, 1, 6, 0, xid, 0, 0, b"\x00"*4, b"\x00"*4, parse_ipv4(server_ip), b"\x00"*4, ch_b, b"\x00"*64, b"\x00"*128)
    magic_cookie = struct.pack("!I", 0x63825363)
    opts = bytes([53, 1, msg_type, 255])
    return hdr + magic_cookie + opts


def make_ntp(
    li: int = 0,
    vn: int = 4,
    mode: int = 3,  # 3=Client, 4=Server, 6=Control, 7=Private/Monlist
    stratum: int = 2,
    poll: int = 4,
    precision: int = -6,
) -> bytes:
    """Builds 48-byte NTP message."""
    b0 = (li << 6) | (vn << 3) | (mode & 0x07)
    hdr = struct.pack("!BBbb", b0, stratum, poll, precision) + b"\x00" * 44
    return hdr


def make_sctp(
    src_port: int = 5000,
    dst_port: int = 5000,
    vtag: int = 0x12345678,
    chunk_type: int = 0,  # 0=DATA, 1=INIT, 2=INIT_ACK, 6=ABORT, 3=SACK
    chunk_flags: int = 0,
    payload: bytes = b"SCTP_PAYLOAD",
) -> bytes:
    """Builds SCTP common header + 1 chunk."""
    chunk_len = 4 + len(payload)
    chunk = struct.pack("!BBH", chunk_type, chunk_flags, chunk_len) + payload
    if len(chunk) % 4 != 0:
        chunk += b"\x00" * (4 - (len(chunk) % 4))
    hdr = struct.pack("!HHI", src_port, dst_port, vtag) + struct.pack("!I", 0xDEADC0DE)
    return hdr + chunk
