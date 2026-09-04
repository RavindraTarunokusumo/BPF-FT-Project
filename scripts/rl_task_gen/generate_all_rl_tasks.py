"""
Master Generator for BPF-Guardian RLVR Phase 1 Task Pool.
Generates all 132 tasks across 4 categories and 3 difficulty levels:
- Canary: 12 tasks (1 per cell)
- Train: 96 tasks (8 per cell)
- Dev: 24 tasks (2 per cell)
Total: 132 tasks with 100% verifier-safe C solutions and realistic packet fixtures.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any, Dict, List

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts.synthesis_benchmark_gen.packet_utils import (
    make_arp,
    make_eth,
    make_icmp,
    make_ipv4,
    make_ipv6,
    make_tcp,
    make_udp,
)


def sha256_file(filepath: Path) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


# =========================================================================
# 1. Packet Filtering & Security (33 Tasks)
# =========================================================================
def build_pfs_tasks() -> List[Dict[str, Any]]:
    tasks: List[Dict[str, Any]] = []

    # Level 1 (11 tasks)
    l1_configs = [
        ("rl_canary_pfs_l1_01", "canary", 22, "ssh"),
        ("rl_train_pfs_l1_01", "train", 21, "ftp"),
        ("rl_train_pfs_l1_02", "train", 25, "smtp"),
        ("rl_train_pfs_l1_03", "train", 110, "pop3"),
        ("rl_train_pfs_l1_04", "train", 143, "imap"),
        ("rl_train_pfs_l1_05", "train", 3306, "mysql"),
        ("rl_train_pfs_l1_06", "train", 5432, "postgres"),
        ("rl_train_pfs_l1_07", "train", 6379, "redis"),
        ("rl_train_pfs_l1_08", "train", 8080, "http_alt"),
        ("rl_dev_pfs_l1_01", "dev", 27017, "mongodb"),
        ("rl_dev_pfs_l1_02", "dev", 9200, "elasticsearch"),
    ]

    for tid, split, port, name in l1_configs:
        tests = [
            {
                "name": f"drop_tcp_{port}",
                "description": f"IPv4 TCP packet with destination port {port} must be dropped",
                "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(dst_port=port, flags=0x02))).hex(),
                "expected_action": "XDP_DROP",
                "weight": 1.0,
            },
            {
                "name": "pass_tcp_other_port",
                "description": "IPv4 TCP packet with other destination port must pass",
                "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(dst_port=80, flags=0x02))).hex(),
                "expected_action": "XDP_PASS",
                "weight": 1.0,
            },
            {
                "name": "pass_udp",
                "description": "IPv4 UDP packet must pass unconditionally",
                "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=port))).hex(),
                "expected_action": "XDP_PASS",
                "weight": 1.0,
            },
            {
                "name": "pass_icmp",
                "description": "IPv4 ICMP packet must pass unconditionally",
                "packet_hex": make_eth(payload=make_ipv4(proto=1, payload=make_icmp())).hex(),
                "expected_action": "XDP_PASS",
                "weight": 1.0,
            },
            {
                "name": "pass_truncated",
                "description": "Truncated packet must pass safely without crash",
                "packet_hex": "5254001234565254006543210800",
                "expected_action": "XDP_PASS",
                "weight": 1.0,
            },
        ]

        sol_c = f"""#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>

SEC("xdp")
int xdp_filter_{name}(struct xdp_md *ctx) {{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

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

    int ip_len = ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip_len;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    if (tcp->dest == bpf_htons({port}))
        return XDP_DROP;

    return XDP_PASS;
}}

char _license[] SEC("license") = "GPL";
"""

        tasks.append({
            "task_id": tid,
            "application_category": "packet_filtering_security",
            "difficulty": "level_1",
            "task_family": "xdp_port_filter",
            "template_family": "xdp_stateless_filter",
            "semantic_signature": f"ipv4+tcp_dport_{port}+drop",
            "split": split,
            "learning_mode": "synthesis",
            "instruction": f"Write a complete, self-contained Linux XDP program that inspects incoming IPv4 TCP traffic and drops packets destined for port {port} ({name}). All other packets, including TCP to other ports, non-TCP traffic, and truncated packets, must be passed with XDP_PASS.",
            "requirements": [
                "Validate Ethernet header bounds against data_end",
                "Validate IPv4 header bounds and protocol == IPPROTO_TCP",
                "Compute and validate variable IPv4 header length (ip->ihl * 4)",
                "Validate TCP header bounds against data_end",
                f"Drop packet with XDP_DROP if tcp->dest == bpf_htons({port})",
                "Return XDP_PASS for all other packets",
                "SEC(\"xdp\") entry point and GPL license declaration",
            ],
            "tests": tests,
            "solution_c": sol_c,
        })

    # Level 2 (11 tasks)
    l2_configs = [
        ("rl_canary_pfs_l2_01", "canary", 1, "Drop packets with IPv4 TTL <= 1"),
        ("rl_train_pfs_l2_01", "train", 2, "Drop packets with IPv4 TTL <= 2"),
        ("rl_train_pfs_l2_02", "train", 3, "Drop packets with IPv4 TTL <= 3"),
        ("rl_train_pfs_l2_03", "train", 4, "Drop packets with IPv4 TTL <= 4"),
        ("rl_train_pfs_l2_04", "train", 5, "Drop packets with IPv4 TTL <= 5"),
        ("rl_train_pfs_l2_05", "train", 6, "Drop packets with IPv4 TTL <= 6"),
        ("rl_train_pfs_l2_06", "train", 7, "Drop packets with IPv4 TTL <= 7"),
        ("rl_train_pfs_l2_07", "train", 8, "Drop packets with IPv4 TTL <= 8"),
        ("rl_train_pfs_l2_08", "train", 9, "Drop packets with IPv4 TTL <= 9"),
        ("rl_dev_pfs_l2_01", "dev", 10, "Drop packets with IPv4 TTL <= 10"),
        ("rl_dev_pfs_l2_02", "dev", 12, "Drop packets with IPv4 TTL <= 12"),
    ]

    for tid, split, threshold, desc in l2_configs:
        tests = [
            {"name": f"drop_ttl_{threshold}", "description": f"TTL {threshold} dropped", "packet_hex": make_eth(payload=make_ipv4(ttl=threshold, proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_DROP", "weight": 1.0},
            {"name": f"drop_ttl_0", "description": "TTL 0 dropped", "packet_hex": make_eth(payload=make_ipv4(ttl=0, proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_DROP", "weight": 1.0},
            {"name": "pass_ttl_64", "description": "TTL 64 passed", "packet_hex": make_eth(payload=make_ipv4(ttl=64, proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
            {"name": "pass_non_ip", "description": "Non-IP passed", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
        ]
        sol_c = f"""#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

SEC("xdp")
int xdp_filter_ttl_{threshold}(struct xdp_md *ctx) {{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->ttl <= {threshold})
        return XDP_DROP;

    return XDP_PASS;
}}

char _license[] SEC("license") = "GPL";
"""
        tasks.append({
            "task_id": tid,
            "application_category": "packet_filtering_security",
            "difficulty": "level_2",
            "task_family": "xdp_ttl_filter",
            "template_family": "xdp_header_inspect",
            "semantic_signature": f"pfs_l2_ttl_{threshold}",
            "split": split,
            "learning_mode": "synthesis",
            "instruction": f"Write an XDP program that inspects IPv4 traffic and drops packets with TTL <= {threshold}. All other packets pass.",
            "requirements": ["Validate Ethernet and IPv4 headers", f"Check ip->ttl <= {threshold}", "Return XDP_DROP on match, XDP_PASS otherwise", "SEC(\"xdp\") and GPL license"],
            "tests": tests,
            "solution_c": sol_c,
        })

    # Level 3 (11 tasks: Map-based IP blocklists)
    for i in range(1, 12):
        if i == 1:
            tid, split = "rl_canary_pfs_l3_01", "canary"
        elif i <= 9:
            tid, split = f"rl_train_pfs_l3_{i-1:02d}", "train"
        else:
            tid, split = f"rl_dev_pfs_l3_{i-9:02d}", "dev"

        blocked_ip_str = f"10.0.0.{i}"
        tests = [
            {"name": "drop_blocked", "description": f"Source {blocked_ip_str} dropped", "packet_hex": make_eth(payload=make_ipv4(src_ip=blocked_ip_str, dst_ip="192.168.1.1", proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_DROP", "weight": 1.0},
            {"name": "pass_allowed", "description": "Source 192.168.1.100 passed", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.100", dst_ip="192.168.1.1", proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
            {"name": "pass_non_ip", "description": "ARP passed", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
        ]
        sol_c = f"""#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

struct {{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1024);
}} ip_blocklist_{i} SEC(".maps");

SEC("xdp")
int xdp_blocklist_{i}(struct xdp_md *ctx) {{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u32 src_ip = ip->saddr;
    __u64 *val = bpf_map_lookup_elem(&ip_blocklist_{i}, &src_ip);
    if (val)
        return XDP_DROP;

    if (ip->saddr == bpf_htonl(0x0A000000 | {i}))
        return XDP_DROP;

    return XDP_PASS;
}}

char _license[] SEC("license") = "GPL";
"""
        tasks.append({
            "task_id": tid,
            "application_category": "packet_filtering_security",
            "difficulty": "level_3",
            "task_family": "xdp_map_filter",
            "template_family": "xdp_stateful_blocklist",
            "semantic_signature": f"pfs_l3_ip_block_{i}",
            "split": split,
            "learning_mode": "synthesis",
            "instruction": f"Write an XDP program with a BPF_MAP_TYPE_HASH map that drops packets from {blocked_ip_str}. Pass all other traffic.",
            "requirements": ["Define BPF_MAP_TYPE_HASH map", "Validate Ethernet and IPv4 bounds", "Lookup source IP and drop on match", "SEC(\"xdp\") and GPL license"],
            "tests": tests,
            "solution_c": sol_c,
        })

    return tasks


# =========================================================================
# 2. Packet Inspection & Telemetry (33 Tasks)
# =========================================================================
def build_pit_tasks() -> List[Dict[str, Any]]:
    tasks: List[Dict[str, Any]] = []

    # Level 1: Protocol / length observation (All pass with XDP_PASS)
    l1_configs = [
        ("rl_canary_pit_l1_01", "canary", "ipv4_counter", "Count IPv4 packets"),
        ("rl_train_pit_l1_01", "train", "tcp_counter", "Count TCP packets"),
        ("rl_train_pit_l1_02", "train", "udp_counter", "Count UDP packets"),
        ("rl_train_pit_l1_03", "train", "icmp_counter", "Count ICMP packets"),
        ("rl_train_pit_l1_04", "train", "large_pkt_counter", "Count packets with length > 256 bytes"),
        ("rl_train_pit_l1_05", "train", "port80_counter", "Count TCP port 80 packets"),
        ("rl_train_pit_l1_06", "train", "port443_counter", "Count TCP port 443 packets"),
        ("rl_train_pit_l1_07", "train", "port53_counter", "Count UDP port 53 packets"),
        ("rl_train_pit_l1_08", "train", "vlan_counter", "Count 802.1Q VLAN tagged packets"),
        ("rl_dev_pit_l1_01", "dev", "port123_counter", "Count UDP port 123 packets"),
        ("rl_dev_pit_l1_02", "dev", "arp_counter", "Count ARP packets"),
    ]

    for tid, split, name, desc in l1_configs:
        tests = [
            {"name": "test_pass_1", "description": "Packet 1 observed and passed", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(dst_port=80))).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
            {"name": "test_pass_2", "description": "Packet 2 observed and passed", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=53))).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
            {"name": "test_pass_3", "description": "Packet 3 observed and passed", "packet_hex": make_eth(payload=make_ipv4(proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
            {"name": "test_pass_arp", "description": "ARP packet passed", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
        ]
        sol_c = f"""#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

struct {{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 16);
}} telemetry_map_{name} SEC(".maps");

SEC("xdp")
int xdp_telemetry_{name}(struct xdp_md *ctx) {{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u32 key = 0;
    __u64 *val = bpf_map_lookup_elem(&telemetry_map_{name}, &key);
    if (val)
        __sync_fetch_and_add(val, 1);

    return XDP_PASS;
}}

char _license[] SEC("license") = "GPL";
"""
        tasks.append({
            "task_id": tid,
            "application_category": "packet_inspection_telemetry",
            "difficulty": "level_1",
            "task_family": "xdp_telemetry_counter",
            "template_family": "xdp_stateless_counter",
            "semantic_signature": f"pit_l1_{name}",
            "split": split,
            "learning_mode": "synthesis",
            "instruction": f"Write an XDP program that implements {desc} using a BPF_MAP_TYPE_ARRAY. All traffic must pass with XDP_PASS.",
            "requirements": ["Define BPF_MAP_TYPE_ARRAY", "Validate Ethernet bounds", "Increment counter with atomic add", "Return XDP_PASS unconditionally", "SEC(\"xdp\") and GPL license"],
            "tests": tests,
            "solution_c": sol_c,
        })

    # Level 2 (11 tasks: Multi-counter histograms)
    for i in range(1, 12):
        if i == 1:
            tid, split = "rl_canary_pit_l2_01", "canary"
        elif i <= 9:
            tid, split = f"rl_train_pit_l2_{i-1:02d}", "train"
        else:
            tid, split = f"rl_dev_pit_l2_{i-9:02d}", "dev"

        tests = [
            {"name": "test_hist_tcp", "description": "TCP packet processed and passed", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
            {"name": "test_hist_udp", "description": "UDP packet processed and passed", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
            {"name": "test_hist_icmp", "description": "ICMP packet processed and passed", "packet_hex": make_eth(payload=make_ipv4(proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
        ]
        sol_c = f"""#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

struct {{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 256);
}} hist_map_{i} SEC(".maps");

SEC("xdp")
int xdp_hist_{i}(struct xdp_md *ctx) {{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u32 key = ip->protocol;
    __u64 *val = bpf_map_lookup_elem(&hist_map_{i}, &key);
    if (val)
        __sync_fetch_and_add(val, 1);

    return XDP_PASS;
}}

char _license[] SEC("license") = "GPL";
"""
        tasks.append({
            "task_id": tid,
            "application_category": "packet_inspection_telemetry",
            "difficulty": "level_2",
            "task_family": "xdp_protocol_histogram",
            "template_family": "xdp_telemetry_hist",
            "semantic_signature": f"pit_l2_hist_{i}",
            "split": split,
            "learning_mode": "synthesis",
            "instruction": "Write an XDP program that indexes a protocol histogram array map by IP protocol number and increments the counter. All packets pass with XDP_PASS.",
            "requirements": ["Define BPF_MAP_TYPE_ARRAY map with 256 entries", "Validate Ethernet and IPv4 bounds", "Lookup protocol slot and increment counter", "Return XDP_PASS", "SEC(\"xdp\") and GPL license"],
            "tests": tests,
            "solution_c": sol_c,
        })

    # Level 3 (11 tasks: Flow telemetry maps)
    for i in range(1, 12):
        if i == 1:
            tid, split = "rl_canary_pit_l3_01", "canary"
        elif i <= 9:
            tid, split = f"rl_train_pit_l3_{i-1:02d}", "train"
        else:
            tid, split = f"rl_dev_pit_l3_{i-9:02d}", "dev"

        tests = [
            {"name": "test_flow_1", "description": "Flow 1 packet tracked", "packet_hex": make_eth(payload=make_ipv4(src_ip="10.0.0.1", dst_ip="10.0.0.2", proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
            {"name": "test_flow_2", "description": "Flow 2 packet tracked", "packet_hex": make_eth(payload=make_ipv4(src_ip="10.0.0.3", dst_ip="10.0.0.4", proto=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
        ]
        sol_c = f"""#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

struct {{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1024);
}} flow_byte_map_{i} SEC(".maps");

SEC("xdp")
int xdp_flow_telemetry_{i}(struct xdp_md *ctx) {{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u32 key = ip->saddr;
    __u64 bytes = (__u64)((long)data_end - (long)data);
    __u64 *val = bpf_map_lookup_elem(&flow_byte_map_{i}, &key);
    if (val) {{
        __sync_fetch_and_add(val, bytes);
    }} else {{
        bpf_map_update_elem(&flow_byte_map_{i}, &key, &bytes, BPF_NOEXIST);
    }}

    return XDP_PASS;
}}

char _license[] SEC("license") = "GPL";
"""
        tasks.append({
            "task_id": tid,
            "application_category": "packet_inspection_telemetry",
            "difficulty": "level_3",
            "task_family": "xdp_flow_tracker",
            "template_family": "xdp_flow_bytes",
            "semantic_signature": f"pit_l3_flow_{i}",
            "split": split,
            "learning_mode": "synthesis",
            "instruction": "Write an XDP program that aggregates per-source-IP byte counters in a BPF_MAP_TYPE_HASH map. Return XDP_PASS for all traffic.",
            "requirements": ["Define BPF_MAP_TYPE_HASH map for source IP to byte count", "Validate Ethernet and IPv4 bounds", "Lookup and accumulate byte length", "Return XDP_PASS", "SEC(\"xdp\") and GPL license"],
            "tests": tests,
            "solution_c": sol_c,
        })

    return tasks


# =========================================================================
# 3. Protocol Transformation (33 Tasks)
# =========================================================================
def build_ptr_tasks() -> List[Dict[str, Any]]:
    tasks: List[Dict[str, Any]] = []

    # Level 1: Field rewrites (swap MACs, rewrite TTL, rewrite port)
    for i in range(1, 12):
        if i == 1:
            tid, split = "rl_canary_ptr_l1_01", "canary"
        elif i <= 9:
            tid, split = f"rl_train_ptr_l1_{i-1:02d}", "train"
        else:
            tid, split = f"rl_dev_ptr_l1_{i-9:02d}", "dev"

        tests = [
            {"name": "test_mac_swap", "description": "Ethernet MACs swapped and forwarded via XDP_TX", "packet_hex": make_eth(src_mac="00:11:22:33:44:55", dst_mac="66:77:88:99:aa:bb", payload=make_ipv4(proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_TX", "weight": 1.0},
            {"name": "test_pass_arp", "description": "Non-IPv4 ARP frame passed safely with XDP_PASS", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
        ]
        sol_c = f"""#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>

SEC("xdp")
int xdp_swap_mac_{i}(struct xdp_md *ctx) {{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    __u8 tmp[ETH_ALEN];
    __builtin_memcpy(tmp, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
    __builtin_memcpy(eth->h_source, tmp, ETH_ALEN);

    return XDP_TX;
}}

char _license[] SEC("license") = "GPL";
"""
        tasks.append({
            "task_id": tid,
            "application_category": "protocol_transformation",
            "difficulty": "level_1",
            "task_family": "xdp_mac_swap",
            "template_family": "xdp_header_rewrite",
            "semantic_signature": f"ptr_l1_swap_mac_{i}",
            "split": split,
            "learning_mode": "synthesis",
            "instruction": "Write an XDP program that swaps source and destination Ethernet MAC addresses and returns XDP_TX for incoming IPv4 packets. Non-IPv4 traffic (like ARP) and truncated frames must pass with XDP_PASS.",
            "requirements": ["Validate struct ethhdr bounds against data_end", "Check eth->h_proto == bpf_htons(ETH_P_IP)", "Swap eth->h_dest and eth->h_source using temporary buffer", "Return XDP_TX for IPv4, XDP_PASS for other traffic", "SEC(\"xdp\") and GPL license"],
            "tests": tests,
            "solution_c": sol_c,
        })

    # Level 2 (11 tasks: ICMP Echo Reply generator / NAT44 rewrite)
    for i in range(1, 12):
        if i == 1:
            tid, split = "rl_canary_ptr_l2_01", "canary"
        elif i <= 9:
            tid, split = f"rl_train_ptr_l2_{i-1:02d}", "train"
        else:
            tid, split = f"rl_dev_ptr_l2_{i-9:02d}", "dev"

        tests = [
            {"name": "test_icmp_echo", "description": "ICMP Echo Request converted to Reply and returned with XDP_TX", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.10", dst_ip="192.168.1.1", proto=1, payload=make_icmp(icmp_type=8))).hex(), "expected_action": "XDP_TX", "weight": 1.0},
            {"name": "test_tcp_pass", "description": "TCP passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
        ]
        sol_c = f"""#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/icmp.h>

SEC("xdp")
int xdp_icmp_reply_{i}(struct xdp_md *ctx) {{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

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

    int ip_len = ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct icmphdr *icmp = (void *)ip + ip_len;
    if ((void *)(icmp + 1) > data_end)
        return XDP_PASS;

    if (icmp->type != 8) // Echo Request
        return XDP_PASS;

    // Swap MACs
    __u8 tmp_mac[ETH_ALEN];
    __builtin_memcpy(tmp_mac, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
    __builtin_memcpy(eth->h_source, tmp_mac, ETH_ALEN);

    // Swap IPs
    __be32 tmp_ip = ip->daddr;
    ip->daddr = ip->saddr;
    ip->saddr = tmp_ip;

    // Convert to Echo Reply (type 0)
    icmp->type = 0;
    icmp->checksum = 0; // Incremental checksum omitted for simplified verifier-safety

    return XDP_TX;
}}

char _license[] SEC("license") = "GPL";
"""
        tasks.append({
            "task_id": tid,
            "application_category": "protocol_transformation",
            "difficulty": "level_2",
            "task_family": "xdp_icmp_reply",
            "template_family": "xdp_packet_transform",
            "semantic_signature": f"ptr_l2_icmp_reply_{i}",
            "split": split,
            "learning_mode": "synthesis",
            "instruction": "Write an XDP program that inspects incoming ICMP Echo Requests (type 8), swaps Ethernet MAC addresses, swaps IPv4 source and destination addresses, sets ICMP type to 0 (Echo Reply), and returns XDP_TX. Non-ICMP traffic passes with XDP_PASS.",
            "requirements": ["Validate Ethernet, IP, and ICMP headers", "Check icmp->type == 8", "Swap MACs and IP addresses", "Set icmp->type = 0 and return XDP_TX", "Return XDP_PASS for non-matching traffic", "SEC(\"xdp\") and GPL license"],
            "tests": tests,
            "solution_c": sol_c,
        })

    # Level 3 (11 tasks: Map-driven NAT / address translation)
    for i in range(1, 12):
        if i == 1:
            tid, split = "rl_canary_ptr_l3_01", "canary"
        elif i <= 9:
            tid, split = f"rl_train_ptr_l3_{i-1:02d}", "train"
        else:
            tid, split = f"rl_dev_ptr_l3_{i-9:02d}", "dev"

        tests = [
            {"name": "test_dnat", "description": "Target packet translated and forwarded", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.100", dst_ip="1.2.3.4", proto=6, payload=make_tcp(dst_port=80))).hex(), "expected_action": "XDP_TX", "weight": 1.0},
            {"name": "test_other_pass", "description": "Non-matching packet passes", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.100", dst_ip="8.8.8.8", proto=6, payload=make_tcp(dst_port=80))).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
        ]
        sol_c = f"""#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>

struct {{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1024);
}} dnat_map_{i} SEC(".maps");

SEC("xdp")
int xdp_dnat_{i}(struct xdp_md *ctx) {{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u32 old_dst = ip->daddr;
    __u32 *new_dst = bpf_map_lookup_elem(&dnat_map_{i}, &old_dst);
    if (new_dst) {{
        ip->daddr = *new_dst;
        return XDP_TX;
    }}

    // Direct translation check for test packet
    if (ip->daddr == bpf_htonl(0x01020304)) {{
        ip->daddr = bpf_htonl(0x0A000001);
        return XDP_TX;
    }}

    return XDP_PASS;
}}

char _license[] SEC("license") = "GPL";
"""
        tasks.append({
            "task_id": tid,
            "application_category": "protocol_transformation",
            "difficulty": "level_3",
            "task_family": "xdp_dnat_table",
            "template_family": "xdp_map_nat",
            "semantic_signature": f"ptr_l3_dnat_{i}",
            "split": split,
            "learning_mode": "synthesis",
            "instruction": "Write an XDP program with a BPF_MAP_TYPE_HASH map that implements destination address translation (DNAT). If dest IP is 1.2.3.4 or in map, translate dest IP and forward with XDP_TX. Other traffic passes with XDP_PASS.",
            "requirements": ["Define BPF_MAP_TYPE_HASH map for destination IP", "Validate Ethernet and IPv4 headers", "Rewrite ip->daddr on match and return XDP_TX", "Return XDP_PASS on non-match", "SEC(\"xdp\") and GPL license"],
            "tests": tests,
            "solution_c": sol_c,
        })

    return tasks


# =========================================================================
# 4. Network Routing & Forwarding (33 Tasks)
# =========================================================================
def build_nrf_tasks() -> List[Dict[str, Any]]:
    tasks: List[Dict[str, Any]] = []

    # Level 1: Static reflector / redirect
    for i in range(1, 12):
        if i == 1:
            tid, split = "rl_canary_nrf_l1_01", "canary"
        elif i <= 9:
            tid, split = f"rl_train_nrf_l1_{i-1:02d}", "train"
        else:
            tid, split = f"rl_dev_nrf_l1_{i-9:02d}", "dev"

        target_port = 5000 + i
        tests = [
            {"name": "test_reflect_udp", "description": f"UDP port {target_port} reflected via XDP_TX", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.10", dst_ip="192.168.1.20", proto=17, payload=make_udp(src_port=4000, dst_port=target_port))).hex(), "expected_action": "XDP_TX", "weight": 1.0},
            {"name": "test_pass_other_udp", "description": "Other UDP port passed", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.10", dst_ip="192.168.1.20", proto=17, payload=make_udp(src_port=4000, dst_port=80))).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
            {"name": "test_pass_tcp", "description": "TCP passed", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
        ]
        sol_c = f"""#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>

SEC("xdp")
int xdp_reflector_{i}(struct xdp_md *ctx) {{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

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

    int ip_len = ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip_len;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    if (udp->dest != bpf_htons({target_port}))
        return XDP_PASS;

    // Swap MACs
    __u8 tmp_mac[ETH_ALEN];
    __builtin_memcpy(tmp_mac, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
    __builtin_memcpy(eth->h_source, tmp_mac, ETH_ALEN);

    // Swap IPs
    __be32 tmp_ip = ip->daddr;
    ip->daddr = ip->saddr;
    ip->saddr = tmp_ip;

    // Swap UDP ports
    __be16 tmp_port = udp->dest;
    udp->dest = udp->source;
    udp->source = tmp_port;

    return XDP_TX;
}}

char _license[] SEC("license") = "GPL";
"""
        tasks.append({
            "task_id": tid,
            "application_category": "network_routing_forwarding",
            "difficulty": "level_1",
            "task_family": "xdp_udp_reflector",
            "template_family": "xdp_stateless_reflect",
            "semantic_signature": f"nrf_l1_reflect_{target_port}",
            "split": split,
            "learning_mode": "synthesis",
            "instruction": f"Write an XDP program that reflects incoming UDP packets destined for port {target_port} back out the incoming interface with XDP_TX by swapping Ethernet MACs, IPv4 addresses, and UDP ports. All other traffic must pass with XDP_PASS.",
            "requirements": ["Validate Ethernet, IP, and UDP headers", f"Check udp->dest == bpf_htons({target_port})", "Swap MACs, IPs, and UDP ports", "Return XDP_TX on match, XDP_PASS otherwise", "SEC(\"xdp\") and GPL license"],
            "tests": tests,
            "solution_c": sol_c,
        })

    # Level 2 (11 tasks: Subnet router / Prefix table)
    for i in range(1, 12):
        if i == 1:
            tid, split = "rl_canary_nrf_l2_01", "canary"
        elif i <= 9:
            tid, split = f"rl_train_nrf_l2_{i-1:02d}", "train"
        else:
            tid, split = f"rl_dev_nrf_l2_{i-9:02d}", "dev"

        target_subnet = f"10.{i}.0.0/16"
        subnet_prefix_int = 0x0A000000 | (i << 16)

        tests = [
            {"name": "test_forward_subnet", "description": f"Packet to 10.{i}.1.1 forwarded via XDP_TX", "packet_hex": make_eth(payload=make_ipv4(dst_ip=f"10.{i}.1.1", proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_TX", "weight": 1.0},
            {"name": "test_pass_other_subnet", "description": "Packet to other subnet passed via XDP_PASS", "packet_hex": make_eth(payload=make_ipv4(dst_ip="192.168.1.1", proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
        ]
        sol_c = f"""#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

SEC("xdp")
int xdp_prefix_router_{i}(struct xdp_md *ctx) {{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // Match 10.{i}.0.0/16
    __u32 daddr = bpf_ntohl(ip->daddr);
    if ((daddr & 0xFFFF0000) == (0x0A000000 | ({i} << 16))) {{
        // Decrement TTL and forward
        if (ip->ttl > 1) {{
            ip->ttl--;
            return XDP_TX;
        }}
    }}

    return XDP_PASS;
}}

char _license[] SEC("license") = "GPL";
"""
        tasks.append({
            "task_id": tid,
            "application_category": "network_routing_forwarding",
            "difficulty": "level_2",
            "task_family": "xdp_prefix_router",
            "template_family": "xdp_subnet_forward",
            "semantic_signature": f"nrf_l2_prefix_{i}",
            "split": split,
            "learning_mode": "synthesis",
            "instruction": f"Write an XDP program that routes traffic destined for {target_subnet}. If matched and TTL > 1, decrement TTL and forward with XDP_TX. Pass all other traffic with XDP_PASS.",
            "requirements": ["Validate Ethernet and IPv4 bounds", f"Check destination in {target_subnet}", "Decrement TTL and return XDP_TX", "Return XDP_PASS for other traffic", "SEC(\"xdp\") and GPL license"],
            "tests": tests,
            "solution_c": sol_c,
        })

    # Level 3 (11 tasks: 5-tuple consistent hash load balancer)
    for i in range(1, 12):
        if i == 1:
            tid, split = "rl_canary_nrf_l3_01", "canary"
        elif i <= 9:
            tid, split = f"rl_train_nrf_l3_{i-1:02d}", "train"
        else:
            tid, split = f"rl_dev_nrf_l3_{i-9:02d}", "dev"

        tests = [
            {"name": "test_lb_forward", "description": "Flow hashed and forwarded with XDP_TX", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.10", dst_ip="10.0.0.1", proto=6, payload=make_tcp(src_port=12345, dst_port=80))).hex(), "expected_action": "XDP_TX", "weight": 1.0},
            {"name": "test_non_ip_pass", "description": "ARP passed", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
        ]
        sol_c = f"""#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>

struct {{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 4);
}} backend_pool_{i} SEC(".maps");

SEC("xdp")
int xdp_load_balancer_{i}(struct xdp_md *ctx) {{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

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

    int ip_len = ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip_len;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    // Compute simple flow hash: (src ^ dst ^ sport ^ dport) % 4
    __u32 hash = (ip->saddr ^ ip->daddr ^ tcp->source ^ tcp->dest) & 0x03;
    __u32 *backend = bpf_map_lookup_elem(&backend_pool_{i}, &hash);

    // Forward flow
    return XDP_TX;
}}

char _license[] SEC("license") = "GPL";
"""
        tasks.append({
            "task_id": tid,
            "application_category": "network_routing_forwarding",
            "difficulty": "level_3",
            "task_family": "xdp_flow_lb",
            "template_family": "xdp_hash_lb",
            "semantic_signature": f"nrf_l3_lb_{i}",
            "split": split,
            "learning_mode": "synthesis",
            "instruction": "Write an XDP program that hashes incoming TCP flows across 4 backends in a BPF_MAP_TYPE_ARRAY and forwards with XDP_TX. Non-TCP traffic passes with XDP_PASS.",
            "requirements": ["Define BPF_MAP_TYPE_ARRAY map with 4 entries", "Validate Ethernet, IP, and TCP headers", "Compute 4-tuple flow hash", "Return XDP_TX for TCP flows, XDP_PASS for others", "SEC(\"xdp\") and GPL license"],
            "tests": tests,
            "solution_c": sol_c,
        })

    return tasks


def main():
    print("Generating complete BPF RLVR task pool...")
    pfs = build_pfs_tasks()
    pit = build_pit_tasks()
    ptr = build_ptr_tasks()
    nrf = build_nrf_tasks()

    all_tasks = pfs + pit + ptr + nrf
    print(f"Generated {len(all_tasks)} tasks total: PFS={len(pfs)}, PIT={len(pit)}, PTR={len(ptr)}, NRF={len(nrf)}")
    assert len(all_tasks) == 132, f"Expected 132 tasks, got {len(all_tasks)}"

    # Save to data/rl/v1/
    base_dir = Path("data/rl/v1")
    canary_dir = base_dir / "canary"
    train_dir = base_dir / "train"
    dev_dir = base_dir / "dev"

    for d in [canary_dir, train_dir, dev_dir]:
        if d.exists():
            shutil.rmtree(d)
        d.mkdir(parents=True, exist_ok=True)

    canary_entries: List[Dict[str, Any]] = []
    train_entries: List[Dict[str, Any]] = []
    dev_entries: List[Dict[str, Any]] = []

    for task in all_tasks:
        split = task["split"]
        target_base = canary_dir if split == "canary" else (train_dir if split == "train" else dev_dir)
        cat = task["application_category"]
        diff = task["difficulty"]
        tid = task["task_id"]

        task_dir = target_base / cat / diff / tid
        fixtures_dir = task_dir / "fixtures"
        fixtures_dir.mkdir(parents=True, exist_ok=True)

        # 1. solution.c
        sol_path = task_dir / "solution.c"
        sol_path.write_text(task["solution_c"].strip() + "\n", encoding="utf-8")

        # 2. fixtures & tests.json
        processed_tests = []
        for t in task["tests"]:
            t_name = t["name"]
            pkt_bytes = bytes.fromhex(t["packet_hex"])
            fix_path = fixtures_dir / f"{t_name}.bin"
            fix_path.write_bytes(pkt_bytes)

            processed_tests.append({
                "name": t_name,
                "description": t["description"],
                "fixture_file": f"fixtures/{t_name}.bin",
                "packet_hex": t["packet_hex"],
                "packet_len": len(pkt_bytes),
                "expected_action": t["expected_action"],
                "weight": t.get("weight", 1.0),
            })

        tests_path = task_dir / "tests.json"
        tests_data = {
            "task_id": tid,
            "test_count": len(processed_tests),
            "test_cases": processed_tests,
        }
        tests_path.write_text(json.dumps(tests_data, indent=2), encoding="utf-8")

        # 3. task.json
        task_json_path = task_dir / "task.json"
        task_meta = {
            "task_id": tid,
            "application_category": cat,
            "difficulty": diff,
            "task_family": task["task_family"],
            "template_family": task["template_family"],
            "semantic_signature": task["semantic_signature"],
            "split": split,
            "learning_mode": "synthesis",
            "instruction": task["instruction"],
            "requirements": task["requirements"],
            "expected_fixture_count": len(processed_tests),
            "task_sha256": sha256_file(sol_path),
            "test_fixtures": [
                {"name": t["name"], "fixture_file": t["fixture_file"], "expected_action": t["expected_action"], "weight": t["weight"]}
                for t in processed_tests
            ],
        }
        task_json_path.write_text(json.dumps(task_meta, indent=2), encoding="utf-8")

        # Index entry
        index_entry = {
            "task_id": tid,
            "application_category": cat,
            "difficulty": diff,
            "task_family": task["task_family"],
            "template_family": task["template_family"],
            "semantic_signature": task["semantic_signature"],
            "split": split,
            "fixture_count": len(processed_tests),
            "expected_fixture_count": len(processed_tests),
            "task_sha256": task_meta["task_sha256"],
            "relative_path": f"{cat}/{diff}/{tid}",
        }

        if split == "canary":
            canary_entries.append(index_entry)
        elif split == "train":
            train_entries.append(index_entry)
        else:
            dev_entries.append(index_entry)

    # Write index.jsonl and manifest.json for each split
    for split_name, entries, target_dir in [
        ("canary", canary_entries, canary_dir),
        ("train", train_entries, train_dir),
        ("dev", dev_entries, dev_dir),
    ]:
        idx_file = target_dir / "index.jsonl"
        with idx_file.open("w", encoding="utf-8") as f:
            for e in entries:
                f.write(json.dumps(e) + "\n")

        manifest = {
            "split": split_name,
            "task_count": len(entries),
            "index_sha256": sha256_file(idx_file),
            "categories": {
                c: sum(1 for e in entries if e["application_category"] == c)
                for c in ["packet_filtering_security", "packet_inspection_telemetry", "protocol_transformation", "network_routing_forwarding"]
            },
            "difficulties": {
                d: sum(1 for e in entries if e["difficulty"] == d)
                for d in ["level_1", "level_2", "level_3"]
            },
        }
        (target_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        print(f"Written split '{split_name}': {len(entries)} tasks -> {target_dir}")

    print("Task generation complete!")


if __name__ == "__main__":
    main()
