"""
BPF-Guardian RLVR Phase 2: Packet Inspection & Telemetry (PIT) Task Definitions.
Contains 66 distinct, verifier-safe tasks with strict task-family disjointness across splits:
- Level 1 (22 tasks):
    * Canary (1): Frame type counter (IPv4 vs IPv6 vs ARP)
    * Train (12): Array map Layer 4 protocol counter (TCP/UDP/ICMP/other)
    * Dev (4): Array map packet wire size histogram (<128, 128-512, 512-1024, >1024)
    * Confirmation (5): Array map TCP flag distribution counter (SYN, ACK, FIN, RST, PSH)
- Level 2 (22 tasks):
    * Canary (1): LRU hash VLAN tag traffic volume counter
    * Train (12): LRU hash per-source IP packet counter
    * Dev (4): LRU hash per-destination IP byte volume accumulator
    * Confirmation (5): LRU hash 5-tuple active flow session tracker
- Level 3 (22 tasks):
    * Canary (1): Dual-map TCP handshake state telemetry
    * Train (12): Dual-map flow table (LRU) and global packet counters (Array)
    * Dev (4): TCP advertised window distribution telemetry
    * Confirmation (5): Flow lifetime duration and timestamp tracking
"""

from __future__ import annotations

from typing import Any, Dict, List, Tuple
from scripts.synthesis_benchmark_gen.packet_utils import (
    make_arp,
    make_eth,
    make_icmp,
    make_ipv4,
    make_tcp,
    make_udp,
)


def get_split_and_index(idx_in_cell: int) -> Tuple[str, int]:
    """Maps 0..21 index within cell to (split, split_sub_index).
    0: canary (1)
    1..12: train (12)
    13..16: dev (4)
    17..21: confirmation (5)
    """
    if idx_in_cell == 0:
        return "canary", 1
    elif idx_in_cell <= 12:
        return "train", idx_in_cell
    elif idx_in_cell <= 16:
        return "dev", idx_in_cell - 12
    else:
        return "confirmation", idx_in_cell - 16


def build_pit_l1_tasks() -> List[Dict[str, Any]]:
    tasks = []

    # --- Canary (idx 0): Frame type counter ---
    canary_task = {
        "task_id": "rl_v2_canary_pit_l1_01",
        "application_category": "packet_inspection_telemetry",
        "difficulty": "level_1",
        "task_family": "canary_pit_l1_frame_type_counter",
        "template_family": "xdp_frame_counter",
        "semantic_signature": "pit_l1_frame_type_canary",
        "split": "canary",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that inspects ingress frames and records EtherType distribution in BPF_MAP_TYPE_ARRAY map 'frame_type_map' with 4 entries: index 1 for IPv4, index 2 for ARP, index 0 for others. Return XDP_PASS for all traffic.",
        "requirements": [
            "Define BPF_MAP_TYPE_ARRAY map 'frame_type_map' with 4 entries and __u64 value type",
            "Verify Ethernet header bounds against data_end",
            "Map eth->h_proto to index: ETH_P_IP -> 1, ETH_P_ARP -> 2, other -> 0",
            "Atomically increment counter at selected index using __sync_fetch_and_add",
            "Return XDP_PASS unconditionally",
            "SEC(\"xdp\") entry point and GPL license declaration",
        ],
        "tests": [
            {"name": "pass_ipv4", "description": "IPv4 counted and passed", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
            {"name": "pass_arp", "description": "ARP counted and passed", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
        ],
        "solution_c": """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 4);
} frame_type_map SEC(".maps");

SEC("xdp")
int xdp_count_frames(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u32 idx = 0;
    if (eth->h_proto == bpf_htons(ETH_P_IP))
        idx = 1;
    else if (eth->h_proto == bpf_htons(ETH_P_ARP))
        idx = 2;

    __u64 *counter = bpf_map_lookup_elem(&frame_type_map, &idx);
    if (counter)
        __sync_fetch_and_add(counter, 1);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
""",
    }
    tasks.append(canary_task)

    # --- Train (idx 1..12): Array map Layer 4 protocol counter (TCP/UDP/ICMP/other) ---
    train_l1_descs = [
        ("proto_stats_01", "record incoming transport layer protocol occurrences in array map 'proto_stats_301'"),
        ("proto_stats_02", "tabulate L4 traffic breakdown across TCP, UDP, and ICMP in map 'proto_stats_302'"),
        ("proto_stats_03", "maintain telemetry protocol histogram in BPF_MAP_TYPE_ARRAY map 'proto_stats_303'"),
        ("proto_stats_04", "classify transport protocol types and update atomic counters in 'proto_stats_304'"),
        ("proto_stats_05", "profile packet protocol frequencies in telemetry array map 'proto_stats_305'"),
        ("proto_stats_06", "track Layer 4 distribution in atomic statistics table 'proto_stats_306'"),
        ("proto_stats_07", "aggregate protocol counters for network monitoring in array map 'proto_stats_307'"),
        ("proto_stats_08", "collect L4 protocol metrics using 16-entry array map 'proto_stats_308'"),
        ("proto_stats_09", "log ingress packet protocol classification stats in array map 'proto_stats_309'"),
        ("proto_stats_10", "count network datagram protocols atomically in array map 'proto_stats_310'"),
        ("proto_stats_11", "record telemetry protocol distribution bins in array map 'proto_stats_311'"),
        ("proto_stats_12", "increment protocol usage counters in BPF_MAP_TYPE_ARRAY map 'proto_stats_312'"),
    ]

    for sub_idx, (name, desc) in enumerate(train_l1_descs, start=1):
        map_id = 300 + sub_idx
        tid = f"rl_v2_train_pit_l1_{sub_idx:02d}"
        fam = f"train_pit_l1_{name}"
        tasks.append({
            "task_id": tid,
            "application_category": "packet_inspection_telemetry",
            "difficulty": "level_1",
            "task_family": fam,
            "template_family": "xdp_protocol_counter",
            "semantic_signature": f"pit_l1_proto_{map_id}",
            "split": "train",
            "learning_mode": "synthesis",
            "instruction": f"Write an XDP program that must {desc}. Map TCP to index 1, UDP to index 2, ICMP to index 3, and other IP/non-IP to index 0. Forward all packets with XDP_PASS.",
            "requirements": [
                f"Define BPF_MAP_TYPE_ARRAY map 'proto_stats_{map_id}' with 16 entries and __u64 values",
                "Safely validate Ethernet and IPv4 header bounds against data_end",
                "Map TCP to index 1, UDP to index 2, ICMP to index 3, non-IP/other to index 0",
                "Perform atomic counter addition using __sync_fetch_and_add",
                "Return XDP_PASS unconditionally",
                "SEC(\"xdp\") entry point and GPL license declaration",
            ],
            "tests": [
                {"name": "pass_tcp", "description": "TCP packet counted and passed", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
                {"name": "pass_udp", "description": "UDP packet counted and passed", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
                {"name": "pass_icmp", "description": "ICMP packet counted and passed", "packet_hex": make_eth(payload=make_ipv4(proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
                {"name": "pass_arp", "description": "ARP frame counted in index 0", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
            ],
            "solution_c": f"""#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>

struct {{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 16);
}} proto_stats_{map_id} SEC(".maps");

SEC("xdp")
int xdp_stats_{map_id}(struct xdp_md *ctx) {{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u32 idx = 0;
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {{
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) <= data_end) {{
            if (ip->protocol == IPPROTO_TCP)
                idx = 1;
            else if (ip->protocol == IPPROTO_UDP)
                idx = 2;
            else if (ip->protocol == IPPROTO_ICMP)
                idx = 3;
        }}
    }}

    __u64 *counter = bpf_map_lookup_elem(&proto_stats_{map_id}, &idx);
    if (counter)
        __sync_fetch_and_add(counter, 1);

    return XDP_PASS;
}}

char _license[] SEC("license") = "GPL";
""",
        })

    # --- Dev (idx 13..16): Array map packet wire size histogram ---
    dev_l1_descs = [
        ("size_hist_dev01", "record packet size distribution in histogram array 'size_hist_01' (<128, 128-512, 512-1024, >1024)"),
        ("size_hist_dev02", "tabulate wire frame length metrics across 4 size bins in 'size_hist_02'"),
        ("size_hist_dev03", "measure packet payload sizes in length histogram array 'size_hist_03'"),
        ("size_hist_dev04", "classify packet length categories into 4 bins using array map 'size_hist_04'"),
    ]

    for sub_idx, (name, desc) in enumerate(dev_l1_descs, start=1):
        tid = f"rl_v2_dev_pit_l1_{sub_idx:02d}"
        fam = f"dev_pit_l1_{name}"
        tasks.append({
            "task_id": tid,
            "application_category": "packet_inspection_telemetry",
            "difficulty": "level_1",
            "task_family": fam,
            "template_family": "xdp_size_histogram",
            "semantic_signature": f"pit_l1_size_hist_{sub_idx}",
            "split": "dev",
            "learning_mode": "synthesis",
            "instruction": f"Write an XDP program that must {desc}. Bin 0: len < 128, Bin 1: 128 <= len < 512, Bin 2: 512 <= len < 1024, Bin 3: len >= 1024. Return XDP_PASS for all frames.",
            "requirements": [
                f"Define BPF_MAP_TYPE_ARRAY map 'size_hist_{sub_idx}' with 4 entries and __u64 values",
                "Calculate total wire frame length as (ctx->data_end - ctx->data)",
                "Assign bin: <128 -> 0, <512 -> 1, <1024 -> 2, >=1024 -> 3",
                "Atomically increment bin counter using __sync_fetch_and_add",
                "Return XDP_PASS unconditionally",
                "SEC(\"xdp\") entry point and GPL license declaration",
            ],
            "tests": [
                {"name": "pass_small", "description": "Small 54 byte frame in bin 0", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
                {"name": "pass_medium", "description": "Medium 200 byte frame in bin 1", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(payload=b"A"*160))).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
            ],
            "solution_c": f"""#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 4);
}} size_hist_{sub_idx} SEC(".maps");

SEC("xdp")
int xdp_hist_{sub_idx}(struct xdp_md *ctx) {{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    long len = (long)data_end - (long)data;
    __u32 bin = 0;
    if (len < 128)
        bin = 0;
    else if (len < 512)
        bin = 1;
    else if (len < 1024)
        bin = 2;
    else
        bin = 3;

    __u64 *val = bpf_map_lookup_elem(&size_hist_{sub_idx}, &bin);
    if (val)
        __sync_fetch_and_add(val, 1);

    return XDP_PASS;
}}

char _license[] SEC("license") = "GPL";
""",
        })

    # --- Confirmation (idx 17..21): Array map TCP flag distribution counter ---
    conf_l1_descs = [
        ("tcp_flag_conf01", "tabulate TCP control flag distribution in array map 'tcp_flags_01' (SYN:0, ACK:1, FIN:2, RST:3, PSH:4)"),
        ("tcp_flag_conf02", "record frequencies of SYN, ACK, FIN, RST, and PSH flags in 'tcp_flags_02'"),
        ("tcp_flag_conf03", "profile TCP handshake and termination flag occurrences in telemetry map 'tcp_flags_03'"),
        ("tcp_flag_conf04", "count TCP control bits across 5 array indices in 'tcp_flags_04'"),
        ("tcp_flag_conf05", "monitor TCP session flags and increment statistics in array map 'tcp_flags_05'"),
    ]

    for sub_idx, (name, desc) in enumerate(conf_l1_descs, start=1):
        tid = f"rl_v2_conf_pit_l1_{sub_idx:02d}"
        fam = f"conf_pit_l1_{name}"
        tasks.append({
            "task_id": tid,
            "application_category": "packet_inspection_telemetry",
            "difficulty": "level_1",
            "task_family": fam,
            "template_family": "xdp_tcp_flag_counter",
            "semantic_signature": f"pit_l1_flags_{sub_idx}",
            "split": "confirmation",
            "learning_mode": "synthesis",
            "instruction": f"Write an XDP program that must {desc}. Map SYN->0, ACK->1, FIN->2, RST->3, PSH->4. Return XDP_PASS for all traffic.",
            "requirements": [
                f"Define BPF_MAP_TYPE_ARRAY map 'tcp_flags_{sub_idx}' with 8 entries and __u64 values",
                "Verify Ethernet, IPv4, and TCP header bounds against data_end",
                "Inspect TCP flags and increment matching index: SYN->0, ACK->1, FIN->2, RST->3, PSH->4",
                "Atomically increment counter via __sync_fetch_and_add",
                "Return XDP_PASS unconditionally",
                "SEC(\"xdp\") entry point and GPL license declaration",
            ],
            "tests": [
                {"name": "pass_syn", "description": "SYN flag incremented", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(flags=0x02))).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
                {"name": "pass_ack", "description": "ACK flag incremented", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(flags=0x10))).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
                {"name": "pass_udp", "description": "Non-TCP passes without counting", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
            ],
            "solution_c": f"""#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>

struct {{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 8);
}} tcp_flags_{sub_idx} SEC(".maps");

SEC("xdp")
int xdp_count_flags_{sub_idx}(struct xdp_md *ctx) {{
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

    __u32 idx = 0;
    if (tcp->syn) idx = 0;
    else if (tcp->ack) idx = 1;
    else if (tcp->fin) idx = 2;
    else if (tcp->rst) idx = 3;
    else if (tcp->psh) idx = 4;
    else return XDP_PASS;

    __u64 *counter = bpf_map_lookup_elem(&tcp_flags_{sub_idx}, &idx);
    if (counter)
        __sync_fetch_and_add(counter, 1);

    return XDP_PASS;
}}

char _license[] SEC("license") = "GPL";
""",
        })

    return tasks


def build_pit_l2_tasks() -> List[Dict[str, Any]]:
    tasks = []

    # --- Canary (idx 0): LRU hash VLAN tag traffic volume counter ---
    canary_task = {
        "task_id": "rl_v2_canary_pit_l2_01",
        "application_category": "packet_inspection_telemetry",
        "difficulty": "level_2",
        "task_family": "canary_pit_l2_vlan_usage",
        "template_family": "xdp_vlan_counter",
        "semantic_signature": "pit_l2_vlan_counter_canary",
        "split": "canary",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that inspects 802.1Q VLAN tagged frames and records traffic volume in BPF_MAP_TYPE_LRU_HASH map 'vlan_usage_map' keyed by VLAN ID. Return XDP_PASS for all traffic.",
        "requirements": [
            "Define BPF_MAP_TYPE_LRU_HASH map 'vlan_usage_map' with key __u16 and value __u64",
            "Verify Ethernet and 802.1Q header bounds against data_end",
            "Extract 12-bit VLAN identifier from vlan->h_vlan_TCI",
            "Lookup VLAN ID in map and atomically increment counter, or initialize with 1",
            "Return XDP_PASS unconditionally",
            "SEC(\"xdp\") entry point and GPL license declaration",
        ],
        "tests": [
            {"name": "pass_vlan_100", "description": "VLAN 100 counted and passed", "packet_hex": make_eth(vlan=100, payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
            {"name": "pass_untagged", "description": "Untagged passed unmodified", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
        ],
        "solution_c": """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u16);
    __type(value, __u64);
    __uint(max_entries, 1024);
} vlan_usage_map SEC(".maps");

struct vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

SEC("xdp")
int xdp_count_vlan(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto == bpf_htons(ETH_P_8021Q)) {
        struct vlan_hdr *vlan = (void *)(eth + 1);
        if ((void *)(vlan + 1) > data_end)
            return XDP_PASS;

        __u16 vid = bpf_ntohs(vlan->h_vlan_TCI) & 0x0FFF;
        __u64 *count = bpf_map_lookup_elem(&vlan_usage_map, &vid);
        if (count) {
            __sync_fetch_and_add(count, 1);
        } else {
            __u64 init_c = 1;
            bpf_map_update_elem(&vlan_usage_map, &vid, &init_c, BPF_NOEXIST);
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
""",
    }
    tasks.append(canary_task)

    # --- Train (idx 1..12): LRU hash per-source IP packet counter ---
    train_l2_descs = [
        ("src_telemetry_01", "track packet count per source IP address in LRU hash table 'src_stat_map_01'"),
        ("src_telemetry_02", "profile client IP traffic volume in LRU hash map 'src_stat_map_02'"),
        ("src_telemetry_03", "monitor source host packet frequencies in BPF_MAP_TYPE_LRU_HASH map 'src_stat_map_03'"),
        ("src_telemetry_04", "record per-sender telemetry in LRU hash table 'src_stat_map_04'"),
        ("src_telemetry_05", "accumulate inbound client frame statistics in 'src_stat_map_05'"),
        ("src_telemetry_06", "maintain source IP activity table using LRU hash map 'src_stat_map_06'"),
        ("src_telemetry_07", "aggregate sender packet volumes in LRU cache 'src_stat_map_07'"),
        ("src_telemetry_08", "log per-host transmission counts in LRU hash map 'src_stat_map_08'"),
        ("src_telemetry_09", "index client network traffic in LRU tracking map 'src_stat_map_09'"),
        ("src_telemetry_10", "count packet arrivals per source endpoint in LRU hash 'src_stat_map_10'"),
        ("src_telemetry_11", "collect source IP flow telemetry in LRU map 'src_stat_map_11'"),
        ("src_telemetry_12", "track sender packet rates in BPF_MAP_TYPE_LRU_HASH map 'src_stat_map_12'"),
    ]

    for sub_idx, (name, desc) in enumerate(train_l2_descs, start=1):
        tid = f"rl_v2_train_pit_l2_{sub_idx:02d}"
        fam = f"train_pit_l2_{name}"
        tasks.append({
            "task_id": tid,
            "application_category": "packet_inspection_telemetry",
            "difficulty": "level_2",
            "task_family": fam,
            "template_family": "xdp_src_ip_counter",
            "semantic_signature": f"pit_l2_src_ip_{sub_idx}",
            "split": "train",
            "learning_mode": "synthesis",
            "instruction": f"Write an XDP program that must {desc}. Return XDP_PASS for all traffic.",
            "requirements": [
                f"Define BPF_MAP_TYPE_LRU_HASH map 'src_stat_map_{sub_idx:02d}' with key __u32 and value __u64",
                "Verify Ethernet and IPv4 header bounds against data_end",
                "Lookup ip->saddr and atomically increment counter, or initialize with 1",
                "Return XDP_PASS unconditionally",
                "SEC(\"xdp\") entry point and GPL license declaration",
            ],
            "tests": [
                {"name": "pass_ip", "description": "IPv4 packet counted and passed", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.10", proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
                {"name": "pass_arp", "description": "ARP frame passes unmodified", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
            ],
            "solution_c": f"""#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

struct {{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1024);
}} src_stat_map_{sub_idx:02d} SEC(".maps");

SEC("xdp")
int xdp_count_src_{sub_idx}(struct xdp_md *ctx) {{
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

    __u32 src = ip->saddr;
    __u64 *count = bpf_map_lookup_elem(&src_stat_map_{sub_idx:02d}, &src);
    if (count) {{
        __sync_fetch_and_add(count, 1);
    }} else {{
        __u64 init_c = 1;
        bpf_map_update_elem(&src_stat_map_{sub_idx:02d}, &src, &init_c, BPF_NOEXIST);
    }}

    return XDP_PASS;
}}

char _license[] SEC("license") = "GPL";
""",
        })

    # --- Dev (idx 13..16): LRU hash per-destination IP byte volume accumulator ---
    dev_l2_descs = [
        ("dst_bytes_dev01", "accumulate total byte volume per destination IP in LRU map 'dst_bytes_01'"),
        ("dst_bytes_dev02", "monitor bandwidth consumption per destination address in 'dst_bytes_02'"),
        ("dst_bytes_dev03", "profile target host wire byte throughput in LRU hash 'dst_bytes_03'"),
        ("dst_bytes_dev04", "track cumulative octets received by destination IPs in 'dst_bytes_04'"),
    ]

    for sub_idx, (name, desc) in enumerate(dev_l2_descs, start=1):
        tid = f"rl_v2_dev_pit_l2_{sub_idx:02d}"
        fam = f"dev_pit_l2_{name}"
        tasks.append({
            "task_id": tid,
            "application_category": "packet_inspection_telemetry",
            "difficulty": "level_2",
            "task_family": fam,
            "template_family": "xdp_dst_byte_counter",
            "semantic_signature": f"pit_l2_dst_bytes_{sub_idx}",
            "split": "dev",
            "learning_mode": "synthesis",
            "instruction": f"Write an XDP program that must {desc}. Accumulate bpf_ntohs(ip->tot_len) bytes for each destination IP. Return XDP_PASS for all traffic.",
            "requirements": [
                f"Define BPF_MAP_TYPE_LRU_HASH map 'dst_bytes_{sub_idx:02d}' with key __u32 and value __u64",
                "Verify Ethernet and IPv4 header bounds against data_end",
                "Extract bpf_ntohs(ip->tot_len) and lookup ip->daddr in map",
                "Atomically add byte count to existing entry or initialize with packet length",
                "Return XDP_PASS unconditionally",
                "SEC(\"xdp\") entry point and GPL license declaration",
            ],
            "tests": [
                {"name": "pass_ip", "description": "IPv4 bytes accumulated and passed", "packet_hex": make_eth(payload=make_ipv4(dst_ip="192.168.1.50", proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
                {"name": "pass_arp", "description": "ARP passed unmodified", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
            ],
            "solution_c": f"""#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

struct {{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1024);
}} dst_bytes_{sub_idx:02d} SEC(".maps");

SEC("xdp")
int xdp_bytes_dst_{sub_idx}(struct xdp_md *ctx) {{
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

    __u32 dst = ip->daddr;
    __u64 pkt_bytes = bpf_ntohs(ip->tot_len);

    __u64 *val = bpf_map_lookup_elem(&dst_bytes_{sub_idx:02d}, &dst);
    if (val) {{
        __sync_fetch_and_add(val, pkt_bytes);
    }} else {{
        bpf_map_update_elem(&dst_bytes_{sub_idx:02d}, &dst, &pkt_bytes, BPF_NOEXIST);
    }}

    return XDP_PASS;
}}

char _license[] SEC("license") = "GPL";
""",
        })

    # --- Confirmation (idx 17..21): LRU hash 5-tuple active flow session tracker ---
    conf_l2_descs = [
        ("flow_5tuple_conf01", "track bidirectional 5-tuple flow sessions in LRU hash table 'flow_table_01'"),
        ("flow_5tuple_conf02", "monitor active TCP and UDP 5-tuple connections in LRU map 'flow_table_02'"),
        ("flow_5tuple_conf03", "maintain 5-tuple session telemetry in BPF_MAP_TYPE_LRU_HASH map 'flow_table_03'"),
        ("flow_5tuple_conf04", "index end-to-end network flows by 5-tuple in LRU map 'flow_table_04'"),
        ("flow_5tuple_conf05", "count packet arrivals per active 5-tuple session in 'flow_table_05'"),
    ]

    for sub_idx, (name, desc) in enumerate(conf_l2_descs, start=1):
        tid = f"rl_v2_conf_pit_l2_{sub_idx:02d}"
        fam = f"conf_pit_l2_{name}"
        tasks.append({
            "task_id": tid,
            "application_category": "packet_inspection_telemetry",
            "difficulty": "level_2",
            "task_family": fam,
            "template_family": "xdp_flow_tracker",
            "semantic_signature": f"pit_l2_flow_5tuple_{sub_idx}",
            "split": "confirmation",
            "learning_mode": "synthesis",
            "instruction": f"Write an XDP program that must {desc}. Key: (saddr, daddr, sport, dport, proto). Return XDP_PASS for all traffic.",
            "requirements": [
                "Define struct flow_key containing saddr, daddr, sport, dport, proto",
                f"Define BPF_MAP_TYPE_LRU_HASH map 'flow_table_{sub_idx:02d}' with key struct flow_key and value __u64",
                "Verify Ethernet, IPv4, and L4 transport header bounds against data_end",
                "Populate 5-tuple key and atomically increment packet count in flow map",
                "Return XDP_PASS unconditionally",
                "SEC(\"xdp\") entry point and GPL license declaration",
            ],
            "tests": [
                {"name": "pass_tcp_flow", "description": "TCP 5-tuple flow tracked and passed", "packet_hex": make_eth(payload=make_ipv4(src_ip="10.1.1.1", dst_ip="10.2.2.2", proto=6, payload=make_tcp(src_port=1000, dst_port=80))).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
                {"name": "pass_arp", "description": "ARP passed unmodified", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
            ],
            "solution_c": f"""#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>

struct flow_key_{sub_idx} {{
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8 proto;
}};

struct {{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct flow_key_{sub_idx});
    __type(value, __u64);
    __uint(max_entries, 1024);
}} flow_table_{sub_idx:02d} SEC(".maps");

SEC("xdp")
int xdp_flow_5tuple_{sub_idx}(struct xdp_md *ctx) {{
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

    int ip_len = ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct flow_key_{sub_idx} key = {{}};
    key.saddr = ip->saddr;
    key.daddr = ip->daddr;
    key.proto = ip->protocol;

    if (ip->protocol == IPPROTO_TCP) {{
        struct tcphdr *tcp = (void *)ip + ip_len;
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        key.sport = tcp->source;
        key.dport = tcp->dest;
    }}

    __u64 *val = bpf_map_lookup_elem(&flow_table_{sub_idx:02d}, &key);
    if (val) {{
        __sync_fetch_and_add(val, 1);
    }} else {{
        __u64 init_c = 1;
        bpf_map_update_elem(&flow_table_{sub_idx:02d}, &key, &init_c, BPF_NOEXIST);
    }}

    return XDP_PASS;
}}

char _license[] SEC("license") = "GPL";
""",
        })

    return tasks


def build_pit_l3_tasks() -> List[Dict[str, Any]]:
    tasks = []

    # --- Canary (idx 0): Dual-map TCP handshake telemetry ---
    canary_task = {
        "task_id": "rl_v2_canary_pit_l3_01",
        "application_category": "packet_inspection_telemetry",
        "difficulty": "level_3",
        "task_family": "canary_pit_l3_handshake_tracker",
        "template_family": "xdp_dual_telemetry",
        "semantic_signature": "pit_l3_dual_handshake_canary",
        "split": "canary",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that records flow telemetry using two maps: update per-client packet counts in LRU hash 'flow_stat_map' and update global totals in array map 'global_traffic_map' (index 0). Return XDP_PASS for all traffic.",
        "requirements": [
            "Define BPF_MAP_TYPE_LRU_HASH map 'flow_stat_map' with key __u32 and value __u64",
            "Define BPF_MAP_TYPE_ARRAY map 'global_traffic_map' with 2 entries and value __u64",
            "Verify Ethernet and IPv4 header bounds against data_end",
            "Update per-client packet count in flow_stat_map for ip->saddr",
            "Atomically increment global counter in global_traffic_map at index 0",
            "Return XDP_PASS unconditionally",
            "SEC(\"xdp\") entry point and GPL license declaration",
        ],
        "tests": [
            {"name": "pass_client", "description": "Client packet counted in dual maps", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.10", proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
            {"name": "pass_arp", "description": "ARP passed unmodified", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
        ],
        "solution_c": """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1024);
} flow_stat_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 2);
} global_traffic_map SEC(".maps");

SEC("xdp")
int xdp_dual_telemetry(struct xdp_md *ctx) {
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

    __u32 src = ip->saddr;
    __u64 *val = bpf_map_lookup_elem(&flow_stat_map, &src);
    if (val) {
        __sync_fetch_and_add(val, 1);
    } else {
        __u64 init_c = 1;
        bpf_map_update_elem(&flow_stat_map, &src, &init_c, BPF_NOEXIST);
    }

    __u32 g_key = 0;
    __u64 *g_cnt = bpf_map_lookup_elem(&global_traffic_map, &g_key);
    if (g_cnt)
        __sync_fetch_and_add(g_cnt, 1);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
""",
    }
    tasks.append(canary_task)

    # --- Train (idx 1..12): Dual-map flow table (LRU) and global packet counters (Array) ---
    train_l3_descs = [
        ("dual_telemetry_01", "maintain client connection cache in LRU hash 'client_flow_01' and system total in array 'sys_stats_01'"),
        ("dual_telemetry_02", "log per-host session stats in 'client_flow_02' alongside global telemetry in 'sys_stats_02'"),
        ("dual_telemetry_03", "profile ingress endpoints in LRU table 'client_flow_03' and accumulate totals in 'sys_stats_03'"),
        ("dual_telemetry_04", "index sender traffic in LRU map 'client_flow_04' while incrementing interface total in 'sys_stats_04'"),
        ("dual_telemetry_05", "track per-client packets in 'client_flow_05' and wire aggregates in array map 'sys_stats_05'"),
        ("dual_telemetry_06", "tabulate host flow metrics in 'client_flow_06' and global volume in 'sys_stats_06'"),
        ("dual_telemetry_07", "maintain sender records in LRU map 'client_flow_07' and total counter in 'sys_stats_07'"),
        ("dual_telemetry_08", "record client packet frequencies in 'client_flow_08' and update aggregate in 'sys_stats_08'"),
        ("dual_telemetry_09", "collect endpoint telemetry in 'client_flow_09' while updating global tally in 'sys_stats_09'"),
        ("dual_telemetry_10", "aggregate per-source frames in 'client_flow_10' and maintain global statistics in 'sys_stats_10'"),
        ("dual_telemetry_11", "profile network clients in LRU map 'client_flow_11' alongside master counter in 'sys_stats_11'"),
        ("dual_telemetry_12", "track active source nodes in 'client_flow_12' and cumulative volume in array 'sys_stats_12'"),
    ]

    for sub_idx, (name, desc) in enumerate(train_l3_descs, start=1):
        tid = f"rl_v2_train_pit_l3_{sub_idx:02d}"
        fam = f"train_pit_l3_{name}"
        tasks.append({
            "task_id": tid,
            "application_category": "packet_inspection_telemetry",
            "difficulty": "level_3",
            "task_family": fam,
            "template_family": "xdp_dual_map_telemetry",
            "semantic_signature": f"pit_l3_dual_map_{sub_idx}",
            "split": "train",
            "learning_mode": "synthesis",
            "instruction": f"Write an XDP program that must {desc}. Return XDP_PASS for all traffic.",
            "requirements": [
                f"Define BPF_MAP_TYPE_LRU_HASH map 'client_flow_{sub_idx:02d}' with key __u32 and value __u64",
                f"Define BPF_MAP_TYPE_ARRAY map 'sys_stats_{sub_idx:02d}' with 4 entries and value __u64",
                "Verify Ethernet and IPv4 header bounds against data_end",
                f"Lookup ip->saddr in client_flow_{sub_idx:02d} and increment counter",
                f"Lookup index 0 in sys_stats_{sub_idx:02d} and increment global counter",
                "Return XDP_PASS unconditionally",
                "SEC(\"xdp\") entry point and GPL license declaration",
            ],
            "tests": [
                {"name": "pass_ip", "description": "IP tracked in both maps and passed", "packet_hex": make_eth(payload=make_ipv4(src_ip="10.0.0.1", proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
                {"name": "pass_arp", "description": "ARP passed unmodified", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
            ],
            "solution_c": f"""#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

struct {{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1024);
}} client_flow_{sub_idx:02d} SEC(".maps");

struct {{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 4);
}} sys_stats_{sub_idx:02d} SEC(".maps");

SEC("xdp")
int xdp_dual_{sub_idx}(struct xdp_md *ctx) {{
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

    __u32 src = ip->saddr;
    __u64 *flow_val = bpf_map_lookup_elem(&client_flow_{sub_idx:02d}, &src);
    if (flow_val) {{
        __sync_fetch_and_add(flow_val, 1);
    }} else {{
        __u64 init_c = 1;
        bpf_map_update_elem(&client_flow_{sub_idx:02d}, &src, &init_c, BPF_NOEXIST);
    }}

    __u32 g_key = 0;
    __u64 *g_val = bpf_map_lookup_elem(&sys_stats_{sub_idx:02d}, &g_key);
    if (g_val)
        __sync_fetch_and_add(g_val, 1);

    return XDP_PASS;
}}

char _license[] SEC("license") = "GPL";
""",
        })

    # --- Dev (idx 13..16): TCP advertised window distribution telemetry ---
    dev_l3_descs = [
        ("tcp_win_dev01", "profile TCP advertised window size distribution across 4 buckets in 'win_dist_01'"),
        ("tcp_win_dev02", "tabulate flow window buffer metrics in array map 'win_dist_02' (<4k, 4k-16k, 16k-64k, >=64k)"),
        ("tcp_win_dev03", "measure TCP receiver window sizes in statistics map 'win_dist_03'"),
        ("tcp_win_dev04", "collect window advertising frequency histogram in array map 'win_dist_04'"),
    ]

    for sub_idx, (name, desc) in enumerate(dev_l3_descs, start=1):
        tid = f"rl_v2_dev_pit_l3_{sub_idx:02d}"
        fam = f"dev_pit_l3_{name}"
        tasks.append({
            "task_id": tid,
            "application_category": "packet_inspection_telemetry",
            "difficulty": "level_3",
            "task_family": fam,
            "template_family": "xdp_tcp_window_telemetry",
            "semantic_signature": f"pit_l3_tcp_win_{sub_idx}",
            "split": "dev",
            "learning_mode": "synthesis",
            "instruction": f"Write an XDP program that must {desc}. Bin 0: win < 4096, Bin 1: 4096 <= win < 16384, Bin 2: 16384 <= win < 65535, Bin 3: win >= 65535. Return XDP_PASS for all frames.",
            "requirements": [
                f"Define BPF_MAP_TYPE_ARRAY map 'win_dist_{sub_idx:02d}' with 4 entries and __u64 values",
                "Verify Ethernet, IPv4, and TCP header bounds against data_end",
                "Inspect bpf_ntohs(tcp->window) and select bucket: <4k -> 0, <16k -> 1, <65535 -> 2, >=65535 -> 3",
                "Atomically increment window bucket counter using __sync_fetch_and_add",
                "Return XDP_PASS unconditionally",
                "SEC(\"xdp\") entry point and GPL license declaration",
            ],
            "tests": [
                {"name": "pass_small_win", "description": "Small window in bin 0 passed", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(window=1000))).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
                {"name": "pass_large_win", "description": "Large window in bin 3 passed", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(window=65535))).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
                {"name": "pass_arp", "description": "ARP passed unmodified", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
            ],
            "solution_c": f"""#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>

struct {{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 4);
}} win_dist_{sub_idx:02d} SEC(".maps");

SEC("xdp")
int xdp_win_{sub_idx}(struct xdp_md *ctx) {{
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

    __u16 win = bpf_ntohs(tcp->window);
    __u32 bin = 0;
    if (win < 4096)
        bin = 0;
    else if (win < 16384)
        bin = 1;
    else if (win < 65535)
        bin = 2;
    else
        bin = 3;

    __u64 *val = bpf_map_lookup_elem(&win_dist_{sub_idx:02d}, &bin);
    if (val)
        __sync_fetch_and_add(val, 1);

    return XDP_PASS;
}}

char _license[] SEC("license") = "GPL";
""",
        })

    # --- Confirmation (idx 17..21): Flow lifetime duration and timestamp tracking ---
    conf_l3_descs = [
        ("flow_ts_conf01", "record first-seen and last-seen timestamps per source IP in 'flow_time_01' using bpf_ktime_get_ns"),
        ("flow_ts_conf02", "track flow duration and active timestamps per host in LRU map 'flow_time_02'"),
        ("flow_ts_conf03", "measure client inter-arrival and session lifespan in telemetry map 'flow_time_03'"),
        ("flow_ts_conf04", "log connection arrival timestamps for latency tracking in 'flow_time_04'"),
        ("flow_ts_conf05", "profile endpoint session timing using nanosecond timestamps in 'flow_time_05'"),
    ]

    for sub_idx, (name, desc) in enumerate(conf_l3_descs, start=1):
        tid = f"rl_v2_conf_pit_l3_{sub_idx:02d}"
        fam = f"conf_pit_l3_{name}"
        tasks.append({
            "task_id": tid,
            "application_category": "packet_inspection_telemetry",
            "difficulty": "level_3",
            "task_family": fam,
            "template_family": "xdp_flow_timestamp_telemetry",
            "semantic_signature": f"pit_l3_flow_ts_{sub_idx}",
            "split": "confirmation",
            "learning_mode": "synthesis",
            "instruction": f"Write an XDP program that must {desc}. Store first_seen and last_seen timestamps. Return XDP_PASS for all traffic.",
            "requirements": [
                "Define struct flow_timing containing __u64 first_seen and __u64 last_seen",
                f"Define BPF_MAP_TYPE_LRU_HASH map 'flow_time_{sub_idx:02d}' with key __u32 and value struct flow_timing",
                "Verify Ethernet and IPv4 header bounds against data_end",
                "Query bpf_ktime_get_ns() and record first_seen and last_seen timestamps for ip->saddr",
                "Return XDP_PASS unconditionally",
                "SEC(\"xdp\") entry point and GPL license declaration",
            ],
            "tests": [
                {"name": "pass_ip", "description": "Timestamp tracked and passed", "packet_hex": make_eth(payload=make_ipv4(src_ip="10.8.0.1", proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
                {"name": "pass_arp", "description": "ARP passed unmodified", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
            ],
            "solution_c": f"""#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

struct flow_timing_{sub_idx} {{
    __u64 first_seen;
    __u64 last_seen;
}};

struct {{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);
    __type(value, struct flow_timing_{sub_idx});
    __uint(max_entries, 1024);
}} flow_time_{sub_idx:02d} SEC(".maps");

SEC("xdp")
int xdp_flow_timing_{sub_idx}(struct xdp_md *ctx) {{
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

    __u32 src = ip->saddr;
    __u64 now = bpf_ktime_get_ns();

    struct flow_timing_{sub_idx} *timing = bpf_map_lookup_elem(&flow_time_{sub_idx:02d}, &src);
    if (timing) {{
        timing->last_seen = now;
    }} else {{
        struct flow_timing_{sub_idx} init_t = {{ .first_seen = now, .last_seen = now }};
        bpf_map_update_elem(&flow_time_{sub_idx:02d}, &src, &init_t, BPF_NOEXIST);
    }}

    return XDP_PASS;
}}

char _license[] SEC("license") = "GPL";
""",
        })

    return tasks
