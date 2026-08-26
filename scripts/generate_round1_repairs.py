#!/usr/bin/env python3
"""
Generate Repair Round 1 (c00-r01.c and c00-r01.meta.json) for failed candidates in batch-001.
Also updates task.json test cases to ensure all boundary packets satisfy Linux kernel ETH_HLEN (14 bytes).
"""

from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
BATCH_DIR = PROJECT_ROOT / "data" / "inbox" / "batch-001"
VAL_DIR = PROJECT_ROOT / "data" / "validation" / "batch-001"


def compute_sha256_str(text: str) -> str:
    digest = hashlib.sha256()
    digest.update(text.encode("utf-8"))
    return digest.hexdigest()


def make_eth_packet(eth_type: int = 0x0800, payload: bytes = b"") -> bytes:
    dst_mac = bytes([0x52, 0x54, 0x00, 0x12, 0x34, 0x56])
    src_mac = bytes([0x52, 0x54, 0x00, 0x65, 0x43, 0x21])
    return dst_mac + src_mac + struct.pack("!H", eth_type) + payload


def make_vlan_eth_packet(vlan_id: int = 100, inner_eth_type: int = 0x0800, payload: bytes = b"") -> bytes:
    dst_mac = bytes([0x52, 0x54, 0x00, 0x12, 0x34, 0x56])
    src_mac = bytes([0x52, 0x54, 0x00, 0x65, 0x43, 0x21])
    vlan_hdr = struct.pack("!HH", 0x8100, vlan_id & 0x0FFF)
    return dst_mac + src_mac + vlan_hdr + struct.pack("!H", inner_eth_type) + payload


def get_c00_diagnostic(task_id: str) -> str:
    val_path = VAL_DIR / f"{task_id}_c00.json"
    if val_path.exists():
        data = json.loads(val_path.read_text(encoding="utf-8"))
        return data.get("diagnostic", "")
    return "Initial candidate failed validation"


def main() -> None:
    # 1. Update boundary packets in task.json for tasks that used sub-14 byte boundary packets
    t1_task = json.loads((BATCH_DIR / "xdp_b01_t01_drop_tcp_port" / "task.json").read_text(encoding="utf-8"))
    t1_task["tests"][-1]["packet_hex"] = make_eth_packet(0x0800, b"").hex()
    (BATCH_DIR / "xdp_b01_t01_drop_tcp_port" / "task.json").write_text(json.dumps(t1_task, indent=2), encoding="utf-8")

    t2_task = json.loads((BATCH_DIR / "xdp_b01_t02_drop_udp_port" / "task.json").read_text(encoding="utf-8"))
    t2_task["tests"][-1]["packet_hex"] = make_eth_packet(0x0800, b"").hex()
    (BATCH_DIR / "xdp_b01_t02_drop_udp_port" / "task.json").write_text(json.dumps(t2_task, indent=2), encoding="utf-8")

    t3_task = json.loads((BATCH_DIR / "xdp_b01_t03_drop_icmp" / "task.json").read_text(encoding="utf-8"))
    t3_task["tests"][-1]["packet_hex"] = make_eth_packet(0x0800, b"").hex()
    (BATCH_DIR / "xdp_b01_t03_drop_icmp" / "task.json").write_text(json.dumps(t3_task, indent=2), encoding="utf-8")

    t6_task = json.loads((BATCH_DIR / "xdp_b01_t06_vlan_drop_http" / "task.json").read_text(encoding="utf-8"))
    t6_task["tests"][-1]["packet_hex"] = make_vlan_eth_packet(100, 0x0800, b"").hex()
    (BATCH_DIR / "xdp_b01_t06_vlan_drop_http" / "task.json").write_text(json.dumps(t6_task, indent=2), encoding="utf-8")

    t7_task = json.loads((BATCH_DIR / "xdp_b01_t07_src_ip_denylist_map" / "task.json").read_text(encoding="utf-8"))
    t7_task["tests"][-1]["packet_hex"] = make_eth_packet(0x0800, b"").hex()
    (BATCH_DIR / "xdp_b01_t07_src_ip_denylist_map" / "task.json").write_text(json.dumps(t7_task, indent=2), encoding="utf-8")

    t8_task = json.loads((BATCH_DIR / "xdp_b01_t08_count_packets_map" / "task.json").read_text(encoding="utf-8"))
    t8_task["tests"][-1]["packet_hex"] = make_eth_packet(0x0800, b"").hex()
    (BATCH_DIR / "xdp_b01_t08_count_packets_map" / "task.json").write_text(json.dumps(t8_task, indent=2), encoding="utf-8")

    # Task 5 passed on c00, set its gold candidate
    t5_task = json.loads((BATCH_DIR / "xdp_b01_t05_drop_oversized" / "task.json").read_text(encoding="utf-8"))
    t5_task["gold_candidate_id"] = "xdp_b01_t05_drop_oversized_c00"
    (BATCH_DIR / "xdp_b01_t05_drop_oversized" / "task.json").write_text(json.dumps(t5_task, indent=2), encoding="utf-8")

    # 2. Generate repairs for failed candidates

    # --- Task 1: Drop TCP 23 ---
    t1_id = "xdp_b01_t01_drop_tcp_port"
    t1_r01_c = """#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int xdp_drop_tcp_23(struct xdp_md *ctx) {
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

    unsigned int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr))
        return XDP_PASS;

    if ((void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip_hdr_len;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    if (tcp->dest == bpf_htons(23))
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    write_repair(t1_id, "c00-r01", t1_r01_c, "c00", 1, get_c00_diagnostic(t1_id))

    # --- Task 2: Drop UDP 53 (r01 fixes include, retains verifier bug) ---
    t2_id = "xdp_b01_t02_drop_udp_port"
    t2_r01_c = """#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int xdp_drop_udp_dns(struct xdp_md *ctx) {
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

    // FAULT: Missing check on (void *)(udp + 1) > data_end before dereferencing udp->dest
    struct udphdr *udp = (void *)ip + (ip->ihl * 4);
    if (udp->dest == bpf_htons(53))
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    write_repair(t2_id, "c00-r01", t2_r01_c, "c00", 1, get_c00_diagnostic(t2_id))

    # --- Task 3: Drop ICMP ---
    t3_id = "xdp_b01_t03_drop_icmp"
    t3_r01_c = """#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int xdp_drop_icmp(struct xdp_md *ctx) {
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

    if (ip->protocol == IPPROTO_ICMP)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    write_repair(t3_id, "c00-r01", t3_r01_c, "c00", 1, get_c00_diagnostic(t3_id))

    # --- Task 4: Drop SYN+FIN ---
    t4_id = "xdp_b01_t04_drop_syn_fin"
    t4_r01_c = """#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int xdp_drop_syn_fin(struct xdp_md *ctx) {
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

    unsigned int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr) || (void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip_hdr_len;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    // Fixed missing semicolon from c00
    __u8 tcp_flags = ((__u8 *)tcp)[13];
    if ((tcp_flags & 0x03) == 0x03)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    write_repair(t4_id, "c00-r01", t4_r01_c, "c00", 1, get_c00_diagnostic(t4_id))

    # --- Task 6: VLAN Drop HTTP (r01 fixes include, retains port comparison endianness bug) ---
    t6_id = "xdp_b01_t06_vlan_drop_http"
    t6_r01_c = """#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

SEC("xdp")
int xdp_vlan_filter(struct xdp_md *ctx) {
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

    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    unsigned int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr) || (void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip_hdr_len;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    // FAULT: Comparing network byte order port with host byte order constant without bpf_htons
    if (tcp->dest == 8080)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    write_repair(t6_id, "c00-r01", t6_r01_c, "c00", 1, get_c00_diagnostic(t6_id))

    # --- Task 7: BPF Map IP Denylist ---
    t7_id = "xdp_b01_t07_src_ip_denylist_map"
    t7_r01_c = """#include <linux/bpf.h>
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
} blocked_ips SEC(".maps");

SEC("xdp")
int xdp_denylist_lookup(struct xdp_md *ctx) {
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
    __u8 *blocked = bpf_map_lookup_elem(&blocked_ips, &src_ip);
    if (blocked && *blocked != 0)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    write_repair(t7_id, "c00-r01", t7_r01_c, "c00", 1, get_c00_diagnostic(t7_id))

    # --- Task 8: BPF Array Map Packet Counter ---
    t8_id = "xdp_b01_t08_count_packets_map"
    t8_r01_c = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} pkt_stats SEC(".maps");

SEC("xdp")
int xdp_count_packets(struct xdp_md *ctx) {
    __u32 key = 0;
    __u64 *count = bpf_map_lookup_elem(&pkt_stats, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    write_repair(t8_id, "c00-r01", t8_r01_c, "c00", 1, get_c00_diagnostic(t8_id))

    # --- Task 9: Drop UDP DNS Amplification (r01 fixes include, retains verifier bug) ---
    t9_id = "xdp_b01_t09_drop_udp_dns_amplification"
    t9_r01_c = """#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int xdp_drop_dns_amp(struct xdp_md *ctx) {
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

    unsigned int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr) || (void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    // FAULT: Missing check on (void *)(udp + 1) > data_end before reading udp->source / udp->dest / udp->len
    struct udphdr *udp = (void *)ip + ip_hdr_len;
    __u16 src = bpf_ntohs(udp->source);
    __u16 dst = bpf_ntohs(udp->dest);
    __u16 ulen = bpf_ntohs(udp->len);

    if ((src == 53 || dst == 53) && ulen > 512)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    write_repair(t9_id, "c00-r01", t9_r01_c, "c00", 1, get_c00_diagnostic(t9_id))

    # --- Task 10: Allow only SSH ---
    t10_id = "xdp_b01_t10_allow_only_ssh"
    t10_r01_c = """#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int xdp_ssh_only(struct xdp_md *ctx) {
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

    unsigned int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr) || (void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip_hdr_len;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    if (tcp->dest != bpf_htons(22))
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    write_repair(t10_id, "c00-r01", t10_r01_c, "c00", 1, get_c00_diagnostic(t10_id))

    print("Round 1 repairs generated successfully.")


def write_repair(
    task_id: str,
    cand_suffix: str,
    source_code: str,
    parent_cand_suffix: str,
    attempt_num: int,
    diagnostic: str,
) -> None:
    t_dir = BATCH_DIR / task_id
    src_file = t_dir / f"{cand_suffix}.c"
    meta_file = t_dir / f"{cand_suffix}.meta.json"

    src_file.write_text(source_code, encoding="utf-8")
    src_sha = compute_sha256_str(source_code)

    cand_id = f"{task_id}_{cand_suffix.replace('-', '_')}"
    parent_cand_id = f"{task_id}_{parent_cand_suffix.replace('-', '_')}"

    meta_data = {
        "candidate_id": cand_id,
        "task_id": task_id,
        "authoring_harness": "agent",
        "authoring_model": "instruction_model",
        "generation_prompt_version": "agent-repair-v1",
        "source_path": f"{cand_suffix}.c",
        "parent_candidate_id": parent_cand_id,
        "repair_attempt": attempt_num,
        "failure_diagnostic": diagnostic,
        "claimed_status": "unvalidated",
        "source_sha256": src_sha,
    }
    meta_file.write_text(json.dumps(meta_data, indent=2), encoding="utf-8")
    print(f"  [+] Wrote repair: {task_id}/{cand_suffix}.c (attempt {attempt_num})")


if __name__ == "__main__":
    main()
