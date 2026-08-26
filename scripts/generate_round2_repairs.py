#!/usr/bin/env python3
"""
Generate Repair Round 2 (c00-r02.c and c00-r02.meta.json) for remaining tasks in batch-001:
- Task 2: Fix verifier bounds checking on UDP header
- Task 6: Fix port endianness conversion (bpf_htons(8080))
- Task 9: Fix verifier bounds checking on UDP header
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
BATCH_DIR = PROJECT_ROOT / "data" / "inbox" / "antigravity" / "batch-001"
VAL_DIR = PROJECT_ROOT / "data" / "validation" / "batch-001"


def compute_sha256_str(text: str) -> str:
    digest = hashlib.sha256()
    digest.update(text.encode("utf-8"))
    return digest.hexdigest()


def get_r01_diagnostic(task_id: str) -> str:
    val_path = VAL_DIR / f"{task_id}_c00_r01.json"
    if val_path.exists():
        data = json.loads(val_path.read_text(encoding="utf-8"))
        return data.get("diagnostic", "")
    return "Round 1 candidate failed validation"


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
        "authoring_harness": "antigravity",
        "authoring_model": "gemini-3.7-flash",
        "generation_prompt_version": "agent-repair-v2",
        "source_path": f"{cand_suffix}.c",
        "parent_candidate_id": parent_cand_id,
        "repair_attempt": attempt_num,
        "failure_diagnostic": diagnostic,
        "claimed_status": "unvalidated",
        "source_sha256": src_sha,
    }
    meta_file.write_text(json.dumps(meta_data, indent=2), encoding="utf-8")
    print(f"  [+] Wrote repair: {task_id}/{cand_suffix}.c (attempt {attempt_num})")


def main() -> None:
    # --- Task 2: Drop UDP 53 (r02 fixes UDP bounds checking) ---
    t2_id = "xdp_antigravity_b01_t02_drop_udp_port"
    t2_r02_c = """#include <linux/bpf.h>
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

    unsigned int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr) || (void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip_hdr_len;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    if (udp->dest == bpf_htons(53))
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    write_repair(t2_id, "c00-r02", t2_r02_c, "c00-r01", 2, get_r01_diagnostic(t2_id))

    # --- Task 6: VLAN Drop HTTP (r02 fixes port endianness bug) ---
    t6_id = "xdp_antigravity_b01_t06_vlan_drop_http"
    t6_r02_c = """#include <linux/bpf.h>
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

    // Fixed endianness conversion using bpf_htons(8080)
    if (tcp->dest == bpf_htons(8080))
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    write_repair(t6_id, "c00-r02", t6_r02_c, "c00-r01", 2, get_r01_diagnostic(t6_id))

    # --- Task 9: Drop UDP DNS Amplification (r02 fixes UDP bounds checking) ---
    t9_id = "xdp_antigravity_b01_t09_drop_udp_dns_amplification"
    t9_r02_c = """#include <linux/bpf.h>
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

    struct udphdr *udp = (void *)ip + ip_hdr_len;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    __u16 src = bpf_ntohs(udp->source);
    __u16 dst = bpf_ntohs(udp->dest);
    __u16 ulen = bpf_ntohs(udp->len);

    if ((src == 53 || dst == 53) && ulen > 512)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
"""
    write_repair(t9_id, "c00-r02", t9_r02_c, "c00-r01", 2, get_r01_diagnostic(t9_id))

    print("Round 2 repairs generated successfully.")


if __name__ == "__main__":
    main()
