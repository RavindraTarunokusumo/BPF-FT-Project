"""
BPF-Guardian RLVR Phase 2: Protocol Transformation (PTR) Task Definitions.
Contains 66 distinct, verifier-safe tasks with strict task-family disjointness across splits:
- Level 1 (22 tasks):
    * Canary (1): UDP checksum zeroing (udp->check = 0)
    * Train (12): IPv4 DSCP / TOS byte remarking with bpf_l3_csum_replace
    * Dev (4): IPv4 TTL decrement with bpf_l3_csum_replace (XDP_PASS)
    * Confirmation (5): IPv4 Explicit Congestion Notification (ECN) marking with bpf_l3_csum_replace
- Level 2 (22 tasks):
    * Canary (1): Basic 802.1Q VLAN tag pop via bpf_xdp_adjust_head
    * Train (12): 802.1Q VLAN tag pop via bpf_xdp_adjust_head
    * Dev (4): In-place 802.1Q VLAN ID retagging (without adjust_head)
    * Confirmation (5): 802.1Q VLAN tag push via bpf_xdp_adjust_head (negative offset)
- Level 3 (22 tasks):
    * Canary (1): Basic IP-in-IP tunnel decapsulation
    * Train (12): IP-in-IP (protocol 4) tunnel decapsulation via bpf_xdp_adjust_head
    * Dev (4): 6in4 (protocol 41) IPv6-in-IPv4 tunnel decapsulation via bpf_xdp_adjust_head
    * Confirmation (5): GRE (protocol 47) tunnel decapsulation via bpf_xdp_adjust_head
"""

from __future__ import annotations

from typing import Any, Dict, List, Tuple
from scripts.synthesis_benchmark_gen.packet_utils import (
    make_arp,
    make_eth,
    make_icmp,
    make_ipv4,
    make_ipv6,
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


def build_ptr_l1_tasks() -> List[Dict[str, Any]]:
    tasks = []

    # --- Canary (idx 0): UDP checksum zeroing ---
    canary_task = {
        "task_id": "rl_v2_canary_ptr_l1_01",
        "application_category": "protocol_transformation",
        "difficulty": "level_1",
        "task_family": "canary_ptr_l1_udp_csum_zero",
        "template_family": "xdp_udp_csum_zero",
        "semantic_signature": "ptr_l1_udp_csum_zero_canary",
        "split": "canary",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that inspects UDP packets and zeroes the UDP checksum field (udp->check = 0) to bypass L4 checksum validation. Forward all traffic with XDP_PASS.",
        "requirements": [
            "Verify Ethernet, IPv4, and UDP header bounds against data_end",
            "Confirm eth->h_proto == ETH_P_IP and ip->protocol == IPPROTO_UDP",
            "Safely calculate variable IPv4 header length (ip->ihl * 4)",
            "Set udp->check = 0 in-place",
            "Return XDP_PASS unconditionally",
            "SEC(\"xdp\") entry point and GPL license declaration",
        ],
        "tests": [
            {"name": "pass_zeroed_udp", "description": "UDP checksum zeroed and passed", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=53, with_csum=True))).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
            {"name": "pass_arp", "description": "ARP passed unmodified", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
        ],
        "solution_c": """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>

SEC("xdp")
int xdp_zero_udp_csum(struct xdp_md *ctx) {
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

    udp->check = 0;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
""",
    }
    tasks.append(canary_task)

    # --- Train (idx 1..12): IPv4 DSCP / TOS byte remarking with bpf_l3_csum_replace ---
    train_l1_configs = [
        ("af11", 0x28, "set Assured Forwarding AF11 class by remarking TOS byte to 0x28 with checksum recalculation"),
        ("af12", 0x30, "assign AF12 priority marking TOS field to 0x30 using incremental bpf_l3_csum_replace"),
        ("af13", 0x38, "classify packet as AF13 by rewriting IP TOS to 0x38 and updating IPv4 checksum"),
        ("af21", 0x48, "mark high-priority transactional traffic with AF21 (TOS 0x48) via bpf_l3_csum_replace"),
        ("af22", 0x50, "apply AF22 QoS policy remarking IPv4 header TOS to 0x50 with checksum replacement"),
        ("af23", 0x58, "rewrite DiffServ codepoint to AF23 (TOS 0x58) updating L3 checksum incrementally"),
        ("af31", 0x68, "designate multimedia streaming priority with AF31 (TOS 0x68) and recalculate checksum"),
        ("af32", 0x70, "enforce AF32 transmission service class by overwriting TOS byte to 0x70"),
        ("af33", 0x78, "apply AF33 drop precedence remarking TOS field to 0x78 with bpf_l3_csum_replace"),
        ("af41", 0x88, "prioritize video conference frames with AF41 classification (TOS 0x88)"),
        ("af42", 0x90, "set interactive real-time QoS class AF42 (TOS 0x90) with L3 checksum fixup"),
        ("af43", 0x98, "assign AF43 traffic class to IP packets by setting TOS to 0x98 and fixing checksum"),
    ]

    for sub_idx, (name, tos_val, desc) in enumerate(train_l1_configs, start=1):
        tid = f"rl_v2_train_ptr_l1_{sub_idx:02d}"
        fam = f"train_ptr_l1_{name}"
        tasks.append({
            "task_id": tid,
            "application_category": "protocol_transformation",
            "difficulty": "level_1",
            "task_family": fam,
            "template_family": "xdp_dscp_remarker",
            "semantic_signature": f"ptr_l1_dscp_{name}_{tos_val}",
            "split": "train",
            "learning_mode": "synthesis",
            "instruction": f"Write an XDP program that must {desc}. Forward all packets with XDP_PASS.",
            "requirements": [
                "Validate Ethernet and IPv4 header bounds against data_end",
                f"Overwrite IPv4 header ip->tos with value {tos_val}",
                "Recalculate IPv4 header checksum ip->check over all 20 bytes",
                "Unconditionally return XDP_PASS",
                "SEC(\"xdp\") entry point and GPL license declaration",
            ],
            "tests": [
                {"name": "pass_remarked_ip", "description": f"IPv4 remarked to {tos_val} and passed", "packet_hex": make_eth(payload=make_ipv4(tos=0, proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
                {"name": "pass_arp", "description": "Non-IP ARP frame passed without alteration", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
            ],
            "solution_c": f"""#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

SEC("xdp")
int xdp_remark_{name}(struct xdp_md *ctx) {{
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

    ip->tos = {tos_val};
    ip->check = 0;

    __u16 *words = (void *)ip;
    __u32 csum = 0;
    #pragma unroll
    for (int i = 0; i < 10; i++) {{
        if ((void *)(words + i + 1) > data_end)
            return XDP_PASS;
        csum += bpf_ntohs(words[i]);
    }}
    while (csum >> 16)
        csum = (csum & 0xFFFF) + (csum >> 16);
    ip->check = bpf_htons((~csum) & 0xFFFF);

    return XDP_PASS;
}}

char _license[] SEC("license") = "GPL";
""",
        })

    # --- Dev (idx 13..16): IPv4 TTL decrement with bpf_l3_csum_replace (XDP_PASS) ---
    dev_l1_configs = [
        ("ttl_pass_dev01", "decrement IPv4 TTL field on development frames and update checksum"),
        ("ttl_pass_dev02", "reduce hop count by 1 on staging datagrams applying bpf_l3_csum_replace"),
        ("ttl_pass_dev03", "apply single-hop decrement to IPv4 TTL with incremental checksum recalculation"),
        ("ttl_pass_dev04", "update packet transit lifetime by decrementing TTL and correcting checksum"),
    ]

    for sub_idx, (name, desc) in enumerate(dev_l1_configs, start=1):
        tid = f"rl_v2_dev_ptr_l1_{sub_idx:02d}"
        fam = f"dev_ptr_l1_{name}"
        tasks.append({
            "task_id": tid,
            "application_category": "protocol_transformation",
            "difficulty": "level_1",
            "task_family": fam,
            "template_family": "xdp_ttl_decrement_pass",
            "semantic_signature": f"ptr_l1_ttl_dec_{sub_idx}",
            "split": "dev",
            "learning_mode": "synthesis",
            "instruction": f"Write an XDP program that must {desc}. Forward all packets with XDP_PASS.",
            "requirements": [
                "Verify Ethernet and IPv4 header bounds against data_end",
                "Decrement ip->ttl by 1 if ip->ttl > 1",
                "Recalculate IPv4 header checksum ip->check over all 20 bytes",
                "Unconditionally return XDP_PASS",
                "SEC(\"xdp\") entry point and GPL license declaration",
            ],
            "tests": [
                {"name": "pass_decremented", "description": "TTL 64 decremented to 63 and passed", "packet_hex": make_eth(payload=make_ipv4(ttl=64, proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
                {"name": "pass_arp", "description": "Non-IP ARP frame passed without alteration", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
            ],
            "solution_c": f"""#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

SEC("xdp")
int xdp_dec_ttl_{sub_idx}(struct xdp_md *ctx) {{
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

    if (ip->ttl > 1) {{
        ip->ttl -= 1;
        ip->check = 0;

        __u16 *words = (void *)ip;
        __u32 csum = 0;
        #pragma unroll
        for (int i = 0; i < 10; i++) {{
            if ((void *)(words + i + 1) > data_end)
                return XDP_PASS;
            csum += bpf_ntohs(words[i]);
        }}
        while (csum >> 16)
            csum = (csum & 0xFFFF) + (csum >> 16);
        ip->check = bpf_htons((~csum) & 0xFFFF);
    }}

    return XDP_PASS;
}}

char _license[] SEC("license") = "GPL";
""",
        })

    # --- Confirmation (idx 17..21): IPv4 ECN marking with bpf_l3_csum_replace ---
    conf_l1_configs = [
        ("ecn_ce_conf01", "mark IPv4 traffic with Congestion Experienced CE (bits 0-1 set to 0x03) in TOS field"),
        ("ecn_ce_conf02", "apply ECN congestion marking to IP header setting lowest 2 bits of TOS to 3"),
        ("ecn_ce_conf03", "rewrite IP ECN codepoint to CE 0x03 and update L3 header checksum incrementally"),
        ("ecn_ce_conf04", "assert Congestion Experienced flag in IPv4 TOS byte using bpf_l3_csum_replace"),
        ("ecn_ce_conf05", "tag IPv4 frames with ECN CE bits (0x03) adjusting IP checksum accordingly"),
    ]

    for sub_idx, (name, desc) in enumerate(conf_l1_configs, start=1):
        tid = f"rl_v2_conf_ptr_l1_{sub_idx:02d}"
        fam = f"conf_ptr_l1_{name}"
        tasks.append({
            "task_id": tid,
            "application_category": "protocol_transformation",
            "difficulty": "level_1",
            "task_family": fam,
            "template_family": "xdp_ecn_marker",
            "semantic_signature": f"ptr_l1_ecn_ce_{sub_idx}",
            "split": "confirmation",
            "learning_mode": "synthesis",
            "instruction": f"Write an XDP program that must {desc}. Forward all packets with XDP_PASS.",
            "requirements": [
                "Verify Ethernet and IPv4 header bounds against data_end",
                "Set lowest 2 bits of ip->tos to 0x03: (ip->tos & 0xFC) | 0x03",
                "Recalculate IPv4 header checksum ip->check over all 20 bytes",
                "Unconditionally return XDP_PASS",
                "SEC(\"xdp\") entry point and GPL license declaration",
            ],
            "tests": [
                {"name": "pass_ecn_marked", "description": "ECN marked with CE and passed", "packet_hex": make_eth(payload=make_ipv4(tos=0, proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
                {"name": "pass_arp", "description": "Non-IP ARP frame passed without alteration", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
            ],
            "solution_c": f"""#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

SEC("xdp")
int xdp_mark_ecn_{sub_idx}(struct xdp_md *ctx) {{
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

    ip->tos = (ip->tos & 0xFC) | 0x03;
    ip->check = 0;

    __u16 *words = (void *)ip;
    __u32 csum = 0;
    #pragma unroll
    for (int i = 0; i < 10; i++) {{
        if ((void *)(words + i + 1) > data_end)
            return XDP_PASS;
        csum += bpf_ntohs(words[i]);
    }}
    while (csum >> 16)
        csum = (csum & 0xFFFF) + (csum >> 16);
    ip->check = bpf_htons((~csum) & 0xFFFF);

    return XDP_PASS;
}}

char _license[] SEC("license") = "GPL";
""",
        })

    return tasks


def build_ptr_l2_tasks() -> List[Dict[str, Any]]:
    tasks = []

    # --- Canary (idx 0): 802.1Q VLAN Priority Code Point (PCP) remarking ---
    canary_task = {
        "task_id": "rl_v2_canary_ptr_l2_01",
        "application_category": "protocol_transformation",
        "difficulty": "level_2",
        "task_family": "canary_ptr_l2_vlan_pcp_remark",
        "template_family": "xdp_vlan_pcp_remarker",
        "semantic_signature": "ptr_l2_vlan_pcp_voice_canary",
        "split": "canary",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that remarks the 3-bit Priority Code Point (PCP) on 802.1Q tagged frames to voice priority level 5 in-place. Forward all packets with XDP_PASS.",
        "requirements": [
            "Ensure Ethernet and 802.1Q VLAN headers are within data_end bounds",
            "Inspect eth->h_proto for ETH_P_8021Q (0x8100)",
            "Extract vlan_TCI, keep VID and DEI bits intact, and overwrite bits 13-15 with PCP value 5",
            "Store modified vlan_TCI in network byte order in-place without head adjustments",
            "Forward all packets unconditionally using XDP_PASS",
            "SEC(\"xdp\") entry point and GPL license declaration",
        ],
        "tests": [
            {"name": "pass_remarked_pcp", "description": "VLAN PCP remarked to 5 and passed", "packet_hex": make_eth(vlan=100, payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
            {"name": "pass_untagged", "description": "Untagged packet passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
        ],
        "solution_c": """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>

struct vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

SEC("xdp")
int xdp_remark_pcp_canary(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto == bpf_htons(ETH_P_8021Q)) {
        struct vlan_hdr *vlan = (void *)(eth + 1);
        if ((void *)(vlan + 1) > data_end)
            return XDP_PASS;

        __u16 tci = bpf_ntohs(vlan->h_vlan_TCI);
        __u16 new_tci = (tci & 0x1FFF) | (5 << 13);
        vlan->h_vlan_TCI = bpf_htons(new_tci);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
""",
    }
    tasks.append(canary_task)

    # --- Train (idx 1..12): 802.1Q VLAN tag pop via bpf_xdp_adjust_head ---
    train_l2_configs = [
        ("vlan_pop_tr01", 151, "pop customer VLAN tag 151 on incoming Ethernet frames"),
        ("vlan_pop_tr02", 152, "strip outer 802.1Q tag 152 restoring native framing"),
        ("vlan_pop_tr03", 153, "decapsulate VLAN tag 153 using bpf_xdp_adjust_head"),
        ("vlan_pop_tr04", 154, "pop 802.1Q header on packets tagged with VLAN 154"),
        ("vlan_pop_tr05", 155, "strip customer VLAN identifier 155 from ingress frames"),
        ("vlan_pop_tr06", 156, "untag virtual circuit traffic marked with VLAN ID 156"),
        ("vlan_pop_tr07", 157, "remove 802.1Q encapsulation from frames with VLAN 157"),
        ("vlan_pop_tr08", 158, "strip bridge VLAN header 158 and advance packet start pointer"),
        ("vlan_pop_tr09", 159, "pop isolation VLAN tag 159 updating Ethernet header"),
        ("vlan_pop_tr10", 160, "decapsulate tagged packets with VLAN ID 160"),
        ("vlan_pop_tr11", 161, "strip transit VLAN tag 161 using bpf_xdp_adjust_head"),
        ("vlan_pop_tr12", 162, "untag incoming frames marked with VLAN 162"),
    ]

    for sub_idx, (name, vid, desc) in enumerate(train_l2_configs, start=1):
        tid = f"rl_v2_train_ptr_l2_{sub_idx:02d}"
        fam = f"train_ptr_l2_{name}"
        tasks.append({
            "task_id": tid,
            "application_category": "protocol_transformation",
            "difficulty": "level_2",
            "task_family": fam,
            "template_family": "xdp_vlan_pop",
            "semantic_signature": f"ptr_l2_pop_{vid}",
            "split": "train",
            "learning_mode": "synthesis",
            "instruction": f"Write an XDP program that must {desc}. Forward all packets with XDP_PASS.",
            "requirements": [
                "Validate Ethernet header bounds against data_end",
                f"Check if eth->h_proto == ETH_P_8021Q and vlan_id == {vid}",
                "Save copy of Ethernet header and update h_proto to encapsulated inner protocol",
                "Invoke bpf_xdp_adjust_head(ctx, (int)sizeof(struct vlan_hdr)) to pop 4 bytes",
                "Re-validate packet pointers data and data_end after bpf_xdp_adjust_head",
                "Restore Ethernet header and return XDP_PASS",
                "SEC(\"xdp\") entry point and GPL license declaration",
            ],
            "tests": [
                {"name": "pass_vlan_decap", "description": f"VLAN {vid} popped and passed", "packet_hex": make_eth(vlan=vid, payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
                {"name": "pass_untagged", "description": "Untagged passed unchanged", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
            ],
            "solution_c": f"""#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>

struct vlan_hdr {{
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
}};

SEC("xdp")
int xdp_decap_{name}(struct xdp_md *ctx) {{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto == bpf_htons(ETH_P_8021Q)) {{
        struct vlan_hdr *vlan = (void *)(eth + 1);
        if ((void *)(vlan + 1) > data_end)
            return XDP_PASS;

        __u16 vlan_id = bpf_ntohs(vlan->h_vlan_TCI) & 0x0FFF;
        if (vlan_id == {vid}) {{
            __u16 inner_proto = vlan->h_vlan_encapsulated_proto;
            struct ethhdr eth_backup;
            __builtin_memcpy(&eth_backup, eth, sizeof(struct ethhdr));
            eth_backup.h_proto = inner_proto;

            if (bpf_xdp_adjust_head(ctx, (int)sizeof(struct vlan_hdr)))
                return XDP_DROP;

            data = (void *)(long)ctx->data;
            data_end = (void *)(long)ctx->data_end;
            eth = data;
            if ((void *)(eth + 1) > data_end)
                return XDP_DROP;

            __builtin_memcpy(eth, &eth_backup, sizeof(struct ethhdr));
        }}
    }}

    return XDP_PASS;
}}

char _license[] SEC("license") = "GPL";
""",
        })

    # --- Dev (idx 13..16): In-place 802.1Q VLAN ID retagging (without adjust_head) ---
    dev_l2_configs = [
        ("vlan_retag_dev01", 100, 200, "rewrite VLAN tag 100 to VLAN 200 in-place without head adjustment"),
        ("vlan_retag_dev02", 110, 210, "retag ingress frames from VLAN 110 to staging VLAN 210 in-place"),
        ("vlan_retag_dev03", 120, 220, "remap customer VLAN identifier 120 to internal transport VLAN 220 in-place"),
        ("vlan_retag_dev04", 130, 230, "reassign virtual network identifier from VLAN 130 to service VLAN 230 in-place"),
    ]

    for sub_idx, (name, old_vid, new_vid, desc) in enumerate(dev_l2_configs, start=1):
        tid = f"rl_v2_dev_ptr_l2_{sub_idx:02d}"
        fam = f"dev_ptr_l2_{name}"
        tasks.append({
            "task_id": tid,
            "application_category": "protocol_transformation",
            "difficulty": "level_2",
            "task_family": fam,
            "template_family": "xdp_vlan_retag",
            "semantic_signature": f"ptr_l2_retag_{old_vid}_{new_vid}",
            "split": "dev",
            "learning_mode": "synthesis",
            "instruction": f"Write an XDP program that must {desc}. Modify the TCI field in-place without adjusting packet head. Forward all packets with XDP_PASS.",
            "requirements": [
                "Verify Ethernet and 802.1Q header bounds against data_end",
                f"Check if eth->h_proto == ETH_P_8021Q and vlan_id == {old_vid}",
                f"Overwrite vlan->h_vlan_TCI in-place preserving priority bits and setting VID to {new_vid}",
                "Return XDP_PASS unconditionally",
                "SEC(\"xdp\") entry point and GPL license declaration",
            ],
            "tests": [
                {"name": "pass_retagged", "description": f"VLAN {old_vid} retagged to {new_vid} and passed", "packet_hex": make_eth(vlan=old_vid, payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
                {"name": "pass_untagged", "description": "Untagged passed unmodified", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
            ],
            "solution_c": f"""#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>

struct vlan_hdr {{
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
}};

SEC("xdp")
int xdp_retag_{sub_idx}(struct xdp_md *ctx) {{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto == bpf_htons(ETH_P_8021Q)) {{
        struct vlan_hdr *vlan = (void *)(eth + 1);
        if ((void *)(vlan + 1) > data_end)
            return XDP_PASS;

        __u16 tci = bpf_ntohs(vlan->h_vlan_TCI);
        __u16 vlan_id = tci & 0x0FFF;
        if (vlan_id == {old_vid}) {{
            __u16 new_tci = (tci & 0xF000) | ({new_vid} & 0x0FFF);
            vlan->h_vlan_TCI = bpf_htons(new_tci);
        }}
    }}

    return XDP_PASS;
}}

char _license[] SEC("license") = "GPL";
""",
        })

    # --- Confirmation (idx 17..21): 802.1Q VLAN tag push via bpf_xdp_adjust_head ---
    conf_l2_configs = [
        ("vlan_push_conf01", 301, "encapsulate untagged IPv4 traffic by pushing 802.1Q VLAN header with ID 301"),
        ("vlan_push_conf02", 302, "prepend 4-byte 802.1Q tag 302 to ingress raw Ethernet frames using adjust_head"),
        ("vlan_push_conf03", 303, "insert VLAN tag 303 between Ethernet header and IP datagram via adjust_head(-4)"),
        ("vlan_push_conf04", 304, "push virtual network tag 304 onto untagged packets expanding packet head"),
        ("vlan_push_conf05", 305, "apply 802.1Q encapsulation tagging untagged traffic with VLAN ID 305"),
    ]

    for sub_idx, (name, push_vid, desc) in enumerate(conf_l2_configs, start=1):
        tid = f"rl_v2_conf_ptr_l2_{sub_idx:02d}"
        fam = f"conf_ptr_l2_{name}"
        tasks.append({
            "task_id": tid,
            "application_category": "protocol_transformation",
            "difficulty": "level_2",
            "task_family": fam,
            "template_family": "xdp_vlan_push",
            "semantic_signature": f"ptr_l2_push_{push_vid}",
            "split": "confirmation",
            "learning_mode": "synthesis",
            "instruction": f"Write an XDP program that must {desc}. Forward all packets with XDP_PASS.",
            "requirements": [
                "Verify Ethernet header bounds against data_end",
                "Check if frame is untagged IPv4 (eth->h_proto == ETH_P_IP)",
                "Invoke bpf_xdp_adjust_head(ctx, -(int)sizeof(struct vlan_hdr)) to expand head by 4 bytes",
                "Re-validate packet pointers and rewrite Ethernet header with ETH_P_8021Q",
                f"Insert struct vlan_hdr with vlan_id == {push_vid} and encapsulated ETH_P_IP",
                "Return XDP_PASS unconditionally",
                "SEC(\"xdp\") entry point and GPL license declaration",
            ],
            "tests": [
                {"name": "pass_untagged_pushed", "description": f"Untagged pushed with VLAN {push_vid} and passed", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
                {"name": "pass_arp", "description": "ARP frame passed unmodified", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
            ],
            "solution_c": f"""#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>

struct vlan_hdr {{
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
}};

SEC("xdp")
int xdp_push_vlan_{sub_idx}(struct xdp_md *ctx) {{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto == bpf_htons(ETH_P_IP)) {{
        struct ethhdr eth_copy;
        __builtin_memcpy(&eth_copy, eth, sizeof(struct ethhdr));

        if (bpf_xdp_adjust_head(ctx, -(int)sizeof(struct vlan_hdr)))
            return XDP_DROP;

        data = (void *)(long)ctx->data;
        data_end = (void *)(long)ctx->data_end;

        struct ethhdr *new_eth = data;
        if ((void *)(new_eth + 1) > data_end)
            return XDP_DROP;

        struct vlan_hdr *vlan = (void *)(new_eth + 1);
        if ((void *)(vlan + 1) > data_end)
            return XDP_DROP;

        __builtin_memcpy(new_eth, &eth_copy, sizeof(struct ethhdr));
        new_eth->h_proto = bpf_htons(ETH_P_8021Q);

        vlan->h_vlan_TCI = bpf_htons({push_vid});
        vlan->h_vlan_encapsulated_proto = bpf_htons(ETH_P_IP);
    }}

    return XDP_PASS;
}}

char _license[] SEC("license") = "GPL";
""",
        })

    return tasks


def build_ptr_l3_tasks() -> List[Dict[str, Any]]:
    tasks = []

    # --- Canary (idx 0): 4in6 (IPv4-over-IPv6) tunnel decapsulation ---
    canary_inner = make_ipv4(src_ip="192.168.30.1", dst_ip="192.168.30.2", proto=6, payload=make_tcp())
    canary_outer = make_eth(eth_type=0x86DD, payload=make_ipv6(src_ip="2001:db8::1", dst_ip="2001:db8::2", next_hdr=4, payload=canary_inner)).hex()

    canary_task = {
        "task_id": "rl_v2_canary_ptr_l3_01",
        "application_category": "protocol_transformation",
        "difficulty": "level_3",
        "task_family": "canary_ptr_l3_4in6_decap_canary",
        "template_family": "xdp_4in6_decap",
        "semantic_signature": "ptr_l3_4in6_decap_canary",
        "split": "canary",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that decapsulates 4in6 (IPv4-over-IPv6) tunnel packets carrying protocol 4 in IPv6 nexthdr. Use bpf_xdp_adjust_head to strip the 40-byte IPv6 header and restore native IPv4 Ethernet framing. Forward all traffic with XDP_PASS.",
        "requirements": [
            "Verify ingress frame has Ethernet and IPv6 headers within data_end bounds",
            "Check eth->h_proto == ETH_P_IPV6 (0x86DD) and ip6->nexthdr == 4 (IPPROTO_IPIP)",
            "Store original Ethernet header copy and set h_proto to ETH_P_IP",
            "Invoke bpf_xdp_adjust_head(ctx, 40) to strip the fixed outer IPv6 header",
            "Re-evaluate packet pointers data and data_end after head adjustment",
            "Copy back Ethernet header and forward packet with XDP_PASS",
            "SEC(\"xdp\") entry point and GPL license declaration",
        ],
        "tests": [
            {"name": "pass_decap_4in6", "description": "4in6 tunnel decapsulated and passed", "packet_hex": canary_outer, "expected_action": "XDP_PASS", "weight": 1.0},
            {"name": "pass_normal_v6", "description": "Standard non-tunneled IPv6 TCP passed unmodified", "packet_hex": make_eth(eth_type=0x86DD, payload=make_ipv6(src_ip="2001:db8::1", dst_ip="2001:db8::2", next_hdr=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
        ],
        "solution_c": """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/in.h>

SEC("xdp")
int xdp_decap_4in6_canary(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IPV6))
        return XDP_PASS;

    struct ipv6hdr *ip6 = (void *)(eth + 1);
    if ((void *)(ip6 + 1) > data_end)
        return XDP_PASS;

    if (ip6->nexthdr == 4) {
        struct ethhdr eth_backup;
        __builtin_memcpy(&eth_backup, eth, sizeof(struct ethhdr));
        eth_backup.h_proto = bpf_htons(ETH_P_IP);

        if (bpf_xdp_adjust_head(ctx, (int)sizeof(struct ipv6hdr)))
            return XDP_DROP;

        data = (void *)(long)ctx->data;
        data_end = (void *)(long)ctx->data_end;
        eth = data;
        if ((void *)(eth + 1) > data_end)
            return XDP_DROP;

        __builtin_memcpy(eth, &eth_backup, sizeof(struct ethhdr));
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
""",
    }
    tasks.append(canary_task)

    # --- Train (idx 1..12): IP-in-IP (protocol 4) tunnel decapsulation via bpf_xdp_adjust_head ---
    train_l3_descs = [
        ("ipip_decap_tr01", "strip outer IP-in-IP tunnel encapsulation on protocol 4 packets exposing inner IPv4 payload"),
        ("ipip_decap_tr02", "remove outer IPIP encapsulation header using bpf_xdp_adjust_head and advance Ethernet frame"),
        ("ipip_decap_tr03", "decapsulate tunnel datagrams carrying IPPROTO_IPIP (4) to forward inner packet natively"),
        ("ipip_decap_tr04", "unwrap IP-in-IP tunnel traffic by removing outer IPv4 header via adjust_head helper"),
        ("ipip_decap_tr05", "strip tunnel wrapper on IPv4 protocol 4 datagrams and restore Ethernet header"),
        ("ipip_decap_tr06", "decapsulate ingress IPIP frames shifting packet head forward by outer IP header length"),
        ("ipip_decap_tr07", "remove outer IPv4 framing on tunnel packets with bpf_xdp_adjust_head for native delivery"),
        ("ipip_decap_tr08", "unwrap IP-in-IP encapsulation on received frames and return XDP_PASS"),
        ("ipip_decap_tr09", "strip outer tunnel header on IPIP protocol 4 packets re-validating packet pointers"),
        ("ipip_decap_tr10", "decapsulate IP-in-IP datagrams by copying Ethernet header and stripping outer IP"),
        ("ipip_decap_tr11", "remove outer IPv4 transport wrapper on protocol 4 tunnel packets returning XDP_PASS"),
        ("ipip_decap_tr12", "unwrap ingress IP-in-IP packets with bpf_xdp_adjust_head forwarding inner content"),
    ]

    for sub_idx, (name, desc) in enumerate(train_l3_descs, start=1):
        tid = f"rl_v2_train_ptr_l3_{sub_idx:02d}"
        fam = f"train_ptr_l3_{name}"
        inner_pkt = make_ipv4(src_ip="192.168.30.1", dst_ip="192.168.30.2", proto=6, payload=make_tcp())
        outer_pkt = make_eth(payload=make_ipv4(src_ip=f"10.88.{sub_idx}.1", dst_ip="10.88.0.254", proto=4, payload=inner_pkt)).hex()
        tasks.append({
            "task_id": tid,
            "application_category": "protocol_transformation",
            "difficulty": "level_3",
            "task_family": fam,
            "template_family": "xdp_tunnel_decap",
            "semantic_signature": f"ptr_l3_ipip_{sub_idx}",
            "split": "train",
            "learning_mode": "synthesis",
            "instruction": f"Write an XDP program that must {desc}. Forward all packets with XDP_PASS.",
            "requirements": [
                "Validate Ethernet and outer IPv4 header bounds against data_end",
                "Verify outer_ip->protocol == 4 (IPPROTO_IPIP)",
                "Calculate variable outer IPv4 header length (outer_ip->ihl * 4)",
                "Back up Ethernet header and shift head forward by outer_len using bpf_xdp_adjust_head",
                "Re-validate packet pointers data and data_end after adjust_head",
                "Restore Ethernet header and return XDP_PASS",
                "SEC(\"xdp\") entry point and GPL license declaration",
            ],
            "tests": [
                {"name": "pass_decap_ipip", "description": "IPIP tunnel packet decapsulated and passed", "packet_hex": outer_pkt, "expected_action": "XDP_PASS", "weight": 1.0},
                {"name": "pass_normal_tcp", "description": "Normal non-tunneled TCP passed unmodified", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
            ],
            "solution_c": f"""#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>

SEC("xdp")
int xdp_decap_ipip_{sub_idx}(struct xdp_md *ctx) {{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *outer_ip = (void *)(eth + 1);
    if ((void *)(outer_ip + 1) > data_end)
        return XDP_PASS;

    if (outer_ip->protocol == 4) {{
        int outer_len = outer_ip->ihl * 4;
        if (outer_len < sizeof(struct iphdr) || (void *)outer_ip + outer_len > data_end)
            return XDP_PASS;

        struct ethhdr eth_backup;
        __builtin_memcpy(&eth_backup, eth, sizeof(struct ethhdr));

        if (bpf_xdp_adjust_head(ctx, outer_len))
            return XDP_DROP;

        data = (void *)(long)ctx->data;
        data_end = (void *)(long)ctx->data_end;
        eth = data;
        if ((void *)(eth + 1) > data_end)
            return XDP_DROP;

        __builtin_memcpy(eth, &eth_backup, sizeof(struct ethhdr));
    }}

    return XDP_PASS;
}}

char _license[] SEC("license") = "GPL";
""",
        })

    # --- Dev (idx 13..16): 6in4 (protocol 41) IPv6-in-IPv4 tunnel decapsulation via bpf_xdp_adjust_head ---
    dev_l3_descs = [
        ("six_in_four_dev01", "decapsulate 6in4 tunnel packets (protocol 41) by stripping outer IPv4 and restoring ETH_P_IPV6"),
        ("six_in_four_dev02", "unwrap IPv6-in-IPv4 transition packets with bpf_xdp_adjust_head and set h_proto to ETH_P_IPV6"),
        ("six_in_four_dev03", "remove outer IPv4 header on proto 41 datagrams exposing native IPv6 frame"),
        ("six_in_four_dev04", "decapsulate SIT / 6in4 tunnels by popping outer IPv4 wrapper and setting Ethernet type to IPv6"),
    ]

    for sub_idx, (name, desc) in enumerate(dev_l3_descs, start=1):
        tid = f"rl_v2_dev_ptr_l3_{sub_idx:02d}"
        fam = f"dev_ptr_l3_{name}"
        inner_v6 = make_ipv6(src_ip="2001:db8::1", dst_ip="2001:db8::2", next_hdr=6, payload=make_tcp())
        outer_6in4 = make_eth(payload=make_ipv4(src_ip=f"10.77.{sub_idx}.1", dst_ip="10.77.0.254", proto=41, payload=inner_v6)).hex()
        tasks.append({
            "task_id": tid,
            "application_category": "protocol_transformation",
            "difficulty": "level_3",
            "task_family": fam,
            "template_family": "xdp_6in4_decap",
            "semantic_signature": f"ptr_l3_6in4_{sub_idx}",
            "split": "dev",
            "learning_mode": "synthesis",
            "instruction": f"Write an XDP program that must {desc}. Forward all packets with XDP_PASS.",
            "requirements": [
                "Verify Ethernet and outer IPv4 header bounds against data_end",
                "Check if outer_ip->protocol == 41 (IPPROTO_IPV6)",
                "Calculate variable outer IPv4 header length (outer_ip->ihl * 4)",
                "Back up Ethernet header and update h_proto to ETH_P_IPV6 (0x86DD)",
                "Invoke bpf_xdp_adjust_head(ctx, outer_len) and restore updated Ethernet header",
                "Return XDP_PASS unconditionally",
                "SEC(\"xdp\") entry point and GPL license declaration",
            ],
            "tests": [
                {"name": "pass_decap_6in4", "description": "6in4 tunnel packet decapsulated and passed", "packet_hex": outer_6in4, "expected_action": "XDP_PASS", "weight": 1.0},
                {"name": "pass_normal_tcp", "description": "Normal non-tunneled TCP passed unmodified", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
            ],
            "solution_c": f"""#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

SEC("xdp")
int xdp_decap_6in4_{sub_idx}(struct xdp_md *ctx) {{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *outer_ip = (void *)(eth + 1);
    if ((void *)(outer_ip + 1) > data_end)
        return XDP_PASS;

    if (outer_ip->protocol == 41) {{
        int outer_len = outer_ip->ihl * 4;
        if (outer_len < sizeof(struct iphdr) || (void *)outer_ip + outer_len > data_end)
            return XDP_PASS;

        struct ethhdr eth_backup;
        __builtin_memcpy(&eth_backup, eth, sizeof(struct ethhdr));
        eth_backup.h_proto = bpf_htons(ETH_P_IPV6);

        if (bpf_xdp_adjust_head(ctx, outer_len))
            return XDP_DROP;

        data = (void *)(long)ctx->data;
        data_end = (void *)(long)ctx->data_end;
        eth = data;
        if ((void *)(eth + 1) > data_end)
            return XDP_DROP;

        __builtin_memcpy(eth, &eth_backup, sizeof(struct ethhdr));
    }}

    return XDP_PASS;
}}

char _license[] SEC("license") = "GPL";
""",
        })

    # --- Confirmation (idx 17..21): GRE (protocol 47) tunnel decapsulation via bpf_xdp_adjust_head ---
    conf_l3_descs = [
        ("gre_decap_conf01", "decapsulate basic GRE tunnels (proto 47) stripping outer IPv4 and 4-byte GRE header"),
        ("gre_decap_conf02", "remove GRE encapsulation wrapper (IPv4 + 4-byte GRE) to expose inner Ethernet/IP frame"),
        ("gre_decap_conf03", "unwrap GRE datagrams using bpf_xdp_adjust_head advancing head past outer headers"),
        ("gre_decap_conf04", "strip outer IPv4 header and GRE framing protocol 47 restoring native payload"),
        ("gre_decap_conf05", "decapsulate ingress Generic Routing Encapsulation packets returning XDP_PASS"),
    ]

    for sub_idx, (name, desc) in enumerate(conf_l3_descs, start=1):
        tid = f"rl_v2_conf_ptr_l3_{sub_idx:02d}"
        fam = f"conf_ptr_l3_{name}"
        # Standard GRE header: 4 bytes (flags=0, proto=0x0800 for IPv4)
        gre_hdr = b"\x00\x00\x08\x00"
        inner_ip = make_ipv4(src_ip="192.168.50.1", dst_ip="192.168.50.2", proto=6, payload=make_tcp())
        outer_gre = make_eth(payload=make_ipv4(src_ip=f"10.66.{sub_idx}.1", dst_ip="10.66.0.254", proto=47, payload=gre_hdr + inner_ip)).hex()
        tasks.append({
            "task_id": tid,
            "application_category": "protocol_transformation",
            "difficulty": "level_3",
            "task_family": fam,
            "template_family": "xdp_gre_decap",
            "semantic_signature": f"ptr_l3_gre_{sub_idx}",
            "split": "confirmation",
            "learning_mode": "synthesis",
            "instruction": f"Write an XDP program that must {desc}. Forward all packets with XDP_PASS.",
            "requirements": [
                "Verify Ethernet and outer IPv4 header bounds against data_end",
                "Check if outer_ip->protocol == 47 (IPPROTO_GRE)",
                "Calculate total encapsulation length: (outer_ip->ihl * 4) + 4 bytes GRE header",
                "Back up Ethernet header and shift packet head forward by outer_len + 4 using bpf_xdp_adjust_head",
                "Re-validate packet pointers and restore Ethernet header with ETH_P_IP",
                "Return XDP_PASS unconditionally",
                "SEC(\"xdp\") entry point and GPL license declaration",
            ],
            "tests": [
                {"name": "pass_decap_gre", "description": "GRE tunnel packet decapsulated and passed", "packet_hex": outer_gre, "expected_action": "XDP_PASS", "weight": 1.0},
                {"name": "pass_normal_tcp", "description": "Normal non-tunneled TCP passed unmodified", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
            ],
            "solution_c": f"""#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

SEC("xdp")
int xdp_decap_gre_{sub_idx}(struct xdp_md *ctx) {{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *outer_ip = (void *)(eth + 1);
    if ((void *)(outer_ip + 1) > data_end)
        return XDP_PASS;

    if (outer_ip->protocol == 47) {{
        int ip_len = outer_ip->ihl * 4;
        int total_len = ip_len + 4; // outer IPv4 + 4-byte GRE
        if (ip_len < sizeof(struct iphdr) || (void *)outer_ip + total_len > data_end)
            return XDP_PASS;

        struct ethhdr eth_backup;
        __builtin_memcpy(&eth_backup, eth, sizeof(struct ethhdr));
        eth_backup.h_proto = bpf_htons(ETH_P_IP);

        if (bpf_xdp_adjust_head(ctx, total_len))
            return XDP_DROP;

        data = (void *)(long)ctx->data;
        data_end = (void *)(long)ctx->data_end;
        eth = data;
        if ((void *)(eth + 1) > data_end)
            return XDP_DROP;

        __builtin_memcpy(eth, &eth_backup, sizeof(struct ethhdr));
    }}

    return XDP_PASS;
}}

char _license[] SEC("license") = "GPL";
""",
        })

    return tasks
