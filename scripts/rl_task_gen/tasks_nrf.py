"""
BPF-Guardian RLVR Phase 2: Network Routing & Forwarding (NRF) Task Definitions.
Contains 66 distinct, verifier-safe tasks with strict task-family disjointness across splits:
- Level 1 (22 tasks):
    * Canary (1): VLAN reflector (XDP_TX)
    * Train (12): Ethernet MAC + IP swap packet reflector (XDP_TX)
    * Dev (4): IPv4 TTL decrement with checksum update and forward (XDP_TX)
    * Confirmation (5): L4 TCP port swap hairpin reflector (XDP_TX)
- Level 2 (22 tasks):
    * Canary (1): Protocol demux router (TCP to XDP_TX, UDP to XDP_PASS)
    * Train (12): Static destination IP subnet gateway router (XDP_TX / XDP_PASS)
    * Dev (4): 802.1Q VLAN demux router (XDP_TX / XDP_PASS)
    * Confirmation (5): 2-way Equal-Cost Multi-Path (ECMP) hash router (XDP_TX)
- Level 3 (22 tasks):
    * Canary (1): Basic LPM trie IPv4 route table
    * Train (12): LPM Trie IPv4 prefix routing with next-hop gateway MAC rewrite
    * Dev (4): LPM Trie routing with fallback default gateway
    * Confirmation (5): LPM Trie routing with bpf_redirect interface forwarding
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


def build_nrf_l1_tasks() -> List[Dict[str, Any]]:
    tasks = []

    # --- Canary (idx 0): VLAN reflector ---
    canary_task = {
        "task_id": "rl_v2_canary_nrf_l1_01",
        "application_category": "network_routing_forwarding",
        "difficulty": "level_1",
        "task_family": "canary_nrf_l1_vlan_reflect",
        "template_family": "xdp_vlan_reflector",
        "semantic_signature": "nrf_l1_vlan_reflect_canary",
        "split": "canary",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that inspects 802.1Q VLAN tagged traffic. If tagged with VLAN ID 100, transmit the packet back out the same interface using XDP_TX. Forward all other packets with XDP_PASS.",
        "requirements": [
            "Verify Ethernet and 802.1Q VLAN header bounds against data_end",
            "Check if eth->h_proto == ETH_P_8021Q and vlan_id == 100",
            "Return XDP_TX for matching VLAN packets",
            "Return XDP_PASS for other VLAN IDs, untagged traffic, or malformed frames",
            "SEC(\"xdp\") entry point and GPL license declaration",
        ],
        "tests": [
            {"name": "tx_vlan_100", "description": "VLAN 100 transmitted", "packet_hex": make_eth(vlan=100, payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_TX", "weight": 1.0},
            {"name": "pass_vlan_200", "description": "VLAN 200 passed", "packet_hex": make_eth(vlan=200, payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
            {"name": "pass_untagged", "description": "Untagged passed", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
            {"name": "pass_arp", "description": "ARP passed", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
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
int xdp_reflect_vlan(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto == bpf_htons(ETH_P_8021Q)) {
        struct vlan_hdr *vlan = (void *)(eth + 1);
        if ((void *)(vlan + 1) > data_end)
            return XDP_PASS;
        __u16 vlan_id = bpf_ntohs(vlan->h_vlan_TCI) & 0x0FFF;
        if (vlan_id == 100)
            return XDP_TX;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
""",
    }
    tasks.append(canary_task)

    # --- Train (idx 1..12): Ethernet MAC + IP swap packet reflector (XDP_TX) ---
    train_l1_descs = [
        ("mac_ip_swap_01", "reflect incoming IPv4 packets by exchanging hardware and IP address pairs with XDP_TX"),
        ("mac_ip_swap_02", "bounce received IPv4 frames back out the arrival interface by reversing Ethernet and IP headers"),
        ("mac_ip_swap_03", "implement a stateless IPv4 packet mirror swapping source and destination MAC and IP addresses"),
        ("mac_ip_swap_04", "reflect inbound IPv4 datagrams using XDP_TX after swapping MAC and IP address fields"),
        ("mac_ip_swap_05", "turn around IPv4 frames by swapping source and destination endpoints at Layer 2 and Layer 3"),
        ("mac_ip_swap_06", "echo incoming IPv4 traffic back to sender by transposing MAC addresses and IP addresses"),
        ("mac_ip_swap_07", "perform packet loopback reflection by swapping Ethernet addresses and IPv4 addresses"),
        ("mac_ip_swap_08", "swap ingress Ethernet source/destination and IPv4 source/destination addresses and transmit via XDP_TX"),
        ("mac_ip_swap_09", "mirror received IPv4 network packets by exchanging both Layer 2 MACs and Layer 3 IP endpoints"),
        ("mac_ip_swap_10", "reflect arriving IPv4 datagrams by inverting source and destination address fields across Ethernet and IP"),
        ("mac_ip_swap_11", "return ingress IPv4 packets out the same port with transposed MAC and IP headers"),
        ("mac_ip_swap_12", "execute two-point address swap on incoming IPv4 frames reversing both MAC and IP addresses"),
    ]

    for sub_idx, (name, desc) in enumerate(train_l1_descs, start=1):
        tid = f"rl_v2_train_nrf_l1_{sub_idx:02d}"
        fam = f"train_nrf_l1_{name}"
        tasks.append({
            "task_id": tid,
            "application_category": "network_routing_forwarding",
            "difficulty": "level_1",
            "task_family": fam,
            "template_family": "xdp_mac_ip_reflector",
            "semantic_signature": f"nrf_l1_mac_ip_{sub_idx}",
            "split": "train",
            "learning_mode": "synthesis",
            "instruction": f"Write an XDP program that must {desc}. Forward all other packets with XDP_PASS.",
            "requirements": [
                "Verify Ethernet and IPv4 header bounds against data_end",
                "Confirm eth->h_proto == ETH_P_IP",
                "Swap Ethernet source and destination hardware addresses in-place",
                "Swap IPv4 source and destination network addresses in-place",
                "Return XDP_TX for reflected packets, XDP_PASS for non-IP or malformed frames",
                "SEC(\"xdp\") entry point and GPL license declaration",
            ],
            "tests": [
                {"name": "tx_reflected_ip", "description": "IPv4 reflected with XDP_TX", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.10", dst_ip="192.168.1.20", proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_TX", "weight": 1.0},
                {"name": "pass_arp", "description": "Non-IP ARP passes", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
                {"name": "pass_truncated", "description": "Truncated passes", "packet_hex": "52540012345652540065432108004500", "expected_action": "XDP_PASS", "weight": 1.0},
            ],
            "solution_c": f"""#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

SEC("xdp")
int xdp_reflect_{sub_idx}(struct xdp_md *ctx) {{
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

    unsigned char tmp_mac[ETH_ALEN];
    for (int i = 0; i < ETH_ALEN; i++) {{
        tmp_mac[i] = eth->h_dest[i];
        eth->h_dest[i] = eth->h_source[i];
        eth->h_source[i] = tmp_mac[i];
    }}

    __u32 tmp_ip = ip->daddr;
    ip->daddr = ip->saddr;
    ip->saddr = tmp_ip;

    return XDP_TX;
}}

char _license[] SEC("license") = "GPL";
""",
        })

    # --- Dev (idx 13..16): IPv4 TTL decrement with checksum update and forward (XDP_TX) ---
    dev_l1_descs = [
        ("ttl_dec_dev01", "decrement TTL on staging network traffic and forward via XDP_TX"),
        ("ttl_dec_dev02", "update hop count on diagnostic IPv4 packets with incremental checksum and transmit"),
        ("ttl_dec_dev03", "forward transit test datagrams with decremented TTL and updated header checksum"),
        ("ttl_dec_dev04", "decrement IPv4 time-to-live field on benchmark traffic and emit via XDP_TX"),
    ]

    for sub_idx, (name, desc) in enumerate(dev_l1_descs, start=1):
        tid = f"rl_v2_dev_nrf_l1_{sub_idx:02d}"
        fam = f"dev_nrf_l1_{name}"
        tasks.append({
            "task_id": tid,
            "application_category": "network_routing_forwarding",
            "difficulty": "level_1",
            "task_family": fam,
            "template_family": "xdp_ttl_decrement_forwarder",
            "semantic_signature": f"nrf_l1_ttl_dec_{sub_idx}",
            "split": "dev",
            "learning_mode": "synthesis",
            "instruction": f"Write an XDP program that must {desc}. Drop packets if TTL is 1 or less; forward non-IP with XDP_PASS.",
            "requirements": [
                "Verify Ethernet and IPv4 header bounds against data_end",
                "Confirm eth->h_proto == ETH_P_IP",
                "Drop packet with XDP_DROP if ip->ttl <= 1",
                "Decrement ip->ttl and recalculate IPv4 header checksum ip->check",
                "Return XDP_TX for forwarded packets, XDP_PASS for non-IP traffic",
                "SEC(\"xdp\") entry point and GPL license declaration",
            ],
            "tests": [
                {"name": "tx_forwarded", "description": "TTL 64 forwarded with XDP_TX", "packet_hex": make_eth(payload=make_ipv4(ttl=64, proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_TX", "weight": 1.0},
                {"name": "drop_expired", "description": "TTL 1 dropped", "packet_hex": make_eth(payload=make_ipv4(ttl=1, proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_DROP", "weight": 1.0},
                {"name": "pass_arp", "description": "ARP passes", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
            ],
            "solution_c": f"""#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

SEC("xdp")
int xdp_fwd_ttl_{sub_idx}(struct xdp_md *ctx) {{
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

    if (ip->ttl <= 1)
        return XDP_DROP;

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

    return XDP_TX;
}}

char _license[] SEC("license") = "GPL";
""",
        })

    # --- Confirmation (idx 17..21): L4 TCP port swap hairpin reflector (XDP_TX) ---
    conf_l1_descs = [
        ("port_hairpin_conf01", "reflect TCP connections by swapping Layer 4 source and destination ports in-place"),
        ("port_hairpin_conf02", "hairpin incoming TCP sessions by reversing source and destination port numbers"),
        ("port_hairpin_conf03", "turn around inbound TCP packets by transposing Layer 4 port endpoints"),
        ("port_hairpin_conf04", "perform TCP port reversal on ingress traffic and transmit with XDP_TX"),
        ("port_hairpin_conf05", "execute hairpin reflection on received TCP segments by exchanging port fields"),
    ]

    for sub_idx, (name, desc) in enumerate(conf_l1_descs, start=1):
        tid = f"rl_v2_conf_nrf_l1_{sub_idx:02d}"
        fam = f"conf_nrf_l1_{name}"
        tasks.append({
            "task_id": tid,
            "application_category": "network_routing_forwarding",
            "difficulty": "level_1",
            "task_family": fam,
            "template_family": "xdp_port_hairpin_reflector",
            "semantic_signature": f"nrf_l1_hairpin_{sub_idx}",
            "split": "confirmation",
            "learning_mode": "synthesis",
            "instruction": f"Write an XDP program that must {desc}. Forward all other packets with XDP_PASS.",
            "requirements": [
                "Verify Ethernet, IPv4, and TCP header bounds against data_end",
                "Confirm eth->h_proto == ETH_P_IP and ip->protocol == IPPROTO_TCP",
                "Safely validate variable IPv4 header length (ip->ihl * 4)",
                "Swap tcp->source and tcp->dest in-place",
                "Return XDP_TX for reflected packets, XDP_PASS for other protocols",
                "SEC(\"xdp\") entry point and GPL license declaration",
            ],
            "tests": [
                {"name": "tx_hairpin", "description": "TCP ports swapped and transmitted", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(src_port=12345, dst_port=80))).hex(), "expected_action": "XDP_TX", "weight": 1.0},
                {"name": "pass_udp", "description": "UDP passed unmodified", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(src_port=12345, dst_port=53))).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
                {"name": "pass_arp", "description": "ARP passed unmodified", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
            ],
            "solution_c": f"""#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>

SEC("xdp")
int xdp_hairpin_{sub_idx}(struct xdp_md *ctx) {{
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

    __be16 tmp_port = tcp->dest;
    tcp->dest = tcp->source;
    tcp->source = tmp_port;

    return XDP_TX;
}}

char _license[] SEC("license") = "GPL";
""",
        })

    return tasks


def build_nrf_l2_tasks() -> List[Dict[str, Any]]:
    tasks = []

    # --- Canary (idx 0): Protocol demux router ---
    canary_task = {
        "task_id": "rl_v2_canary_nrf_l2_01",
        "application_category": "network_routing_forwarding",
        "difficulty": "level_2",
        "task_family": "canary_nrf_l2_proto_demux",
        "template_family": "xdp_proto_demux_router",
        "semantic_signature": "nrf_l2_proto_demux_canary",
        "split": "canary",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that demuxes traffic: forward all incoming TCP traffic out the interface with XDP_TX, and pass all UDP and other traffic to the host stack with XDP_PASS.",
        "requirements": [
            "Verify Ethernet and IPv4 header bounds against data_end",
            "Inspect ip->protocol: return XDP_TX if IPPROTO_TCP",
            "Return XDP_PASS for UDP, ICMP, other protocols, and non-IP frames",
            "SEC(\"xdp\") entry point and GPL license declaration",
        ],
        "tests": [
            {"name": "tx_tcp", "description": "TCP transmitted", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_TX", "weight": 1.0},
            {"name": "pass_udp", "description": "UDP passed", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp())).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
            {"name": "pass_arp", "description": "ARP passed", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
        ],
        "solution_c": """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>

SEC("xdp")
int xdp_demux_proto(struct xdp_md *ctx) {
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

    if (ip->protocol == IPPROTO_TCP)
        return XDP_TX;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
""",
    }
    tasks.append(canary_task)

    # --- Train (idx 1..12): Static destination IP subnet gateway router (XDP_TX / XDP_PASS) ---
    for sub_idx in range(1, 13):
        subnet_octet = 10 + sub_idx
        tid = f"rl_v2_train_nrf_l2_{sub_idx:02d}"
        fam = f"train_nrf_l2_subnet_router_{sub_idx:02d}"
        tasks.append({
            "task_id": tid,
            "application_category": "network_routing_forwarding",
            "difficulty": "level_2",
            "task_family": fam,
            "template_family": "xdp_subnet_router",
            "semantic_signature": f"nrf_l2_subnet_{subnet_octet}",
            "split": "train",
            "learning_mode": "synthesis",
            "instruction": f"Write an XDP program that routes traffic: if destination IP belongs to subnet 10.{subnet_octet}.0.0/16, rewrite destination MAC to next-hop gateway 52:54:00:00:00:01 and return XDP_TX. Forward all other packets with XDP_PASS.",
            "requirements": [
                "Verify Ethernet and IPv4 header bounds against data_end",
                f"Check if ip->daddr matches subnet prefix 10.{subnet_octet}.0.0/16",
                "Rewrite eth->h_dest to 52:54:00:00:00:01 on match and return XDP_TX",
                "Return XDP_PASS for other destination IPs and non-IP traffic",
                "SEC(\"xdp\") entry point and GPL license declaration",
            ],
            "tests": [
                {"name": "tx_matched_subnet", "description": f"Subnet 10.{subnet_octet}.x transmitted", "packet_hex": make_eth(payload=make_ipv4(dst_ip=f"10.{subnet_octet}.1.50", proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_TX", "weight": 1.0},
                {"name": "pass_unmatched_ip", "description": "Other subnet passes", "packet_hex": make_eth(payload=make_ipv4(dst_ip="192.168.1.1", proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
                {"name": "pass_arp", "description": "ARP passes", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
            ],
            "solution_c": f"""#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

SEC("xdp")
int xdp_route_sub_{sub_idx}(struct xdp_md *ctx) {{
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

    __u32 mask = bpf_htonl(0xFFFF0000);
    __u32 target = bpf_htonl((10 << 24) | ({subnet_octet} << 16));

    if ((ip->daddr & mask) == target) {{
        eth->h_dest[0] = 0x52;
        eth->h_dest[1] = 0x54;
        eth->h_dest[2] = 0x00;
        eth->h_dest[3] = 0x00;
        eth->h_dest[4] = 0x00;
        eth->h_dest[5] = 0x01;
        return XDP_TX;
    }}

    return XDP_PASS;
}}

char _license[] SEC("license") = "GPL";
""",
        })

    # --- Dev (idx 13..16): 802.1Q VLAN demux router (XDP_TX / XDP_PASS) ---
    vlan_dev_list = [
        ("vlan_10", 10, "route frames carrying 802.1Q VLAN tag 10 out interface via XDP_TX"),
        ("vlan_20", 20, "forward frames carrying 802.1Q VLAN tag 20 out interface via XDP_TX"),
        ("vlan_30", 30, "transmit virtual network frames with VLAN tag 30 via XDP_TX"),
        ("vlan_40", 40, "direct isolated segment frames marked with VLAN 40 to XDP_TX"),
    ]

    for sub_idx, (name, vid, desc) in enumerate(vlan_dev_list, start=1):
        tid = f"rl_v2_dev_nrf_l2_{sub_idx:02d}"
        fam = f"dev_nrf_l2_{name}"
        tasks.append({
            "task_id": tid,
            "application_category": "network_routing_forwarding",
            "difficulty": "level_2",
            "task_family": fam,
            "template_family": "xdp_vlan_demux_router",
            "semantic_signature": f"nrf_l2_vlan_{vid}",
            "split": "dev",
            "learning_mode": "synthesis",
            "instruction": f"Write an XDP program that demuxes VLAN traffic: {desc}. Pass all other packets with XDP_PASS.",
            "requirements": [
                "Verify Ethernet and 802.1Q header bounds against data_end",
                f"Check if eth->h_proto == ETH_P_8021Q and vlan_id == {vid}",
                "Return XDP_TX on matching VLAN ID",
                "Return XDP_PASS for other VLAN IDs, untagged packets, and non-IP traffic",
                "SEC(\"xdp\") entry point and GPL license declaration",
            ],
            "tests": [
                {"name": f"tx_vlan_{vid}", "description": f"VLAN {vid} transmitted", "packet_hex": make_eth(vlan=vid, payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_TX", "weight": 1.0},
                {"name": "pass_other_vlan", "description": "VLAN 999 passed", "packet_hex": make_eth(vlan=999, payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
                {"name": "pass_untagged", "description": "Untagged passed", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
                {"name": "pass_arp", "description": "ARP passed", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
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
int xdp_vlan_demux_{sub_idx}(struct xdp_md *ctx) {{
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
        if (vlan_id == {vid})
            return XDP_TX;
    }}

    return XDP_PASS;
}}

char _license[] SEC("license") = "GPL";
""",
        })

    # --- Confirmation (idx 17..21): 2-way Equal-Cost Multi-Path (ECMP) hash router (XDP_TX) ---
    conf_l2_descs = [
        ("ecmp_conf01", "balance traffic across dual uplinks using 2-way XOR hash on source and destination IP"),
        ("ecmp_conf02", "perform ECMP route distribution across Gateway A and Gateway B using LSB of address XOR"),
        ("ecmp_conf03", "split egress flows between two gateway MAC addresses using 2-tuple IP hash parity"),
        ("ecmp_conf04", "route packets evenly between redundant gateways based on least significant bit of address XOR"),
        ("ecmp_conf05", "execute dual-path gateway balancing by directing even hashes to Gateway A and odd to Gateway B"),
    ]

    for sub_idx, (name, desc) in enumerate(conf_l2_descs, start=1):
        tid = f"rl_v2_conf_nrf_l2_{sub_idx:02d}"
        fam = f"conf_nrf_l2_{name}"
        tasks.append({
            "task_id": tid,
            "application_category": "network_routing_forwarding",
            "difficulty": "level_2",
            "task_family": fam,
            "template_family": "xdp_ecmp_router",
            "semantic_signature": f"nrf_l2_ecmp_{sub_idx}",
            "split": "confirmation",
            "learning_mode": "synthesis",
            "instruction": f"Write an XDP program that must {desc}. Forward all other traffic with XDP_PASS.",
            "requirements": [
                "Verify Ethernet and IPv4 header bounds against data_end",
                "Confirm eth->h_proto == ETH_P_IP",
                "Compute 2-tuple XOR hash: (ip->saddr ^ ip->daddr)",
                "If LSB is 0, set eth->h_dest to 52:54:00:00:00:0a; if LSB is 1, set eth->h_dest to 52:54:00:00:00:0b",
                "Return XDP_TX for routed packets, XDP_PASS for non-IP traffic",
                "SEC(\"xdp\") entry point and GPL license declaration",
            ],
            "tests": [
                {"name": "tx_gw_a", "description": "Even hash routed to Gateway A", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.10", dst_ip="192.168.1.20", proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_TX", "weight": 1.0},
                {"name": "tx_gw_b", "description": "Odd hash routed to Gateway B", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.10", dst_ip="192.168.1.21", proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_TX", "weight": 1.0},
                {"name": "pass_arp", "description": "ARP passes unmodified", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
            ],
            "solution_c": f"""#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

SEC("xdp")
int xdp_ecmp_{sub_idx}(struct xdp_md *ctx) {{
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

    __u32 hash = ip->saddr ^ ip->daddr;
    eth->h_dest[0] = 0x52;
    eth->h_dest[1] = 0x54;
    eth->h_dest[2] = 0x00;
    eth->h_dest[3] = 0x00;
    eth->h_dest[4] = 0x00;

    if ((hash & 1) == 0)
        eth->h_dest[5] = 0x0a;
    else
        eth->h_dest[5] = 0x0b;

    return XDP_TX;
}}

char _license[] SEC("license") = "GPL";
""",
        })

    return tasks


def build_nrf_l3_tasks() -> List[Dict[str, Any]]:
    tasks = []

    # --- Canary (idx 0): Basic LPM trie IPv4 route table ---
    canary_task = {
        "task_id": "rl_v2_canary_nrf_l3_01",
        "application_category": "network_routing_forwarding",
        "difficulty": "level_3",
        "task_family": "canary_nrf_l3_lpm_router",
        "template_family": "xdp_lpm_router",
        "semantic_signature": "nrf_l3_lpm_canary",
        "split": "canary",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that performs IPv4 route lookups using BPF_MAP_TYPE_LPM_TRIE map 'route_table_canary'. On route match, transmit with XDP_TX; on route miss, forward with XDP_PASS.",
        "requirements": [
            "Define BPF_MAP_TYPE_LPM_TRIE map 'route_table_canary' with BPF_F_NO_PREALLOC",
            "Define LPM key struct with __u32 prefixlen and __u32 data members",
            "Verify Ethernet and IPv4 header bounds against data_end",
            "Perform bpf_map_lookup_elem with prefixlen=32 on ip->daddr",
            "Return XDP_TX on route match, XDP_PASS on route miss or non-IP",
            "SEC(\"xdp\") entry point and GPL license declaration",
        ],
        "tests": [
            {"name": "pass_unrouted", "description": "Unrouted IP passes", "packet_hex": make_eth(payload=make_ipv4(dst_ip="192.168.1.50", proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
            {"name": "pass_arp", "description": "ARP passes", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
        ],
        "solution_c": """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

struct lpm_key {
    __u32 prefixlen;
    __u32 data;
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_key);
    __type(value, __u32);
    __uint(max_entries, 256);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} route_table_canary SEC(".maps");

SEC("xdp")
int xdp_route_canary(struct xdp_md *ctx) {
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

    struct lpm_key key;
    key.prefixlen = 32;
    key.data = ip->daddr;

    __u32 *route = bpf_map_lookup_elem(&route_table_canary, &key);
    if (route)
        return XDP_TX;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
""",
    }
    tasks.append(canary_task)

    # --- Train (idx 1..12): LPM Trie IPv4 prefix routing with next-hop gateway MAC rewrite ---
    train_l3_descs = [
        ("route_gw_01", "consult prefix routing table 'routing_trie_201' to route traffic toward next-hop gateway"),
        ("route_gw_02", "query LPM routing trie 'routing_trie_202' to update next-hop MAC and forward"),
        ("route_gw_03", "evaluate destination addresses against LPM trie 'routing_trie_203' for gateway forwarding"),
        ("route_gw_04", "perform prefix lookup in routing trie 'routing_trie_204' and rewrite gateway destination MAC"),
        ("route_gw_05", "inspect destination subnet in 'routing_trie_205' to apply next-hop Layer 2 rewriting"),
        ("route_gw_06", "forward IPv4 datagrams using longest prefix match in 'routing_trie_206' to target gateway"),
        ("route_gw_07", "interrogate routing trie 'routing_trie_207' and rewrite destination hardware address on hit"),
        ("route_gw_08", "determine egress gateway MAC by consulting LPM route table 'routing_trie_208'"),
        ("route_gw_09", "dispatch matching traffic to next-hop gateway registered in LPM trie 'routing_trie_209'"),
        ("route_gw_10", "lookup route entry in 'routing_trie_210' and update Ethernet destination address"),
        ("route_gw_11", "match destination prefix in 'routing_trie_211' and forward out to specified gateway MAC"),
        ("route_gw_12", "execute routing table lookup in trie 'routing_trie_212' and emit via XDP_TX"),
    ]

    for sub_idx, (name, desc) in enumerate(train_l3_descs, start=1):
        map_id = 200 + sub_idx
        tid = f"rl_v2_train_nrf_l3_{sub_idx:02d}"
        fam = f"train_nrf_l3_{name}"
        tasks.append({
            "task_id": tid,
            "application_category": "network_routing_forwarding",
            "difficulty": "level_3",
            "task_family": fam,
            "template_family": "xdp_lpm_mac_router",
            "semantic_signature": f"nrf_l3_lpm_route_{map_id}",
            "split": "train",
            "learning_mode": "synthesis",
            "instruction": f"Write an XDP program that must {desc}. On route hit, rewrite destination MAC to next-hop gateway and return XDP_TX; on route miss, return XDP_PASS.",
            "requirements": [
                f"Define BPF_MAP_TYPE_LPM_TRIE map 'routing_trie_{map_id}' with BPF_F_NO_PREALLOC",
                "Define LPM key struct with __u32 prefixlen and __u32 data members",
                "Verify Ethernet and IPv4 header bounds against data_end",
                "Perform bpf_map_lookup_elem on ip->daddr with prefixlen=32",
                "On route match, update eth->h_dest with next-hop MAC and return XDP_TX",
                "On route miss or non-IP, return XDP_PASS",
                "SEC(\"xdp\") entry point and GPL license declaration",
            ],
            "tests": [
                {"name": "pass_unmatched", "description": "Unmatched IP passes default", "packet_hex": make_eth(payload=make_ipv4(dst_ip="192.168.1.50", proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
                {"name": "pass_arp", "description": "ARP passes unmodified", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
            ],
            "solution_c": f"""#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

struct lpm_key_{map_id} {{
    __u32 prefixlen;
    __u32 data;
}};

struct route_entry_{map_id} {{
    unsigned char next_hop_mac[ETH_ALEN];
}};

struct {{
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_key_{map_id});
    __type(value, struct route_entry_{map_id});
    __uint(max_entries, 256);
    __uint(map_flags, BPF_F_NO_PREALLOC);
}} routing_trie_{map_id} SEC(".maps");

SEC("xdp")
int xdp_route_lpm_{map_id}(struct xdp_md *ctx) {{
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

    struct lpm_key_{map_id} key;
    key.prefixlen = 32;
    key.data = ip->daddr;

    struct route_entry_{map_id} *route = bpf_map_lookup_elem(&routing_trie_{map_id}, &key);
    if (route) {{
        for (int i = 0; i < ETH_ALEN; i++)
            eth->h_dest[i] = route->next_hop_mac[i];
        return XDP_TX;
    }}

    return XDP_PASS;
}}

char _license[] SEC("license") = "GPL";
""",
        })

    # --- Dev (idx 13..16): LPM Trie routing with fallback default gateway ---
    dev_l3_descs = [
        ("fallback_dev01", "route IPv4 traffic using 'dev_route_table_01' and fallback to default gateway on miss"),
        ("fallback_dev02", "lookup staging routes in 'dev_route_table_02' directing misses to upstream default gateway"),
        ("fallback_dev03", "query test prefix table 'dev_route_table_03' forwarding unindexed destinations to default router"),
        ("fallback_dev04", "dispatch packets via 'dev_route_table_04' rewriting to default gateway MAC when no route matches"),
    ]

    for sub_idx, (name, desc) in enumerate(dev_l3_descs, start=1):
        tid = f"rl_v2_dev_nrf_l3_{sub_idx:02d}"
        fam = f"dev_nrf_l3_{name}"
        tasks.append({
            "task_id": tid,
            "application_category": "network_routing_forwarding",
            "difficulty": "level_3",
            "task_family": fam,
            "template_family": "xdp_lpm_fallback_router",
            "semantic_signature": f"nrf_l3_fallback_{sub_idx}",
            "split": "dev",
            "learning_mode": "synthesis",
            "instruction": f"Write an XDP program that must {desc}. On route hit, rewrite destination MAC to route gateway and XDP_TX; on route miss, rewrite destination MAC to default gateway 52:54:00:00:00:fe and forward with XDP_TX.",
            "requirements": [
                f"Define BPF_MAP_TYPE_LPM_TRIE map 'dev_route_table_{sub_idx}' with BPF_F_NO_PREALLOC",
                "Define LPM key struct with __u32 prefixlen and __u32 data members",
                "Verify Ethernet and IPv4 header bounds against data_end",
                f"Lookup ip->daddr in dev_route_table_{sub_idx}",
                "On hit rewrite destination MAC to route MAC; on miss rewrite to default gateway 52:54:00:00:00:fe",
                "Return XDP_TX for all routed IPv4 packets, XDP_PASS for non-IP",
                "SEC(\"xdp\") entry point and GPL license declaration",
            ],
            "tests": [
                {"name": "tx_default_gw", "description": "Unmatched routed to default gateway", "packet_hex": make_eth(payload=make_ipv4(dst_ip="192.168.99.1", proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_TX", "weight": 1.0},
                {"name": "pass_arp", "description": "ARP passes unmodified", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
            ],
            "solution_c": f"""#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

struct lpm_key_{sub_idx} {{
    __u32 prefixlen;
    __u32 data;
}};

struct {{
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_key_{sub_idx});
    __type(value, unsigned char[6]);
    __uint(max_entries, 256);
    __uint(map_flags, BPF_F_NO_PREALLOC);
}} dev_route_table_{sub_idx} SEC(".maps");

SEC("xdp")
int xdp_route_fallback_{sub_idx}(struct xdp_md *ctx) {{
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

    struct lpm_key_{sub_idx} key;
    key.prefixlen = 32;
    key.data = ip->daddr;

    unsigned char (*mac)[6] = bpf_map_lookup_elem(&dev_route_table_{sub_idx}, &key);
    if (mac) {{
        for (int i = 0; i < 6; i++)
            eth->h_dest[i] = (*mac)[i];
    }} else {{
        eth->h_dest[0] = 0x52;
        eth->h_dest[1] = 0x54;
        eth->h_dest[2] = 0x00;
        eth->h_dest[3] = 0x00;
        eth->h_dest[4] = 0x00;
        eth->h_dest[5] = 0xfe;
    }}

    return XDP_TX;
}}

char _license[] SEC("license") = "GPL";
""",
        })

    # --- Confirmation (idx 17..21): LPM Trie routing with bpf_redirect interface forwarding ---
    conf_l3_descs = [
        ("redirect_conf01", "redirect matching IPv4 packets to egress interfaces registered in 'redirect_route_01'"),
        ("redirect_conf02", "perform port redirection via bpf_redirect using interface indices from 'redirect_route_02'"),
        ("redirect_conf03", "dispatch verified traffic across network interfaces looked up in 'redirect_route_03'"),
        ("redirect_conf04", "forward packets to target port interfaces queried from trie 'redirect_route_04'"),
        ("redirect_conf05", "execute interface redirection for matched destination subnets via 'redirect_route_05'"),
    ]

    for sub_idx, (name, desc) in enumerate(conf_l3_descs, start=1):
        tid = f"rl_v2_conf_nrf_l3_{sub_idx:02d}"
        fam = f"conf_nrf_l3_{name}"
        tasks.append({
            "task_id": tid,
            "application_category": "network_routing_forwarding",
            "difficulty": "level_3",
            "task_family": fam,
            "template_family": "xdp_lpm_redirect_router",
            "semantic_signature": f"nrf_l3_redirect_{sub_idx}",
            "split": "confirmation",
            "learning_mode": "synthesis",
            "instruction": f"Write an XDP program that must {desc}. On route match, lookup returns target interface index ifindex; forward packet with bpf_redirect(ifindex, 0). On route miss, return XDP_PASS.",
            "requirements": [
                f"Define BPF_MAP_TYPE_LPM_TRIE map 'redirect_route_{sub_idx}' with BPF_F_NO_PREALLOC and __u32 ifindex value",
                "Define LPM key struct with __u32 prefixlen and __u32 data members",
                "Verify Ethernet and IPv4 header bounds against data_end",
                f"Lookup ip->daddr in redirect_route_{sub_idx} with prefixlen=32",
                "On route hit invoke bpf_redirect(*ifindex, 0); on route miss return XDP_PASS",
                "SEC(\"xdp\") entry point and GPL license declaration",
            ],
            "tests": [
                {"name": "pass_unrouted", "description": "Unrouted IP passes", "packet_hex": make_eth(payload=make_ipv4(dst_ip="10.0.0.1", proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
                {"name": "pass_arp", "description": "ARP passes", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
            ],
            "solution_c": f"""#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

struct lpm_key_{sub_idx} {{
    __u32 prefixlen;
    __u32 data;
}};

struct {{
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_key_{sub_idx});
    __type(value, __u32);
    __uint(max_entries, 256);
    __uint(map_flags, BPF_F_NO_PREALLOC);
}} redirect_route_{sub_idx} SEC(".maps");

SEC("xdp")
int xdp_redirect_route_{sub_idx}(struct xdp_md *ctx) {{
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

    struct lpm_key_{sub_idx} key;
    key.prefixlen = 32;
    key.data = ip->daddr;

    __u32 *ifindex = bpf_map_lookup_elem(&redirect_route_{sub_idx}, &key);
    if (ifindex)
        return bpf_redirect(*ifindex, 0);

    return XDP_PASS;
}}

char _license[] SEC("license") = "GPL";
""",
        })

    return tasks
