"""
BPF-Guardian RLVR Phase 2: Packet Filtering & Security (PFS) Task Definitions.
Contains 66 distinct, verifier-safe tasks with strict task-family disjointness across splits:
- Level 1 (22 tasks):
    * Canary (1): ICMP Echo Request drop (type 8)
    * Train (12): TCP destination port drop (ports 20, 21, 23, 25, 80, 110, 143, 443, 3306, 5432, 6379, 11211)
    * Dev (4): UDP destination port drop (ports 69, 123, 161, 514)
    * Confirmation (5): IP Protocol number drop (protocols 47, 50, 89, 112, 132)
- Level 2 (22 tasks):
    * Canary (1): Truncated UDP packet drop (udp->len < 8)
    * Train (12): TCP destination port range drop (dport in [min, max])
    * Dev (4): IPv4 header attribute drops (TTL <= 5, IHL > 5, frame < 40, fragments)
    * Confirmation (5): TCP flag combination drops (Xmas, Null, SYN-FIN, window==0, RST-ACK)
- Level 3 (22 tasks):
    * Canary (1): Array map IP filter
    * Train (12): LPM Trie IPv4 CIDR Blocklist
    * Dev (4): Dynamic LRU Hash Quarantine & Connection Limits
    * Confirmation (5): Stateful Destination Port Quotas & IP Pair Limiter
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


def build_pfs_l1_tasks() -> List[Dict[str, Any]]:
    tasks = []

    # --- Canary (idx 0): ICMP Echo Request drop ---
    canary_task = {
        "task_id": "rl_v2_canary_pfs_l1_01",
        "application_category": "packet_filtering_security",
        "difficulty": "level_1",
        "task_family": "canary_pfs_l1_icmp_echo",
        "template_family": "xdp_icmp_filter",
        "semantic_signature": "pfs_l1_icmp_echo_req",
        "split": "canary",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that inspects network traffic and drops incoming ICMP echo request packets (type 8). Forward all other packets with XDP_PASS.",
        "requirements": [
            "Verify Ethernet header bounds against data_end",
            "Verify IPv4 header bounds and confirm protocol is IPPROTO_ICMP",
            "Verify ICMP header bounds against data_end",
            "Drop packet with XDP_DROP if icmp->type equals 8",
            "Return XDP_PASS for non-matching or malformed traffic",
            "SEC(\"xdp\") entry point and GPL license declaration",
        ],
        "tests": [
            {"name": "drop_echo_req", "description": "ICMP echo request must be dropped", "packet_hex": make_eth(payload=make_ipv4(proto=1, payload=make_icmp(icmp_type=8, icmp_code=0))).hex(), "expected_action": "XDP_DROP", "weight": 1.0},
            {"name": "pass_echo_reply", "description": "ICMP echo reply must pass", "packet_hex": make_eth(payload=make_ipv4(proto=1, payload=make_icmp(icmp_type=0, icmp_code=0))).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
            {"name": "pass_tcp", "description": "Normal TCP packet must pass", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(dst_port=80))).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
            {"name": "pass_arp", "description": "Non-IP ARP frame must pass", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
            {"name": "pass_truncated", "description": "Truncated header must pass safely", "packet_hex": "525400123456525400654321080045000010", "expected_action": "XDP_PASS", "weight": 1.0},
        ],
        "solution_c": """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>

struct icmphdr {
    __u8 type;
    __u8 code;
    __sum16 checksum;
    union {
        struct {
            __be16 id;
            __be16 sequence;
        } echo;
        __be32 gateway;
        struct {
            __be16 __unused;
            __be16 mtu;
        } frag;
    } un;
};

SEC("xdp")
int xdp_filter_icmp_echo(struct xdp_md *ctx) {
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

    if (icmp->type == 8)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
""",
    }
    tasks.append(canary_task)

    # --- Train (idx 1..12): TCP destination port drops ---
    tcp_train_ports = [
        ("ftp_data", 20, "unencrypted FTP active data channel connections on TCP port 20"),
        ("ftp_ctrl", 21, "interactive FTP control channel commands on TCP port 21"),
        ("telnet", 23, "insecure cleartext Telnet remote management sessions on TCP port 23"),
        ("smtp", 25, "unauthenticated outbound SMTP mail relay traffic arriving on TCP port 25"),
        ("http", 80, "unencrypted standard HTTP web requests arriving on TCP port 80"),
        ("pop3", 110, "legacy POP3 mailbox retrieval queries on TCP port 110"),
        ("imap", 143, "cleartext IMAP email synchronization connections on TCP port 143"),
        ("https", 443, "inbound TLS web sessions targeted at restricted HTTPS port 443"),
        ("mysql", 3306, "remote database management connection attempts to MySQL on TCP port 3306"),
        ("postgres", 5432, "external SQL query sessions destined for PostgreSQL service on TCP port 5432"),
        ("redis", 6379, "unauthenticated cache command packets sent to Redis server on TCP port 6379"),
        ("memcached", 11211, "insecure in-memory caching requests targeted at Memcached on TCP port 11211"),
    ]

    for sub_idx, (name, port, desc) in enumerate(tcp_train_ports, start=1):
        tid = f"rl_v2_train_pfs_l1_{sub_idx:02d}"
        fam = f"train_pfs_l1_{name}"
        tasks.append({
            "task_id": tid,
            "application_category": "packet_filtering_security",
            "difficulty": "level_1",
            "task_family": fam,
            "template_family": "xdp_tcp_port_filter",
            "semantic_signature": f"pfs_l1_tcp_{name}_{port}",
            "split": "train",
            "learning_mode": "synthesis",
            "instruction": f"Write an XDP program that inspects network traffic and drops {desc}. Forward all other packets.",
            "requirements": [
                "Verify Ethernet header bounds against data_end",
                "Verify IPv4 header bounds and confirm protocol is IPPROTO_TCP",
                "Safely calculate and validate variable IPv4 header length (ip->ihl * 4)",
                "Verify TCP header bounds against data_end",
                f"Drop packet with XDP_DROP if destination port equals {port}",
                "Return XDP_PASS for non-matching or malformed traffic",
                "SEC(\"xdp\") entry point and GPL license declaration",
            ],
            "tests": [
                {"name": f"drop_{name}", "description": f"TCP port {port} dropped", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(dst_port=port, flags=0x02))).hex(), "expected_action": "XDP_DROP", "weight": 1.0},
                {"name": "pass_unrelated", "description": "Other TCP port passes", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(dst_port=9999, flags=0x02))).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
                {"name": "drop_with_options", "description": "TCP with IP options dropped", "packet_hex": make_eth(payload=make_ipv4(ihl=6, proto=6, options=b"\x00\x00\x00\x00", payload=make_tcp(dst_port=port, flags=0x02))).hex(), "expected_action": "XDP_DROP", "weight": 1.0},
                {"name": "pass_arp", "description": "ARP frame passes", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
                {"name": "pass_truncated", "description": "Truncated header passes", "packet_hex": "525400123456525400654321080045000010", "expected_action": "XDP_PASS", "weight": 1.0},
            ],
            "solution_c": f"""#include <linux/bpf.h>
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
""",
        })

    # --- Dev (idx 13..16): UDP destination port drops ---
    udp_dev_ports = [
        ("tftp", 69, "unauthorized TFTP bootstrap file transfers arriving on UDP port 69"),
        ("ntp", 123, "unauthenticated Network Time Protocol synchronization requests on UDP port 123"),
        ("snmp", 161, "unauthorized SNMP management agent queries arriving over UDP port 161"),
        ("syslog", 514, "unencrypted remote system log notification datagrams sent on UDP port 514"),
    ]

    for sub_idx, (name, port, desc) in enumerate(udp_dev_ports, start=1):
        tid = f"rl_v2_dev_pfs_l1_{sub_idx:02d}"
        fam = f"dev_pfs_l1_{name}"
        tasks.append({
            "task_id": tid,
            "application_category": "packet_filtering_security",
            "difficulty": "level_1",
            "task_family": fam,
            "template_family": "xdp_udp_port_filter",
            "semantic_signature": f"pfs_l1_udp_{name}_{port}",
            "split": "dev",
            "learning_mode": "synthesis",
            "instruction": f"Write an XDP program that monitors UDP traffic and drops {desc}. Pass all other network traffic.",
            "requirements": [
                "Verify Ethernet header bounds against data_end",
                "Verify IPv4 header bounds and confirm protocol is IPPROTO_UDP",
                "Safely validate variable IPv4 header length (ip->ihl * 4)",
                "Verify UDP header bounds against data_end",
                f"Drop packet with XDP_DROP if UDP destination port equals {port}",
                "Return XDP_PASS for non-matching or malformed traffic",
                "SEC(\"xdp\") entry point and GPL license declaration",
            ],
            "tests": [
                {"name": f"drop_{name}", "description": f"UDP port {port} dropped", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=port))).hex(), "expected_action": "XDP_DROP", "weight": 1.0},
                {"name": "pass_unrelated_udp", "description": "Other UDP port passes", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=9999))).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
                {"name": "pass_tcp", "description": "TCP traffic passes", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(dst_port=port))).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
                {"name": "pass_arp", "description": "ARP frame passes", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
                {"name": "pass_truncated", "description": "Truncated header passes", "packet_hex": "525400123456525400654321080045000010", "expected_action": "XDP_PASS", "weight": 1.0},
            ],
            "solution_c": f"""#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>

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
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    int ip_len = ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip_len;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    if (udp->dest == bpf_htons({port}))
        return XDP_DROP;

    return XDP_PASS;
}}

char _license[] SEC("license") = "GPL";
""",
        })

    # --- Confirmation (idx 17..21): IP Protocol number drops ---
    proto_conf_list = [
        ("gre", 47, "Generic Routing Encapsulation GRE tunnel datagrams matching IPv4 protocol 47"),
        ("esp", 50, "Encapsulating Security Payload IPsec transport frames matching IPv4 protocol 50"),
        ("ospf", 89, "Open Shortest Path First routing exchange packets matching IPv4 protocol 89"),
        ("vrrp", 112, "Virtual Router Redundancy Protocol advertisement multicasts matching IPv4 protocol 112"),
        ("sctp", 132, "Stream Control Transmission Protocol multihomed traffic matching IPv4 protocol 132"),
    ]

    for sub_idx, (name, proto_num, desc) in enumerate(proto_conf_list, start=1):
        tid = f"rl_v2_conf_pfs_l1_{sub_idx:02d}"
        fam = f"conf_pfs_l1_{name}"
        tasks.append({
            "task_id": tid,
            "application_category": "packet_filtering_security",
            "difficulty": "level_1",
            "task_family": fam,
            "template_family": "xdp_ip_protocol_filter",
            "semantic_signature": f"pfs_l1_proto_{name}_{proto_num}",
            "split": "confirmation",
            "learning_mode": "synthesis",
            "instruction": f"Write an XDP program that inspects network layer packets and drops {desc}. Forward all other packets.",
            "requirements": [
                "Verify Ethernet header bounds against data_end",
                "Verify IPv4 header bounds and inspect ip->protocol",
                f"Drop packet with XDP_DROP if ip->protocol equals {proto_num}",
                "Return XDP_PASS for non-matching protocols or malformed frames",
                "SEC(\"xdp\") entry point and GPL license declaration",
            ],
            "tests": [
                {"name": f"drop_{name}", "description": f"Protocol {proto_num} dropped", "packet_hex": make_eth(payload=make_ipv4(proto=proto_num, payload=b"\xaa\xbb\xcc\xdd\xee\xff\x11\x22")).hex(), "expected_action": "XDP_DROP", "weight": 1.0},
                {"name": "pass_tcp", "description": "Standard TCP passes", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(dst_port=80))).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
                {"name": "pass_udp", "description": "Standard UDP passes", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=53))).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
                {"name": "pass_arp", "description": "Non-IP ARP passes", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
                {"name": "pass_truncated", "description": "Truncated header passes", "packet_hex": "525400123456525400654321080045000010", "expected_action": "XDP_PASS", "weight": 1.0},
            ],
            "solution_c": f"""#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

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

    if (ip->protocol == {proto_num})
        return XDP_DROP;

    return XDP_PASS;
}}

char _license[] SEC("license") = "GPL";
""",
        })

    return tasks


def build_pfs_l2_tasks() -> List[Dict[str, Any]]:
    tasks = []

    # --- Canary (idx 0): Truncated UDP packet drop ---
    canary_task = {
        "task_id": "rl_v2_canary_pfs_l2_01",
        "application_category": "packet_filtering_security",
        "difficulty": "level_2",
        "task_family": "canary_pfs_l2_udp_length_check",
        "template_family": "xdp_udp_boundary_filter",
        "semantic_signature": "pfs_l2_udp_min_len",
        "split": "canary",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that inspects incoming UDP datagrams and drops corrupted packets where UDP header length field is less than 8 bytes. Forward all other traffic with XDP_PASS.",
        "requirements": [
            "Verify Ethernet and IPv4 header bounds against data_end",
            "Confirm IPv4 protocol is IPPROTO_UDP and calculate IPv4 header length",
            "Verify UDP header bounds against data_end",
            "Drop packet with XDP_DROP if bpf_ntohs(udp->len) < 8",
            "Return XDP_PASS for valid UDP packets, other protocols, and malformed frames",
            "SEC(\"xdp\") entry point and GPL license declaration",
        ],
        "tests": [
            {"name": "drop_corrupt_udp", "description": "UDP with declared length 4 dropped", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=b"\x12\x34\x00\x35\x00\x04\x00\x00")).hex(), "expected_action": "XDP_DROP", "weight": 1.0},
            {"name": "pass_valid_udp", "description": "Valid UDP packet passes", "packet_hex": make_eth(payload=make_ipv4(proto=17, payload=make_udp(dst_port=53))).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
            {"name": "pass_tcp", "description": "TCP packet passes", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(dst_port=80))).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
            {"name": "pass_arp", "description": "ARP frame passes", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
        ],
        "solution_c": """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>

SEC("xdp")
int xdp_filter_udp_len(struct xdp_md *ctx) {
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

    if (bpf_ntohs(udp->len) < 8)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
""",
    }
    tasks.append(canary_task)

    # --- Train (idx 1..12): TCP destination port ranges ---
    port_ranges = [
        ("range_5000", 5000, 5050, "TCP destination port range between 5000 and 5050 inclusive"),
        ("range_6000", 6000, 6050, "unregistered private service port range between 6000 and 6050 inclusive"),
        ("range_7000", 7000, 7050, "diagnostic socket port range between 7000 and 7050 inclusive"),
        ("range_8000", 8000, 8050, "alternative HTTP proxy development ports between 8000 and 8050 inclusive"),
        ("range_9000", 9000, 9050, "storage cluster internal ports between 9000 and 9050 inclusive"),
        ("range_10000", 10000, 10050, "high-range ephemeral test ports between 10000 and 10050 inclusive"),
        ("range_11000", 11000, 11050, "distributed database inter-node ports between 11000 and 11050 inclusive"),
        ("range_12000", 12000, 12050, "application gateway proxy ports between 12000 and 12050 inclusive"),
        ("range_13000", 13000, 13050, "streaming ingestion ports between 13000 and 13050 inclusive"),
        ("range_14000", 14000, 14050, "analytics telemetry ingestion ports between 14000 and 14050 inclusive"),
        ("range_15000", 15000, 15050, "microservice mesh control ports between 15000 and 15050 inclusive"),
        ("range_16000", 16000, 16050, "experimental staging RPC ports between 16000 and 16050 inclusive"),
    ]

    for sub_idx, (name, min_p, max_p, desc) in enumerate(port_ranges, start=1):
        tid = f"rl_v2_train_pfs_l2_{sub_idx:02d}"
        fam = f"train_pfs_l2_{name}"
        tasks.append({
            "task_id": tid,
            "application_category": "packet_filtering_security",
            "difficulty": "level_2",
            "task_family": fam,
            "template_family": "xdp_port_range_filter",
            "semantic_signature": f"pfs_l2_range_{min_p}_{max_p}",
            "split": "train",
            "learning_mode": "synthesis",
            "instruction": f"Write an XDP program that inspects network traffic and drops incoming TCP packets targeting {desc}. Forward all other packets.",
            "requirements": [
                "Verify Ethernet header bounds against data_end",
                "Verify IPv4 header bounds and confirm protocol is IPPROTO_TCP",
                "Safely validate variable IPv4 header length (ip->ihl * 4)",
                "Verify TCP header bounds against data_end",
                f"Drop packet with XDP_DROP if destination port satisfies dport >= {min_p} and dport <= {max_p}",
                "Return XDP_PASS for non-matching or malformed traffic",
                "SEC(\"xdp\") entry point and GPL license declaration",
            ],
            "tests": [
                {"name": "drop_min", "description": f"Port {min_p} dropped", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(dst_port=min_p, flags=0x02))).hex(), "expected_action": "XDP_DROP", "weight": 1.0},
                {"name": "drop_max", "description": f"Port {max_p} dropped", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(dst_port=max_p, flags=0x02))).hex(), "expected_action": "XDP_DROP", "weight": 1.0},
                {"name": "pass_below", "description": f"Port {min_p - 1} passes", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(dst_port=min_p - 1, flags=0x02))).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
                {"name": "pass_above", "description": f"Port {max_p + 1} passes", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(dst_port=max_p + 1, flags=0x02))).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
                {"name": "pass_arp", "description": "ARP frame passes", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
            ],
            "solution_c": f"""#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>

SEC("xdp")
int xdp_range_{name}(struct xdp_md *ctx) {{
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

    __u16 dport = bpf_ntohs(tcp->dest);
    if (dport >= {min_p} && dport <= {max_p})
        return XDP_DROP;

    return XDP_PASS;
}}

char _license[] SEC("license") = "GPL";
""",
        })

    # --- Dev (idx 13..16): IPv4 Header Attribute Filters ---
    dev_boundary_configs = [
        (
            "ttl_boundary",
            "discard IPv4 packets with hop count or TTL less than or equal to 5",
            [
                "Verify Ethernet header bounds against data_end",
                "Verify IPv4 header bounds against data_end",
                "Drop packet with XDP_DROP if ip->ttl <= 5",
                "Return XDP_PASS for TTL > 5 or non-IP frames",
                "SEC(\"xdp\") entry point and GPL license declaration",
            ],
            [
                {"name": "drop_ttl_5", "description": "TTL 5 dropped", "packet_hex": make_eth(payload=make_ipv4(ttl=5, proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_DROP", "weight": 1.0},
                {"name": "pass_ttl_64", "description": "TTL 64 passes", "packet_hex": make_eth(payload=make_ipv4(ttl=64, proto=1, payload=make_icmp())).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
                {"name": "pass_arp", "description": "ARP passes", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
            ],
            """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

SEC("xdp")
int xdp_filter_ttl(struct xdp_md *ctx) {
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

    if (ip->ttl <= 5)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
""",
        ),
        (
            "ip_options_drop",
            "drop IPv4 datagrams carrying IP options where internet header length IHL exceeds 5",
            [
                "Verify Ethernet header bounds against data_end",
                "Verify IPv4 header bounds against data_end",
                "Drop packet with XDP_DROP if ip->ihl > 5",
                "Return XDP_PASS for standard IHL 5 or non-IP traffic",
                "SEC(\"xdp\") entry point and GPL license declaration",
            ],
            [
                {"name": "drop_ihl_6", "description": "IHL 6 with options dropped", "packet_hex": make_eth(payload=make_ipv4(ihl=6, options=b"\x00\x00\x00\x00", proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_DROP", "weight": 1.0},
                {"name": "pass_ihl_5", "description": "Standard IHL 5 passes", "packet_hex": make_eth(payload=make_ipv4(ihl=5, proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
                {"name": "pass_arp", "description": "ARP passes", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
            ],
            """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

SEC("xdp")
int xdp_filter_ip_options(struct xdp_md *ctx) {
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

    if (ip->ihl > 5)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
""",
        ),
        (
            "runt_frame_drop",
            "discard undersized runt frames where total packet wire length is strictly less than 40 bytes",
            [
                "Calculate total packet length from ctx->data and ctx->data_end",
                "Drop packet with XDP_DROP if length is strictly less than 40 bytes",
                "Return XDP_PASS for frames with length >= 40 bytes",
                "SEC(\"xdp\") entry point and GPL license declaration",
            ],
            [
                {"name": "drop_runt_28", "description": "28 byte runt dropped", "packet_hex": "52540012345652540065432108004500000e000000004000", "expected_action": "XDP_DROP", "weight": 1.0},
                {"name": "pass_normal_54", "description": "54 byte frame passes", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
            ],
            """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_filter_runt(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    long len = (long)data_end - (long)data;
    if (len < 40)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
""",
        ),
        (
            "ip_fragment_drop",
            "drop fragmented IPv4 datagrams where more fragments MF flag is set or fragment offset is non-zero",
            [
                "Verify Ethernet header bounds against data_end",
                "Verify IPv4 header bounds against data_end",
                "Check frag_off field for IP_MF flag (0x2000) or offset bits (0x1FFF)",
                "Drop packet with XDP_DROP if (bpf_ntohs(ip->frag_off) & 0x3FFF) != 0",
                "Return XDP_PASS for non-fragmented packets and non-IP traffic",
                "SEC(\"xdp\") entry point and GPL license declaration",
            ],
            [
                {"name": "drop_mf_set", "description": "MF fragment dropped", "packet_hex": make_eth(payload=make_ipv4(frag_off=0x2000, proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_DROP", "weight": 1.0},
                {"name": "pass_unfragmented", "description": "Unfragmented passes", "packet_hex": make_eth(payload=make_ipv4(frag_off=0, proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
                {"name": "pass_arp", "description": "ARP passes", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
            ],
            """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

SEC("xdp")
int xdp_filter_frag(struct xdp_md *ctx) {
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

    __u16 frag = bpf_ntohs(ip->frag_off);
    if (frag & 0x3FFF)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
""",
        ),
    ]

    for sub_idx, (name, desc, reqs, tests, sol_c) in enumerate(dev_boundary_configs, start=1):
        tid = f"rl_v2_dev_pfs_l2_{sub_idx:02d}"
        fam = f"dev_pfs_l2_{name}"
        tasks.append({
            "task_id": tid,
            "application_category": "packet_filtering_security",
            "difficulty": "level_2",
            "task_family": fam,
            "template_family": "xdp_ip_attribute_filter",
            "semantic_signature": f"pfs_l2_attr_{name}",
            "split": "dev",
            "learning_mode": "synthesis",
            "instruction": f"Write an XDP program that inspects network traffic and must {desc}. Forward all other packets with XDP_PASS.",
            "requirements": reqs,
            "tests": tests,
            "solution_c": sol_c,
        })

    # --- Confirmation (idx 17..21): TCP Flag combination filters ---
    conf_flag_configs = [
        (
            "tcp_xmas",
            "drop TCP Xmas scan probes where FIN, PSH, and URG flags are simultaneously asserted",
            [
                "Verify Ethernet header bounds against data_end",
                "Verify IPv4 header bounds and confirm protocol is IPPROTO_TCP",
                "Safely validate variable IPv4 header length (ip->ihl * 4)",
                "Verify TCP header bounds against data_end",
                "Drop packet with XDP_DROP if (tcp->fin && tcp->psh && tcp->urg)",
                "Return XDP_PASS for non-matching or malformed traffic",
                "SEC(\"xdp\") entry point and GPL license declaration",
            ],
            [
                {"name": "drop_xmas", "description": "Xmas scan FIN+PSH+URG dropped", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(flags=0x29))).hex(), "expected_action": "XDP_DROP", "weight": 1.0},
                {"name": "pass_syn", "description": "Normal SYN passes", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(flags=0x02))).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
                {"name": "pass_arp", "description": "ARP passes", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
            ],
            """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>

SEC("xdp")
int xdp_filter_xmas(struct xdp_md *ctx) {
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

    if (tcp->fin && tcp->psh && tcp->urg)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
""",
        ),
        (
            "tcp_null",
            "drop TCP Null scan packets where all control flags are clear (flags equal zero)",
            [
                "Verify Ethernet header bounds against data_end",
                "Verify IPv4 header bounds and confirm protocol is IPPROTO_TCP",
                "Safely validate variable IPv4 header length (ip->ihl * 4)",
                "Verify TCP header bounds against data_end",
                "Drop packet with XDP_DROP if TCP control flags byte is zero",
                "Return XDP_PASS for non-matching or malformed traffic",
                "SEC(\"xdp\") entry point and GPL license declaration",
            ],
            [
                {"name": "drop_null", "description": "Null scan flags 0 dropped", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(flags=0x00))).hex(), "expected_action": "XDP_DROP", "weight": 1.0},
                {"name": "pass_syn", "description": "Normal SYN passes", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(flags=0x02))).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
                {"name": "pass_arp", "description": "ARP passes", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
            ],
            """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>

SEC("xdp")
int xdp_filter_null(struct xdp_md *ctx) {
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

    __u8 *flags = (__u8 *)tcp + 13;
    if (*flags == 0)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
""",
        ),
        (
            "tcp_syn_fin",
            "block anomalous TCP packets asserting both SYN and FIN flags simultaneously",
            [
                "Verify Ethernet header bounds against data_end",
                "Verify IPv4 header bounds and confirm protocol is IPPROTO_TCP",
                "Safely validate variable IPv4 header length (ip->ihl * 4)",
                "Verify TCP header bounds against data_end",
                "Drop packet with XDP_DROP if (tcp->syn && tcp->fin)",
                "Return XDP_PASS for non-matching or malformed traffic",
                "SEC(\"xdp\") entry point and GPL license declaration",
            ],
            [
                {"name": "drop_syn_fin", "description": "SYN+FIN scan dropped", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(flags=0x03))).hex(), "expected_action": "XDP_DROP", "weight": 1.0},
                {"name": "pass_syn", "description": "SYN alone passes", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(flags=0x02))).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
                {"name": "pass_arp", "description": "ARP passes", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
            ],
            """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>

SEC("xdp")
int xdp_filter_syn_fin(struct xdp_md *ctx) {
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

    if (tcp->syn && tcp->fin)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
""",
        ),
        (
            "tcp_zero_window",
            "drop unsolicited TCP packets with advertised window size equal to zero",
            [
                "Verify Ethernet header bounds against data_end",
                "Verify IPv4 header bounds and confirm protocol is IPPROTO_TCP",
                "Safely validate variable IPv4 header length (ip->ihl * 4)",
                "Verify TCP header bounds against data_end",
                "Drop packet with XDP_DROP if tcp->window equals 0",
                "Return XDP_PASS for non-matching or malformed traffic",
                "SEC(\"xdp\") entry point and GPL license declaration",
            ],
            [
                {"name": "drop_zero_win", "description": "Zero window dropped", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(window=0))).hex(), "expected_action": "XDP_DROP", "weight": 1.0},
                {"name": "pass_win_64k", "description": "Window 65535 passes", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(window=65535))).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
                {"name": "pass_arp", "description": "ARP passes", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
            ],
            """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>

SEC("xdp")
int xdp_filter_zero_win(struct xdp_md *ctx) {
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

    if (tcp->window == 0)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
""",
        ),
        (
            "tcp_rst_ack",
            "drop TCP connection reset packets that simultaneously assert both the RST and ACK flags",
            [
                "Verify Ethernet header bounds against data_end",
                "Verify IPv4 header bounds and confirm protocol is IPPROTO_TCP",
                "Safely validate variable IPv4 header length (ip->ihl * 4)",
                "Verify TCP header bounds against data_end",
                "Drop packet with XDP_DROP if (tcp->rst && tcp->ack)",
                "Return XDP_PASS for non-matching or malformed traffic",
                "SEC(\"xdp\") entry point and GPL license declaration",
            ],
            [
                {"name": "drop_rst_ack", "description": "RST+ACK dropped", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(flags=0x14))).hex(), "expected_action": "XDP_DROP", "weight": 1.0},
                {"name": "pass_syn", "description": "SYN passes", "packet_hex": make_eth(payload=make_ipv4(proto=6, payload=make_tcp(flags=0x02))).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
                {"name": "pass_arp", "description": "ARP passes", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
            ],
            """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>

SEC("xdp")
int xdp_filter_rst_ack(struct xdp_md *ctx) {
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

    if (tcp->rst && tcp->ack)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
""",
        ),
    ]

    for sub_idx, (name, desc, reqs, tests, sol_c) in enumerate(conf_flag_configs, start=1):
        tid = f"rl_v2_conf_pfs_l2_{sub_idx:02d}"
        fam = f"conf_pfs_l2_{name}"
        tasks.append({
            "task_id": tid,
            "application_category": "packet_filtering_security",
            "difficulty": "level_2",
            "task_family": fam,
            "template_family": "xdp_tcp_flags_filter",
            "semantic_signature": f"pfs_l2_flags_{name}",
            "split": "confirmation",
            "learning_mode": "synthesis",
            "instruction": f"Write an XDP program that inspects network traffic and must {desc}. Forward all other packets with XDP_PASS.",
            "requirements": reqs,
            "tests": tests,
            "solution_c": sol_c,
        })

    return tasks


def build_pfs_l3_tasks() -> List[Dict[str, Any]]:
    tasks = []

    # --- Canary (idx 0): Array map IP filter ---
    canary_task = {
        "task_id": "rl_v2_canary_pfs_l3_01",
        "application_category": "packet_filtering_security",
        "difficulty": "level_3",
        "task_family": "canary_pfs_l3_array_ip_filter",
        "template_family": "xdp_array_filter",
        "semantic_signature": "pfs_l3_array_ip_canary",
        "split": "canary",
        "learning_mode": "synthesis",
        "instruction": "Write an XDP program that inspects incoming IPv4 packets and checks if the source IP address matches index 0 in BPF_MAP_TYPE_ARRAY map 'blocked_ip_map'. If matched, drop the packet with XDP_DROP; otherwise pass with XDP_PASS.",
        "requirements": [
            "Define BPF_MAP_TYPE_ARRAY map 'blocked_ip_map' with max_entries 1 and value_size __u32",
            "Verify Ethernet and IPv4 header bounds against data_end",
            "Perform bpf_map_lookup_elem with key index 0",
            "Drop packet with XDP_DROP if map lookup succeeds and ip->saddr equals *blocked_ip",
            "Return XDP_PASS otherwise",
            "SEC(\"xdp\") entry point and GPL license declaration",
        ],
        "tests": [
            {"name": "pass_unmatched", "description": "Unmatched IP passes", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.50", proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
            {"name": "pass_arp", "description": "ARP passes", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
        ],
        "solution_c": """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} blocked_ip_map SEC(".maps");

SEC("xdp")
int xdp_filter_array_ip(struct xdp_md *ctx) {
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

    __u32 key = 0;
    __u32 *blocked = bpf_map_lookup_elem(&blocked_ip_map, &key);
    if (blocked && ip->saddr == *blocked)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
""",
    }
    tasks.append(canary_task)

    # --- Train (idx 1..12): LPM Trie IPv4 CIDR Blocklist ---
    for sub_idx in range(1, 13):
        map_id = 100 + sub_idx
        tid = f"rl_v2_train_pfs_l3_{sub_idx:02d}"
        fam = f"train_pfs_l3_lpm_block_{sub_idx:02d}"
        tasks.append({
            "task_id": tid,
            "application_category": "packet_filtering_security",
            "difficulty": "level_3",
            "task_family": fam,
            "template_family": "xdp_lpm_trie_filter",
            "semantic_signature": f"pfs_l3_lpm_blocklist_{map_id}",
            "split": "train",
            "learning_mode": "synthesis",
            "instruction": f"Write an XDP program that inspects incoming IPv4 traffic and queries BPF_MAP_TYPE_LPM_TRIE map 'lpm_blocklist_{map_id}' to drop packets matching blacklisted source CIDR prefixes. Pass all other packets.",
            "requirements": [
                f"Define BPF_MAP_TYPE_LPM_TRIE map 'lpm_blocklist_{map_id}' with BPF_F_NO_PREALLOC",
                "Define LPM key struct with __u32 prefixlen as first field and __u32 data as second field",
                "Verify Ethernet and IPv4 header bounds against data_end",
                "Perform bpf_map_lookup_elem with prefixlen=32 on ip->saddr",
                "Return XDP_DROP on match, XDP_PASS otherwise",
                "SEC(\"xdp\") entry point and GPL license declaration",
            ],
            "tests": [
                {"name": "pass_unmatched", "description": "Unmatched IP passes default", "packet_hex": make_eth(payload=make_ipv4(src_ip="192.168.1.50", proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
                {"name": "pass_other_net", "description": "Different network segment passes", "packet_hex": make_eth(payload=make_ipv4(src_ip="172.16.1.1", proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
                {"name": "pass_arp", "description": "Non-IP ARP frame passes", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
                {"name": "pass_truncated", "description": "Truncated header passes safely", "packet_hex": "5254001234565254006543210800", "expected_action": "XDP_PASS", "weight": 1.0},
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

struct {{
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_key_{map_id});
    __type(value, __u32);
    __uint(max_entries, 256);
    __uint(map_flags, BPF_F_NO_PREALLOC);
}} lpm_blocklist_{map_id} SEC(".maps");

SEC("xdp")
int xdp_filter_lpm_{map_id}(struct xdp_md *ctx) {{
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
    key.data = ip->saddr;

    __u32 *val = bpf_map_lookup_elem(&lpm_blocklist_{map_id}, &key);
    if (val)
        return XDP_DROP;

    return XDP_PASS;
}}

char _license[] SEC("license") = "GPL";
""",
        })

    # --- Dev (idx 13..16): Dynamic LRU Hash Quarantine & Connection Limits ---
    dev_l3_configs = [
        (
            "lru_quarantine",
            "drop packets from quarantined source IP addresses registered in BPF_MAP_TYPE_LRU_HASH map 'quarantine_map'",
            [
                "Define BPF_MAP_TYPE_LRU_HASH map 'quarantine_map' with key __u32 and max_entries 1024",
                "Verify Ethernet and IPv4 header bounds against data_end",
                "Lookup ip->saddr in quarantine_map",
                "Drop packet with XDP_DROP if lookup succeeds",
                "Return XDP_PASS otherwise",
                "SEC(\"xdp\") entry point and GPL license declaration",
            ],
            """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, 1024);
} quarantine_map SEC(".maps");

SEC("xdp")
int xdp_filter_quarantine(struct xdp_md *ctx) {
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
    __u8 *val = bpf_map_lookup_elem(&quarantine_map, &src);
    if (val)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
""",
        ),
        (
            "client_rate_quota",
            "enforce per-source packet quota in BPF_MAP_TYPE_LRU_HASH map 'client_quota_map' dropping after 100 packets",
            [
                "Define BPF_MAP_TYPE_LRU_HASH map 'client_quota_map' with key __u32 and value __u64",
                "Verify Ethernet and IPv4 header bounds against data_end",
                "Lookup ip->saddr in client_quota_map and atomically increment count",
                "Drop packet with XDP_DROP if packet count exceeds 100",
                "Return XDP_PASS otherwise",
                "SEC(\"xdp\") entry point and GPL license declaration",
            ],
            """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1024);
} client_quota_map SEC(".maps");

SEC("xdp")
int xdp_filter_quota(struct xdp_md *ctx) {
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
    __u64 *val = bpf_map_lookup_elem(&client_quota_map, &src);
    if (val) {
        __sync_fetch_and_add(val, 1);
        if (*val > 100)
            return XDP_DROP;
    } else {
        __u64 init_val = 1;
        bpf_map_update_elem(&client_quota_map, &src, &init_val, BPF_NOEXIST);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
""",
        ),
        (
            "port_knock_auth",
            "verify source host IP against BPF_MAP_TYPE_HASH map 'blocked_knock_map' dropping blocked traffic",
            [
                "Define BPF_MAP_TYPE_HASH map 'blocked_knock_map' with key __u32 and max_entries 512",
                "Verify Ethernet and IPv4 header bounds against data_end",
                "Lookup ip->saddr in blocked_knock_map",
                "Drop packet with XDP_DROP if lookup succeeds (host is blocked)",
                "Return XDP_PASS otherwise",
                "SEC(\"xdp\") entry point and GPL license declaration",
            ],
            """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 512);
} blocked_knock_map SEC(".maps");

SEC("xdp")
int xdp_filter_knock(struct xdp_md *ctx) {
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
    __u32 *blocked = bpf_map_lookup_elem(&blocked_knock_map, &src);
    if (blocked)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
""",
        ),
        (
            "burst_throttle",
            "throttle bursty IP packets using BPF_MAP_TYPE_HASH map 'burst_timestamp_map' dropping back-to-back arrivals",
            [
                "Define BPF_MAP_TYPE_HASH map 'burst_timestamp_map' with key __u32 and value __u64",
                "Verify Ethernet and IPv4 header bounds against data_end",
                "Query current timestamp with bpf_ktime_get_ns() and lookup ip->saddr",
                "Drop packet with XDP_DROP if (now - last_time) < 1000000ULL",
                "Update timestamp in map and return XDP_PASS",
                "SEC(\"xdp\") entry point and GPL license declaration",
            ],
            """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1024);
} burst_timestamp_map SEC(".maps");

SEC("xdp")
int xdp_filter_burst(struct xdp_md *ctx) {
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
    __u64 *last = bpf_map_lookup_elem(&burst_timestamp_map, &src);
    if (last) {
        if (now - *last < 1000000ULL)
            return XDP_DROP;
        *last = now;
    } else {
        bpf_map_update_elem(&burst_timestamp_map, &src, &now, BPF_ANY);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
""",
        ),
    ]

    for sub_idx, (name, desc, reqs, sol_c) in enumerate(dev_l3_configs, start=1):
        tid = f"rl_v2_dev_pfs_l3_{sub_idx:02d}"
        fam = f"dev_pfs_l3_{name}"
        tasks.append({
            "task_id": tid,
            "application_category": "packet_filtering_security",
            "difficulty": "level_3",
            "task_family": fam,
            "template_family": "xdp_stateful_filter",
            "semantic_signature": f"pfs_l3_dev_{name}",
            "split": "dev",
            "learning_mode": "synthesis",
            "instruction": f"Write an XDP program that inspects network traffic and must {desc}. Forward all other packets with XDP_PASS.",
            "requirements": reqs,
            "tests": [
                {"name": "pass_untracked", "description": "Untracked client passes", "packet_hex": make_eth(payload=make_ipv4(src_ip="10.1.1.50", proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
                {"name": "pass_arp", "description": "ARP passes", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
            ],
            "solution_c": sol_c,
        })

    # --- Confirmation (idx 17..21): Stateful Quotas & Destination Filters ---
    conf_l3_configs = [
        (
            "dst_port_quota",
            "enforce service quota in BPF_MAP_TYPE_HASH map 'port_quota_map' dropping when destination port hits 1000 packets",
            [
                "Define BPF_MAP_TYPE_HASH map 'port_quota_map' with key __u16 and value __u64",
                "Verify Ethernet, IPv4, and TCP header bounds against data_end",
                "Lookup tcp->dest in port_quota_map and atomically increment count",
                "Drop packet with XDP_DROP if packet count exceeds 1000",
                "Return XDP_PASS otherwise",
                "SEC(\"xdp\") entry point and GPL license declaration",
            ],
            """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u16);
    __type(value, __u64);
    __uint(max_entries, 512);
} port_quota_map SEC(".maps");

SEC("xdp")
int xdp_filter_port_quota(struct xdp_md *ctx) {
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

    __u16 dport = bpf_ntohs(tcp->dest);
    __u64 *count = bpf_map_lookup_elem(&port_quota_map, &dport);
    if (count) {
        __sync_fetch_and_add(count, 1);
        if (*count > 1000)
            return XDP_DROP;
    } else {
        __u64 init_c = 1;
        bpf_map_update_elem(&port_quota_map, &dport, &init_c, BPF_NOEXIST);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
""",
        ),
        (
            "ip_pair_limiter",
            "restrict bidirectional sessions in BPF_MAP_TYPE_LRU_HASH map 'ip_pair_map' dropping when src-dst pair exceeds 50 packets",
            [
                "Define struct ip_pair with saddr and daddr fields",
                "Define BPF_MAP_TYPE_LRU_HASH map 'ip_pair_map' with key struct ip_pair and value __u64",
                "Verify Ethernet and IPv4 header bounds against data_end",
                "Lookup pair key and increment counter, dropping with XDP_DROP if count > 50",
                "Return XDP_PASS otherwise",
                "SEC(\"xdp\") entry point and GPL license declaration",
            ],
            """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

struct ip_pair {
    __u32 saddr;
    __u32 daddr;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct ip_pair);
    __type(value, __u64);
    __uint(max_entries, 1024);
} ip_pair_map SEC(".maps");

SEC("xdp")
int xdp_filter_pair(struct xdp_md *ctx) {
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

    struct ip_pair key = { .saddr = ip->saddr, .daddr = ip->daddr };
    __u64 *count = bpf_map_lookup_elem(&ip_pair_map, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);
        if (*count > 50)
            return XDP_DROP;
    } else {
        __u64 init_c = 1;
        bpf_map_update_elem(&ip_pair_map, &key, &init_c, BPF_NOEXIST);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
""",
        ),
        (
            "protocol_quota_enforce",
            "enforce protocol budget in BPF_MAP_TYPE_ARRAY map 'protocol_budget_map' dropping when protocol count exceeds limit",
            [
                "Define BPF_MAP_TYPE_ARRAY map 'protocol_budget_map' with 256 entries and value __u64",
                "Verify Ethernet and IPv4 header bounds against data_end",
                "Lookup ip->protocol index and increment count",
                "Drop packet with XDP_DROP if protocol count exceeds 50000",
                "Return XDP_PASS otherwise",
                "SEC(\"xdp\") entry point and GPL license declaration",
            ],
            """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 256);
} protocol_budget_map SEC(".maps");

SEC("xdp")
int xdp_filter_proto_budget(struct xdp_md *ctx) {
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

    __u32 proto_idx = ip->protocol;
    __u64 *count = bpf_map_lookup_elem(&protocol_budget_map, &proto_idx);
    if (count) {
        __sync_fetch_and_add(count, 1);
        if (*count > 50000)
            return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
""",
        ),
        (
            "syn_flood_subnet_guard",
            "defend against SYN floods using BPF_MAP_TYPE_HASH map 'syn_subnet_map' dropping TCP SYN packets from subnets exceeding rate",
            [
                "Define BPF_MAP_TYPE_HASH map 'syn_subnet_map' with key __u32 (/24 prefix) and value __u32",
                "Verify Ethernet, IPv4, and TCP header bounds against data_end",
                "If tcp->syn is asserted, extract /24 subnet (ip->saddr & 0x00FFFFFF) and lookup in map",
                "Drop packet with XDP_DROP if SYN count exceeds 200",
                "Return XDP_PASS otherwise",
                "SEC(\"xdp\") entry point and GPL license declaration",
            ],
            """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1024);
} syn_subnet_map SEC(".maps");

SEC("xdp")
int xdp_filter_syn_subnet(struct xdp_md *ctx) {
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

    if (tcp->syn) {
        __u32 subnet = ip->saddr & bpf_htonl(0xFFFFFF00);
        __u32 *count = bpf_map_lookup_elem(&syn_subnet_map, &subnet);
        if (count) {
            __sync_fetch_and_add(count, 1);
            if (*count > 200)
                return XDP_DROP;
        } else {
            __u32 init_c = 1;
            bpf_map_update_elem(&syn_subnet_map, &subnet, &init_c, BPF_NOEXIST);
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
""",
        ),
        (
            "mac_ip_spoof_defense",
            "enforce anti-spoofing security using BPF_MAP_TYPE_HASH map 'mac_ip_auth_map' dropping frames where source MAC mismatches source IP",
            [
                "Define BPF_MAP_TYPE_HASH map 'mac_ip_auth_map' with key __u32 (IP) and value unsigned char[6] (MAC)",
                "Verify Ethernet and IPv4 header bounds against data_end",
                "Lookup ip->saddr in mac_ip_auth_map",
                "If registered in map, drop packet with XDP_DROP if eth->h_source does not match expected MAC",
                "Return XDP_PASS otherwise",
                "SEC(\"xdp\") entry point and GPL license declaration",
            ],
            """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, unsigned char[6]);
    __uint(max_entries, 1024);
} mac_ip_auth_map SEC(".maps");

SEC("xdp")
int xdp_filter_mac_spoof(struct xdp_md *ctx) {
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
    unsigned char (*mac)[6] = bpf_map_lookup_elem(&mac_ip_auth_map, &src_ip);
    if (mac) {
        for (int i = 0; i < 6; i++) {
            if (eth->h_source[i] != (*mac)[i])
                return XDP_DROP;
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
""",
        ),
    ]

    for sub_idx, (name, desc, reqs, sol_c) in enumerate(conf_l3_configs, start=1):
        tid = f"rl_v2_conf_pfs_l3_{sub_idx:02d}"
        fam = f"conf_pfs_l3_{name}"
        tasks.append({
            "task_id": tid,
            "application_category": "packet_filtering_security",
            "difficulty": "level_3",
            "task_family": fam,
            "template_family": "xdp_stateful_quota_filter",
            "semantic_signature": f"pfs_l3_conf_{name}",
            "split": "confirmation",
            "learning_mode": "synthesis",
            "instruction": f"Write an XDP program that inspects network traffic and must {desc}. Forward all other packets with XDP_PASS.",
            "requirements": reqs,
            "tests": [
                {"name": "pass_untracked", "description": "Untracked client passes", "packet_hex": make_eth(payload=make_ipv4(src_ip="10.2.2.50", proto=6, payload=make_tcp())).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
                {"name": "pass_arp", "description": "ARP passes", "packet_hex": make_eth(eth_type=0x0806, payload=make_arp()).hex(), "expected_action": "XDP_PASS", "weight": 1.0},
            ],
            "solution_c": sol_c,
        })

    return tasks
