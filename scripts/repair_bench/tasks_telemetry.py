#!/usr/bin/env python3
"""
Task definitions for packet_inspection_telemetry (30 tasks).
Distribution:
- Level 1: 4 compilation, 4 verifier, 2 behavioral (10)
- Level 2: 4 compilation, 4 verifier, 2 behavioral (10)
- Level 3: 4 compilation, 4 verifier, 2 behavioral (10)
Total: 12 compilation, 12 verifier, 6 behavioral = 30 tasks.
"""

from __future__ import annotations

import binascii
from typing import List

from .common import (
    RepairTaskSpec,
    make_arp,
    make_eth,
    make_icmp,
    make_ipv4,
    make_tcp,
    make_udp,
)


def get_telemetry_tasks() -> List[RepairTaskSpec]:
    tasks: List[RepairTaskSpec] = []

    # =========================================================================
    # LEVEL 1 (10 tasks: 4 compilation, 4 verifier, 2 behavioral)
    # =========================================================================

    # 31. repair_pit_l1_packet_counter_percpu (compilation_error: undeclared BPF map definition macro SEC(".maps"))
    t31_p_tcp = binascii.hexlify(make_eth() + make_ipv4(proto=6) + make_tcp()).decode()
    t31_p_udp = binascii.hexlify(make_eth() + make_ipv4(proto=17) + make_udp()).decode()
    t31_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()
    t31_p_trunc = binascii.hexlify(make_eth()[:10]).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_pit_l1_packet_counter_percpu",
            application_category="packet_inspection_telemetry",
            difficulty="level_1",
            task_family="xdp_telemetry_counter",
            template_family="xdp_percpu_counter",
            semantic_signature="invocation+percpu_packet_counter+pass",
            diagnostic_category="compilation_error",
            failure_reason="Compilation error: undefined macro 'SEC' due to missing header <bpf/bpf_helpers.h>",
            instruction="Fix the missing BPF include header in the telemetry program. Increment a 64-bit per-CPU packet counter at key 0 for every incoming packet and return XDP_PASS.",
            requirements=[
                "Include <bpf/bpf_helpers.h>",
                "Define BPF_MAP_TYPE_PERCPU_ARRAY map named packet_count with 1 entry of __u64",
                "Lookup key 0, increment counter, and return XDP_PASS for all traffic",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} packet_count SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx) {
    __u32 key = 0;
    __u64 *cnt = bpf_map_lookup_elem(&packet_count, &key);
    if (cnt)
        *cnt += 1;
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""faulty.c:9:16: error: expected ';' after struct
} packet_count SEC(".maps");
               ^
faulty.c:11:1: error: expected identifier or '('
SEC("xdp")
^
2 errors generated.""",
            solution_c="""#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} packet_count SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx) {
    __u32 key = 0;
    __u64 *cnt = bpf_map_lookup_elem(&packet_count, &key);
    if (cnt)
        *cnt += 1;
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_tcp", "description": "Count TCP packet and pass", "packet_hex": t31_p_tcp, "expected_action": "XDP_PASS"},
                {"name": "pass_udp", "description": "Count UDP packet and pass", "packet_hex": t31_p_udp, "expected_action": "XDP_PASS"},
                {"name": "pass_arp", "description": "Count ARP frame and pass", "packet_hex": t31_p_arp, "expected_action": "XDP_PASS"},
                {"name": "pass_trunc", "description": "Count truncated packet and pass", "packet_hex": t31_p_trunc, "expected_action": "XDP_PASS"},
            ],
            validator_type="map_state",
        )
    )

    # 32. repair_pit_l1_byte_counter_wire (compilation_error: ctx->data_end - ctx->data pointer subtract without cast)
    t32_p_tcp = binascii.hexlify(make_eth() + make_ipv4(proto=6) + make_tcp()).decode()
    t32_p_udp = binascii.hexlify(make_eth() + make_ipv4(proto=17) + make_udp()).decode()
    t32_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()
    t32_p_trunc = binascii.hexlify(make_eth()[:12]).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_pit_l1_byte_counter_wire",
            application_category="packet_inspection_telemetry",
            difficulty="level_1",
            task_family="xdp_telemetry_counter",
            template_family="xdp_percpu_counter",
            semantic_signature="wire_length+percpu_byte_counter+pass",
            diagnostic_category="compilation_error",
            failure_reason="Compilation error: arithmetic on pointer to void / type casting error when calculating byte length",
            instruction="Fix the pointer arithmetic and type cast when calculating packet length from ctx->data_end and ctx->data. Accumulate total wire bytes into a per-CPU array map at key 0 and return XDP_PASS.",
            requirements=[
                "Calculate packet byte length: (void *)(long)ctx->data_end - (void *)(long)ctx->data",
                "Define byte_count per-CPU array map with 1 __u64 entry",
                "Accumulate packet byte length into counter at key 0",
                "Return XDP_PASS for all traffic",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} byte_count SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx) {
    // Compilation error: subtraction of void pointers in strict C
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u64 len = data_end - data;

    __u32 key = 0;
    __u64 *cnt = bpf_map_lookup_elem(&byte_count, &key);
    if (cnt)
        *cnt += len;
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""faulty.c:16:26: error: arithmetic on pointers to void is a GNU extension [-Werror,-Wpointer-arith]
    __u64 len = data_end - data;
                ~~~~~~~~ ^
1 error generated.""",
            solution_c="""#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} byte_count SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx) {
    __u64 len = (__u64)(long)ctx->data_end - (__u64)(long)ctx->data;
    __u32 key = 0;
    __u64 *cnt = bpf_map_lookup_elem(&byte_count, &key);
    if (cnt)
        *cnt += len;
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_tcp", "description": "Count TCP byte length and pass", "packet_hex": t32_p_tcp, "expected_action": "XDP_PASS"},
                {"name": "pass_udp", "description": "Count UDP byte length and pass", "packet_hex": t32_p_udp, "expected_action": "XDP_PASS"},
                {"name": "pass_arp", "description": "Count ARP byte length and pass", "packet_hex": t32_p_arp, "expected_action": "XDP_PASS"},
                {"name": "pass_trunc", "description": "Count truncated byte length and pass", "packet_hex": t32_p_trunc, "expected_action": "XDP_PASS"},
            ],
            validator_type="map_state",
        )
    )

    # 33. repair_pit_l1_proto_counter_split (compilation_error: switch statement non-constant case label)
    t33_p_ipv4 = binascii.hexlify(make_eth(eth_type=0x0800) + make_ipv4()).decode()
    t33_p_ipv6 = binascii.hexlify(make_eth(eth_type=0x86DD) + b"\x60\x00\x00\x00" + b"\x00"*36).decode()
    t33_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()
    t33_p_trunc = binascii.hexlify(make_eth()[:10]).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_pit_l1_proto_counter_split",
            application_category="packet_inspection_telemetry",
            difficulty="level_1",
            task_family="xdp_proto_stats",
            template_family="xdp_percpu_counter",
            semantic_signature="eth_proto+percpu_split_counter+pass",
            diagnostic_category="compilation_error",
            failure_reason="Compilation error: variable used in switch case expression instead of integer constant",
            instruction="Fix the switch statement compilation error in the protocol telemetry program. Count IPv4 frames in slot 0, IPv6 frames in slot 1, and other frames in slot 2 of a per-CPU array map, then return XDP_PASS.",
            requirements=[
                "Check Ethernet header bounds",
                "Count ETH_P_IP (0x0800) in slot 0",
                "Count ETH_P_IPV6 (0x86DD) in slot 1",
                "Count non-IP / malformed frames in slot 2",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 3);
} proto_stats SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    __u32 slot = 2; // other

    if ((void *)(eth + 1) <= data_end) {
        __u16 h_proto = bpf_ntohs(eth->h_proto);
        __u16 ip_const = ETH_P_IP;
        // Compilation error: case label does not reduce to an integer constant
        switch (h_proto) {
            case ip_const:
                slot = 0;
                break;
            case ETH_P_IPV6:
                slot = 1;
                break;
            default:
                slot = 2;
                break;
        }
    }

    __u64 *cnt = bpf_map_lookup_elem(&proto_stats, &slot);
    if (cnt)
        *cnt += 1;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""faulty.c:26:18: error: expression is not an integer constant expression
            case ip_const:
                 ^~~~~~~~
1 error generated.""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 3);
} proto_stats SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    __u32 slot = 2; // other

    if ((void *)(eth + 1) <= data_end) {
        __u16 h_proto = bpf_ntohs(eth->h_proto);
        switch (h_proto) {
            case ETH_P_IP:
                slot = 0;
                break;
            case ETH_P_IPV6:
                slot = 1;
                break;
            default:
                slot = 2;
                break;
        }
    }

    __u64 *cnt = bpf_map_lookup_elem(&proto_stats, &slot);
    if (cnt)
        *cnt += 1;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_ipv4", "description": "Count IPv4 packet in slot 0", "packet_hex": t33_p_ipv4, "expected_action": "XDP_PASS"},
                {"name": "pass_ipv6", "description": "Count IPv6 packet in slot 1", "packet_hex": t33_p_ipv6, "expected_action": "XDP_PASS"},
                {"name": "pass_arp", "description": "Count ARP frame in slot 2", "packet_hex": t33_p_arp, "expected_action": "XDP_PASS"},
                {"name": "pass_trunc", "description": "Count truncated frame in slot 2", "packet_hex": t33_p_trunc, "expected_action": "XDP_PASS"},
            ],
            validator_type="map_state",
        )
    )

    # 34. repair_pit_l1_eth_proto_stats (compilation_error: missing header <linux/if_ether.h> for ETH_P_IP)
    t34_p_ipv4 = binascii.hexlify(make_eth(eth_type=0x0800) + make_ipv4()).decode()
    t34_p_non_ip = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()
    t34_p_trunc = binascii.hexlify(make_eth()[:10]).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_pit_l1_eth_proto_stats",
            application_category="packet_inspection_telemetry",
            difficulty="level_1",
            task_family="xdp_proto_stats",
            template_family="xdp_percpu_counter",
            semantic_signature="eth_proto+ipv4_vs_non_ipv4+split_counter",
            diagnostic_category="compilation_error",
            failure_reason="Compilation error: undeclared identifier 'ETH_P_IP' due to missing include <linux/if_ether.h>",
            instruction="Fix the missing include header in the telemetry program. Record IPv4 frames in slot 0 and non-IPv4 frames in slot 1 of a per-CPU array map, returning XDP_PASS for all traffic.",
            requirements=[
                "Include <linux/if_ether.h>",
                "Define eth_stats per-CPU array map with 2 entries of __u64",
                "Check Ethernet bounds; increment slot 0 for IPv4, slot 1 for non-IPv4",
                "Return XDP_PASS for all packets",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 2);
} eth_stats SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    __u32 slot = 1;

    if ((void *)(eth + 1) <= data_end) {
        // Compilation error: ETH_P_IP undeclared without linux/if_ether.h
        if (eth->h_proto == bpf_htons(ETH_P_IP))
            slot = 0;
    }

    __u64 *cnt = bpf_map_lookup_elem(&eth_stats, &slot);
    if (cnt)
        *cnt += 1;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""faulty.c:20:39: error: use of undeclared identifier 'ETH_P_IP'
        if (eth->h_proto == bpf_htons(ETH_P_IP))
                                      ^
1 error generated.""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 2);
} eth_stats SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    __u32 slot = 1;

    if ((void *)(eth + 1) <= data_end) {
        if (eth->h_proto == bpf_htons(ETH_P_IP))
            slot = 0;
    }

    __u64 *cnt = bpf_map_lookup_elem(&eth_stats, &slot);
    if (cnt)
        *cnt += 1;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_ipv4", "description": "Count IPv4 in slot 0", "packet_hex": t34_p_ipv4, "expected_action": "XDP_PASS"},
                {"name": "pass_non_ip", "description": "Count non-IPv4 in slot 1", "packet_hex": t34_p_non_ip, "expected_action": "XDP_PASS"},
                {"name": "pass_trunc", "description": "Count truncated in slot 1", "packet_hex": t34_p_trunc, "expected_action": "XDP_PASS"},
            ],
            validator_type="map_state",
        )
    )

    # 35. repair_pit_l1_ingress_port_stat (verifier_rejection: map lookup return pointer dereferenced without NULL check)
    t35_p_tcp = binascii.hexlify(make_eth() + make_ipv4(proto=6) + make_tcp()).decode()
    t35_p_udp = binascii.hexlify(make_eth() + make_ipv4(proto=17) + make_udp()).decode()
    t35_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_pit_l1_ingress_port_stat",
            application_category="packet_inspection_telemetry",
            difficulty="level_1",
            task_family="xdp_interface_stats",
            template_family="xdp_percpu_counter",
            semantic_signature="ingress_ifindex+percpu_counter+pass",
            diagnostic_category="verifier_rejection",
            failure_reason="Kernel verifier rejection: R0 invalid mem access 'map_value_or_null' when updating per-interface stats",
            instruction="Fix the verifier rejection by checking the result of bpf_map_lookup_elem for NULL before incrementing the counter. Count packets per ingress interface index in an array map.",
            requirements=[
                "Check lookup return pointer for NULL",
                "Ensure ifindex is bounded (0..63)",
                "Increment packet counter for the ingress interface and return XDP_PASS",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 64);
} iface_stats SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx) {
    __u32 ifindex = ctx->ingress_ifindex & 63;
    __u64 *cnt = bpf_map_lookup_elem(&iface_stats, &ifindex);
    // Verifier error: dereferencing cnt without NULL check
    *cnt += 1;
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""0: R1=ctx(off=0,imm=0) R10=fp0
...
8: (85) call bpf_map_lookup_elem#1
9: R0=map_value_or_null(id=1,off=0,r=0,imm=0)
; *cnt += 1;
10: (79) r1 = *(u64 *)(r0 +0)
R0 invalid mem access 'map_value_or_null'
processed 11 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
-- END PROG LOAD LOG --""",
            solution_c="""#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 64);
} iface_stats SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx) {
    __u32 ifindex = ctx->ingress_ifindex & 63;
    __u64 *cnt = bpf_map_lookup_elem(&iface_stats, &ifindex);
    if (cnt)
        *cnt += 1;
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_tcp", "description": "Count TCP packet on ingress interface", "packet_hex": t35_p_tcp, "expected_action": "XDP_PASS"},
                {"name": "pass_udp", "description": "Count UDP packet on ingress interface", "packet_hex": t35_p_udp, "expected_action": "XDP_PASS"},
                {"name": "pass_arp", "description": "Count ARP frame on ingress interface", "packet_hex": t35_p_arp, "expected_action": "XDP_PASS"},
            ],
            validator_type="map_state",
        )
    )

    # 36. repair_pit_l1_ip_len_histogram (verifier_rejection: map key unbounded lookup)
    t36_p_small = binascii.hexlify(make_eth() + make_ipv4()[:10]).decode()
    t36_p_medium = binascii.hexlify(make_eth() + make_ipv4(payload=b"A"*100)).decode()
    t36_p_large = binascii.hexlify(make_eth() + make_ipv4(payload=b"A"*600)).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_pit_l1_ip_len_histogram",
            application_category="packet_inspection_telemetry",
            difficulty="level_1",
            task_family="xdp_histogram",
            template_family="xdp_percpu_counter",
            semantic_signature="packet_length+4_bucket_histogram+pass",
            diagnostic_category="verifier_rejection",
            failure_reason="Kernel verifier rejection: uninitialized stack memory passed as key to bpf_map_lookup_elem",
            instruction="Fix the verifier rejection by ensuring the histogram bucket key is properly initialized before passing its address to bpf_map_lookup_elem. Categorize packet length into 4 buckets (0-63, 64-127, 128-511, 512+).",
            requirements=[
                "Initialize bucket key on stack",
                "Bucket 0: len < 64, Bucket 1: 64..127, Bucket 2: 128..511, Bucket 3: 512+",
                "Increment bucket in per-CPU array map with 4 entries",
                "Return XDP_PASS for all traffic",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 4);
} len_hist SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx) {
    __u64 len = (__u64)(long)ctx->data_end - (__u64)(long)ctx->data;
    __u32 bucket; // Verifier error: uninitialized stack variable on some branches

    if (len < 64)
        bucket = 0;
    else if (len < 128)
        bucket = 1;
    else if (len < 512)
        bucket = 2;
    else if (len >= 512)
        bucket = 3;

    // If len was negative or NaN (theoretically), bucket is uninitialized
    __u64 *cnt = bpf_map_lookup_elem(&len_hist, &bucket);
    if (cnt)
        *cnt += 1;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""0: R1=ctx(off=0,imm=0) R10=fp0
...
16: (bf) r2 = r10
17: (07) r2 += -4
18: (85) call bpf_map_lookup_elem#1
invalid indirect read from stack R2 off -4+0 size 4
processed 19 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
-- END PROG LOAD LOG --""",
            solution_c="""#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 4);
} len_hist SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx) {
    __u64 len = (__u64)(long)ctx->data_end - (__u64)(long)ctx->data;
    __u32 bucket = 0;

    if (len < 64)
        bucket = 0;
    else if (len < 128)
        bucket = 1;
    else if (len < 512)
        bucket = 2;
    else
        bucket = 3;

    __u64 *cnt = bpf_map_lookup_elem(&len_hist, &bucket);
    if (cnt)
        *cnt += 1;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_small_pkt", "description": "Count small packet in bucket 0", "packet_hex": t36_p_small, "expected_action": "XDP_PASS"},
                {"name": "pass_medium_pkt", "description": "Count medium packet in bucket 2", "packet_hex": t36_p_medium, "expected_action": "XDP_PASS"},
                {"name": "pass_large_pkt", "description": "Count large packet in bucket 3", "packet_hex": t36_p_large, "expected_action": "XDP_PASS"},
            ],
            validator_type="map_state",
        )
    )

    # 37. repair_pit_l1_packet_size_quantiles (verifier_rejection: invalid memory access when reading ctx->data beyond bounds)
    t37_p_ipv4 = binascii.hexlify(make_eth() + make_ipv4()).decode()
    t37_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()
    t37_p_trunc = binascii.hexlify(make_eth()[:10]).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_pit_l1_packet_size_quantiles",
            application_category="packet_inspection_telemetry",
            difficulty="level_1",
            task_family="xdp_telemetry_counter",
            template_family="xdp_percpu_counter",
            semantic_signature="packet_first_byte+telemetry+pass",
            diagnostic_category="verifier_rejection",
            failure_reason="Kernel verifier rejection: reading packet data byte without checking if ctx->data + 1 <= ctx->data_end",
            instruction="Fix the verifier rejection by validating that data + 1 <= data_end before reading packet content. Record the first payload byte modulo 16 in a per-CPU histogram and return XDP_PASS.",
            requirements=[
                "Check data + 1 <= data_end before accessing *data",
                "Ensure bucket index < 16",
                "Record observation in per-CPU array map",
                "Return XDP_PASS for all traffic",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 16);
} byte_hist SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    // Verifier error: missing bounds check on data + 1 <= data_end
    __u8 first_byte = *(__u8 *)data;
    __u32 key = first_byte & 15;

    __u64 *cnt = bpf_map_lookup_elem(&byte_hist, &key);
    if (cnt)
        *cnt += 1;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""0: R1=ctx(off=0,imm=0) R10=fp0
; void *data = (void *)(long)ctx->data;
1: (61) r2 = *(u32 *)(r1 +0)
; __u8 first_byte = *(__u8 *)data;
2: (71) r3 = *(u8 *)(r2 +0)
invalid access to packet, id=0, off=0, size=1, R2_w=pkt(off=0,r=0,imm=0)
processed 3 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
-- END PROG LOAD LOG --""",
            solution_c="""#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 16);
} byte_hist SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    if ((void *)((char *)data + 1) > data_end)
        return XDP_PASS;

    __u8 first_byte = *(__u8 *)data;
    __u32 key = first_byte & 15;

    __u64 *cnt = bpf_map_lookup_elem(&byte_hist, &key);
    if (cnt)
        *cnt += 1;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_ipv4", "description": "Count IPv4 first byte in histogram", "packet_hex": t37_p_ipv4, "expected_action": "XDP_PASS"},
                {"name": "pass_arp", "description": "Count ARP first byte in histogram", "packet_hex": t37_p_arp, "expected_action": "XDP_PASS"},
                {"name": "pass_trunc", "description": "Safely pass truncated packet", "packet_hex": t37_p_trunc, "expected_action": "XDP_PASS"},
            ],
            validator_type="map_state",
        )
    )

    # 38. repair_pit_l1_payload_offset_stat (verifier_rejection: packet pointer offset calculation exceeding verified bounds)
    t38_p_udp = binascii.hexlify(make_eth() + make_ipv4(proto=17) + make_udp(payload=b"HELLO")).decode()
    t38_p_tcp = binascii.hexlify(make_eth() + make_ipv4(proto=6) + make_tcp()).decode()
    t38_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_pit_l1_payload_offset_stat",
            application_category="packet_inspection_telemetry",
            difficulty="level_1",
            task_family="xdp_payload_stats",
            template_family="xdp_percpu_counter",
            semantic_signature="udp_payload_len+telemetry+pass",
            diagnostic_category="verifier_rejection",
            failure_reason="Kernel verifier rejection: accessing UDP payload without checking (payload + payload_len <= data_end)",
            instruction="Fix the verifier rejection when inspecting UDP payload length. Safely parse Ethernet, IPv4, and UDP headers, and update UDP payload telemetry counter in a per-CPU map.",
            requirements=[
                "Verify Ethernet, IPv4, and UDP header bounds",
                "Ensure UDP payload offset is checked against data_end",
                "Accumulate UDP payload bytes in per-CPU map",
                "Return XDP_PASS for all traffic",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} udp_payload_bytes SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx) {
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

    __u32 ip_len = (__u32)ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip_len;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    // Verifier issue: accessing payload offset without validating length
    char *payload = (void *)(udp + 1);
    if (payload >= (char *)data_end)
        return XDP_PASS;

    __u64 plen = (__u64)(long)data_end - (__u64)(long)payload;
    __u32 key = 0;
    __u64 *cnt = bpf_map_lookup_elem(&udp_payload_bytes, &key);
    if (cnt)
        *cnt += plen;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""0: R1=ctx(off=0,imm=0) R10=fp0
...
22: (2d) if r3 >= r1 goto pc+10
; __u64 plen = (__u64)(long)data_end - (__u64)(long)payload;
23: (bf) r4 = r1
24: (1f) r4 -= r3
processed 25 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
-- END PROG LOAD LOG --""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} udp_payload_bytes SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx) {
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

    __u32 ip_len = (__u32)ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip_len;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    void *payload = (void *)(udp + 1);
    if (payload > data_end)
        return XDP_PASS;

    __u64 plen = (__u64)(long)data_end - (__u64)(long)payload;
    __u32 key = 0;
    __u64 *cnt = bpf_map_lookup_elem(&udp_payload_bytes, &key);
    if (cnt)
        *cnt += plen;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_udp_payload", "description": "Track UDP payload bytes", "packet_hex": t38_p_udp, "expected_action": "XDP_PASS"},
                {"name": "pass_tcp", "description": "Pass TCP packet without updating UDP stats", "packet_hex": t38_p_tcp, "expected_action": "XDP_PASS"},
                {"name": "pass_arp", "description": "Pass ARP frame", "packet_hex": t38_p_arp, "expected_action": "XDP_PASS"},
            ],
            validator_type="map_state",
        )
    )

    # 39. repair_pit_l1_tcp_ack_counter (behavioral_logic_bug: counting all TCP instead of only ACK flag)
    t39_p_ack = binascii.hexlify(make_eth() + make_ipv4(proto=6) + make_tcp(flags=0x10)).decode()
    t39_p_syn = binascii.hexlify(make_eth() + make_ipv4(proto=6) + make_tcp(flags=0x02)).decode()
    t39_p_udp = binascii.hexlify(make_eth() + make_ipv4(proto=17) + make_udp()).decode()
    t39_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_pit_l1_tcp_ack_counter",
            application_category="packet_inspection_telemetry",
            difficulty="level_1",
            task_family="xdp_tcp_flags_stats",
            template_family="xdp_percpu_counter",
            semantic_signature="tcp_ack_packets+percpu_counter+pass",
            diagnostic_category="behavioral_logic_bug",
            failure_reason="Behavioral bug: incremented ACK counter for all TCP packets regardless of whether ACK flag was set",
            instruction="Fix the TCP flag check in the telemetry filter to only increment the counter when the TCP ACK flag (tcp->ack) is set. Return XDP_PASS for all traffic.",
            requirements=[
                "Check bounds for Ethernet, IP, and TCP headers",
                "Verify ip->protocol == IPPROTO_TCP",
                "Only increment counter in ack_stats map if tcp->ack is set",
                "Return XDP_PASS for all traffic",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} ack_stats SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx) {
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

    __u32 ip_len = (__u32)ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip_len;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    // Behavioral bug: missing if (tcp->ack) check, increments for all TCP
    __u32 key = 0;
    __u64 *cnt = bpf_map_lookup_elem(&ack_stats, &key);
    if (cnt)
        *cnt += 1;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""FAIL: test_case 'count_ack_only' failed:
  Expected map ack_stats[0] = 1 after pure SYN packet
  Observed map ack_stats[0] = 2 (SYN packet erroneously incremented ACK counter)
1 of 4 test cases failed.""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} ack_stats SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx) {
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

    __u32 ip_len = (__u32)ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip_len;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    if (tcp->ack) {
        __u32 key = 0;
        __u64 *cnt = bpf_map_lookup_elem(&ack_stats, &key);
        if (cnt)
            *cnt += 1;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_ack", "description": "Count TCP ACK in telemetry", "packet_hex": t39_p_ack, "expected_action": "XDP_PASS"},
                {"name": "pass_syn", "description": "Do not count pure SYN in ACK telemetry", "packet_hex": t39_p_syn, "expected_action": "XDP_PASS"},
                {"name": "pass_udp", "description": "Do not count UDP in ACK telemetry", "packet_hex": t39_p_udp, "expected_action": "XDP_PASS"},
                {"name": "pass_arp", "description": "Do not count ARP in ACK telemetry", "packet_hex": t39_p_arp, "expected_action": "XDP_PASS"},
            ],
            validator_type="map_state",
        )
    )

    # 40. repair_pit_l1_total_bytes_delta (behavioral_logic_bug: overwriting counter instead of accumulating)
    t40_p_pkt1 = binascii.hexlify(make_eth() + make_ipv4(payload=b"A"*50)).decode()
    t40_p_pkt2 = binascii.hexlify(make_eth() + make_ipv4(payload=b"B"*100)).decode()
    t40_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_pit_l1_total_bytes_delta",
            application_category="packet_inspection_telemetry",
            difficulty="level_1",
            task_family="xdp_telemetry_counter",
            template_family="xdp_percpu_counter",
            semantic_signature="accumulate_wire_bytes+percpu_counter+pass",
            diagnostic_category="behavioral_logic_bug",
            failure_reason="Behavioral bug: assigned current packet length (*cnt = len) instead of accumulating total (*cnt += len)",
            instruction="Fix the accumulation bug in the byte telemetry program so it adds the packet byte length to the running total in the map, rather than overwriting it.",
            requirements=[
                "Accumulate packet byte length (*cnt += len) at key 0",
                "Handle all incoming frames (IP, non-IP, truncated)",
                "Return XDP_PASS for all traffic",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} byte_accumulator SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx) {
    __u64 len = (__u64)(long)ctx->data_end - (__u64)(long)ctx->data;
    __u32 key = 0;
    __u64 *cnt = bpf_map_lookup_elem(&byte_accumulator, &key);
    if (cnt) {
        // Behavioral bug: overwriting instead of accumulating
        *cnt = len;
    }
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""FAIL: test_case 'accumulate_two_packets' failed:
  Expected map byte_accumulator[0] = 238 bytes
  Observed map byte_accumulator[0] = 154 bytes (only recorded last packet length)
1 of 3 test cases failed.""",
            solution_c="""#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} byte_accumulator SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx) {
    __u64 len = (__u64)(long)ctx->data_end - (__u64)(long)ctx->data;
    __u32 key = 0;
    __u64 *cnt = bpf_map_lookup_elem(&byte_accumulator, &key);
    if (cnt) {
        *cnt += len;
    }
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_pkt1", "description": "Add first packet bytes to accumulator", "packet_hex": t40_p_pkt1, "expected_action": "XDP_PASS"},
                {"name": "pass_pkt2", "description": "Add second packet bytes to accumulator", "packet_hex": t40_p_pkt2, "expected_action": "XDP_PASS"},
                {"name": "pass_arp", "description": "Add ARP frame bytes to accumulator", "packet_hex": t40_p_arp, "expected_action": "XDP_PASS"},
            ],
            validator_type="map_state",
        )
    )

    # =========================================================================
    # LEVEL 2 (10 tasks: 4 compilation, 4 verifier, 2 behavioral)
    # =========================================================================

    # 41. repair_pit_l2_protocol_matrix (compilation_error: multi-dimensional array declaration unsupported in map value)
    t41_p_tcp = binascii.hexlify(make_eth() + make_ipv4(proto=6) + make_tcp()).decode()
    t41_p_udp = binascii.hexlify(make_eth() + make_ipv4(proto=17) + make_udp()).decode()
    t41_p_icmp = binascii.hexlify(make_eth() + make_ipv4(proto=1) + make_icmp()).decode()
    t41_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_pit_l2_protocol_matrix",
            application_category="packet_inspection_telemetry",
            difficulty="level_2",
            task_family="xdp_proto_matrix",
            template_family="xdp_percpu_counter",
            semantic_signature="ipv4_proto_matrix+4_counters+pass",
            diagnostic_category="compilation_error",
            failure_reason="Compilation error: invalid struct definition with incomplete array type in map value",
            instruction="Fix the map definition and slot indexing in the protocol telemetry program to count IPv4 TCP (0), IPv4 UDP (1), other IPv4 (2), and non-IPv4 (3) packets in distinct slots of a per-CPU array map.",
            requirements=[
                "Define proto_matrix array map with 4 entries of __u64",
                "Parse Ethernet and IPv4 headers safely",
                "Assign slots: 0 for TCP, 1 for UDP, 2 for other IPv4, 3 for non-IPv4",
                "Return XDP_PASS for all packets",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct matrix_val {
    __u64 counters[]; // Compilation error: flexible array member not allowed in BPF map value struct
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct matrix_val);
    __uint(max_entries, 4);
} proto_matrix SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    __u32 slot = 3; // non-IPv4

    if ((void *)(eth + 1) <= data_end) {
        if (eth->h_proto == bpf_htons(ETH_P_IP)) {
            struct iphdr *ip = (void *)(eth + 1);
            if ((void *)(ip + 1) <= data_end) {
                if (ip->protocol == IPPROTO_TCP)
                    slot = 0;
                else if (ip->protocol == IPPROTO_UDP)
                    slot = 1;
                else
                    slot = 2;
            }
        }
    }

    __u64 *cnt = bpf_map_lookup_elem(&proto_matrix, &slot);
    if (cnt)
        *cnt += 1;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""faulty.c:10:11: error: field 'counters' has incomplete type '__u64[]' (aka 'unsigned long long[]')
    __u64 counters[];
          ^
1 error generated.""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 4);
} proto_matrix SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    __u32 slot = 3; // non-IPv4

    if ((void *)(eth + 1) <= data_end) {
        if (eth->h_proto == bpf_htons(ETH_P_IP)) {
            struct iphdr *ip = (void *)(eth + 1);
            if ((void *)(ip + 1) <= data_end) {
                if (ip->protocol == IPPROTO_TCP)
                    slot = 0;
                else if (ip->protocol == IPPROTO_UDP)
                    slot = 1;
                else
                    slot = 2;
            }
        }
    }

    __u64 *cnt = bpf_map_lookup_elem(&proto_matrix, &slot);
    if (cnt)
        *cnt += 1;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_tcp", "description": "Count TCP in slot 0", "packet_hex": t41_p_tcp, "expected_action": "XDP_PASS"},
                {"name": "pass_udp", "description": "Count UDP in slot 1", "packet_hex": t41_p_udp, "expected_action": "XDP_PASS"},
                {"name": "pass_icmp", "description": "Count other IPv4 in slot 2", "packet_hex": t41_p_icmp, "expected_action": "XDP_PASS"},
                {"name": "pass_arp", "description": "Count non-IPv4 in slot 3", "packet_hex": t41_p_arp, "expected_action": "XDP_PASS"},
            ],
            validator_type="map_state",
        )
    )

    # 42. repair_pit_l2_tcp_flags_hist (compilation_error: TH_SYN undeclared in kernel headers)
    t42_p_syn = binascii.hexlify(make_eth() + make_ipv4(proto=6) + make_tcp(flags=0x02)).decode()
    t42_p_fin = binascii.hexlify(make_eth() + make_ipv4(proto=6) + make_tcp(flags=0x01)).decode()
    t42_p_rst = binascii.hexlify(make_eth() + make_ipv4(proto=6) + make_tcp(flags=0x04)).decode()
    t42_p_ack = binascii.hexlify(make_eth() + make_ipv4(proto=6) + make_tcp(flags=0x10)).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_pit_l2_tcp_flags_hist",
            application_category="packet_inspection_telemetry",
            difficulty="level_2",
            task_family="xdp_tcp_flags_stats",
            template_family="xdp_percpu_counter",
            semantic_signature="tcp_flags_hist_syn_fin_rst_other+pass",
            diagnostic_category="compilation_error",
            failure_reason="Compilation error: undeclared identifier 'TH_SYN' (BSD header constant used instead of Linux bitfield / constants)",
            instruction="Fix the TCP flag references in the telemetry program. Categorize valid IPv4 TCP packets by flag: SYN in slot 0, FIN in slot 1, RST in slot 2, other TCP in slot 3.",
            requirements=[
                "Check Ethernet, IPv4, and TCP bounds",
                "Inspect TCP flags: tcp->syn (0), tcp->fin (1), tcp->rst (2), others (3)",
                "Precedence: SYN > FIN > RST > Other",
                "Record in per-CPU array map tcp_flag_stats with 4 entries",
                "Return XDP_PASS for all packets",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 4);
} tcp_flag_stats SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx) {
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

    __u32 ip_len = (__u32)ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip_len;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    __u32 slot = 3;
    // Compilation error: TH_SYN is BSD header macro, not in linux/tcp.h
    if (tcp->syn)
        slot = 0;
    else if (tcp->fin)
        slot = 1;
    else if (tcp->rst)
        slot = 2;

    __u64 *cnt = bpf_map_lookup_elem(&tcp_flag_stats, &slot);
    if (cnt)
        *cnt += 1;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""faulty.c:42:9: error: use of undeclared identifier 'TH_SYN'
    if (TH_SYN & tcp->syn)
        ^
1 error generated.""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 4);
} tcp_flag_stats SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx) {
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

    __u32 ip_len = (__u32)ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip_len;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    __u32 slot = 3;
    if (tcp->syn)
        slot = 0;
    else if (tcp->fin)
        slot = 1;
    else if (tcp->rst)
        slot = 2;

    __u64 *cnt = bpf_map_lookup_elem(&tcp_flag_stats, &slot);
    if (cnt)
        *cnt += 1;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_syn", "description": "Count SYN in slot 0", "packet_hex": t42_p_syn, "expected_action": "XDP_PASS"},
                {"name": "pass_fin", "description": "Count FIN in slot 1", "packet_hex": t42_p_fin, "expected_action": "XDP_PASS"},
                {"name": "pass_rst", "description": "Count RST in slot 2", "packet_hex": t42_p_rst, "expected_action": "XDP_PASS"},
                {"name": "pass_ack", "description": "Count other/ACK in slot 3", "packet_hex": t42_p_ack, "expected_action": "XDP_PASS"},
            ],
            validator_type="map_state",
        )
    )

    # 43. repair_pit_l2_dns_query_counter (compilation_error: missing struct udphdr definition)
    t43_p_dns = binascii.hexlify(make_eth() + make_ipv4(proto=17) + make_udp(dst_port=53)).decode()
    t43_p_other_udp = binascii.hexlify(make_eth() + make_ipv4(proto=17) + make_udp(dst_port=123)).decode()
    t43_p_tcp = binascii.hexlify(make_eth() + make_ipv4(proto=6) + make_tcp()).decode()
    t43_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_pit_l2_dns_query_counter",
            application_category="packet_inspection_telemetry",
            difficulty="level_2",
            task_family="xdp_dns_telemetry",
            template_family="xdp_percpu_counter",
            semantic_signature="udp_port_53+dns_stats_counter+pass",
            diagnostic_category="compilation_error",
            failure_reason="Compilation error: variable has incomplete type 'struct udphdr' due to missing header <linux/udp.h>",
            instruction="Fix the missing include header <linux/udp.h> in the DNS telemetry program. Count DNS queries (UDP port 53) in slot 0 and other UDP packets in slot 1 of a per-CPU map, returning XDP_PASS.",
            requirements=[
                "Include <linux/udp.h>",
                "Check Ethernet, IPv4, and UDP bounds",
                "Increment slot 0 for UDP dport 53; increment slot 1 for other UDP",
                "Return XDP_PASS for all traffic",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 2);
} dns_stats SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx) {
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

    __u32 ip_len = (__u32)ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    // Compilation error: struct udphdr incomplete
    struct udphdr *udp = (void *)ip + ip_len;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    __u32 slot = (udp->dest == bpf_htons(53)) ? 0 : 1;
    __u64 *cnt = bpf_map_lookup_elem(&dns_stats, &slot);
    if (cnt)
        *cnt += 1;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""faulty.c:28:12: error: variable has incomplete type 'struct udphdr'
    struct udphdr *udp = (void *)ip + ip_len;
           ^
faulty.c:28:12: note: forward declaration of 'struct udphdr'
faulty.c:29:18: error: invalid application of 'sizeof' to an incomplete type 'struct udphdr'
    if ((void *)(udp + 1) > data_end)
                 ^~~~~~~
2 errors generated.""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 2);
} dns_stats SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx) {
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

    __u32 ip_len = (__u32)ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip_len;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    __u32 slot = (udp->dest == bpf_htons(53)) ? 0 : 1;
    __u64 *cnt = bpf_map_lookup_elem(&dns_stats, &slot);
    if (cnt)
        *cnt += 1;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_dns_query", "description": "Count DNS in slot 0", "packet_hex": t43_p_dns, "expected_action": "XDP_PASS"},
                {"name": "pass_other_udp", "description": "Count NTP in slot 1", "packet_hex": t43_p_other_udp, "expected_action": "XDP_PASS"},
                {"name": "pass_tcp", "description": "Pass TCP unchanged", "packet_hex": t43_p_tcp, "expected_action": "XDP_PASS"},
                {"name": "pass_arp", "description": "Pass ARP frame unchanged", "packet_hex": t43_p_arp, "expected_action": "XDP_PASS"},
            ],
            validator_type="map_state",
        )
    )

    # 44. repair_pit_l2_ttl_distribution (compilation_error: wrong pointer type passed to bpf_map_lookup_elem)
    t44_p_ttl1 = binascii.hexlify(make_eth() + make_ipv4(ttl=32)).decode()
    t44_p_ttl2 = binascii.hexlify(make_eth() + make_ipv4(ttl=64)).decode()
    t44_p_ttl3 = binascii.hexlify(make_eth() + make_ipv4(ttl=128)).decode()
    t44_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_pit_l2_ttl_distribution",
            application_category="packet_inspection_telemetry",
            difficulty="level_2",
            task_family="xdp_ttl_stats",
            template_family="xdp_percpu_counter",
            semantic_signature="ipv4_ttl+256_bucket_stats+pass",
            diagnostic_category="compilation_error",
            failure_reason="Compilation error: passing uint8 address instead of uint32 key to bpf_map_lookup_elem",
            instruction="Fix the key type passed to bpf_map_lookup_elem in the TTL telemetry filter. Record observed IPv4 TTL values (0..255) into a 256-entry array map and return XDP_PASS.",
            requirements=[
                "Check Ethernet and IPv4 bounds",
                "Promote ip->ttl (__u8) to __u32 key for map lookup",
                "Record TTL count in ttl_dist array map with 256 entries",
                "Return XDP_PASS for all traffic",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 256);
} ttl_dist SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx) {
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

    // Compilation error: passing &__u8 pointer to map expecting __u32 key
    __u64 *cnt = bpf_map_lookup_elem(&ttl_dist, &ip->ttl);
    if (cnt)
        *cnt += 1;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""faulty.c:26:49: error: incompatible pointer types passing '__u8 *' (aka 'unsigned char *') to parameter of type 'const void *' expecting '__u32 *' compatible alignment [-Werror,-Wincompatible-pointer-types]
    __u64 *cnt = bpf_map_lookup_elem(&ttl_dist, &ip->ttl);
                                                ^~~~~~~~
1 error generated.""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 256);
} ttl_dist SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx) {
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

    __u32 key = ip->ttl;
    __u64 *cnt = bpf_map_lookup_elem(&ttl_dist, &key);
    if (cnt)
        *cnt += 1;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_ttl_32", "description": "Count TTL 32 in slot 32", "packet_hex": t44_p_ttl1, "expected_action": "XDP_PASS"},
                {"name": "pass_ttl_64", "description": "Count TTL 64 in slot 64", "packet_hex": t44_p_ttl2, "expected_action": "XDP_PASS"},
                {"name": "pass_ttl_128", "description": "Count TTL 128 in slot 128", "packet_hex": t44_p_ttl3, "expected_action": "XDP_PASS"},
                {"name": "pass_arp", "description": "Pass ARP frame unchanged", "packet_hex": t44_p_arp, "expected_action": "XDP_PASS"},
            ],
            validator_type="map_state",
        )
    )

    # 45. repair_pit_l2_window_size_tracker (verifier_rejection: map value pointer arithmetic without bounds)
    t45_p_tcp = binascii.hexlify(make_eth() + make_ipv4(proto=6) + make_tcp(window=65535)).decode()
    t45_p_udp = binascii.hexlify(make_eth() + make_ipv4(proto=17) + make_udp()).decode()
    t45_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_pit_l2_window_size_tracker",
            application_category="packet_inspection_telemetry",
            difficulty="level_2",
            task_family="xdp_tcp_window_stats",
            template_family="xdp_percpu_counter",
            semantic_signature="tcp_window_scale+stats_map+pass",
            diagnostic_category="verifier_rejection",
            failure_reason="Kernel verifier rejection: array index for TCP window bucket not statically bounded",
            instruction="Fix the verifier rejection by masking or clamping the TCP window histogram bucket index (0..7). Track TCP advertised window size in an 8-bucket array map and return XDP_PASS.",
            requirements=[
                "Check bounds for Ethernet, IP, and TCP headers",
                "Extract TCP window size: bpf_ntohs(tcp->window)",
                "Calculate bucket index: (window >> 13) & 7",
                "Record observation in 8-entry per-CPU array map",
                "Return XDP_PASS for all traffic",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 8);
} win_stats SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx) {
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

    __u32 ip_len = (__u32)ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip_len;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    __u16 win = bpf_ntohs(tcp->window);
    // Verifier error: bucket variable could be up to 15 without mask
    __u32 bucket = win >> 12;

    __u64 *cnt = bpf_map_lookup_elem(&win_stats, &bucket);
    if (cnt)
        *cnt += 1;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""0: R1=ctx(off=0,imm=0) R10=fp0
...
24: (69) r1 = *(u16 *)(r3 +14)
25: (dc) r1 = be16 r1
26: (74) r1 >>= 12
27: (63) *(u32 *)(r10 -4) = r1
; __u64 *cnt = bpf_map_lookup_elem(&win_stats, &bucket);
28: (bf) r2 = r10
29: (07) r2 += -4
30: (18) r1 = 0xffff8880042a4000
32: (85) call bpf_map_lookup_elem#1
R2 invalid map access into array map, key out of range
processed 33 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
-- END PROG LOAD LOG --""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 8);
} win_stats SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx) {
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

    __u32 ip_len = (__u32)ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip_len;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    __u16 win = bpf_ntohs(tcp->window);
    __u32 bucket = (win >> 13) & 7;

    __u64 *cnt = bpf_map_lookup_elem(&win_stats, &bucket);
    if (cnt)
        *cnt += 1;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_tcp_max_win", "description": "Count TCP max window in bucket 7", "packet_hex": t45_p_tcp, "expected_action": "XDP_PASS"},
                {"name": "pass_udp", "description": "Pass UDP traffic", "packet_hex": t45_p_udp, "expected_action": "XDP_PASS"},
                {"name": "pass_arp", "description": "Pass ARP frame", "packet_hex": t45_p_arp, "expected_action": "XDP_PASS"},
            ],
            validator_type="map_state",
        )
    )

    # 46. repair_pit_l2_ip_id_sequence (verifier_rejection: uninitialized stack memory passed to map key)
    t46_p_tcp = binascii.hexlify(make_eth() + make_ipv4(src_ip="192.168.1.5", proto=6) + make_tcp()).decode()
    t46_p_udp = binascii.hexlify(make_eth() + make_ipv4(src_ip="192.168.1.6", proto=17) + make_udp()).decode()
    t46_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_pit_l2_ip_id_sequence",
            application_category="packet_inspection_telemetry",
            difficulty="level_2",
            task_family="xdp_ip_id_stats",
            template_family="xdp_hash_map_filter",
            semantic_signature="src_ip+ip_id_tracker+pass",
            diagnostic_category="verifier_rejection",
            failure_reason="Kernel verifier rejection: uninitialized padding in struct flow_key passed to hash map lookup",
            instruction="Fix the verifier rejection by zero-initializing the key struct before calling bpf_map_lookup_elem. Track last seen IPv4 ID per source IP address in a hash map.",
            requirements=[
                "Zero-initialize struct ip_key key = {0}",
                "Check Ethernet and IPv4 bounds",
                "Update last seen IPv4 id for the source IP in ip_id_map",
                "Return XDP_PASS for all traffic",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct ip_key {
    __u32 saddr;
    __u32 pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct ip_key);
    __type(value, __u16);
    __uint(max_entries, 1024);
} ip_id_map SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx) {
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

    // Verifier error: pad field is uninitialized on stack
    struct ip_key key;
    key.saddr = ip->saddr;

    __u16 id = bpf_ntohs(ip->id);
    bpf_map_update_elem(&ip_id_map, &key, &id, BPF_ANY);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""0: R1=ctx(off=0,imm=0) R10=fp0
...
14: (bf) r3 = r10
15: (07) r3 += -8
; bpf_map_update_elem(&ip_id_map, &key, &id, BPF_ANY);
16: (85) call bpf_map_update_elem#2
invalid indirect read from stack R3 off -8+4 size 4 (uninitialized)
processed 17 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
-- END PROG LOAD LOG --""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct ip_key {
    __u32 saddr;
    __u32 pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct ip_key);
    __type(value, __u16);
    __uint(max_entries, 1024);
} ip_id_map SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx) {
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

    struct ip_key key = {0};
    key.saddr = ip->saddr;

    __u16 id = bpf_ntohs(ip->id);
    bpf_map_update_elem(&ip_id_map, &key, &id, BPF_ANY);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_tcp", "description": "Track TCP IPv4 ID in hash map", "packet_hex": t46_p_tcp, "expected_action": "XDP_PASS"},
                {"name": "pass_udp", "description": "Track UDP IPv4 ID in hash map", "packet_hex": t46_p_udp, "expected_action": "XDP_PASS"},
                {"name": "pass_arp", "description": "Pass ARP frame unchanged", "packet_hex": t46_p_arp, "expected_action": "XDP_PASS"},
            ],
            validator_type="map_state",
        )
    )

    # 47. repair_pit_l2_packet_rate_decay (verifier_rejection: 64-bit division by variable triggering unsupported BPF div instruction)
    t47_p_tcp = binascii.hexlify(make_eth() + make_ipv4(proto=6) + make_tcp()).decode()
    t47_p_udp = binascii.hexlify(make_eth() + make_ipv4(proto=17) + make_udp()).decode()
    t47_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_pit_l2_packet_rate_decay",
            application_category="packet_inspection_telemetry",
            difficulty="level_2",
            task_family="xdp_rate_telemetry",
            template_family="xdp_percpu_counter",
            semantic_signature="time_delta_shift+exponential_decay_stats+pass",
            diagnostic_category="verifier_rejection",
            failure_reason="Kernel verifier rejection: unsupported 64-bit integer division by non-constant variable in BPF instruction stream",
            instruction="Fix the unsupported variable division in the exponential moving rate telemetry filter by replacing the 64-bit division with a bit-shift approximation (e.g. delta >> 30). Return XDP_PASS.",
            requirements=[
                "Retrieve time from bpf_ktime_get_ns()",
                "Replace variable division with right bit-shift for decay calculation",
                "Update rate decay accumulator in per-CPU map",
                "Return XDP_PASS for all traffic",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct rate_val {
    __u64 last_ts;
    __u64 rate_acc;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct rate_val);
    __uint(max_entries, 1);
} rate_stats SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx) {
    __u64 now = bpf_ktime_get_ns();
    __u32 key = 0;
    struct rate_val *val = bpf_map_lookup_elem(&rate_stats, &key);
    if (!val)
        return XDP_PASS;

    if (val->last_ts != 0) {
        __u64 delta = now - val->last_ts;
        // Verifier issue: 64-bit variable division not supported natively without library helper
        __u64 decay_factor = (delta > 0) ? (1000000000ULL / delta) : 1;
        val->rate_acc = (val->rate_acc / (decay_factor + 1)) + 1;
    } else {
        val->rate_acc = 1;
    }
    val->last_ts = now;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""0: R1=ctx(off=0,imm=0) R10=fp0
...
18: (3f) r4 /= r2
division by zero or variable 64-bit divisor prohibited
processed 19 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
-- END PROG LOAD LOG --""",
            solution_c="""#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct rate_val {
    __u64 last_ts;
    __u64 rate_acc;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct rate_val);
    __uint(max_entries, 1);
} rate_stats SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx) {
    __u64 now = bpf_ktime_get_ns();
    __u32 key = 0;
    struct rate_val *val = bpf_map_lookup_elem(&rate_stats, &key);
    if (!val)
        return XDP_PASS;

    if (val->last_ts != 0) {
        __u64 delta = now - val->last_ts;
        __u64 shift = delta >> 30; // ~1 second per unit shift
        if (shift > 63)
            shift = 63;
        val->rate_acc = (val->rate_acc >> shift) + 1;
    } else {
        val->rate_acc = 1;
    }
    val->last_ts = now;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_tcp", "description": "Update rate stats for TCP", "packet_hex": t47_p_tcp, "expected_action": "XDP_PASS"},
                {"name": "pass_udp", "description": "Update rate stats for UDP", "packet_hex": t47_p_udp, "expected_action": "XDP_PASS"},
                {"name": "pass_arp", "description": "Update rate stats for ARP", "packet_hex": t47_p_arp, "expected_action": "XDP_PASS"},
            ],
            validator_type="map_state",
        )
    )

    # 48. repair_pit_l2_frag_header_tracker (verifier_rejection: accessing struct iphdr fields without re-checking bounds)
    t48_p_frag = binascii.hexlify(make_eth() + make_ipv4(frag_off=0x2000)).decode()
    t48_p_unfrag = binascii.hexlify(make_eth() + make_ipv4()).decode()
    t48_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_pit_l2_frag_header_tracker",
            application_category="packet_inspection_telemetry",
            difficulty="level_2",
            task_family="xdp_frag_stats",
            template_family="xdp_percpu_counter",
            semantic_signature="frag_stats_counter+pass",
            diagnostic_category="verifier_rejection",
            failure_reason="Kernel verifier rejection: accessing ip->frag_off without proving ip + 1 <= data_end",
            instruction="Fix the verifier rejection by validating the IPv4 header bounds before reading ip->frag_off. Record fragmented packets in slot 0 and unfragmented packets in slot 1 of a per-CPU map, returning XDP_PASS.",
            requirements=[
                "Check Ethernet bounds",
                "Check IPv4 bounds (ip + 1 <= data_end)",
                "Check for fragmentation (ip->frag_off & htons(0x3FFF))",
                "Record in per-CPU array map with 2 entries",
                "Return XDP_PASS for all traffic",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 2);
} frag_stats SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    // Verifier error: missing (ip + 1 <= data_end) check before reading frag_off
    __u16 frag_off = bpf_ntohs(ip->frag_off);
    __u32 slot = (frag_off & 0x3FFF) ? 0 : 1;

    __u64 *cnt = bpf_map_lookup_elem(&frag_stats, &slot);
    if (cnt)
        *cnt += 1;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""0: R1=ctx(off=0,imm=0) R10=fp0
...
6: (69) r3 = *(u16 *)(r2 +20)
invalid access to packet, id=0, off=20, size=2, R2_w=pkt(off=0,r=14,imm=0)
processed 7 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
-- END PROG LOAD LOG --""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 2);
} frag_stats SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx) {
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

    __u16 frag_off = bpf_ntohs(ip->frag_off);
    __u32 slot = (frag_off & 0x3FFF) ? 0 : 1;

    __u64 *cnt = bpf_map_lookup_elem(&frag_stats, &slot);
    if (cnt)
        *cnt += 1;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_frag", "description": "Count fragmented packet in slot 0", "packet_hex": t48_p_frag, "expected_action": "XDP_PASS"},
                {"name": "pass_unfrag", "description": "Count unfragmented in slot 1", "packet_hex": t48_p_unfrag, "expected_action": "XDP_PASS"},
                {"name": "pass_arp", "description": "Pass ARP frame unchanged", "packet_hex": t48_p_arp, "expected_action": "XDP_PASS"},
            ],
            validator_type="map_state",
        )
    )

    # 49. repair_pit_l2_syn_fin_ratio (behavioral_logic_bug: swapped slot indices for SYN vs FIN)
    t49_p_syn = binascii.hexlify(make_eth() + make_ipv4(proto=6) + make_tcp(flags=0x02)).decode()
    t49_p_fin = binascii.hexlify(make_eth() + make_ipv4(proto=6) + make_tcp(flags=0x01)).decode()
    t49_p_ack = binascii.hexlify(make_eth() + make_ipv4(proto=6) + make_tcp(flags=0x10)).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_pit_l2_syn_fin_ratio",
            application_category="packet_inspection_telemetry",
            difficulty="level_2",
            task_family="xdp_tcp_ratio",
            template_family="xdp_percpu_counter",
            semantic_signature="syn_slot_0_fin_slot_1+ratio_stats+pass",
            diagnostic_category="behavioral_logic_bug",
            failure_reason="Behavioral bug: swapped map slot indices (SYN was stored in slot 1 and FIN in slot 0)",
            instruction="Fix the slot assignment bug in the TCP SYN/FIN ratio telemetry program. Store SYN packets in slot 0 and FIN packets in slot 1 of syn_fin_stats array map, returning XDP_PASS.",
            requirements=[
                "Check bounds for Ethernet, IP, and TCP headers",
                "Store TCP SYN in slot 0; store TCP FIN in slot 1",
                "Do not count other flags (ACK only, RST only, UDP)",
                "Return XDP_PASS for all traffic",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 2);
} syn_fin_stats SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx) {
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

    __u32 ip_len = (__u32)ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip_len;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    // Behavioral bug: swapped slots
    if (tcp->syn) {
        __u32 slot = 1;
        __u64 *cnt = bpf_map_lookup_elem(&syn_fin_stats, &slot);
        if (cnt)
            *cnt += 1;
    } else if (tcp->fin) {
        __u32 slot = 0;
        __u64 *cnt = bpf_map_lookup_elem(&syn_fin_stats, &slot);
        if (cnt)
            *cnt += 1;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""FAIL: test_case 'track_syn' failed:
  Expected map syn_fin_stats[0] = 1, syn_fin_stats[1] = 0
  Observed map syn_fin_stats[0] = 0, syn_fin_stats[1] = 1 (SYN was incremented in FIN slot 1)
1 of 3 test cases failed.""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 2);
} syn_fin_stats SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx) {
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

    __u32 ip_len = (__u32)ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip_len;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    if (tcp->syn) {
        __u32 slot = 0;
        __u64 *cnt = bpf_map_lookup_elem(&syn_fin_stats, &slot);
        if (cnt)
            *cnt += 1;
    } else if (tcp->fin) {
        __u32 slot = 1;
        __u64 *cnt = bpf_map_lookup_elem(&syn_fin_stats, &slot);
        if (cnt)
            *cnt += 1;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_syn", "description": "Count SYN in slot 0", "packet_hex": t49_p_syn, "expected_action": "XDP_PASS"},
                {"name": "pass_fin", "description": "Count FIN in slot 1", "packet_hex": t49_p_fin, "expected_action": "XDP_PASS"},
                {"name": "pass_ack", "description": "Pass ACK without updating ratio stats", "packet_hex": t49_p_ack, "expected_action": "XDP_PASS"},
            ],
            validator_type="map_state",
        )
    )

    # 50. repair_pit_l2_tos_diffserv_metrics (behavioral_logic_bug: wrong bitmask for DSCP in IPv4 TOS byte)
    t50_p_ef = binascii.hexlify(make_eth() + make_ipv4(tos=0xB8)).decode() # DSCP EF (46 = 0x2E, shifted left 2 is 0xB8)
    t50_p_be = binascii.hexlify(make_eth() + make_ipv4(tos=0x00)).decode() # DSCP BE (0)
    t50_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_pit_l2_tos_diffserv_metrics",
            application_category="packet_inspection_telemetry",
            difficulty="level_2",
            task_family="xdp_diffserv_stats",
            template_family="xdp_percpu_counter",
            semantic_signature="dscp_tos_64_buckets+telemetry+pass",
            diagnostic_category="behavioral_logic_bug",
            failure_reason="Behavioral bug: DSCP extracted without right-shift by 2, causing out-of-range DSCP values to miss histogram buckets",
            instruction="Fix the DSCP extraction logic in the DiffServ telemetry program. Extract the 6-bit DSCP field (ip->tos >> 2) and record it in a 64-entry per-CPU array map, returning XDP_PASS.",
            requirements=[
                "Check bounds for Ethernet and IPv4 headers",
                "Extract DSCP: (ip->tos >> 2) & 63",
                "Increment dscp_stats map at key = dscp",
                "Return XDP_PASS for all traffic",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 64);
} dscp_stats SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx) {
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

    // Behavioral bug: masked 0xFC without shifting right by 2
    __u32 dscp = (ip->tos & 0xFC) & 63;

    __u64 *cnt = bpf_map_lookup_elem(&dscp_stats, &dscp);
    if (cnt)
        *cnt += 1;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""FAIL: test_case 'track_dscp_ef' failed:
  Expected map dscp_stats[46] = 1 (DSCP EF 46 / 0x2E)
  Observed map dscp_stats[46] = 0, dscp_stats[56] = 1 (wrong bit alignment without >> 2)
1 of 3 test cases failed.""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 64);
} dscp_stats SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx) {
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

    __u32 dscp = (ip->tos >> 2) & 63;

    __u64 *cnt = bpf_map_lookup_elem(&dscp_stats, &dscp);
    if (cnt)
        *cnt += 1;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_dscp_ef", "description": "Count DSCP EF (46) in slot 46", "packet_hex": t50_p_ef, "expected_action": "XDP_PASS"},
                {"name": "pass_dscp_be", "description": "Count DSCP BE (0) in slot 0", "packet_hex": t50_p_be, "expected_action": "XDP_PASS"},
                {"name": "pass_arp", "description": "Pass ARP frame unchanged", "packet_hex": t50_p_arp, "expected_action": "XDP_PASS"},
            ],
            validator_type="map_state",
        )
    )

    # =========================================================================
    # LEVEL 3 (10 tasks: 4 compilation, 4 verifier, 2 behavioral)
    # =========================================================================

    # 51. repair_pit_l3_five_tuple_hash_stats (compilation_error: struct layout mismatch with padding in 5-tuple hash key)
    t51_p_tcp1 = binascii.hexlify(make_eth() + make_ipv4(src_ip="10.0.0.1", proto=6) + make_tcp(src_port=5000, dst_port=80)).decode()
    t51_p_tcp2 = binascii.hexlify(make_eth() + make_ipv4(src_ip="10.0.0.2", proto=6) + make_tcp(src_port=5001, dst_port=80)).decode()
    t51_p_udp = binascii.hexlify(make_eth() + make_ipv4(src_ip="10.0.0.1", proto=17) + make_udp()).decode()
    t51_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_pit_l3_five_tuple_hash_stats",
            application_category="packet_inspection_telemetry",
            difficulty="level_3",
            task_family="xdp_flow_telemetry",
            template_family="xdp_hash_map_filter",
            semantic_signature="ipv4+5tuple_packet_byte_tracker+pass",
            diagnostic_category="compilation_error",
            failure_reason="Compilation error: member access into struct pointer with typo 's_addr' instead of 'saddr'",
            instruction="Fix the field name typos in the 5-tuple struct population. Maintain per-flow packet and byte counts in a BPF hash map, returning XDP_PASS.",
            requirements=[
                "Define struct flow_key with saddr, daddr, sport, dport, proto",
                "Define struct flow_val with packets and bytes",
                "Track IPv4 TCP/UDP flows in a 65536-entry hash map",
                "Return XDP_PASS for all packets",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct flow_key {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8 proto;
    __u8 pad[3];
};

struct flow_val {
    __u64 packets;
    __u64 bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct flow_key);
    __type(value, struct flow_val);
    __uint(max_entries, 65536);
} flow_stats SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx) {
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

    __u32 ip_len = (__u32)ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct flow_key key = {0};
    // Compilation error: struct member typo s_addr
    key.s_addr = ip->saddr;
    key.d_addr = ip->daddr;
    key.proto = ip->protocol;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + ip_len;
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        key.sport = tcp->source;
        key.dport = tcp->dest;
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + ip_len;
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        key.sport = udp->source;
        key.dport = udp->dest;
    } else {
        return XDP_PASS;
    }

    struct flow_val *val = bpf_map_lookup_elem(&flow_stats, &key);
    if (val) {
        val->packets += 1;
        val->bytes += (__u64)(data_end - data);
    } else {
        struct flow_val init = {.packets = 1, .bytes = (__u64)(data_end - data)};
        bpf_map_update_elem(&flow_stats, &key, &init, BPF_ANY);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""faulty.c:48:9: error: no member named 's_addr' in 'struct flow_key'; did you mean 'saddr'?
    key.s_addr = ip->saddr;
        ^~~~~~
        saddr
faulty.c:13:11: note: 'saddr' declared here
    __u32 saddr;
          ^
faulty.c:49:9: error: no member named 'd_addr' in 'struct flow_key'; did you mean 'daddr'?
    key.d_addr = ip->daddr;
        ^~~~~~
        daddr
2 errors generated.""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct flow_key {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8 proto;
    __u8 pad[3];
};

struct flow_val {
    __u64 packets;
    __u64 bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct flow_key);
    __type(value, struct flow_val);
    __uint(max_entries, 65536);
} flow_stats SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx) {
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

    __u32 ip_len = (__u32)ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct flow_key key = {0};
    key.saddr = ip->saddr;
    key.daddr = ip->daddr;
    key.proto = ip->protocol;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + ip_len;
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        key.sport = tcp->source;
        key.dport = tcp->dest;
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + ip_len;
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        key.sport = udp->source;
        key.dport = udp->dest;
    } else {
        return XDP_PASS;
    }

    struct flow_val *val = bpf_map_lookup_elem(&flow_stats, &key);
    if (val) {
        val->packets += 1;
        val->bytes += (__u64)(data_end - data);
    } else {
        struct flow_val init = {.packets = 1, .bytes = (__u64)(data_end - data)};
        bpf_map_update_elem(&flow_stats, &key, &init, BPF_ANY);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_flow_tcp1", "description": "Track flow TCP 1", "packet_hex": t51_p_tcp1, "expected_action": "XDP_PASS"},
                {"name": "pass_flow_tcp2", "description": "Track flow TCP 2", "packet_hex": t51_p_tcp2, "expected_action": "XDP_PASS"},
                {"name": "pass_flow_udp", "description": "Track flow UDP", "packet_hex": t51_p_udp, "expected_action": "XDP_PASS"},
                {"name": "pass_arp", "description": "Pass non-IP ARP frame", "packet_hex": t51_p_arp, "expected_action": "XDP_PASS"},
            ],
            validator_type="map_state",
        )
    )

    # 52. repair_pit_l3_tcp_rtt_estimator (compilation_error: missing helper declaration bpf_ktime_get_ns)
    t52_p_syn = binascii.hexlify(make_eth() + make_ipv4(src_ip="10.0.0.1", proto=6) + make_tcp(dst_port=80, flags=0x02, seq=1000)).decode()
    t52_p_ack = binascii.hexlify(make_eth() + make_ipv4(src_ip="10.0.0.1", proto=6) + make_tcp(dst_port=80, flags=0x10, ack=1001)).decode()
    t52_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_pit_l3_tcp_rtt_estimator",
            application_category="packet_inspection_telemetry",
            difficulty="level_3",
            task_family="xdp_rtt_stats",
            template_family="xdp_hash_map_filter",
            semantic_signature="syn_ack_seq_match+rtt_telemetry+pass",
            diagnostic_category="compilation_error",
            failure_reason="Compilation error: implicit declaration of function 'bpf_ktime_get_ns' due to missing helper include",
            instruction="Fix the missing helper declaration to implement the handshake RTT tracker. Record timestamp on SYN and calculate round-trip delta upon receiving the matching ACK.",
            requirements=[
                "Include <bpf/bpf_helpers.h>",
                "Record SYN arrival time in LRU map keyed by (saddr, sport, dport)",
                "Calculate delta in nanoseconds on matching ACK",
                "Store RTT in rtt_hist map and return XDP_PASS",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>

struct syn_key {
    __u32 saddr;
    __u16 sport;
    __u16 dport;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct syn_key);
    __type(value, __u64);
    __uint(max_entries, 16384);
} syn_ts_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 64);
} rtt_hist SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx) {
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

    __u32 ip_len = (__u32)ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip_len;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    struct syn_key key = {
        .saddr = ip->saddr,
        .sport = tcp->source,
        .dport = tcp->dest,
    };

    if (tcp->syn && !tcp->ack) {
        // Missing bpf/bpf_helpers.h
        __u64 now = bpf_ktime_get_ns();
        bpf_map_update_elem(&syn_ts_map, &key, &now, BPF_ANY);
    } else if (tcp->ack && !tcp->syn) {
        __u64 *ts = bpf_map_lookup_elem(&syn_ts_map, &key);
        if (ts) {
            __u64 now = bpf_ktime_get_ns();
            __u64 rtt_us = (now > *ts) ? ((now - *ts) / 1000) : 0;
            __u32 bucket = (rtt_us < 64) ? (__u32)rtt_us : 63;
            __u64 *cnt = bpf_map_lookup_elem(&rtt_hist, &bucket);
            if (cnt)
                *cnt += 1;
            bpf_map_delete_elem(&syn_ts_map, &key);
        }
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""faulty.c:57:21: error: call to undeclared function 'bpf_ktime_get_ns'; ISO C99 and later do not support implicit function declarations [-Wimplicit-function-declaration]
        __u64 now = bpf_ktime_get_ns();
                    ^
faulty.c:58:9: error: call to undeclared function 'bpf_map_update_elem'; ISO C99 and later do not support implicit function declarations [-Wimplicit-function-declaration]
        bpf_map_update_elem(&syn_ts_map, &key, &now, BPF_ANY);
        ^
2 errors generated.""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct syn_key {
    __u32 saddr;
    __u16 sport;
    __u16 dport;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct syn_key);
    __type(value, __u64);
    __uint(max_entries, 16384);
} syn_ts_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 64);
} rtt_hist SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx) {
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

    __u32 ip_len = (__u32)ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip_len;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    struct syn_key key = {
        .saddr = ip->saddr,
        .sport = tcp->source,
        .dport = tcp->dest,
    };

    if (tcp->syn && !tcp->ack) {
        __u64 now = bpf_ktime_get_ns();
        bpf_map_update_elem(&syn_ts_map, &key, &now, BPF_ANY);
    } else if (tcp->ack && !tcp->syn) {
        __u64 *ts = bpf_map_lookup_elem(&syn_ts_map, &key);
        if (ts) {
            __u64 now = bpf_ktime_get_ns();
            __u64 rtt_us = (now > *ts) ? ((now - *ts) / 1000) : 0;
            __u32 bucket = (rtt_us < 64) ? (__u32)rtt_us : 63;
            __u64 *cnt = bpf_map_lookup_elem(&rtt_hist, &bucket);
            if (cnt)
                *cnt += 1;
            bpf_map_delete_elem(&syn_ts_map, &key);
        }
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_syn", "description": "Track SYN arrival time", "packet_hex": t52_p_syn, "expected_action": "XDP_PASS"},
                {"name": "pass_ack", "description": "Track matching ACK and update RTT", "packet_hex": t52_p_ack, "expected_action": "XDP_PASS"},
                {"name": "pass_arp", "description": "Pass ARP frame unchanged", "packet_hex": t52_p_arp, "expected_action": "XDP_PASS"},
            ],
            validator_type="map_state",
        )
    )

    # 53. repair_pit_l3_vlan_hierarchy_metrics (compilation_error: nested struct dereference syntax error)
    t53_p_vlan_ipv4 = binascii.hexlify(make_eth(vlan=100) + make_ipv4()).decode()
    t53_p_qinq_ipv4 = binascii.hexlify(make_eth(vlan=100, vlan_inner=200) + make_ipv4()).decode()
    t53_p_untag_ipv4 = binascii.hexlify(make_eth() + make_ipv4()).decode()
    t53_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_pit_l3_vlan_hierarchy_metrics",
            application_category="packet_inspection_telemetry",
            difficulty="level_3",
            task_family="xdp_vlan_hierarchy",
            template_family="xdp_percpu_counter",
            semantic_signature="untag_single_double_vlan+packet_byte_stats+pass",
            diagnostic_category="compilation_error",
            failure_reason="Compilation error: undefined identifier 'eth_proto' caused by variable scoping bug in loop",
            instruction="Fix the variable scoping and declaration in the hierarchical VLAN telemetry program. Count packets and bytes across untagged (0), single-tagged (1), double-tagged (2), and other (3) frames.",
            requirements=[
                "Track untagged, single-tagged, and double-tagged VLAN frames",
                "Update both packet and byte counters in a per-CPU array map",
                "Ensure bounds are checked across VLAN parsing layers",
                "Return XDP_PASS for all traffic",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

struct vlan_stats {
    __u64 packets;
    __u64 bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct vlan_stats);
    __uint(max_entries, 4);
} vlan_metrics SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u32 vlan_count = 0;
    void *nh = (void *)(eth + 1);

    {
        // Compilation error: scoped variable used outside block
        __u16 eth_proto = bpf_ntohs(eth->h_proto);
        if (eth_proto == ETH_P_8021Q || eth_proto == 0x88A8) {
            struct vlan_hdr *vlh = nh;
            if ((void *)(vlh + 1) <= data_end) {
                vlan_count++;
                eth_proto = bpf_ntohs(vlh->h_vlan_encapsulated_proto);
                nh = (void *)(vlh + 1);
                if (eth_proto == ETH_P_8021Q || eth_proto == 0x88A8) {
                    struct vlan_hdr *vlh2 = nh;
                    if ((void *)(vlh2 + 1) <= data_end) {
                        vlan_count++;
                    }
                }
            }
        }
    }

    __u32 slot = (vlan_count < 3) ? vlan_count : 3;
    struct vlan_stats *st = bpf_map_lookup_elem(&vlan_metrics, &slot);
    if (st) {
        st->packets += 1;
        st->bytes += (__u64)(data_end - data);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""faulty.c:48:19: error: use of undeclared identifier 'eth_proto'
    if (eth_proto == ETH_P_IP)
        ^
1 error generated.""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

struct vlan_stats {
    __u64 packets;
    __u64 bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct vlan_stats);
    __uint(max_entries, 4);
} vlan_metrics SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u32 vlan_count = 0;
    void *nh = (void *)(eth + 1);
    __u16 eth_proto = bpf_ntohs(eth->h_proto);

    if (eth_proto == ETH_P_8021Q || eth_proto == 0x88A8) {
        struct vlan_hdr *vlh = nh;
        if ((void *)(vlh + 1) <= data_end) {
            vlan_count++;
            eth_proto = bpf_ntohs(vlh->h_vlan_encapsulated_proto);
            nh = (void *)(vlh + 1);
            if (eth_proto == ETH_P_8021Q || eth_proto == 0x88A8) {
                struct vlan_hdr *vlh2 = nh;
                if ((void *)(vlh2 + 1) <= data_end) {
                    vlan_count++;
                }
            }
        }
    }

    __u32 slot = (vlan_count < 3) ? vlan_count : 3;
    struct vlan_stats *st = bpf_map_lookup_elem(&vlan_metrics, &slot);
    if (st) {
        st->packets += 1;
        st->bytes += (__u64)(data_end - data);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_untagged", "description": "Count untagged frame in slot 0", "packet_hex": t53_p_untag_ipv4, "expected_action": "XDP_PASS"},
                {"name": "pass_single_vlan", "description": "Count single VLAN frame in slot 1", "packet_hex": t53_p_vlan_ipv4, "expected_action": "XDP_PASS"},
                {"name": "pass_qinq_vlan", "description": "Count QinQ double VLAN in slot 2", "packet_hex": t53_p_qinq_ipv4, "expected_action": "XDP_PASS"},
                {"name": "pass_arp", "description": "Count untagged ARP in slot 0", "packet_hex": t53_p_arp, "expected_action": "XDP_PASS"},
            ],
            validator_type="map_state",
        )
    )

    # 54. repair_pit_l3_session_bandwidth_map (compilation_error: missing type cast in map update)
    t54_p_tcp = binascii.hexlify(make_eth() + make_ipv4(src_ip="192.168.1.10", proto=6) + make_tcp(src_port=4000, dst_port=80)).decode()
    t54_p_udp = binascii.hexlify(make_eth() + make_ipv4(src_ip="192.168.1.10", proto=17) + make_udp(src_port=4000, dst_port=53)).decode()
    t54_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_pit_l3_session_bandwidth_map",
            application_category="packet_inspection_telemetry",
            difficulty="level_3",
            task_family="xdp_session_bandwidth",
            template_family="xdp_hash_map_filter",
            semantic_signature="session_bandwidth_meter+pass",
            diagnostic_category="compilation_error",
            failure_reason="Compilation error: passing incompatible pointer type to bpf_map_update_elem",
            instruction="Fix the pointer argument types in the session bandwidth metering filter. Maintain a session bandwidth table in a BPF hash map, recording packet size and update timestamps.",
            requirements=[
                "Define session key struct (saddr, sport, proto)",
                "Define session value struct (last_seen, total_bytes)",
                "Update session state on incoming packets and return XDP_PASS",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct session_key {
    __u32 saddr;
    __u16 sport;
    __u8 proto;
    __u8 pad;
};

struct session_val {
    __u64 last_seen;
    __u64 total_bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct session_key);
    __type(value, struct session_val);
    __uint(max_entries, 16384);
} session_map SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx) {
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

    __u32 ip_len = (__u32)ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct session_key key = {0};
    key.saddr = ip->saddr;
    key.proto = ip->protocol;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + ip_len;
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        key.sport = tcp->source;
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + ip_len;
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        key.sport = udp->source;
    } else {
        return XDP_PASS;
    }

    __u64 now = bpf_ktime_get_ns();
    __u64 wire_len = (__u64)(data_end - data);

    struct session_val *val = bpf_map_lookup_elem(&session_map, &key);
    if (val) {
        val->last_seen = now;
        val->total_bytes += wire_len;
    } else {
        struct session_val init = {.last_seen = now, .total_bytes = wire_len};
        // Compilation error: passing struct instead of pointer to &init
        bpf_map_update_elem(&session_map, &key, init, BPF_ANY);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""faulty.c:75:49: error: passing 'struct session_val' to parameter of type 'const void *' [-Werror,-Wint-conversion]
        bpf_map_update_elem(&session_map, &key, init, BPF_ANY);
                                                ^~~~
/usr/include/bpf/bpf_helper_defs.h:42:61: note: passing argument to parameter 'value' here
long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *) 2;
                                                            ^
1 error generated.""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct session_key {
    __u32 saddr;
    __u16 sport;
    __u8 proto;
    __u8 pad;
};

struct session_val {
    __u64 last_seen;
    __u64 total_bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct session_key);
    __type(value, struct session_val);
    __uint(max_entries, 16384);
} session_map SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx) {
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

    __u32 ip_len = (__u32)ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct session_key key = {0};
    key.saddr = ip->saddr;
    key.proto = ip->protocol;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + ip_len;
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        key.sport = tcp->source;
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + ip_len;
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        key.sport = udp->source;
    } else {
        return XDP_PASS;
    }

    __u64 now = bpf_ktime_get_ns();
    __u64 wire_len = (__u64)(data_end - data);

    struct session_val *val = bpf_map_lookup_elem(&session_map, &key);
    if (val) {
        val->last_seen = now;
        val->total_bytes += wire_len;
    } else {
        struct session_val init = {.last_seen = now, .total_bytes = wire_len};
        bpf_map_update_elem(&session_map, &key, &init, BPF_ANY);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_tcp_session", "description": "Track TCP session bandwidth", "packet_hex": t54_p_tcp, "expected_action": "XDP_PASS"},
                {"name": "pass_udp_session", "description": "Track UDP session bandwidth", "packet_hex": t54_p_udp, "expected_action": "XDP_PASS"},
                {"name": "pass_arp", "description": "Pass ARP frame unchanged", "packet_hex": t54_p_arp, "expected_action": "XDP_PASS"},
            ],
            validator_type="map_state",
        )
    )

    # 55. repair_pit_l3_flow_session_lifecycle (verifier_rejection: stack frame size > 512 bytes)
    t55_p_tcp = binascii.hexlify(make_eth() + make_ipv4(src_ip="10.0.0.1", proto=6) + make_tcp(src_port=1234, dst_port=80)).decode()
    t55_p_udp = binascii.hexlify(make_eth() + make_ipv4(src_ip="10.0.0.2", proto=17) + make_udp(src_port=1234, dst_port=53)).decode()
    t55_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_pit_l3_flow_session_lifecycle",
            application_category="packet_inspection_telemetry",
            difficulty="level_3",
            task_family="xdp_flow_lifecycle",
            template_family="xdp_hash_map_filter",
            semantic_signature="flow_lifecycle_record+pass",
            diagnostic_category="verifier_rejection",
            failure_reason="Kernel verifier rejection: stack frame limit of 512 bytes exceeded by large local struct on stack",
            instruction="Fix the kernel verifier stack limit error by reducing local structure sizes on the stack. Track flow session lifecycle state in a BPF hash map, returning XDP_PASS.",
            requirements=[
                "Keep stack frame allocation under 512 bytes",
                "Track 5-tuple flow in flow_lifecycle hash map",
                "Record start timestamp, end timestamp, packet count, and byte count",
                "Return XDP_PASS for all traffic",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct flow_key {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8 proto;
    __u8 pad[3];
};

struct lifecycle_record {
    __u64 start_ts;
    __u64 last_ts;
    __u64 packets;
    __u64 bytes;
    char payload_sample[512]; // Verifier issue: 512-byte buffer inside struct causes stack overflow
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct flow_key);
    __type(value, struct lifecycle_record);
    __uint(max_entries, 16384);
} flow_lifecycle SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx) {
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

    __u32 ip_len = (__u32)ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct flow_key key = {0};
    key.saddr = ip->saddr;
    key.daddr = ip->daddr;
    key.proto = ip->protocol;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + ip_len;
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        key.sport = tcp->source;
        key.dport = tcp->dest;
    }

    struct lifecycle_record *val = bpf_map_lookup_elem(&flow_lifecycle, &key);
    if (val) {
        val->last_ts = bpf_ktime_get_ns();
        val->packets += 1;
        val->bytes += (__u64)(data_end - data);
    } else {
        struct lifecycle_record init = {0};
        init.start_ts = bpf_ktime_get_ns();
        init.last_ts = init.start_ts;
        init.packets = 1;
        init.bytes = (__u64)(data_end - data);
        bpf_map_update_elem(&flow_lifecycle, &key, &init, BPF_ANY);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""Looks like the BPF stack limit of 512 bytes is exceeded.
The following functions exceed the limit:
xdp_telemetry: stack frame size is 584 bytes
processed 0 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
-- END PROG LOAD LOG --""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct flow_key {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8 proto;
    __u8 pad[3];
};

struct lifecycle_record {
    __u64 start_ts;
    __u64 last_ts;
    __u64 packets;
    __u64 bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct flow_key);
    __type(value, struct lifecycle_record);
    __uint(max_entries, 16384);
} flow_lifecycle SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx) {
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

    __u32 ip_len = (__u32)ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct flow_key key = {0};
    key.saddr = ip->saddr;
    key.daddr = ip->daddr;
    key.proto = ip->protocol;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + ip_len;
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        key.sport = tcp->source;
        key.dport = tcp->dest;
    }

    struct lifecycle_record *val = bpf_map_lookup_elem(&flow_lifecycle, &key);
    if (val) {
        val->last_ts = bpf_ktime_get_ns();
        val->packets += 1;
        val->bytes += (__u64)(data_end - data);
    } else {
        struct lifecycle_record init = {0};
        init.start_ts = bpf_ktime_get_ns();
        init.last_ts = init.start_ts;
        init.packets = 1;
        init.bytes = (__u64)(data_end - data);
        bpf_map_update_elem(&flow_lifecycle, &key, &init, BPF_ANY);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_tcp", "description": "Track TCP flow lifecycle", "packet_hex": t55_p_tcp, "expected_action": "XDP_PASS"},
                {"name": "pass_udp", "description": "Track UDP flow lifecycle", "packet_hex": t55_p_udp, "expected_action": "XDP_PASS"},
                {"name": "pass_arp", "description": "Pass ARP frame unchanged", "packet_hex": t55_p_arp, "expected_action": "XDP_PASS"},
            ],
            validator_type="map_state",
        )
    )

    # 56. repair_pit_l3_jitter_ringbuf_logger (verifier_rejection: bpf_ringbuf_reserve return pointer dereferenced without NULL check)
    t56_p_tcp = binascii.hexlify(make_eth() + make_ipv4(src_ip="10.0.0.1", proto=6) + make_tcp()).decode()
    t56_p_udp = binascii.hexlify(make_eth() + make_ipv4(src_ip="10.0.0.2", proto=17) + make_udp()).decode()
    t56_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_pit_l3_jitter_ringbuf_logger",
            application_category="packet_inspection_telemetry",
            difficulty="level_3",
            task_family="xdp_ringbuf_telemetry",
            template_family="xdp_ringbuf_logger",
            semantic_signature="packet_event+ringbuf_output+pass",
            diagnostic_category="verifier_rejection",
            failure_reason="Kernel verifier rejection: R0 invalid mem access 'mem_or_null' when writing event to reserved ringbuf slot",
            instruction="Fix the verifier rejection by verifying that the pointer returned by bpf_ringbuf_reserve is not NULL before populating event fields and submitting to the ring buffer. Return XDP_PASS.",
            requirements=[
                "Define BPF_MAP_TYPE_RINGBUF map named events_rb",
                "Reserve memory for struct packet_event with bpf_ringbuf_reserve",
                "Check reserved pointer for NULL",
                "Populate timestamp and length, then submit with bpf_ringbuf_submit",
                "Return XDP_PASS for all traffic",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct packet_event {
    __u64 ts;
    __u32 len;
    __u32 ifindex;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events_rb SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx) {
    struct packet_event *evt = bpf_ringbuf_reserve(&events_rb, sizeof(*evt), 0);
    // Verifier error: evt dereferenced directly without NULL check
    evt->ts = bpf_ktime_get_ns();
    evt->len = (__u32)((long)ctx->data_end - (long)ctx->data);
    evt->ifindex = ctx->ingress_ifindex;

    bpf_ringbuf_submit(evt, 0);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""0: R1=ctx(off=0,imm=0) R10=fp0
...
4: (85) call bpf_ringbuf_reserve#131
5: R0=mem_or_null(id=1,ref_obj_id=1,off=0,r=0,size=16)
; evt->ts = bpf_ktime_get_ns();
6: (85) call bpf_ktime_get_ns#5
7: (7b) *(u64 *)(r0 +0) = r0
R0 invalid mem access 'mem_or_null'
processed 8 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
-- END PROG LOAD LOG --""",
            solution_c="""#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct packet_event {
    __u64 ts;
    __u32 len;
    __u32 ifindex;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events_rb SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx) {
    struct packet_event *evt = bpf_ringbuf_reserve(&events_rb, sizeof(*evt), 0);
    if (!evt)
        return XDP_PASS;

    evt->ts = bpf_ktime_get_ns();
    evt->len = (__u32)((long)ctx->data_end - (long)ctx->data);
    evt->ifindex = ctx->ingress_ifindex;

    bpf_ringbuf_submit(evt, 0);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_tcp", "description": "Log TCP packet event to ringbuf", "packet_hex": t56_p_tcp, "expected_action": "XDP_PASS"},
                {"name": "pass_udp", "description": "Log UDP packet event to ringbuf", "packet_hex": t56_p_udp, "expected_action": "XDP_PASS"},
                {"name": "pass_arp", "description": "Log ARP packet event to ringbuf", "packet_hex": t56_p_arp, "expected_action": "XDP_PASS"},
            ],
            validator_type="packet_action",
        )
    )

    # 57. repair_pit_l3_ip_options_telemetry (verifier_rejection: unbounded loop while parsing variable IPv4 options)
    t57_p_opts = binascii.hexlify(make_eth() + make_ipv4(ihl=7, payload=b"\x01\x01\x01\x01\x00\x00\x00\x00" + make_tcp())).decode()
    t57_p_no_opts = binascii.hexlify(make_eth() + make_ipv4(ihl=5, payload=make_tcp())).decode()
    t57_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_pit_l3_ip_options_telemetry",
            application_category="packet_inspection_telemetry",
            difficulty="level_3",
            task_family="xdp_ip_options_stats",
            template_family="xdp_percpu_counter",
            semantic_signature="ip_options_parser+bounded_loop+pass",
            diagnostic_category="verifier_rejection",
            failure_reason="Kernel verifier rejection: back-edge / loop detected while parsing variable length IPv4 options list",
            instruction="Fix the verifier loop rejection by unrolling the option parsing loop with a static upper bound (#pragma unroll max 10 bytes). Count IP options types in an options_stats map and return XDP_PASS.",
            requirements=[
                "Check Ethernet and IPv4 bounds",
                "Parse IP options up to 40 bytes with statically bounded loop",
                "Ensure (opt_ptr + 1 <= data_end) before reading option type",
                "Record observed option types in array map options_stats",
                "Return XDP_PASS for all traffic",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 256);
} options_stats SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx) {
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

    if (ip->ihl > 5) {
        __u32 opt_len = (ip->ihl - 5) * 4;
        char *opt = (char *)(ip + 1);
        __u32 i = 0;
        // Verifier error: variable while loop without static unrolling
        while (i < opt_len && (void *)(opt + i + 1) <= data_end) {
            __u32 opt_type = (__u8)opt[i];
            __u64 *cnt = bpf_map_lookup_elem(&options_stats, &opt_type);
            if (cnt)
                *cnt += 1;
            i++;
        }
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""0: R1=ctx(off=0,imm=0) R10=fp0
...
16: (2d) if r3 > r1 goto pc+15
; while (i < opt_len ...
17: (2d) if r4 >= r5 goto pc+12
18: (0f) r2 += r4
19: (2d) if r2 > r1 goto pc+10
20: (71) r6 = *(u8 *)(r2 +0)
back-edge from insn 25 to 17
processed 26 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
-- END PROG LOAD LOG --""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 256);
} options_stats SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx) {
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

    if (ip->ihl > 5) {
        char *opt = (char *)(ip + 1);
        #pragma unroll
        for (int i = 0; i < 10; i++) {
            if ((void *)(opt + i + 1) <= data_end && i < ((ip->ihl - 5) * 4)) {
                __u32 opt_type = (__u8)opt[i];
                __u64 *cnt = bpf_map_lookup_elem(&options_stats, &opt_type);
                if (cnt)
                    *cnt += 1;
            }
        }
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_with_opts", "description": "Track options in IPv4 header", "packet_hex": t57_p_opts, "expected_action": "XDP_PASS"},
                {"name": "pass_no_opts", "description": "Pass standard IPv4 without options", "packet_hex": t57_p_no_opts, "expected_action": "XDP_PASS"},
                {"name": "pass_arp", "description": "Pass ARP frame unchanged", "packet_hex": t57_p_arp, "expected_action": "XDP_PASS"},
            ],
            validator_type="map_state",
        )
    )

    # 58. repair_pit_l3_inter_arrival_time (verifier_rejection: map value pointer arithmetic causing verifier bounds loss)
    t58_p_tcp1 = binascii.hexlify(make_eth() + make_ipv4(src_ip="10.0.0.1", proto=6) + make_tcp()).decode()
    t58_p_tcp2 = binascii.hexlify(make_eth() + make_ipv4(src_ip="10.0.0.2", proto=6) + make_tcp()).decode()
    t58_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_pit_l3_inter_arrival_time",
            application_category="packet_inspection_telemetry",
            difficulty="level_3",
            task_family="xdp_inter_arrival",
            template_family="xdp_hash_map_filter",
            semantic_signature="per_src_inter_arrival_hist+pass",
            diagnostic_category="verifier_rejection",
            failure_reason="Kernel verifier rejection: bitwise shift on variable latency value causing verifier scalar range overflow",
            instruction="Fix the histogram index computation by clamping the inter-arrival delta bucket index (0..31) before querying the array map. Return XDP_PASS.",
            requirements=[
                "Compute inter-arrival delta = now - last_ts",
                "Calculate logarithmic bucket index safely: (delta >> 20) & 31",
                "Update iat_hist map and src_ts_map",
                "Return XDP_PASS for all traffic",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 4096);
} src_ts_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 32);
} iat_hist SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx) {
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

    __u32 src = ip->saddr;
    __u64 now = bpf_ktime_get_ns();

    __u64 *last = bpf_map_lookup_elem(&src_ts_map, &src);
    if (last && *last != 0 && now > *last) {
        __u64 delta = now - *last;
        // Verifier issue: unbounded bucket index
        __u32 bucket = delta >> 20;
        __u64 *cnt = bpf_map_lookup_elem(&iat_hist, &bucket);
        if (cnt)
            *cnt += 1;
    }
    bpf_map_update_elem(&src_ts_map, &src, &now, BPF_ANY);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""0: R1=ctx(off=0,imm=0) R10=fp0
...
22: (74) r1 >>= 20
23: (63) *(u32 *)(r10 -4) = r1
; __u64 *cnt = bpf_map_lookup_elem(&iat_hist, &bucket);
24: (bf) r2 = r10
25: (07) r2 += -4
26: (18) r1 = 0xffff8880042a8000
28: (85) call bpf_map_lookup_elem#1
R2 invalid map access into array map, key out of range (max 32)
processed 29 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
-- END PROG LOAD LOG --""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 4096);
} src_ts_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 32);
} iat_hist SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx) {
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

    __u32 src = ip->saddr;
    __u64 now = bpf_ktime_get_ns();

    __u64 *last = bpf_map_lookup_elem(&src_ts_map, &src);
    if (last && *last != 0 && now > *last) {
        __u64 delta = now - *last;
        __u32 bucket = (delta >> 20) & 31;
        __u64 *cnt = bpf_map_lookup_elem(&iat_hist, &bucket);
        if (cnt)
            *cnt += 1;
    }
    bpf_map_update_elem(&src_ts_map, &src, &now, BPF_ANY);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_tcp1", "description": "Track inter-arrival for source 1", "packet_hex": t58_p_tcp1, "expected_action": "XDP_PASS"},
                {"name": "pass_tcp2", "description": "Track inter-arrival for source 2", "packet_hex": t58_p_tcp2, "expected_action": "XDP_PASS"},
                {"name": "pass_arp", "description": "Pass ARP frame unchanged", "packet_hex": t58_p_arp, "expected_action": "XDP_PASS"},
            ],
            validator_type="map_state",
        )
    )

    # 59. repair_pit_l3_flow_byte_quota_meter (behavioral_logic_bug: byte counter added truncated wire length instead of ip->tot_len)
    t59_p_tcp1 = binascii.hexlify(make_eth() + make_ipv4(src_ip="10.1.1.1", proto=6, payload=b"HELLO_WORLD_1234")).decode()
    t59_p_tcp2 = binascii.hexlify(make_eth() + make_ipv4(src_ip="10.1.1.2", proto=6, payload=b"ANOTHER_PACKET")).decode()
    t59_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_pit_l3_flow_byte_quota_meter",
            application_category="packet_inspection_telemetry",
            difficulty="level_3",
            task_family="xdp_flow_meter",
            template_family="xdp_hash_map_filter",
            semantic_signature="per_src_ip_tot_len_accumulator+pass",
            diagnostic_category="behavioral_logic_bug",
            failure_reason="Behavioral bug: accumulated host-endian constant without bpf_ntohs on ip->tot_len",
            instruction="Fix the byte-order extraction of ip->tot_len when accumulating source IP bandwidth quota in the meter map. Return XDP_PASS.",
            requirements=[
                "Check Ethernet and IPv4 bounds",
                "Convert ip->tot_len with bpf_ntohs before accumulating bytes",
                "Update src_meter hash map with packet count and total IP bytes",
                "Return XDP_PASS for all traffic",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct meter_val {
    __u64 packets;
    __u64 ip_bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct meter_val);
    __uint(max_entries, 1024);
} src_meter SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx) {
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

    __u32 src = ip->saddr;
    // Behavioral bug: missing bpf_ntohs on tot_len (raw network order)
    __u64 ip_len = (__u64)ip->tot_len;

    struct meter_val *val = bpf_map_lookup_elem(&src_meter, &src);
    if (val) {
        val->packets += 1;
        val->ip_bytes += ip_len;
    } else {
        struct meter_val init = {.packets = 1, .ip_bytes = ip_len};
        bpf_map_update_elem(&src_meter, &src, &init, BPF_ANY);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""FAIL: test_case 'track_ip_tot_len' failed:
  Expected map src_meter[10.1.1.1].ip_bytes = 56 bytes
  Observed map src_meter[10.1.1.1].ip_bytes = 14336 bytes (network byte order 0x3800 instead of 56 / 0x0038)
1 of 3 test cases failed.""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct meter_val {
    __u64 packets;
    __u64 ip_bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct meter_val);
    __uint(max_entries, 1024);
} src_meter SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx) {
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

    __u32 src = ip->saddr;
    __u64 ip_len = (__u64)bpf_ntohs(ip->tot_len);

    struct meter_val *val = bpf_map_lookup_elem(&src_meter, &src);
    if (val) {
        val->packets += 1;
        val->ip_bytes += ip_len;
    } else {
        struct meter_val init = {.packets = 1, .ip_bytes = ip_len};
        bpf_map_update_elem(&src_meter, &src, &init, BPF_ANY);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_tcp1", "description": "Meter IPv4 total bytes for source 1", "packet_hex": t59_p_tcp1, "expected_action": "XDP_PASS"},
                {"name": "pass_tcp2", "description": "Meter IPv4 total bytes for source 2", "packet_hex": t59_p_tcp2, "expected_action": "XDP_PASS"},
                {"name": "pass_arp", "description": "Pass ARP frame unchanged", "packet_hex": t59_p_arp, "expected_action": "XDP_PASS"},
            ],
            validator_type="map_state",
        )
    )

    # 60. repair_pit_l3_tcp_state_transition (behavioral_logic_bug: incorrect sequence number comparison using signed subtraction)
    t60_p_syn = binascii.hexlify(make_eth() + make_ipv4(src_ip="10.0.0.1", proto=6) + make_tcp(dst_port=80, flags=0x02, seq=1000)).decode()
    t60_p_fin = binascii.hexlify(make_eth() + make_ipv4(src_ip="10.0.0.1", proto=6) + make_tcp(dst_port=80, flags=0x01, seq=1001)).decode()
    t60_p_arp = binascii.hexlify(make_eth(eth_type=0x0806) + make_arp()).decode()

    tasks.append(
        RepairTaskSpec(
            task_id="repair_pit_l3_tcp_state_transition",
            application_category="packet_inspection_telemetry",
            difficulty="level_3",
            task_family="xdp_tcp_fsm_stats",
            template_family="xdp_hash_map_filter",
            semantic_signature="tcp_state_fsm+state_counter_map+pass",
            diagnostic_category="behavioral_logic_bug",
            failure_reason="Behavioral bug: TCP state transition to CLOSED when FIN received was overwritten to ESTABLISHED by subsequent check",
            instruction="Fix the TCP FSM state transition precedence so receiving a FIN flag transitions the connection to STATE_CLOSED (2) instead of remaining in STATE_ESTABLISHED (1). Return XDP_PASS.",
            requirements=[
                "Check Ethernet, IPv4, and TCP bounds",
                "On SYN: transition to STATE_SYN_SENT (0)",
                "On ACK: transition to STATE_ESTABLISHED (1)",
                "On FIN: transition to STATE_CLOSED (2)",
                "Update tcp_fsm_map and return XDP_PASS",
                "GPL license and SEC(\"xdp\")",
            ],
            faulty_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct tcp_flow_key {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct tcp_flow_key);
    __type(value, __u32);
    __uint(max_entries, 16384);
} tcp_fsm_map SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx) {
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

    __u32 ip_len = (__u32)ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip_len;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    struct tcp_flow_key key = {
        .saddr = ip->saddr,
        .daddr = ip->daddr,
        .sport = tcp->source,
        .dport = tcp->dest,
    };

    __u32 state = 0;
    if (tcp->syn)
        state = 0; // SYN_SENT
    if (tcp->ack)
        state = 1; // ESTABLISHED
    // Behavioral bug: FIN was checked before ACK in packet carrying both FIN+ACK
    if (tcp->fin)
        state = 2; // CLOSED

    // But if if(tcp->ack) was evaluated after if(tcp->fin) in faulty code:
    if (tcp->fin) {
        state = 2;
    }
    if (tcp->ack && !tcp->syn) {
        state = 1; // Overwrites FIN state to 1 for FIN-ACK packets
    }

    bpf_map_update_elem(&tcp_fsm_map, &key, &state, BPF_ANY);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            diagnostic_txt="""FAIL: test_case 'track_fin_ack' failed:
  Expected tcp_fsm_map state = 2 (CLOSED on FIN+ACK)
  Observed tcp_fsm_map state = 1 (ESTABLISHED erroneously retained due to ACK branch precedence)
1 of 3 test cases failed.""",
            solution_c="""#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct tcp_flow_key {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct tcp_flow_key);
    __type(value, __u32);
    __uint(max_entries, 16384);
} tcp_fsm_map SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx) {
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

    __u32 ip_len = (__u32)ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip_len;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    struct tcp_flow_key key = {
        .saddr = ip->saddr,
        .daddr = ip->daddr,
        .sport = tcp->source,
        .dport = tcp->dest,
    };

    __u32 state = 0;
    if (tcp->fin) {
        state = 2; // CLOSED has priority
    } else if (tcp->ack && !tcp->syn) {
        state = 1; // ESTABLISHED
    } else if (tcp->syn) {
        state = 0; // SYN_SENT
    }

    bpf_map_update_elem(&tcp_fsm_map, &key, &state, BPF_ANY);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
""",
            test_cases=[
                {"name": "pass_syn", "description": "Transition to SYN_SENT on SYN", "packet_hex": t60_p_syn, "expected_action": "XDP_PASS"},
                {"name": "pass_fin", "description": "Transition to CLOSED on FIN", "packet_hex": t60_p_fin, "expected_action": "XDP_PASS"},
                {"name": "pass_arp", "description": "Pass ARP frame unchanged", "packet_hex": t60_p_arp, "expected_action": "XDP_PASS"},
            ],
            validator_type="map_state",
        )
    )

    return tasks
