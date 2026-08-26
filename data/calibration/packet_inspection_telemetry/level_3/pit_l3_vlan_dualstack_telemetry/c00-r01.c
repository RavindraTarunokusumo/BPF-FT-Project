#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <bpf/bpf_endian.h>

struct vlan_telemetry_val {
    __u64 packets;
    __u64 bytes;
};

SEC("xdp")
int xdp_vlan_telemetry(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    __be16 eth_type;
    int slot = 3;
    __u32 pkt_len;

    // Check Ethernet header is valid
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }
    eth_type = eth->h_proto;

    // Determine slot
    if (eth_type == bpf_htons(ETH_P_IP)) {
        slot = 0;
    } else if (eth_type == bpf_htons(ETH_P_8021Q)) {
        // Check if VLAN tag is present and inner Ethernet header is accessible
        // VLAN tag is 4 bytes after Ethernet header (14 bytes)
        // Inner Ethernet header starts at data + 14 + 4 = data + 18
        // Inner Ethernet type is at data + 18 + 12 = data + 30
        if ((void *)(data + 18) > data_end) {
            slot = 3;
        } else {
            if ((void *)(data + 30) > data_end) {
                slot = 3;
            } else {
                __be16 inner_eth_type = *(__be16 *)(data + 30);
                if (inner_eth_type == bpf_htons(ETH_P_IP)) {
                    slot = 1;
                } else if (inner_eth_type == bpf_htons(ETH_P_IPV6)) {
                    slot = 2;
                } else {
                    slot = 3;
                }
            }
        }
    } else {
        // Check if it's IPv6 or other
        if (eth_type == bpf_htons(ETH_P_IPV6)) {
            slot = 3;
        } else {
            slot = 3;
        }
    }

    // Compute pkt_len
    pkt_len = data_end - data;

    // Update the map
    __u32 key = slot;
    struct vlan_telemetry_val *val;
    val = bpf_map_lookup_elem(&vlan_telemetry_map, &key);
    if (val) {
        val->packets += 1;
        val->bytes += pkt_len;
    }

    return XDP_PASS;
}

// Declare the map as a global variable
struct bpf_map_def SEC("vlan_telemetry_map") vlan_telemetry_map = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct vlan_telemetry_val),
    .max_entries = 4,
};

char _license[] SEC("license") = "GPL";
