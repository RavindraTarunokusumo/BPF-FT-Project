#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct vlan_telemetry_val {
    __u64 packets;
    __u64 bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, struct vlan_telemetry_val);
} vlan_telemetry_map SEC(".maps");

SEC("xdp")
int xdp_telemetry_pit_l3_vlan_dualstack_telemetry(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u32 pkt_len = (__u32)(data_end - (void *)eth);
    __u32 slot = 3;

    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        slot = 0;
    } else if (eth->h_proto == bpf_htons(ETH_P_8021Q)) {
        struct vlan_hdr *vlan = (void *)(eth + 1);
        if ((void *)(vlan + 1) > data_end)
            return XDP_PASS;
        if (vlan->h_proto == bpf_htons(ETH_P_IP))
            slot = 1;
        else if (vlan->h_proto == bpf_htons(ETH_P_IPV6))
            slot = 2;
    }

    struct vlan_telemetry_val *val = bpf_map_lookup_elem(&vlan_telemetry_map, &slot);
    if (val) {
        __sync_fetch_and_add(&val->packets, 1);
        __sync_fetch_and_add(&val->bytes, pkt_len);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
