#include <linux/bpf.h>
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
