#include <linux/bpf.h>
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
