#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>

struct mpls_stats {
    __u64 pkts;
    __u64 bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32); // 20-bit VPN label
    __type(value, struct mpls_stats);
    __uint(max_entries, 1024);
} vpn_stats_map SEC(".maps");

SEC("xdp")
int xdp_mpls_vpn_telemetry(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(0x8847))
        return XDP_PASS;

    __u32 *ptr = (void *)(eth + 1);
    __u32 vpn_label = 0;
    int found = 0;

    #pragma unroll
    for (int i = 0; i < 4; i++) {
        if ((void *)(ptr + 1) > data_end)
            break;

        __u32 entry = bpf_ntohl(*ptr);
        __u32 label = entry >> 12;
        int bos = (entry & 0x00000100) != 0;

        if (bos) {
            vpn_label = label;
            found = 1;
            break;
        }
        ptr += 1;
    }

    if (found) {
        __u64 pkt_len = (__u64)((void *)data_end - (void *)data);
        struct mpls_stats *st = bpf_map_lookup_elem(&vpn_stats_map, &vpn_label);
        if (!st) {
            struct mpls_stats new_st = { .pkts = 1, .bytes = pkt_len };
            bpf_map_update_elem(&vpn_stats_map, &vpn_label, &new_st, BPF_ANY);
        } else {
            st->pkts += 1;
            st->bytes += pkt_len;
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
