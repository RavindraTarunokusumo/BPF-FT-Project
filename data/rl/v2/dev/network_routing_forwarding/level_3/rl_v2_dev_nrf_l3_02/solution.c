#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

struct lpm_key_2 {
    __u32 prefixlen;
    __u32 data;
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_key_2);
    __type(value, unsigned char[6]);
    __uint(max_entries, 256);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} dev_route_table_2 SEC(".maps");

SEC("xdp")
int xdp_route_fallback_2(struct xdp_md *ctx) {
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

    struct lpm_key_2 key;
    key.prefixlen = 32;
    key.data = ip->daddr;

    unsigned char (*mac)[6] = bpf_map_lookup_elem(&dev_route_table_2, &key);
    if (mac) {
        for (int i = 0; i < 6; i++)
            eth->h_dest[i] = (*mac)[i];
    } else {
        eth->h_dest[0] = 0x52;
        eth->h_dest[1] = 0x54;
        eth->h_dest[2] = 0x00;
        eth->h_dest[3] = 0x00;
        eth->h_dest[4] = 0x00;
        eth->h_dest[5] = 0xfe;
    }

    return XDP_TX;
}

char _license[] SEC("license") = "GPL";
