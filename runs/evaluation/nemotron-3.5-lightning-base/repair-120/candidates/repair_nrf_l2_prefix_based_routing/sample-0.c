#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

/* Define the LPM trie key structure */
struct lpm_key {
    __u8 prefixlen;
    __u8 addr[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_key);
    __type(value, __u32);
    __uint(max_entries, 256);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} lpm_routes SEC(".maps");

SEC("xdp")
int xdp_forward(struct xdp_md *ctx) {
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

    /* Lookup the destination IP in the LPM trie */
    struct lpm_key key = {
        .prefixlen = ip->daddr & 0xFF,   /* example: use low 8 bits as prefix length */
        .addr = { ( __u8 )(ip->daddr >> 24),
                  ( __u8 )(ip->daddr >> 16),
                  ( __u8 )(ip->daddr >> 8),
                  ( __u8 )(ip->daddr) }
    };
    __u32 ifindex = 0;
    int ret = bpf_lpm_trie_lookup(&lpm_routes, &key, &ifindex, sizeof(ifindex));
    if (ret == 0) {
        /* Route found – redirect to the interface index */
        return bpf_redirect(ifindex, 0);
    }

    /* No matching route – pass the packet to the next handler */
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
