#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

/* DEVMAP with 2 entries: key 0 -> slot 0, key 1 -> slot 1 */
struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 2);
} proto_devmap SEC(".maps");

SEC("xdp")
int xdp_forward(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;

    /* Verify Ethernet frame bounds */
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* Only process IPv4 packets */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);

    /* Verify IPv4 header bounds */
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->protocol == IPPROTO_TCP) {
        /* Redirect TCP traffic through DEVMAP key 0 */
        return bpf_redirect_map(&proto_devmap, 0, 0);
    } else if (ip->protocol == IPPROTO_UDP) {
        /* Redirect UDP traffic through DEVMAP key 1 */
        return bpf_redirect_map(&proto_devmap, 1, 0);
    }

    /* Pass all other protocols */
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
