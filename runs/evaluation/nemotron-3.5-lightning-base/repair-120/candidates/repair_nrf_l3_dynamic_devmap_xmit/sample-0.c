#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

/* Egress table: source IP (__u32) -> egress port (__u32) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 256);
} egress_table SEC(".maps");

/* DEVMAP with 4 Tx ports indexed 0..3 */
struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 4);
} tx_ports SEC(".maps");

SEC("xdp")
int xdp_forward(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;

    /* Verify Ethernet header fits */
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    /* Verify IP header fits */
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u32 src = ip->saddr;

    /* Lookup egress port for the source IP */
    __u32 *val = bpf_map_lookup_elem(&egress_table, &src);
    if (val) {
        /* val already holds the egress port (__u32) */
        __u32 port = *val & 3;      /* mask to lower 2 bits for port index */
        return bpf_redirect_map(&tx_ports, port, 0);
    }

    /* No route found – pass the packet to the normal stack */
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
