#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/socket.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int xdp_router(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Check Ethernet header bounds and protocol
    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // Check IPv4 header bounds and TTL
    struct iphdr *ip = data + sizeof(*eth);
    if ((void*)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->ttl <= 1)
        return XDP_PASS;

    // Initialize fib lookup parameters
    struct bpf_fib_lookup fib_params = {};
    fib_params.family = AF_INET;
    fib_params.ipv4_src = ip->saddr;
    fib_params.ipv4_dst = ip->daddr;
    fib_params.tot_len = bpf_ntohs(ip->tot_len);
    fib_params.ifindex = ctx->ingress_ifindex;

    int ret = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
    if (ret != BPF_FIB_LKUP_RET_SUCCESS)
        return XDP_PASS;

    // Modify TTL and checksum
    ip->ttl--;
    ip->check += 0x0100;

    // Update Ethernet header with new MAC addresses
    struct ethhdr *eth_out = data;
    eth_out->h_dest[0] = fib_params.dmac[0];
    eth_out->h_dest[1] = fib_params.dmac[1];
    eth_out->h_dest[2] = fib_params.dmac[2];
    eth_out->h_dest[3] = fib_params.dmac[3];
    eth_out->h_dest[4] = fib_params.dmac[4];
    eth_out->h_dest[5] = fib_params.dmac[5];

    eth_out->h_source[0] = fib_params.smac[0];
    eth_out->h_source[1] = fib_params.smac[1];
    eth_out->h_source[2] = fib_params.smac[2];
    eth_out->h_source[3] = fib_params.smac[3];
    eth_out->h_source[4] = fib_params.smac[4];
    eth_out->h_source[5] = fib_params.smac[5];

    // Redirect packet
    if (fib_params.ifindex == ctx->ingress_ifindex)
        return XDP_TX;
    else
        return bpf_redirect(fib_params.ifindex, 0);
}

char _license[] SEC("license") = "GPL";
