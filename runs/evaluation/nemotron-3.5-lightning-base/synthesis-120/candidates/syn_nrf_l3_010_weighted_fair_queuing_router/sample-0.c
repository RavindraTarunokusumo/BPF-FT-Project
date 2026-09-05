#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

/* XDP program entry point */
SEC("xdp")
int wfq_scheduler(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Validate Ethernet header bounds */
    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    /* Only process IPv4 traffic (ETH_P_IP = 0x0800) */
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    /* Validate IPv4 header bounds */
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    /* Check total packet length against the 256-byte threshold */
    if (ctx->data_end - ctx->data <= 256) {
        /* Short packets (<= 256 bytes) -> low-latency queue */
        return bpf_redirect(100, 0);
    } else {
        /* Long packets (> 256 bytes) -> bulk queue */
        return bpf_redirect(101, 0);
    }
}

char LICENSE[] SEC("license") = "GPL";
