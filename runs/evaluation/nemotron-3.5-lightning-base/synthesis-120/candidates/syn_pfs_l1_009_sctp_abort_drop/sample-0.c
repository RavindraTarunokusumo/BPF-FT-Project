#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/sctp.h>

/* XDP program entry point */
SEC("xdp")
int xdp_sctp_abort_drop(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* 1. Validate Ethernet frame boundaries */
    struct eth_hdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    /* 2. Validate IPv4 protocol and IHL */
    /* Only process IPv4 (ETH_P_IP = 0x0800) */
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;

    /* Verify IPv4 Internet Header Length (IHL) is at least 5 (20 bytes) */
    if (ip->ihl < 5)
        return XDP_PASS;

    /* 3. Verify IP protocol == 132 (SCTP) */
    if (ip->protocol != 132)
        return XDP_PASS;

    /* 4. Validate SCTP common header (12 bytes) boundaries */
    struct sctphdr *sctp = (struct sctphdr *)(ip + 1);
    if ((void *)sctp + 12 > data_end)
        return XDP_PASS;

    /* 5. Validate first SCTP chunk header (4 bytes) boundaries */
    struct sctp_chunkhdr *chunk = (struct sctp_chunkhdr *)(sctp + 1);
    if ((void *)chunk + 4 > data_end)
        return XDP_PASS;

    /* 6. Drop if chunk type is ABORT (6) */
    if (chunk->chunk_type == 6)
        return XDP_DROP;

    /* 7. Pass all other traffic */
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
