#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

SEC("xdp")
int xdp_coap_redirect(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    /* Validate Ethernet header */
    struct eth_hdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    /* Validate IPv4 header */
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    /* Must be UDP */
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    /* Validate UDP header */
    struct udphdr *udp = (struct udphdr *)(ip + 1);
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    /* Check destination port 5683 (CoAP) in network byte order */
    if (udp->dest != htons(5683))
        return XDP_PASS;

    /* Redirect to IoT server interface ifindex 5 */
    return bpf_redirect(5, 0);
}

char LICENSE[] SEC("license") = "GPL";
