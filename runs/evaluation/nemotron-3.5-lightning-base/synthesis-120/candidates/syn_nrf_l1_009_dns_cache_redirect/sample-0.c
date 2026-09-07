/* XDP program: DNS cache redirect
 * Redirect IPv4 UDP packets with destination port 53 to local DNS caching accelerator ifindex 6
 * All other traffic is passed through
 *
 * Compilation: clang -target bpf -O2 -c dns_redirect.c -o dns_redirect.o
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/ctx/sk_buff.h>

SEC("xdp")
int dns_redirect_xdp(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    /* Validate Ethernet header */
    struct eth_hdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    /* Validate IPv4 protocol */
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    /* Validate IPv4 header */
    struct iphdr *ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;

    /* Must be UDP */
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    /* Validate UDP header */
    struct udphdr *udp = (void *)ip + sizeof(*ip);
    if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp) > data_end)
        return XDP_PASS;

    /* Check destination port 53 (DNS) */
    if (udp->dest != htons(53))
        return XDP_PASS;

    /* Redirect to local DNS caching accelerator ifindex 6 */
    return bpf_redirect(6, 0);
}

char LICENSE[] SEC("license") = "GPL";
