/* XDP program for QUIC edge router
 * Redirects IPv4 UDP packets with destination port 443 to interface index 7
 * All other traffic is passed through
 *
 * Compilation: clang -target bpf -O2 -c xdp_quic_redirect.c -o xdp_quic_redirect.o
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

SEC("xdp")
int xdp_quic_redirect(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    /* Validate Ethernet header */
    struct eth_hdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    /* Validate IPv4 protocol */
    /* EtherType 0x0800 = IPv4 */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

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

    /* Check destination port 443 (QUIC / HTTP/3) */
    if (udp->dest != bpf_htons(443))
        return XDP_PASS;

    /* Redirect to edge termination cluster interface index 7 */
    return bpf_redirect(7, 0);
}

char LICENSE[] SEC("license") = "GPL";
