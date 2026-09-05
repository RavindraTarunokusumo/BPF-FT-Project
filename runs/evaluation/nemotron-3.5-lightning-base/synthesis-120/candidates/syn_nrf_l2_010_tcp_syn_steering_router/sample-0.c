/* XDP TCP SYN/Ack Steering Router
 *
 * Redirects TCP SYN packets to connection distributor (ifindex 15)
 * and established TCP packets (ACK set) to fast-path worker (ifindex 16).
 * All other traffic is passed through.
 *
 * Compilation: clang -target bpf -O2 -c tcpxdp.c -o tcpxdp.o
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/ctx/sk_buff.h>

SEC("xdp")
int tcpxdp_steer(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    /* Validate Ethernet header */
    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    /* Only process IPv4 traffic */
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    /* Validate IPv4 header */
    struct iphdr *ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;

    /* Only process TCP protocol */
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    /* Validate TCP header */
    struct tcphdr *tcp = (void *)ip + ip->ihl * 4;
    if (data + sizeof(*eth) + ip->ihl * 4 + sizeof(*tcp) > data_end)
        return XDP_PASS;

    /* TCP SYN: syn=1, ack=0 -> redirect to connection distributor (ifindex 15) */
    if (tcp->syn && !tcp->ack) {
        return bpf_redirect(15, 0);
    }

    /* Established TCP: ack=1 -> redirect to fast-path worker (ifindex 16) */
    if (tcp->ack) {
        return bpf_redirect(16, 0);
    }

    /* All other TCP (e.g., FIN, RST, or plain data without flags) -> pass */
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
