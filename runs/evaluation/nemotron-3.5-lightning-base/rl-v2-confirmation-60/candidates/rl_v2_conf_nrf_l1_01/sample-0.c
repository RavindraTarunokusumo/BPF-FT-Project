/* XDP program: Reflect TCP connections by swapping L4 source/destination ports.
 * Forward all other packets.
 *
 * Compilation: clang -target bpf -O2 -c xdp_reflect.c -o xdp_reflect.o
 * Load:      ip link set dev <iface> xdp obj xdp_reflect.o sec xdp_reflect
 * Unload:    ip link set dev <iface> xdp off
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/ctx/sk_buff.h>

SEC("xdp")
int xdp_reflect(struct bpf_xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* 1. Verify Ethernet frame minimum size */
    struct ethhdr *eth;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    eth = data;
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    /* 2. Verify IPv4 header bounds */
    struct iphdr *ip;
    if (data + sizeof(*ip) > data_end)
        return XDP_PASS;

    ip = data + sizeof(*eth);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    /* 3. Validate IPv4 header length (IHL * 4 bytes) */
    u32 ihl = ip->ihl * 4;
    if (ihl < sizeof(struct iphdr) || data + ihl > data_end)
        return XDP_PASS;

    /* 4. Confirm IP protocol is TCP */
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    /* 5. Verify TCP header bounds */
    struct tcphdr *tcp;
    if (data + ihl + sizeof(*tcp) > data_end)
        return XDP_PASS;

    tcp = (struct tcphdr *)(data + ihl);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    /* 6. Swap TCP source and destination ports in-place */
    u16 tmp = tcp->source;
    tcp->source = tcp->dest;
    tcp->dest = tmp;

    /* 7. Reflect the packet */
    return XDP_TX;
}

char LICENSE[] SEC("license") = "GPL";
