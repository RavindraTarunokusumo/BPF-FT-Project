/* XDP program: Drop TCP traffic targeting destination port 443
 * inside untagged IPv4 frames or single 802.1Q VLAN-tagged frames.
 * All other traffic is passed.
 *
 * Compilation: clang -target bpf -O2 -c xdp_drop_443.c -o xdp_drop_443.o
 * License: GPL
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/ctx/skb.h>

/* Helper to safely access the Ethernet header */
static __always_inline struct eth_hdr *eth_hdr(struct bpf_sock_ops *skb)
{
    return (struct eth_hdr *)bpf_skb_load_data(skb, 0, sizeof(struct eth_hdr), NULL);
}

/* Helper to safely access the IP header */
static __always_inline struct iphdr *ip_hdr(struct bpf_sock_ops *skb,
                                            struct eth_hdr *eth)
{
    /* IP header starts right after Ethernet header */
    return (struct iphdr *)(eth + 1);
}

/* Helper to safely access the TCP header */
static __always_inline struct tcphdr *tcp_hdr(struct bpf_sock_ops *skb,
                                              struct iphdr *ip)
{
    /* TCP header starts right after IP header, IHL is in 32-bit words */
    return (struct tcphdr *)(ip + 1);
}

SEC("xdp")
int xdp_drop_443(struct bpf_sock_ops *skb)
{
    void *data_end;
    void *data;
    struct eth_hdr *eth;
    struct iphdr *ip;
    struct tcphdr *tcp;
    __u16 h_proto;
    __u8 protocol;
    __u16 src_port, dst_port;
    __u32 ihl;

    /* Load Ethernet header, check bounds */
    data = (void *)(long)bpf_skb_load_data(skb, 0, 0, &data_end);
    if (!data)
        return XDP_PASS;

    eth = data;
    /* Ensure Ethernet header fits within the frame */
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    h_proto = eth->h_proto;

    /* -------------------------------------------------------
     * Case 1: Untagged IPv4 (EtherType 0x0800)
     * ------------------------------------------------------- */
    if (h_proto == bpf_htons(ETH_P_IP)) {
        ip = ip_hdr(skb, eth);
        /* Verify IP header fits */
        if ((void *)(ip + 1) > data_end)
            return XDP_PASS;

        /* Verify IP protocol is TCP */
        if (ip->protocol != IPPROTO_TCP)
            return XDP_PASS;

        /* Parse TCP header safely */
        tcp = tcp_hdr(skb, ip);
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;

        /* Extract source and destination ports (network byte order) */
        src_port = tcp->source;
        dst_port = tcp->dest;

        /* Drop if destination port is 443 */
        if (dst_port == bpf_htons(443))
            return XDP_DROP;

        /* Pass all other TCP traffic */
        return XDP_PASS;
    }

    /* -------------------------------------------------------
     * Case 2: VLAN-tagged frame (EtherType 0x8100)
     * ------------------------------------------------------- */
    if (h_proto == bpf_htons(ETH_P_8021Q)) {
        struct vlan_hdr *vlan;

        /* Ensure VLAN header fits */
        if ((void *)(eth + 1) > data_end)
            return XDP_PASS;

        vlan = (struct vlan_hdr *)(eth + 1);

        /* Extract inner EtherType (4 bytes after VLAN tag control info) */
        /* vlan->h_vlan_encapsulated_proto is already in host byte order
         * on little-endian systems, but we use bpf_htons for safety.
         * Actually, the field is stored in network byte order.
         */
        if (bpf_ntohs(vlan->h_vlan_encapsulated_proto) != ETH_P_IP)
            return XDP_PASS;

        /* Now we have an inner IPv4 packet; advance past VLAN header */
        ip = ip_hdr(skb, (struct eth_hdr *)((void *)vlan + sizeof(struct vlan_hdr)));
        /* Verify inner IP header fits */
        if ((void *)(ip + 1) > data_end)
            return XDP_PASS;

        /* Verify IP protocol is TCP */
        if (ip->protocol != IPPROTO_TCP)
            return XDP_PASS;

        /* Parse TCP header safely */
        tcp = tcp_hdr(skb, ip);
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;

        /* Extract destination port */
        dst_port = tcp->dest;

        /* Drop if destination port is 443 */
        if (dst_port == bpf_htons(443))
            return XDP_DROP;

        /* Pass all other TCP traffic inside VLAN frames */
        return XDP_PASS;
    }

    /* -------------------------------------------------------
     * All other frames (non-IPv4, non-VLAN, etc.)
     * ------------------------------------------------------- */
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
