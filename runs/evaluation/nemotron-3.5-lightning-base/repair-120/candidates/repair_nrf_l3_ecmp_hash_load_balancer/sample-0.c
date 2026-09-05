#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

/* ECMP device map: 4 egress interfaces indexed 0..3 */
struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 4);
} ecmp_devmap SEC(".maps");

SEC("xdp")
int xdp_forward(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;

    /* Verify Ethernet frame is large enough */
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* Only process IPv4 */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    /* Verify IP header fits */
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    /* Only TCP packets */
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    __u32 ip_len = (__u32)ip->ihl * 4;
    /* Verify IP header length and that payload fits */
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip_len;
    /* Verify TCP header fits */
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    /* Extract 5-tuple fields safely (all values are already in host order
       after BPF map lookup, but here we just read the raw fields) */
    __u32 saddr = ip->saddr;
    __u32 daddr = ip->daddr;
    __u16 sport = tcp->source;
    __u16 dport = tcp->dest;
    __u8  proto = ip->protocol;

    /* Inline 5-tuple hash: (saddr ^ daddr ^ sport ^ dport ^ proto) & 3 */
    __u32 slot = (saddr ^ daddr ^ sport ^ dport ^ proto) & 3;

    /* Redirect through the DEVMAP to the selected egress interface */
    return bpf_redirect_map(&ecmp_devmap, slot, 0);
}

char LICENSE[] SEC("license") = "GPL";
