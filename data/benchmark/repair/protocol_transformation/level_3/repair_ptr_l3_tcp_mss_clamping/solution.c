#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_transform(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    __u32 ip_len = (__u32)ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip_len;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    if (tcp->syn && tcp->doff > 5) {
        __u8 *opt = (void *)(tcp + 1);
        if ((void *)(opt + 4) <= data_end) {
            if (opt[0] == 2 && opt[1] == 4) {
                __u16 *mss_val = (__u16 *)(opt + 2);
                __u16 old_mss = bpf_ntohs(*mss_val);
                if (old_mss > 1220) {
                    *mss_val = bpf_htons(1220);
                    __u32 csum = bpf_ntohs(tcp->check);
                    csum += old_mss + (~1220 & 0xFFFF);
                    while (csum >> 16)
                        csum = (csum & 0xFFFF) + (csum >> 16);
                    tcp->check = bpf_htons((__u16)csum);
                }
            }
        }
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
