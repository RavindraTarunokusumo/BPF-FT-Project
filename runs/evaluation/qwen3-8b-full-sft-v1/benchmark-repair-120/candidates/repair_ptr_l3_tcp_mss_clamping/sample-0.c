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
        if ((void *)(opt + 4) > data_end)
            return XDP_PASS;
        if (opt[0] == 2 && opt[1] == 4) {
            __u16 *mss_val = (__u16 *)(opt + 2);
            if (bpf_ntohs(*mss_val) > 1220) {
                __u16 new_mss = bpf_htons(1220);
                __u32 old_val = (unsigned char)(*mss_val) | (unsigned char)(mss_val[1]);
                __u32 new_val = (unsigned char)new_mss | (unsigned char)(new_mss >> 8);
                __u32 delta = new_val - old_val;
                // Adjust checksum
                __u32 csum = (__u32)tcp->check + delta;
                while (csum >> 16)
                    csum = (csum & 0xFFFF) + (csum >> 16);
                tcp->check = (__u16)csum;
                *mss_val = new_mss;
            }
        }
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
