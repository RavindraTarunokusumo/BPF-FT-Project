#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

SEC("xdp")
int xdp_tcp_mss_clamp(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

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

    int ip_len = ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip_len;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    if (!tcp->syn)
        return XDP_PASS;

    int tcp_hdr_len = tcp->doff * 4;
    if (tcp_hdr_len <= sizeof(struct tcphdr) || (void *)tcp + tcp_hdr_len > data_end)
        return XDP_PASS;

    __u8 *opt = (void *)(tcp + 1);
    __u8 *opt_end = (void *)tcp + tcp_hdr_len;

    #pragma unroll
    for (int i = 0; i < 10; i++) {
        if (opt + 1 > opt_end || opt + 1 > data_end)
            break;

        __u8 kind = *opt;
        if (kind == 0) break;
        if (kind == 1) { opt += 1; continue; }

        if (opt + 2 > opt_end || opt + 2 > data_end)
            break;
        __u8 len = *(opt + 1);
        if (len < 2) break;

        if (kind == 2 && len == 4) {
            if (opt + 4 > opt_end || opt + 4 > data_end)
                break;

            __u16 old_mss = ((__u16)*(opt + 2) << 8) | (__u16)*(opt + 3);
            if (old_mss > 1300) {
                __u16 new_mss = 1300;
                *(opt + 2) = (__u8)(new_mss >> 8);
                *(opt + 3) = (__u8)(new_mss & 0xFF);

                __u32 csum = (~bpf_ntohs(tcp->check)) & 0xFFFF;
                csum += (~old_mss) & 0xFFFF;
                csum += new_mss;
                while (csum >> 16)
                    csum = (csum & 0xFFFF) + (csum >> 16);
                csum = (~csum) & 0xFFFF;
                if (csum == 0) csum = 0xFFFF;
                tcp->check = bpf_htons((__u16)csum);
            }
            break;
        }

        opt += len;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
