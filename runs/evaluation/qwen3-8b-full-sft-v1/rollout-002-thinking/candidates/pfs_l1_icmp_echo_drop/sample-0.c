#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int xdp_filter_pfs_l1_icmp_echo_drop(struct xdp_md *ctx) {
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

    if (ip->protocol != IPPROTO_ICMP)
        return XDP_PASS;

    unsigned int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr))
        return XDP_PASS;

    if ((void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    struct icmphdr *icmp = (void *)ip + ip_hdr_len;
    if ((void *)(icmp + 1) > data_end)
        return XDP_PASS;

    if (icmp->type == 8)
        return XDP_DROP;

    return XDP_PASS;
}

GPLicense
}

Wait, but the ip_hdr_len is the length of the IP header. So, the IP header must be at least 20 bytes (ihl >=5). So, if ip->ihl < 5, then the IP header is too small. So, in that case, return XDP_PASS.

So, in code:

    if (ip->ihl < 5)
        return XDP_PASS;

    unsigned int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr))
        return XDP_PASS;

    if ((void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

Wait, but ip_hdr_len is ip->ihl *4. So, if ip->ihl is 5, then ip_hdr_len is 20, which is the size of struct iphdr. So, the check ip_hdr_len < sizeof(struct iphdr) would be 20 < 20? No. So that's not correct. So, perhaps the check is if ip_hdr_len < sizeof(struct iphdr), then return XDP_PASS. But that's not right. Because the struct iphdr is 20 bytes. So, if ip->ihl is 5, then ip_hdr_len is 20, which is correct. So, if ip_hdr_len < 20, then it's invalid. So, the check should be if (ip->ihl < 5) return XDP_PASS. Because the minimum IHL is 5. So, that's the first check.

So, in code:

    if (ip->ihl < 5)
        return XDP_PASS;

    unsigned int ip_hdr_len = ip->ihl * 4;
    if ((void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    if (ip_hdr_len < sizeof(struct iphdr))
        return XDP_PASS;

Wait, but if ip_hdr_len is 20, which is the size of struct iphdr, then that's okay. So, perhaps the check is redundant. Because if ip->ihl >=5, then ip_hdr_len is >=20. So, the check ip_hdr_len < sizeof(struct iphdr) would be 20 < 20? No. So, that check is not needed. So, maybe the code can be:

    if (ip->ihl < 5)
        return XDP_PASS;

    unsigned int ip_hdr_len = ip->ihl * 4;
    if ((void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    struct icmphdr *icmp = (void *)ip + ip_hdr_len;
    if ((void *)(icmp + 1) > data_end)
        return XDP_PASS;

    if (icmp->type == 8)
        return XDP_DROP;

    return XDP_PASS;

But wait, the IP header's tot_len field must be >= ip_hdr_len. So, the code should check that ip->tot_len >= ip_hdr_len. Because if the IP header is 20 bytes, but the tot_len is 15, then the packet is malformed. So, that's another check.

So, adding:

    if (ip->tot_len < (ip_hdr_len))
        return XDP_PASS;

But how to handle that? Because ip->tot_len is a 16-bit field. So, for example, if the IP header is 20 bytes, but the tot_len is 15, then the packet is invalid. So, that's a check.

So, in code:

    if (ip->ihl < 5)
        return XDP_PASS;

    unsigned int ip_hdr_len = ip->ihl * 4;
    if (ip->tot_len < ip_hdr_len)
        return XDP_PASS;

    if ((void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    struct icmphdr *icmp = (void *)ip + ip_hdr_len;
    if ((void *)(icmp + 1) > data_end)
        return XDP_PASS;

    if (icmp->type == 8)
        return XDP_DROP;

    return XDP_PASS;

That's better. So, the code now checks that the IP header is at least 20 bytes, and that the total length is at least that. Also, that the ICMP header is within the data_end.

So, putting all that together.

Now, the code should be safe. Also, the GPL license and SEC("xdp") entry point.

So, the final code would be:

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int xdp_filter_pfs_l1_icmp_echo_drop(struct xdp_md *ctx) {
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

    if (ip->ihl < 5)
        return XDP_PASS;

    unsigned int ip_hdr_len = ip->ihl * 4;
    if (ip->tot_len < ip_hdr_len)
        return XDP_PASS;

    if ((void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    struct icmphdr *icmp = (void *)ip + ip_hdr_len;
    if ((void *)(icmp + 1) > data_end)
        return XDP_PASS;

    if (icmp->type == 8)
        return XDP_DROP;

    return XDP_PASS;
}

SEC("license")
char _license[] SEC("license") = "GPL";
