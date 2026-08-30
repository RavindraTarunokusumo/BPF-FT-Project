SEC("xdp")
int xdp_filter_pfs_l2_syn_privileged_ports(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    unsigned int ip_hdr_len = eth->h_len;
    if (ip_hdr_len < sizeof(struct iphdr))
        return XDP_PASS;

    void *ip_hdr = (void *)(eth + 1);
    if ((void *)ip_hdr + ip_hdr_len > data_end)
        return XDP_PASS;

    if (ip_hdr->protocol != IPPROTO_TCP)
        return XDP_PASS;

    unsigned int ip_hdr_len_words = ip_hdr->ihl;
    if (ip_hdr_len_words < 5)
        return XDP_PASS;

    unsigned int tcp_hdr_start = ip_hdr_len_words * 4;
    if ((void *)ip_hdr + tcp_hdr_start > data_end)
        return XDP_PASS;

    struct tcphdr *tcp_hdr = (void *)ip_hdr + tcp_hdr_start;
    if ((void *)tcp_hdr + sizeof(struct tcphdr) > data_end)
        return XDP_PASS;

    if ((tcp_hdr->flags & 0x12) != 0x02)
        return XDP_PASS;

    __u16 dport = tcp_hdr->dest;
    if (dport >= 1 && dport <= 1023)
        return XDP_DROP;

    return XDP_PASS;
}

Wait, but the ip_hdr_len is eth->h_len, which is the total length of the Ethernet frame. But in the code above, the ip_hdr is (void *)(eth + 1), and then we check if (void *)ip_hdr + ip_hdr_len <= data_end. But eth->h_len is the total length of the Ethernet frame, which includes the IP header and data. So, the IP header's length is ip_hdr->ihl * 4. So, perhaps the code should check that ip_hdr->ihl * 4 is <= eth->h_len. But since the IP header is part of the Ethernet frame, we need to ensure that the IP header is within the Ethernet frame.

But in the code above, the eth->h_len is the total length of the Ethernet frame. So, the IP header must be at least 20 bytes (ihl >= 5). So, the code checks that ip_hdr_len >= sizeof(struct iphdr) (which is 20 bytes). But the ip_hdr_len is eth->h_len, which is the total length of the Ethernet frame. Wait, no. Wait, eth->h_len is the total length of the Ethernet frame. So, the IP header is part of that. So, the code is using eth->h_len as the IP header length? No, that's incorrect. Wait, the eth->h_len is the total length of the Ethernet frame. The IP header is part of that. So, the code above is wrong. Because in the code, ip_hdr_len is eth->h_len, which is the total Ethernet frame length. But that's not correct. The IP header's length is ip_hdr->ihl * 4. So, the code should check that ip_hdr->ihl * 4 is <= eth->h_len. But how?

Wait, the code is:

struct ethhdr *eth = data;
if ((void *)(eth + 1) > data_end)
    return XDP_PASS;

if (eth->h_proto != bpf_htons(ETH_P_IP))
    return XDP_PASS;

unsigned int ip_hdr_len = eth->h_len;
if (ip_hdr_len < sizeof(struct iphdr))
    return XDP_PASS;

void *ip_hdr = (void *)(eth + 1);
if ((void *)ip_hdr + ip_hdr_len > data_end)
    return XDP_PASS;

But eth->h_len is the total length of the Ethernet frame. So, the IP header is part of that. So, the code is checking that the IP header (which is eth->h_len bytes) is within the Ethernet frame. But that's not correct. Because the IP header is part of the Ethernet frame. So, the code is wrong here. Because eth->h_len is the total length of the Ethernet frame, which includes the IP header and data. So, the IP header's length is ip_hdr->ihl * 4. So, the code should check that ip_hdr->ihl * 4 is <= eth->h_len. But how?

Wait, the code is using eth->h_len as the IP header length, which is incorrect. That's a mistake. So, the correct approach is:

After checking that eth->h_proto is ETH_P_IP, then the IP header starts at (void *)(eth + 1). The IP header's length is ip_hdr->ihl * 4. So, we need to check that (void *)ip_hdr + ip_hdr->ihl * 4 <= data_end. Also, ip_hdr->ihl must be >= 5 (since minimum IP header is 20 bytes).

So, the code should be:

struct ethhdr *eth = data;
if ((void *)(eth + 1) > data_end)
    return XDP_PASS;

if (eth->h_proto != bpf_htons(ETH_P_IP))
    return XDP_PASS;

void *ip_hdr = (void *)(eth + 1);
if ((void *)ip_hdr + sizeof(struct iphdr) > data_end)
    return XDP_PASS;

if (ip_hdr->protocol != IPPROTO_TCP)
    return XDP_PASS;

unsigned int ip_hdr_len = ip_hdr->ihl * 4;
if ((void *)ip_hdr + ip_hdr_len > data_end)
    return XDP_PASS;

if (ip_hdr_len < sizeof(struct iphdr))
    return XDP_PASS;

struct tcphdr *tcp_hdr = (void *)ip_hdr + ip_hdr_len;
if ((void *)tcp_hdr + sizeof(struct tcphdr) > data_end)
    return XDP_PASS;

if ((tcp_hdr->flags & 0x12) != 0x02)
    return XDP_PASS;

__u16
