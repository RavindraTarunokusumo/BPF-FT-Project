SEC("xdp")
int xdp_filter_pfs_l2_vlan_tcp443(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    if ((void *)eth + sizeof(struct ethhdr) > data_end)
        return XDP_PASS;

    struct iphdr *ip = (void *)eth + sizeof(struct ethhdr);
    if ((void *)ip + sizeof(struct iphdr) > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    unsigned int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr) || (void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    if ((void *)ip + ip_hdr_len + sizeof(struct tcphdr) > data_end)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip_hdr_len;
    if (tcp->dest != bpf_htons(443))
        return XDP_PASS;

    return XDP_DROP;
}

Wait, but this code doesn't handle VLAN. So, I need to add the VLAN case.

So, first, check if eth->h_proto is VLAN (0x8100). If yes, then check if there's enough space for VLAN tag (4 bytes). Then, check the inner EtherType.

So, modifying the code:

SEC("xdp")
int xdp_filter_pfs_l2_vlan_tcp443(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto == bpf_htons(ETH_P_8100)) {
        if ((void *)eth + sizeof(struct ethhdr) + 4 > data_end)
            return XDP_PASS;
        __u16 *vlan = (__u16 *)eth + 1;
        if (*vlan != bpf_htons(ETH_P_IP))
            return XDP_PASS;
        // Now, inner Ethernet header starts at eth + sizeof(ethhdr) + 4
        struct ethhdr *inner_eth = (void *)eth + sizeof(struct ethhdr) + 4;
        if ((void *)(inner_eth + 1) > data_end)
            return XDP_PASS;
        if (inner_eth->h_proto != bpf_htons(ETH_P_IP))
            return XDP_PASS;
        // Now, process IP header
        if ((void *)inner_eth + sizeof(struct ethhdr) > data_end)
            return XDP_PASS;
        struct iphdr *ip = (void *)inner_eth + sizeof(struct ethhdr);
        if ((void *)ip + sizeof(struct iphdr) > data_end)
            return XDP_PASS;
        if (ip->protocol != IPPROTO_TCP)
            return XDP_PASS;
        unsigned int ip_hdr_len = ip->ihl * 4;
        if (ip_hdr_len < sizeof(struct iphdr) || (void *)ip + ip_hdr_len > data_end)
            return XDP_PASS;
