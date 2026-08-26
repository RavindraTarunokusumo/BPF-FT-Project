#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int xdp_vlan_pop(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Check Ethernet header bounds
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_PASS;

    struct ethhdr *eth = data;
    if (eth->h_proto != bpf_htons(ETH_P_8021Q))
        return XDP_PASS;

    // Extract inner EtherType
    __be16 inner_ethertype = *( (__be16 *)((char *)data + sizeof(struct ethhdr) + 2));

    // Check if inner EtherType is VLAN (double-tagged)
    if (inner_ethertype == bpf_htons(ETH_P_8021Q)) {
        return XDP_PASS;
    }

    // Check VLAN header bounds
    if (data + sizeof(struct ethhdr) + 4 > data_end)
        return XDP_PASS;

    // Adjust head by +4 bytes
    int res = bpf_xdp_adjust_head(ctx, 4);
    if (res < 0)
        return XDP_PASS;

    // Update Ethernet header's h_proto
    struct ethhdr *new_eth = (struct ethhdr *)((void *)data - 4);
    new_eth->h_proto = inner_ethertype;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
