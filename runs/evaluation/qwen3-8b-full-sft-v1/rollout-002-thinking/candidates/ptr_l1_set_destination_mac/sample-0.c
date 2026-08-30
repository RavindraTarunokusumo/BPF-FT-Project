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
int xdp_transform_ptr_l1_set_destination_mac(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    __u64 data_len = ctx->data_len;

    if (data_len < sizeof(struct ethhdr))
        return XDP_PASS;

    struct ethhdr *eth = data;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    eth->h_dest[0] = 0x02;
    eth->h_dest[1] = 0x00;
    eth->h_dest[2] = 0x00;
    eth->h_dest[3] = 0x00;
    eth->h_dest[4] = 0x00;
    eth->h_dest[5] = 0x99;

    return XDP_PASS;
}

But wait, the task says to preserve the EtherType. So the code should not modify eth->h_proto. So the code above checks if the EtherType is IP, but that's not necessary. The task says to preserve the EtherType. So the code should not modify it. So the code should not have that check. So the code should be:

SEC("xdp")
int xdp_transform_ptr_l1_set_destination_mac(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    __u64 data_len = ctx->data_len;

    if (data_len < sizeof(struct ethhdr))
        return XDP_PASS;

    struct ethhdr *eth = data;
    eth->h_dest[0] = 0x02;
    eth->h_dest[1] = 0x00;
    eth->h_dest[2] = 0x00;
    eth->h_dest[3] = 0x00;
    eth->h_dest[4] = 0x00;
    eth->h_dest[5] = 0x99;

    return XDP_PASS;
}

But wait, the task says to preserve the source MAC, EtherType, and payload. So the code should not modify eth->h_source, eth->h_proto, or the payload. So the code is correct in that it only modifies h_dest.

But in the code above, the eth->h_source is not modified. So that's correct.

But what about if the packet is not an Ethernet frame? Well, the XDP program is supposed to handle all packets. But if the data is less than 14 bytes, it's passed through. Otherwise, it's assumed to be an Ethernet frame. So the code is correct.

So the final code would be as above.

Now, the license is GPL. So the code should include the GPL header.

Putting it all together, the code would be:

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
int xdp_transform_ptr_l1_set_destination_mac(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    __u64 data_len = ctx->data_len;

    if (data_len < sizeof(struct ethhdr))
        return XDP_PASS;

    struct ethhdr *eth = data;
    eth->h_dest[0] = 0x02;
    eth->h_dest[1] = 0x00;
    eth->h_dest[2] = 0x00;
    eth->h_dest[3] = 0x00;
    eth->h_dest[4] = 0x00;
    eth->h_dest[5] = 0x99;

    return XDP_PASS;
}

SEC("license")
char _license[] SEC("license") = "GPL";
