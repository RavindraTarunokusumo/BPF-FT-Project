/* XDP program: Replace Ethernet source MAC with 02:00:00:00:00:42 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/string.h>

/* Define the fixed source MAC address */
static const unsigned char src_mac[6] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x42 };

SEC("xdp")
int xdp_replace_src_mac(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    /* Ensure the Ethernet header fits within the packet */
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_PASS;

    struct ethhdr *eth = data;

    /* Verify we have at least 14 bytes (minimum Ethernet frame) */
    if (data + 14 > data_end)
        return XDP_PASS;

    /* Replace the source MAC address */
    eth->h_source[0] = src_mac[0];
    eth->h_source[1] = src_mac[1];
    eth->h_source[2] = src_mac[2];
    eth->h_source[3] = src_mac[3];
    eth->h_source[4] = src_mac[4];
    eth->h_source[5] = src_mac[5];

    /* Destination MAC, EtherType, and payload are left untouched */

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
