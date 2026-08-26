#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int xdp_swap_mac(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Check if the packet is at least 14 bytes (Ethernet header)
    if (data_end - data < 14) {
        return XDP_PASS;
    }

    // Ensure all memory accesses are within bounds
    if (data + 6 > data_end || data + 12 > data_end) {
        return XDP_PASS;
    }

    // Swap MAC addresses
    unsigned char dest_mac[6];
    unsigned char src_mac[6];

    // Read destination MAC (first 6 bytes)
    dest_mac[0] = ((unsigned char *)data)[0];
    dest_mac[1] = ((unsigned char *)data)[1];
    dest_mac[2] = ((unsigned char *)data)[2];
    dest_mac[3] = ((unsigned char *)data)[3];
    dest_mac[4] = ((unsigned char *)data)[4];
    dest_mac[5] = ((unsigned char *)data)[5];

    // Read source MAC (next 6 bytes)
    src_mac[0] = ((unsigned char *)data)[6];
    src_mac[1] = ((unsigned char *)data)[7];
    src_mac[2] = ((unsigned char *)data)[8];
    src_mac[3] = ((unsigned char *)data)[9];
    src_mac[4] = ((unsigned char *)data)[10];
    src_mac[5] = ((unsigned char *)data)[11];

    // Write source MAC to destination
    ((unsigned char *)data)[0] = src_mac[0];
    ((unsigned char *)data)[1] = src_mac[1];
    ((unsigned char *)data)[2] = src_mac[2];
    ((unsigned char *)data)[3] = src_mac[3];
    ((unsigned char *)data)[4] = src_mac[4];
    ((unsigned char *)data)[5] = src_mac[5];

    // Write destination MAC to source
    ((unsigned char *)data)[6] = dest_mac[0];
    ((unsigned char *)data)[7] = dest_mac[1];
    ((unsigned char *)data)[8] = dest_mac[2];
    ((unsigned char *)data)[9] = dest_mac[3];
    ((unsigned char *)data)[10] = dest_mac[4];
    ((unsigned char *)data)[11] = dest_mac[5];

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
