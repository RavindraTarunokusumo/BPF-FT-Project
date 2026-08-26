#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Check if packet is at least 14 bytes (Ethernet header size)
    if (data_end - data < 14) {
        return XDP_PASS;
    }

    struct ethhdr *eth = data;

    // Ensure the entire Ethernet header is within bounds
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    // Set source MAC to 02:00:00:00:00:42
    eth->h_source[0] = 0x02;
    eth->h_source[1] = 0x00;
    eth->h_source[2] = 0x00;
    eth->h_source[3] = 0x00;
    eth->h_source[4] = 0x00;
    eth->h_source[5] = 0x42;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
