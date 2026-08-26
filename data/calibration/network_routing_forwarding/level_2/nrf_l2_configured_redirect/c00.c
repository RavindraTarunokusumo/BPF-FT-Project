#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("maps")
struct bpf_map_def forwarding_config = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 1,
};

char _license[] SEC("license") = "GPL";

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Check if packet is at least 14 bytes (Ethernet header)
    if (data_end - data < 14) {
        return XDP_PASS;
    }

    // Ensure Ethernet header bounds are valid
    if ((void *)(data + 12) > data_end) {
        return XDP_PASS;
    }

    // Lookup key 0 in forwarding_config map
    __u32 key = 0;
    __u32 *val = bpf_map_lookup_elem(&forwarding_config, &key);
    if (!val) {
        return XDP_ABORTED;
    }

    // Check if the retrieved ifindex is non-zero
    if (*val == 0) {
        return XDP_ABORTED;
    }

    // Redirect packet to the configured interface
    return bpf_redirect(*val, 0);
}
