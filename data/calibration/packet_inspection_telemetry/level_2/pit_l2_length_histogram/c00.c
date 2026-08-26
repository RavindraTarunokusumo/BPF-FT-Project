#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC(".maps")
struct {
    .name = "length_histogram",
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 4,
} length_histogram SEC(".maps");

char _license[] SEC("license") = "GPL";

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u32 pkt_len = data_end - data;

    // Determine the slot based on packet length
    __u32 slot;
    if (pkt_len < 64) {
        slot = 0;
    } else if (pkt_len < 128) {
        slot = 1;
    } else if (pkt_len < 512) {
        slot = 2;
    } else {
        slot = 3;
    }

    // Lookup and increment the counter in the per-CPU array
    __u64 *count = bpf_map_lookup_elem(&length_histogram, &slot);
    if (count) {
        *count += 1;
    }

    return XDP_PASS;
}
