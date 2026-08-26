#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u64 pkt_len = data_end - data;

    // Enforce strict packet bounds check
    if (data_end <= data) {
        return XDP_PASS;
    }

    __u32 key = 0;
    struct { __u64 count; } *val;
    int ret = bpf_map_lookup_elem(&total_byte_counter, &key, &val);
    if (ret == 0) {
        *val += pkt_len;
    }

    return XDP_PASS;
}

struct {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 1,
} total_byte_counter SEC(".maps");

char _license[] SEC("license") = "GPL";
