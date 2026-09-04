#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 16);
} telemetry_map_port123_counter SEC(".maps");

SEC("xdp")
int xdp_telemetry_port123_counter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u32 key = 0;
    __u64 *val = bpf_map_lookup_elem(&telemetry_map_port123_counter, &key);
    if (val)
        __sync_fetch_and_add(val, 1);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
