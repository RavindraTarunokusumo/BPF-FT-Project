#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} packet_count SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx) {
    __u32 key = 0;
    __u64 *cnt = bpf_map_lookup_elem(&packet_count, &key);
    if (cnt)
        *cnt += 1;
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
