#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char _license[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} total_packet_counter SEC(".maps");

SEC("xdp")
int xdp_program(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Ensure packet data is within bounds (no data access required)
    if ((void *)(data + 0) > data_end) {
        return XDP_DROP;
    }

    __u32 key = 0;
    __u64 *counter;
    counter = bpf_map_lookup_elem(&total_packet_counter, &key);
    if (counter) {
        *counter += 1;
    }

    return XDP_PASS;
}
