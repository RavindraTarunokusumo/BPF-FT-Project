#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 2);
} metrics_map SEC(".maps");

SEC("xdp")
int xdp_count_metrics(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u64 pkt_len = (long)data_end - (long)data;

    __u32 key_pkts = 0;
    __u64 *pkts = bpf_map_lookup_elem(&metrics_map, &key_pkts);
    if (pkts)
        __sync_fetch_and_add(pkts, 1);

    __u32 key_bytes = 1;
    __u64 *bytes = bpf_map_lookup_elem(&metrics_map, &key_bytes);
    if (bytes)
        __sync_fetch_and_add(bytes, pkt_len);

    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
