#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1024);
} flow_byte_map_6 SEC(".maps");

SEC("xdp")
int xdp_flow_telemetry_6(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u32 key = ip->saddr;
    __u64 bytes = (__u64)((long)data_end - (long)data);
    __u64 *val = bpf_map_lookup_elem(&flow_byte_map_6, &key);
    if (val) {
        __sync_fetch_and_add(val, bytes);
    } else {
        bpf_map_update_elem(&flow_byte_map_6, &key, &bytes, BPF_NOEXIST);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
