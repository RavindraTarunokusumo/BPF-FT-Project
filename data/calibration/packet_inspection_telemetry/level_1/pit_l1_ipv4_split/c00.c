#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("license")
char _license[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} ip_split_counter SEC(".maps");

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Check Ethernet header bounds
    if (data + sizeof(struct ethhdr) > data_end) {
        return XDP_PASS;
    }

    struct ethhdr *eth = data;
    __be16 h_proto = eth->h_proto;

    int slot = (h_proto == bpf_htons(ETH_P_IP)) ? 0 : 1;

    __u64 *counter;
    int err = bpf_map_lookup_elem(&ip_split_counter, &slot, &counter);
    if (err) {
        return XDP_PASS;
    }
    (*counter)++;
    bpf_map_update_elem(&ip_split_counter, &slot, counter, BPF_ANY);

    return XDP_PASS;
}
