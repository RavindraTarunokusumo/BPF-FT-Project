#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 2); // 0=Single encapsulation, 1=Double nested encapsulation
} ipinip_depth_map SEC(".maps");

SEC("xdp")
int xdp_ipinip_depth_telemetry(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip1 = (void *)(eth + 1);
    if ((void *)(ip1 + 1) > data_end)
        return XDP_PASS;
    if (ip1->protocol != 4) // Not IP-in-IP
        return XDP_PASS;

    int ip1_len = ip1->ihl * 4;
    if (ip1_len < sizeof(struct iphdr) || (void *)ip1 + ip1_len > data_end)
        return XDP_PASS;

    struct iphdr *ip2 = (void *)ip1 + ip1_len;
    if ((void *)(ip2 + 1) > data_end)
        return XDP_PASS;

    __u32 key = 0; // Single encapsulation by default
    if (ip2->protocol == 4) { // Nested second encapsulation
        key = 1;
    }

    __u64 *cnt = bpf_map_lookup_elem(&ipinip_depth_map, &key);
    if (cnt)
        *cnt += 1;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
