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
    .name = "source_quota_map",
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 10240,
} source_quota_map SEC(".maps");

SEC("xdp")
int xdp_program(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Check Ethernet header bounds
    if (data + ETH_HLEN > data_end) {
        return XDP_PASS;
    }
    struct ethhdr *eth = data;
    if (eth->h_proto != htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    // Check IPv4 header bounds
    if (data + ETH_HLEN + sizeof(struct iphdr) > data_end) {
        return XDP_PASS;
    }
    struct iphdr *ip = data + ETH_HLEN;
    if ((ip->version << 4) != 4) {
        return XDP_PASS;
    }

    // Convert source IP to host byte order
    __u32 saddr = be32_to_cpu(ip->saddr);

    // Lookup in the source quota map
    __u64 *count = bpf_map_lookup_elem(&source_quota_map, &saddr);
    if (count) {
        if (*count < 5) {
            *count += 1;
            return XDP_PASS;
        } else {
            *count += 1;
            return XDP_DROP;
        }
    } else {
        // Insert new entry with count=1
        __u64 count_val = 1;
        bpf_map_update_elem(&source_quota_map, &saddr, &count_val, BPF_ANY);
        return XDP_PASS;
    }
}

char _license[] SEC("license") = "GPL";
