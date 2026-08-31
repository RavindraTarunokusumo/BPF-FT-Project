#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct meter_val {
    __u64 packets;
    __u64 ip_bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct meter_val);
    __uint(max_entries, 1024);
} src_meter SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u32 src = ip->saddr;
    __u32 ip_len = (__u32)ip->tot_len;
    if (ip_len < sizeof(struct iphdr))
        return XDP_PASS;

    __u64 ip_bytes = (__u64)ip_len - (__u64)sizeof(struct iphdr);
    if (ip_bytes < 0)
        return XDP_PASS;

    struct meter_val *val = bpf_map_lookup_elem(&src_meter, &src);
    if (val) {
        val->packets += 1;
        __u64 new_ip_bytes = val->ip_bytes + ip_bytes;
        if (new_ip_bytes < val->ip_bytes) // Check for overflow
            return XDP_PASS;
        val->ip_bytes = new_ip_bytes;
    } else {
        struct meter_val init = {.packets = 1, .ip_bytes = ip_bytes};
        bpf_map_update_elem(&src_meter, &src, &init, BPF_ANY);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
