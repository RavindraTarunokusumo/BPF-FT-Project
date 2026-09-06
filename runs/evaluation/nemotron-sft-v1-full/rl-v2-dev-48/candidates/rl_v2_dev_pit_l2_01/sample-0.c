#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);
    __type(value, __u64);
} dst_bytes_01 SEC(".maps");

SEC("xdp")
int xdp_telemetry_rl_v2_dev_pit_l2_01(struct xdp_md *ctx) {
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

    __u32 key = ip->daddr;
    __u64 len = bpf_ntohs(ip->tot_len);

    __u64 *cnt = bpf_map_lookup_elem(&dst_bytes_01, &key);
    if (cnt)
        __sync_fetch_and_add(cnt, len);
    else
        bpf_map_update_elem(&dst_bytes_01, &key, &len, BPF_ANY);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
