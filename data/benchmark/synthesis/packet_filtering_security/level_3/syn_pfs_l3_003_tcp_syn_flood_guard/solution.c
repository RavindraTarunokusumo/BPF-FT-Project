#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#define WINDOW_NS 100000000ULL // 100ms
#define MAX_SYNS_PER_WINDOW 10

struct syn_rate_state {
    __u64 window_start_ns;
    __u32 syn_count;
    __u32 drop_count;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __be32);
    __type(value, struct syn_rate_state);
    __uint(max_entries, 1024);
} syn_flood_map SEC(".maps");

SEC("xdp")
int xdp_syn_flood_guard(struct xdp_md *ctx) {
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
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    int ip_len = ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip_len;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    if (!tcp->syn || tcp->ack)
        return XDP_PASS;

    __be32 src_ip = ip->saddr;
    __u64 now = bpf_ktime_get_ns();

    struct syn_rate_state *st = bpf_map_lookup_elem(&syn_flood_map, &src_ip);
    if (!st) {
        struct syn_rate_state new_st;
        new_st.window_start_ns = now;
        new_st.syn_count = 1;
        new_st.drop_count = 0;
        bpf_map_update_elem(&syn_flood_map, &src_ip, &new_st, BPF_ANY);
        return XDP_PASS;
    }

    if (now - st->window_start_ns >= WINDOW_NS) {
        st->window_start_ns = now;
        st->syn_count = 1;
        return XDP_PASS;
    }

    if (st->syn_count >= MAX_SYNS_PER_WINDOW) {
        st->drop_count += 1;
        return XDP_DROP;
    }

    st->syn_count += 1;
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
