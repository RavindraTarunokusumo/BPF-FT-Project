#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#define KNOCK_TIMEOUT_NS 10000000000ULL // 10 seconds

struct knock_state {
    __u32 stage;
    __u64 last_knock_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __be32);
    __type(value, struct knock_state);
    __uint(max_entries, 1024);
} knock_map SEC(".maps");

SEC("xdp")
int xdp_port_knock_auth(struct xdp_md *ctx) {
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

    int ip_len = ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    __be32 src_ip = ip->saddr;
    __u64 now = bpf_ktime_get_ns();

    // Check UDP knock sequence (7000 -> 8000 -> 9000)
    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + ip_len;
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;

        __u16 dport = bpf_ntohs(udp->dest);
        struct knock_state *st = bpf_map_lookup_elem(&knock_map, &src_ip);

        if (dport == 7000) {
            struct knock_state new_st = { .stage = 1, .last_knock_ns = now };
            bpf_map_update_elem(&knock_map, &src_ip, &new_st, BPF_ANY);
            return XDP_PASS;
        } else if (dport == 8000) {
            if (st && st->stage == 1 && (now - st->last_knock_ns <= KNOCK_TIMEOUT_NS)) {
                st->stage = 2;
                st->last_knock_ns = now;
            }
            return XDP_PASS;
        } else if (dport == 9000) {
            if (st && st->stage == 2 && (now - st->last_knock_ns <= KNOCK_TIMEOUT_NS)) {
                st->stage = 3; // Fully authenticated
                st->last_knock_ns = now;
            }
            return XDP_PASS;
        }
        return XDP_PASS;
    }

    // Check protected TCP port 22
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + ip_len;
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;

        if (tcp->dest == bpf_htons(22)) {
            struct knock_state *st = bpf_map_lookup_elem(&knock_map, &src_ip);
            if (!st || st->stage != 3 || (now - st->last_knock_ns > KNOCK_TIMEOUT_NS))
                return XDP_DROP;
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
