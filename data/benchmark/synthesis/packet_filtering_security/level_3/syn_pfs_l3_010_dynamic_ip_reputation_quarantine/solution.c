#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#define QUARANTINE_DURATION_NS 60000000000ULL // 60 seconds

struct ip_reputation {
    __u32 bad_event_count;
    __u64 quarantine_until_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __be32);
    __type(value, struct ip_reputation);
    __uint(max_entries, 1024);
} quarantine_map SEC(".maps");

SEC("xdp")
int xdp_reputation_quarantine(struct xdp_md *ctx) {
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

    __be32 src_ip = ip->saddr;
    __u64 now = bpf_ktime_get_ns();

    struct ip_reputation *rep = bpf_map_lookup_elem(&quarantine_map, &src_ip);

    // Check if source IP is currently in active quarantine
    if (rep && rep->quarantine_until_ns > now)
        return XDP_DROP;

    // Detect abnormal TCP flag combinations (e.g. SYN+FIN = 0x03, NULL scan = 0x00)
    int is_abnormal = 0;
    if (ip->protocol == IPPROTO_TCP) {
        int ip_len = ip->ihl * 4;
        if (ip_len >= sizeof(struct iphdr) && (void *)ip + ip_len <= data_end) {
            struct tcphdr *tcp = (void *)ip + ip_len;
            if ((void *)(tcp + 1) <= data_end) {
                if (tcp->syn && tcp->fin) // SYN+FIN illegal combo
                    is_abnormal = 1;
                else if (!tcp->syn && !tcp->ack && !tcp->rst && !tcp->fin) // NULL scan
                    is_abnormal = 1;
            }
        }
    }

    if (is_abnormal) {
        if (!rep) {
            struct ip_reputation new_rep = { .bad_event_count = 1, .quarantine_until_ns = 0 };
            bpf_map_update_elem(&quarantine_map, &src_ip, &new_rep, BPF_ANY);
            return XDP_PASS;
        }

        rep->bad_event_count += 1;
        if (rep->bad_event_count >= 3) {
            rep->quarantine_until_ns = now + QUARANTINE_DURATION_NS;
            return XDP_DROP;
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
