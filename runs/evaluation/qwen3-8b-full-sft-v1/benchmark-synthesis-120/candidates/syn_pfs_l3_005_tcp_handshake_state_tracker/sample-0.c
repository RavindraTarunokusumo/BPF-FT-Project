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


struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u16 pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 2048);
    __type(key, struct flow_key);
    __type(value, __u32);
} ct_map_5 SEC(".maps");

SEC("xdp")
int xdp_track_syn_pfs_l3_005(struct xdp_md *ctx) {
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

    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    unsigned int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr) || (void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip_hdr_len;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    struct flow_key key = {};
    key.src_ip = ip->saddr;
    key.dst_ip = ip->daddr;
    key.src_port = tcp->source;
    key.dst_port = tcp->dest;

    __u32 *state = bpf_map_lookup_elem(&ct_map_5, &key);
    if (!state) {
        if (tcp->syn && !tcp->ack) {
            // Initiate new SYN_SENT
            __u32 new_state = 1;
            bpf_map_update_elem(&ct_map_5, &key, &new_state, BPF_ANY);
            return XDP_PASS;
        }
        // Unsolicited non-SYN TCP traffic
        return XDP_DROP;
    }

    if (*state == 1) {
        if (tcp->ack && tcp->syn) {
            // SYN-ACK, promote both directions
            __u32 new_state = 2;
            bpf_map_update_elem(&ct_map_5, &key, &new_state, BPF_ANY);
            return XDP_PASS;
        }
        // Already in SYN_SENT, drop unsolicited data
        return XDP_DROP;
    }

    if (*state == 2) {
        // Established connection, allow all TCP traffic
        return XDP_PASS;
    }

    if (tcp->fin || tcp->rst) {
        __u32 new_state = 3;
        bpf_map_update_elem(&ct_map_5, &key, &new_state, BPF_ANY);
        return XDP_PASS;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
