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
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    __u8   proto;
    __u8   pad[3];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 2048);
    __type(key, struct flow_key);
    __type(value, __u32);
} ct_map SEC(".maps");

SEC("xdp")
int xdp_track_syn_pfs_l3_005_tcp_handshake_state_tracker(struct xdp_md *ctx) {
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
    key.proto = ip->protocol;

    __u32 *state = bpf_map_lookup_elem(&ct_map, &key);
    if (!state) {
        if (tcp->syn && !tcp->ack) {
            // Unsolicited SYN, initialize state
            *state = 1; // SYN_SENT
            bpf_map_update_elem(&ct_map, &key, state, BPF_ANY);
        } else {
            // Unsolicited non-SYN, drop
            return XDP_DROP;
        }
    } else {
        if (tcp->syn && tcp->ack) {
            // SYN-ACK, promote both directions
            struct flow_key rev_key = {};
            rev_key.src_ip = key.dst_ip;
            rev_key.dst_ip = key.src_ip;
            rev_key.src_port = key.dst_port;
            rev_key.dst_port = key.src_port;
            rev_key.proto = ip->protocol;

            __u32 *rev_state = bpf_map_lookup_elem(&ct_map, &rev_key);
            if (rev_state) {
                *rev_state = 2;
                bpf_map_update_elem(&ct_map, &rev_key, rev_state, BPF_ANY);
            }
            *state = 2;
            bpf_map_update_elem(&ct_map, &key, state, BPF_ANY);
        } else if (tcp->fin || tcp->rst) {
            // Teardown, mark as closed
            *state = 3;
            bpf_map_update_elem(&ct_map, &key, state, BPF_ANY);
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
