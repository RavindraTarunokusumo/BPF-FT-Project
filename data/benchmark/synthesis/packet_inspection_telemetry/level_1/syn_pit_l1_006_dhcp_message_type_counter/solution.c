#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 4); // 0=Discover(1), 1=Offer(2), 2=Request(3), 3=Ack(5)
} dhcp_type_map SEC(".maps");

SEC("xdp")
int xdp_dhcp_type_counter(struct xdp_md *ctx) {
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
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    int ip_len = ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip_len;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    if ((udp->source != bpf_htons(67) && udp->source != bpf_htons(68)) ||
        (udp->dest != bpf_htons(67) && udp->dest != bpf_htons(68)))
        return XDP_PASS;

    void *dhcp_start = (void *)(udp + 1);
    if (dhcp_start + 243 > data_end)
        return XDP_PASS;

    __be32 *magic = (void *)dhcp_start + 236;
    if (*magic != bpf_htonl(0x63825363))
        return XDP_PASS;

    __u8 *opt = (void *)dhcp_start + 240;
    if (*opt != 53 || *(opt + 1) != 1) // Option 53 (DHCP Message Type)
        return XDP_PASS;

    __u8 msg_type = *(opt + 2);
    __u32 key = 99;
    if (msg_type == 1) key = 0;      // Discover
    else if (msg_type == 2) key = 1; // Offer
    else if (msg_type == 3) key = 2; // Request
    else if (msg_type == 5) key = 3; // Ack

    if (key < 4) {
        __u64 *cnt = bpf_map_lookup_elem(&dhcp_type_map, &key);
        if (cnt)
            *cnt += 1;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
