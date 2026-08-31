#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __be32);
    __uint(max_entries, 1);
} auth_dhcp_server SEC(".maps");

SEC("xdp")
int xdp_dhcp_rogue_filter(struct xdp_md *ctx) {
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

    // DHCP server responses originate from port 67 targeting client port 68
    if (udp->source != bpf_htons(67) || udp->dest != bpf_htons(68))
        return XDP_PASS;

    // Fixed DHCP body is 236 bytes followed by 4-byte magic cookie
    void *dhcp_start = (void *)(udp + 1);
    if (dhcp_start + 240 > data_end)
        return XDP_PASS;

    __u8 op = *(__u8 *)dhcp_start;
    if (op != 2) // 2 = BOOTREPLY / DHCP server response
        return XDP_PASS;

    __be32 *magic = (void *)dhcp_start + 236;
    if (*magic != bpf_htonl(0x63825363))
        return XDP_PASS;

    __u32 key = 0;
    __be32 *auth_ip = bpf_map_lookup_elem(&auth_dhcp_server, &key);
    __be32 expected_ip = auth_ip ? *auth_ip : bpf_htonl(0xC0A80101); // Default 192.168.1.1

    if (ip->saddr != expected_ip)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
