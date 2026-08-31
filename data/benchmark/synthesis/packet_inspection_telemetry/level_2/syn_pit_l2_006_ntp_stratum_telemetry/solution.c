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
    __uint(max_entries, 4); // 0=Stratum 1, 1=Stratum 2, 2=Stratum 3-15, 3=Unsynchronized(0 or >=16)
} ntp_stratum_map SEC(".maps");

SEC("xdp")
int xdp_ntp_stratum_telemetry(struct xdp_md *ctx) {
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
    if (udp->dest != bpf_htons(123) && udp->source != bpf_htons(123))
        return XDP_PASS;

    __u8 *ntp = (void *)(udp + 1);
    if (ntp + 2 > data_end)
        return XDP_PASS;

    __u8 stratum = *(ntp + 1);
    __u32 key = 3; // Unsynchronized (0 or >= 16)
    if (stratum == 1) key = 0;
    else if (stratum == 2) key = 1;
    else if (stratum >= 3 && stratum <= 15) key = 2;

    __u64 *cnt = bpf_map_lookup_elem(&ntp_stratum_map, &key);
    if (cnt)
        *cnt += 1;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
