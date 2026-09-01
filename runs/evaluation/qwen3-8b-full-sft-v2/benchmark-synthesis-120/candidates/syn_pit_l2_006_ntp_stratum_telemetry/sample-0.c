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
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} ntp_stratum_map SEC(".maps");

SEC("xdp")
int xdp_telemetry_syn_pit_l2_006_ntp_stratum(struct xdp_md *ctx) {
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

    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    unsigned int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr) || (void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip_hdr_len;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    if (udp->dest != bpf_htons(123))
        return XDP_PASS;

    __u32 key = 3; // Unsynchronized / reserved
    if (udp->dgram_len >= (unsigned int)sizeof(struct udphdr) + 48) {
        char *payload = (void *)udp + sizeof(struct udphdr);
        if (payload + 1 <= data_end) {
            __u8 stratum = payload[1];
            if (stratum == 1)
                key = 0;
            else if (stratum == 2)
                key = 1;
            else if (stratum >= 3 && stratum <= 15)
                key = 2;
        }
    }

    __u64 *cnt = bpf_map_lookup_elem(&ntp_stratum_map, &key);
    if (cnt)
        *cnt += 1;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
