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
} dhcp_type_map_6 SEC(".maps");

SEC("xdp")
int xdp_telemetry_syn_pit_l1_006_dhcp(struct xdp_md *ctx) {
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
    if (ip_hdr_len < sizeof(struct iphdr))
        return XDP_PASS;

    if ((void *)ip + ip_hdr_len > data_end)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip_hdr_len;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    if (udp->dest != bpf_htons(67) && udp->src != bpf_htons(68))
        return XDP_PASS;

    unsigned int udp_hdr_len = sizeof(struct udphdr);
    if ((void *)udp + udp_hdr_len > data_end)
        return XDP_PASS;

    unsigned char *payload = (void *)udp + udp_hdr_len;
    if (payload + 243 > data_end)
        return XDP_PASS;

    __u32 *key = NULL;
    __u64 *cnt = NULL;

    if (payload[236] != 0x63 || payload[237] != 0x82 ||
        payload[238] != 0x53 || payload[239] != 0x63)
        return XDP_PASS;

    while (payload < data_end) {
        if (*payload < 2)
            break;
        __u8 opt_type = *payload;
        __u8 opt_len = payload[1];
        if (payload + 2 + opt_len > data_end)
            break;
        if (opt_type == 53) {
            __u8 msg_type = payload[2];
            if (msg_type == 1)
                key = (__u32 *)1;
            else if (msg_type == 2)
                key = (__u32 *)2;
            else if (msg_type == 3)
                key = (__u32 *)3;
            else if (msg_type == 5)
                key = (__u32 *)4;
            if (key) {
                __u64 *cnt = bpf_map_lookup_elem(&dhcp_type_map_6, key);
                if (cnt)
                    __sync_fetch_and_add(cnt, 1);
            }
        }
        payload += 2 + opt_len;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
