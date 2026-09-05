#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

/*
 * Per-CPU array map to accumulate UDP payload byte counts.
 * Key 0 selects the counter; value is a __u64.
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} udp_payload_bytes SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;

    /* Verify Ethernet header fits. */
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* Only process IPv4. */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    /* IPv4 header starts right after Ethernet. */
    struct iphdr *ip = (void *)(eth + 1);
    /* Verify IPv4 header minimum size and that it does not exceed the packet. */
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    /* ip->ihl is in 4-byte units; multiply by 4 to get byte length. */
    __u32 ip_len = (__u32)ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    /* UDP header starts after the IPv4 header. */
    struct udphdr *udp = (void *)ip + ip_len;
    /* Verify UDP header fits. */
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    /* Payload starts right after the UDP header.
     * The critical fix: validate that payload does not go past data_end
     * before computing the byte difference. */
    char *payload = (void *)(udp + 1);
    if (payload >= (char *)data_end)
        return XDP_PASS;

    /* Safe 64-bit subtraction; plen now represents the number of payload bytes. */
    __u64 plen = (__u64)(long)data_end - (__u64)(long)payload;

    __u32 key = 0;
    __u64 *cnt = bpf_map_lookup_elem(&udp_payload_bytes, &key);
    if (cnt)
        *cnt += plen;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
