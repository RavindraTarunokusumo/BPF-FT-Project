#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 2);
} frag_stats SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;

    /* Validate Ethernet frame bounds */
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* Only process IPv4 packets */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    /* ip points immediately after the Ethernet header */
    struct iphdr *ip = (void *)(eth + 1);

    /* Validate IPv4 header bounds before reading frag_off.
     * ip + 1 <= data_end ensures the at least the first 4 bytes
     * (minimum IP header size) are present, preventing out-of-bounds
     * access to ip->frag_off at offset 20. */
    if (ip + 1 > data_end)
        return XDP_PASS;

    /* Check for fragmentation fragments_off lower 13 bits */
    __u16 frag_off = bpf_ntohs(ip->frag_off);
    __u32 slot = (frag_off & 0x3FFF) ? 0 : 1;

    /* Record in per-CPU array map: slot 0 = fragmented, slot 1 = unfragmented */
    __u64 *cnt = bpf_map_lookup_elem(&frag_stats, &slot);
    if (cnt)
        *cnt += 1;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
