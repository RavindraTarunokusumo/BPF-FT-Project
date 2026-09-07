#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>

/* Map to hold the window size distribution counters.
 * 4 buckets: <4096, [4096,16384), [16384,65535), >=65535 */
SEC("xdp")
int xdp_win_dist(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Verify Ethernet frame minimum size */
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_PASS;

    struct ethhdr *eth = data;
    /* Skip Ethernet header */
    data += sizeof(struct ethhdr);
    if (data + sizeof(struct iphdr) > data_end)
        return XDP_PASS;

    /* Verify IPv4 protocol */
    struct iphdr *ip = data;
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    data += ip->ihl * 4;
    if (data + sizeof(struct tcphdr) > data_end)
        return XDP_PASS;

    struct tcphdr *tcp = data;

    /* Inspect TCP advertised window (network byte order) */
    __u16 win = bpf_ntohs(tcp->window);

    /* Select bucket:
     * Bin 0: win < 4096
     * Bin 1: 4096 <= win < 16384
     * Bin 2: 16384 <= win < 65535
     * Bin 3: win >= 65535
     */
    int bucket;
    if (win < 4096)
        bucket = 0;
    else if (win < 16384)
        bucket = 1;
    else if (win < 65535)
        bucket = 2;
    else
        bucket = 3;

    /* Atomically increment the per-CPU/per-entry counter */
    __sync_fetch_and_add(&win_dist_01[bucket], 1);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";

/* Map definition: BPF_MAP_TYPE_ARRAY with 4 entries of type __u64 */
SEC("maps")
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 4);
    __u64 values[4]; /* win_dist_01 */
} win_dist_01 = {};
