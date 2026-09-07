#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

/* Port bitmap: 2048 __u32 entries => 65536 bits covering ports 0 .. 65535 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 2048);
} port_bitmap SEC(".maps");

SEC("xdp")
int xdp_filter(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;

    /* Basic Ethernet header bounds check */
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    /* IP header bounds check */
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    /* IP header length (ihl is in 4‑byte units) */
    __u32 ip_len = (__u32)ip->ihl * 4;
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip_len;
    /* TCP header bounds check */
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    __u16 dport = bpf_ntohs(tcp->dest);

    /* ---- Verifier fix: bound the port index before the map lookup ---- */
    /* dport is a __u16 (0‑65535).  Compute word and bit indices safely. */
    __u32 word_idx = dport >> 5;   /* port / 32 */
    __u32 bit_idx  = dport & 31;   /* port % 32 */

    /* Ensure word index is within the bitmap (0 … 2047). */
    if (word_idx >= 2048)
        return XDP_PASS;

    __u32 *val = bpf_map_lookup_elem(&port_bitmap, &word_idx);
    if (!val)
        return XDP_PASS;

    /* Drop TCP ports whose bit in the bitmap is set. */
    if (*val & (1U << bit_idx))
        return XDP_DROP;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
