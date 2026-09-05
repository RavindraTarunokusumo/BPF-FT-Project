#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

/* LRU Hash map: key = destination IP (__u32), value = accumulated bytes (__u64) */
struct {
    __uint	type, BPF_MAP_TYPE_LRU_HASH;
    __uint	max_entries, 256;
    __type(__u32);
    __type(__u64);
} dst_bytes_03 SEC(".maps");

SEC("xdp")
int xdp_prog_l2_03(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    /* Verify Ethernet header bounds */
    struct eth_hdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    /* Verify IPv4 header bounds */
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;

    /* Only process IPv4 packets (version check) */
    if (ip->version != 4)
        return XDP_PASS;

    /* Lookup destination IP in the LRU hash map */
    __u32 key = ip->daddr;
    __u64 *val = bpf_map_lookup_elem(dst_bytes_03, &key);

    if (val) {
        /* Atomically add byte count to existing entry */
        *val = bpf_add64(*val, bpf_ntohs(ip->tot_len));
    } else {
        /* Initialize entry with packet length */
        __u64 init_val = bpf_ntohs(ip->tot_len);
        bpf_map_update_elem(dst_bytes_03, &key, &init_val, BPF_ANY);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
