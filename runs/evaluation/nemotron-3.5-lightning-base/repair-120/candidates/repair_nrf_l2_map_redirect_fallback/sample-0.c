#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

/* Map holding the egress interface index. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} forwarding_config SEC(".maps");

SEC("xdp")
int xdp_forward(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;

    /* Basic packet size check. */
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u32 key = 0;
    __u32 *ifindex;

    /* Lookup key 0; bpf_map_lookup_elem may return NULL. */
    ifindex = bpf_map_lookup_elem(&forwarding_config, &key);
    if (!ifindex)
        return XDP_ABORTED;

    /* If the stored interface index is 0, treat as missing. */
    if (*ifindex == 0)
        return XDP_ABORTED;

    /* Redirect the frame to the interface stored in the map. */
    return bpf_redirect(*ifindex, 0);
}

char LICENSE[] SEC("license") = "GPL";
