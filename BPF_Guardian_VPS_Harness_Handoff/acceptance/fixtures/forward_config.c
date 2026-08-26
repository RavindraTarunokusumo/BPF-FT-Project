#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} forwarding_config SEC(".maps");

SEC("xdp")
int forward_config(struct xdp_md *ctx)
{
    (void)ctx;
    __u32 key = 0;
    __u32 *egress_ifindex = bpf_map_lookup_elem(&forwarding_config, &key);

    if (!egress_ifindex || *egress_ifindex == 0)
        return XDP_ABORTED;
    return bpf_redirect(*egress_ifindex, 0);
}

char LICENSE[] SEC("license") = "GPL";
