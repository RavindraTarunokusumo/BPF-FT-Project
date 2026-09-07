#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int transform_noop(struct xdp_md *ctx)
{
    (void)ctx;
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
