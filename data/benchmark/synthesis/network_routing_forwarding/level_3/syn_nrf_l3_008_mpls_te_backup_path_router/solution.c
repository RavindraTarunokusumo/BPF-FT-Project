#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>

struct mpls_label {
    __u32 entry;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} te_health_map SEC(".maps");

SEC("xdp")
int xdp_mpls_frr_router(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(0x8847))
        return XDP_PASS;

    struct mpls_label *mpls = (void *)(eth + 1);
    if ((void *)(mpls + 1) > data_end)
        return XDP_PASS;

    __u32 label = bpf_ntohl(mpls->entry) >> 12;
    if (label == 1000) {
        __u32 key = 0;
        __u32 *status = bpf_map_lookup_elem(&te_health_map, &key);
        if (status && *status == 0)
            return bpf_redirect(91, 0); // Backup TE path
        return bpf_redirect(90, 0); // Primary TE path
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
