#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

/* Array map holding per-ingress-interface packet counters.
 * Key:   interface index (bounded to 0..63)
 * Value: 64-bit packet counter (per-CPU array element) */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 64);
} iface_stats SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx) {
    __u32 ifindex = ctx->ingress_ifindex & 63;   /* bound to 0..63 */
    __u64 *cnt;

    /* Lookup the per-CPU array element; returns pointer or NULL */
    cnt = bpf_map_lookup_elem(&iface_stats, &ifindex);
    if (!cnt) {
        /* Key out of range or map not yet populated – skip */
        return XDP_PASS;
    }

    (*cnt) += 1;   /* safe increment after NULL check */
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
