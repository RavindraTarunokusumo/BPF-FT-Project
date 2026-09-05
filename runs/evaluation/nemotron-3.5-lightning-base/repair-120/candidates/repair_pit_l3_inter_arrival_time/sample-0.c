#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

/*
 * Map to store the last timestamp per source IP.
 * Uses HASH map type for key-value lookups.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 4096);
} src_ts_map SEC(".maps");

/*
 * Map to histogram Inter-Arrival Time (IAT).
 * Uses PERCPU_ARRAY map type with 32 buckets (indices 0..31).
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 32);
} iat_hist SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    
    // Basic bounds check
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    
    // Only process IPv4 traffic
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    
    // Basic bounds check
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u32 src = ip->saddr;
    __u64 now = bpf_ktime_get_ns();

    // Lookup the last timestamp for this source IP
    __u64 *last = bpf_map_lookup_elem(&src_ts_map, &src);
    
    // Calculate bucket only if we have a valid previous timestamp and current time is ahead
    if (last && *last != 0 && now > *last) {
        __u64 delta = now - *last;
        
        // Calculate logarithmic bucket index: (delta >> 20) & 31
        // Clamp the index to the valid range [0..31] to prevent verifier "key out of range" error.
        __u32 bucket = (delta >> 20) & 31;
        bucket = bucket > 31 ? 31 : bucket; // Clamp to max index

        // Lookup and increment the counter in the per-CPU array map
        __u64 *cnt = bpf_map_lookup_elem(&iat_hist, &bucket);
        if (cnt)
            *cnt += 1;
    }

    // Update the source timestamp map with the current time
    bpf_map_update_elem(&src_ts_map, &src, &now, BPF_ANY);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
