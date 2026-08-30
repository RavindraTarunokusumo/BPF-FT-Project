// valid eth header
else
    // invalid, count as non-IPv4

But how to handle that in eBPF? Well, the problem says to count all packets, so even if the Ethernet header is invalid, we should count it as non-IPv4. So perhaps we can proceed.

So, in code:

struct ethhdr *eth = ctx->data;
if ((void *)(eth + 1) > (void *)ctx->data + ctx->data_len)
    slot = 3;
else {
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        slot = 3;
    else {
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > (void *)ctx->data + ctx->data_len)
            slot = 3;
        else {
            if (ip->protocol == IPPROTO_TCP)
                slot = 0;
            else if (ip->protocol == IPPROTO_UDP)
                slot = 1;
            else
                slot = 2;
        }
    }
}

But how to handle the h_proto? It's a __u16, so we need to compare with bpf_htons(ETH_P_IP).

Once the slot is determined, we need to increment the corresponding counter in the per-CPU array.

So, the code would be:

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} protocol_counters_2 SEC(".maps");

Then, in the XDP function:

__u32 key = 3; // non-IPv4

struct ethhdr *eth = ctx->data;
if ((void *)(eth + 1) <= (void *)ctx->data + ctx->data_len) {
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) <= (void *)ctx->data + ctx->data_len) {
            if (ip->protocol == IPPROTO_TCP)
                key = 0;
            else if (ip->protocol == IPPROTO_UDP)
                key = 1;
            else
                key = 2;
        }
    }
}

__u64 *cnt = bpf_map_lookup_elem(&protocol_counters_2, &key);
if (cnt)
    __sync_fetch_and_add(cnt, 1);

return XDP_PASS;

Wait, but in eBPF, the __sync_fetch_and_add is allowed? Or should we use atomic operations. Well, the BPF verifier allows incrementing with atomic operations. So using __sync_fetch_and_add is okay.

But in eBPF, the correct way is to use the BPF helper functions. Wait, but in the case of per-CPU maps, the BPF_MAP_TYPE_PERCPU_ARRAY is per-CPU, so each CPU has its own copy. So when we do bpf_map_lookup_elem, it returns the per-CPU entry. So the increment is safe as long as we are using the same key. So the code should be okay.

Now, the code structure.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} protocol_counters_2 SEC(".maps");

SEC("xdp")
int xdp_telemetry_pit_l2_protocol_counters(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data + ctx->data_len;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u32 key = 3; // non-IPv4

    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) <= data_end) {
            if (ip->protocol == IPPROTO_TCP)
                key = 0;
            else if (ip->protocol == IPPROTO_UDP)
                key = 1;
            else
                key = 2;
        }
    }

    __u64 *cnt = bpf_map_lookup_elem(&protocol_counters_2, &key);
    if (cnt)
        __sync_fetch_and_add(cnt, 1);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
