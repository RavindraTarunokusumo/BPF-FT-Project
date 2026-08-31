#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 2); // 0=Request(1), 1=Reply(2)
} arp_opcode_map SEC(".maps");

SEC("xdp")
int xdp_arp_opcode_counter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_ARP))
        return XDP_PASS;

    struct arphdr *arp = (void *)(eth + 1);
    if ((void *)(arp + 1) > data_end)
        return XDP_PASS;

    __u16 op = bpf_ntohs(arp->ar_op);
    if (op == ARPOP_REQUEST) {
        __u32 key = 0;
        __u64 *cnt = bpf_map_lookup_elem(&arp_opcode_map, &key);
        if (cnt)
            *cnt += 1;
    } else if (op == ARPOP_REPLY) {
        __u32 key = 1;
        __u64 *cnt = bpf_map_lookup_elem(&arp_opcode_map, &key);
        if (cnt)
            *cnt += 1;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
