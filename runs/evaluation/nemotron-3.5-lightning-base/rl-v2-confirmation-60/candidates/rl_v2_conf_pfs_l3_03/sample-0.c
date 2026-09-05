#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>

/* 
 * BPF map to track protocol budget.
 * Key: __u32 (protocol number, e.g., IPPROTO_TCP=6)
 * Value: __u64 (packet count for that protocol)
 */
SEC("xdp")
int xdp_protocol_budget(struct xdp_md *ctx)
{
    void *data_end;
    void *data;
    struct iphdr *ip;
    __u32 proto_key;
    __u64 *pkt_count;
    __u64 one = 1;
    __u64 limit = 50000;

    /* Pointer initialization for bounds checking */
    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    /* Verify Ethernet header bounds */
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_PASS;

    /* Pointer to IPv4 header (ethhdr + iphdr) */
    ip = (struct iphdr *)(data + sizeof(struct ethhdr));

    /* Verify IPv4 header bounds */
    if ((void *)ip + sizeof(struct iphdr) > data_end)
        return XDP_PASS;

    /* Only process IPv4 packets (version check) */
    if (ip->version != 4)
        return XDP_PASS;

    /* Extract protocol field (e.g., IPPROTO_TCP=6, IPPROTO_UDP=17) */
    proto_key = (__u32)ip->protocol;

    /* Lookup or insert the protocol count in the map.
       bpf_map_lookup_elem returns 0 on success, -key_exists on hit. */
    pkt_count = bpf_map_lookup_elem(
        bpf_map_fd_protocol_budget_map,   /* map fd is passed via external definition or extern */
        &proto_key,
        &one,                             /* dummy value pointer, not used for update */
        BPF_ANY                           /* operation: update if exists, insert if not */
    );

    /* Handle lookup/update result */
    if (pkt_count) {
        /* Packet count already exists, increment it */
        (*pkt_count)++;
    } else {
        /* First time seeing this protocol, initialize count to 1 */
        pkt_count = bpf_map_update_elem(
            bpf_map_fd_protocol_budget_map,
            &proto_key,
            &one,
            BPF_ANY
        );
        if (!pkt_count)
            return XDP_PASS; /* update failed, but continue */
    }

    /* Check if protocol count exceeds the budget limit */
    if (*pkt_count > limit) {
        return XDP_DROP;
    }

    /* All other packets are forwarded */
    return XDP_PASS;
}

/* Map definition.
 * The map fd must be loaded by the calling program (e.g., via bpftool or bpf_link_create).
 * For standalone compilation verification, the map_fd is typically resolved at load time.
 * Here we declare the map extern so the verifier knows its type without a real fd.
 */
struct bpf_map *bpf_map_fd_protocol_budget_map SEC("maps");

char LICENSE[] SEC("license") = "GPL";
