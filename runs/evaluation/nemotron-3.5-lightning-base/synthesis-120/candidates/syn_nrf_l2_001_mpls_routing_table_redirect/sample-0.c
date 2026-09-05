#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* MPLS header definition (RFC 3032) */
struct mpls_header {
    __be32 label_exp_s_flags; /* 20-bit label, 3-bit exp, 1-bit bottom-of-stack, 1-bit S */
};

/* Define the hash map for MPLS routing table.
 * Key: __u32 (label)
 * Value: __u32 (egress_ifindex)
 * Max entries: 1024 */
struct bpf_map_def __attribute__((section("maps"))) mpls_route_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 1024,
};

/* XDP program entry point */
SEC("xdp")
int xdp_mpls_redirect(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    /* Validate Ethernet frame minimum size */
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_PASS;

    /* Get Ethernet header */
    struct ethhdr *eth = data;

    /* Check for MPLS EtherType (0x8847) */
    if (eth->h_proto != bpf_htons(ETH_P_MPLS_UC) &&
        eth->h_proto != bpf_htons(ETH_P_MPLS_MC))
        return XDP_PASS;

    /* Pointer to the first MPLS label entry.
     * MPLS header is 4 bytes: 20-bit label + 3-bit exp + 1-bit S + 1-bit bottom-of-stack.
     * The first label is at eth + 1 (after the Ethernet header). */
    struct mpls_label *mpls_label;
    /* We use a pointer to __u32 to safely access the 20-bit label field. */
    __u32 *label_word;

    /* The first MPLS label starts immediately after the Ethernet header.
     * Offset: sizeof(struct ethhdr) */
    mpls_label = data + sizeof(struct ethhdr);
    
    /* Verify that the first MPLS label fits within the frame */
    if ((void *)(mpls_label + 1) > data_end)
        return XDP_PASS;

    /* Extract the 20-bit label from the first label entry.
     * label_exp_s_flags is __be32. We need to mask out the top 12 bits.
     * Layout: [20-bit label][3-bit exp][1-bit S][1-bit BOS]
     * In network byte order (big-endian), the label is in the most significant 20 bits. */
    label_word = (__u32 *)mpls_label;
    __u32 label = bpf_ntohl(*label_word) >> 12; /* Shift right 12 to get 20-bit label */

    /* Special label handling per requirements */
    if (label == 500) {
        /* Redirect to ifindex 20 */
        bpf_redirect(20, 0);
        return XDP_PASS; /* Unreachable but kept for clarity */
    }

    if (label == 600) {
        /* Redirect to ifindex 21 */
        bpf_redirect(21, 0);
        return XDP_PASS; /* Unreachable but kept for clarity */
    }

    /* Lookup the label in the MPLS routing hash map.
     * BPF hash map lookup: map_lookup_elem(map_ptr, &key) returns value or NULL. */
    __u32 key = label;
    __u32 *value;

    value = bpf_map_lookup_elem(&mpls_route_map, &key);
    if (value) {
        /* Route found: redirect to the egress interface index */
        bpf_redirect(*value, 0);
        return XDP_PASS; /* Unreachable but kept for clarity */
    }

    /* No route found for this label -> pass frame up the stack */
    return XDP_PASS;
}

char LICENSE[] = "GPL";
