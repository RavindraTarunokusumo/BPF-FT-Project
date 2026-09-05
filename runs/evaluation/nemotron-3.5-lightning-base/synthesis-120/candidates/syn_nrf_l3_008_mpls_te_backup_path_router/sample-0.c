#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* MPLS header definition (RFC 3032) */
struct mpls_header {
    __be32 label_exp_s_flags; /* 20 bits label, 3 bits exp, 1 bit bottom-of-stack, 8 bits TTL */
};

/* BPF array map to store TE tunnel health status */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} te_health_map SEC(".maps");

/* XDP program entry point */
SEC("xdp")
int xdp_mpls_frr(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    /* Validate Ethernet frame minimum size */
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_PASS;

    /* Ethernet header */
    struct ethhdr *eth = data;

    /* Only process IPv4 or MPLS directly over Ethernet (EtherType 0x8847) */
    if (eth->h_proto == bpf_htons(ETH_P_MPLS_UC) ||
        eth->h_proto == bpf_htons(ETH_P_MPLS_MC)) {
        /* Check if there's enough room for at least one MPLS label */
        if (data + sizeof(struct ethhdr) + sizeof(struct mpls_header) > data_end)
            return XDP_PASS;

        struct mpls_header *mpls = data + sizeof(struct ethhdr);

        /* Extract 20-bit label (top 20 bits of the 32-bit word) */
        __u32 label = bpff_ntohl(mpls->label_exp_s_flags) >> 12;

        /* Check if this is the TE tunnel label 1000 */
        if (label == 1000) {
            /* Look up tunnel health status in the BPF array map */
            __u32 key = 0;
            __u32 *status;

            status = bpf_map_lookup_elem(&te_health_map, &key, NULL);
            if (status) {
                /* Primary tunnel UP (status == 1) -> redirect to ifindex 90 */
                if (*status == 1) {
                    bpf_xdp_adjust_head(ctx, 0); /* keep packet intact */
                    /* Redirect to primary TE interface */
                    bpf_xdp_redirect_map(ctx, &te_health_map, 90, 0);
                    return XDP_REDIRECT;
                }
                /* Primary tunnel DOWN (status == 0) -> fail over to ifindex 91 */
                else if (*status == 0) {
                    bpf_xdp_adjust_head(ctx, 0); /* keep packet intact */
                    /* Redirect to backup TE interface */
                    bpf_xdp_redirect_map(ctx, &te_health_map, 91, 0);
                    return XDP_REDIRECT;
                }
            }
            /* If map lookup fails or key not present, pass traffic */
            return XDP_PASS;
        }
        /* For other MPLS labels, pass through */
        return XDP_PASS;
    }

    /* Non-MPLS traffic: pass through */
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
