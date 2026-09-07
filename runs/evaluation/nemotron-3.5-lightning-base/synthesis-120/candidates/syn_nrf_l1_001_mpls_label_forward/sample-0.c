#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* MPLS header definition.
 * The first 32-bit word (entry) contains:
 *   - Topmost label: 20 bits (bits 20-1)
 *   - Experimental (QoS) bits: 3 bits (bits 2-0)
 *   - Bottom of Stack: 1 bit (bit 0)
 */
struct mpls_header {
    __be32 entry;
};

/* XDP program entry point.
 * Inspects MPLS unicast frames (EtherType 0x8847).
 * Redirects based on the outer label value.
 */
SEC("xdp")
int mpls_label_forward(struct xdp_md *ctx)
{
    void *data_end;
    void *data;
    struct ethhdr *eth;
    struct mpls_header *mpls;
    __u32 label;

    /* Define packet boundaries for verifier safety */
    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    /* Validate Ethernet header exists */
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    eth = data;

    /* Check for MPLS EtherType (0x8847) */
    if (eth->h_proto != bpf_htons(0x8847))
        return XDP_PASS;

    /* Validate MPLS label header fits within packet */
    if (data + sizeof(*mpls) > data_end)
        return XDP_PASS;

    mpls = data + sizeof(*eth);

    /* Extract the 20-bit label from the outer label stack entry.
     * bpf_ntohl converts from network byte order to host byte order.
     * >> 12 shifts right by 12 bits to isolate the 20-bit label field.
     */
    label = (bpf_ntohl(mpls->entry) >> 12) & 0xFFFFF;

    /* Redirect based on label value */
    if (label == 100) {
        /* Redirect to interface with ifindex 2 */
        return bpf_redirect(2, 0);
    } else if (label == 200) {
        /* Redirect to interface with ifindex 3 */
        return bpf_redirect(3, 0);
    }

    /* Pass all other MPLS labels, non-MPLS frames, and malformed packets */
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
