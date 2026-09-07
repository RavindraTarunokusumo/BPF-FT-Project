/* XDP VLAN Trunk Reflector
 * ========================
 * Reflects 802.1Q tagged frames with VID == 100 by swapping
 * MAC addresses and transmitting on the ingress interface.
 * All other traffic is passed through unchanged.
 *
 * Compilation:  clang -target bpf -O2 -c vlan_reflector.c -o vlan_reflector.o
 * License:     GPL
 */

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>

/* VLAN tag header as defined by the Linux kernel.
 * This struct mirrors the first 2 bytes of the 802.1Q tag.
 * The full tag is 4 bytes: TCI (2 bytes) + VLAN ID (12 bits).
 */
struct vlan_hdr {
    __be16 h_vlan_TCI;  /* Priority + CFI + VLAN ID */
};

/* XDP action return values */
#define XDP_PASS  0
#define XDP_TX    1

/* Helper: load a 16-bit value from a pointer with bounds checking.
 * Returns 0 on failure (out of bounds), otherwise the value.
 */
static __always_inline __u16 load_u16_safe(void *ptr, int offset, int size)
{
    if (ptr == NULL || offset + size > sizeof(struct vlan_hdr))
        return 0;
    return *(__u16 *)((void *)ptr + offset);
}

/* XDP program entry point */
SEC("xdp")
int vlan_trunk_reflector(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* --- Validate Ethernet frame header --- */
    struct eth_hdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS; /* truncated frame */

    /* Check for 802.1Q VLAN tag: EtherType == 0x8100 */
    if (eth->h_proto != bpf_htons(ETH_P_8021Q))
        return XDP_PASS;

    /* --- Validate VLAN tag bounds --- */
    /* The VLAN tag follows the Ethernet header immediately.
     * struct eth_hdr is 14 bytes; the tag starts at offset 12
     * (after the 2-byte EtherType). */
    struct vlan_hdr *vlan = data + 12;
    if ((void *)(vlan + 1) > data_end)
        return XDP_PASS; /* truncated VLAN tag */

    /* --- Extract 12-bit VLAN ID --- */
    __u16 tci = load_u16_safe(vlan, 0, sizeof(__u16));
    if (tci == 0)
        return XDP_PASS; /* defensive: zero TCI */

    __u16 vid = tci & 0x0FFF; /* isolate lower 12 bits */

    /* --- VID == 100 reflector logic --- */
    if (vid == 100) {
        /* Swap Ethernet DA and SA.
         * eth->h_dest is the destination MAC (6 bytes).
         * eth->h_source is the source MAC (6 bytes).
         */
        __u8 tmp[6];

        bpf_probe_read_kernel(tmp, sizeof(tmp), eth->h_dest);
        bpf_probe_read_kernel(eth->h_dest, sizeof(tmp), eth->h_source);
        bpf_probe_read_kernel(eth->h_source, sizeof(tmp), tmp);

        /* Return XDP_TX to reflect the frame out the ingress interface.
         * The frame data remains in the driver ring; XDP_TX
         * re-injects it without altering the payload. */
        return XDP_TX;
    }

    /* --- All other traffic: pass through --- */
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
