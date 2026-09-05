/* XDP program: nrf_l2_prefix_redirect
 *
 * Selects one of two egress interfaces based on IPv4 destination prefix:
 *   - 10.0.0.0/8  (mask 0xFF000000) -> key 0 in 'prefix_config' map
 *   - 172.16.0.0/12 (mask 0xFFF00000) -> key 1 in 'prefix_config' map
 *
 * If a prefix matches and the resolved ifindex is non-zero, redirect
 * to that interface. Otherwise pass the frame.
 *
 * GPL license
 */
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* Map: key=__u32, val=__u32 ifindex, max_entries=2 */
SEC("xdp")
int nrf_l2_prefix_redirect(struct xdp_md *ctx)
{
    void *data_end;
    void *data;

    /* Obtain packet data pointers */
    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    /* Verify Ethernet frame is large enough for an Ethernet header */
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_PASS;

    /* Verify IPv4 payload exists after Ethernet header */
    struct ethhdr *eth = data;
    if (data + sizeof(*eth) + sizeof(struct iphdr) > data_end)
        return XDP_PASS;

    /* Only process IPv4 (ETH_P_IP == 0x0800) */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (struct iphdr *)(eth + 1);

    /* Check destination prefix 10.0.0.0/8  -> mask 0xFF000000, key 0 */
    if ((bpf_ntohl(ip->daddr) & 0xFF000000) == 0x0A000000) {
        __u32 key = 0;
        __u32 ifindex = 0;

        /* Lookup ifindex in prefix_config map */
        int ret = bpf_map_lookup_elem(
            (void *)(long)BPF_MAP_TYPE_ARRAY, /* map_fd is implicit via section */
            &key,
            &ifindex,
            BPF_ANY
        );

        if (ret == 0 && ifindex != 0) {
            bpf_redirect(ifindex, 0);
            return 0;
        }
        /* Fall through to XDP_PASS if lookup failed or ifindex == 0 */
    }

    /* Check destination prefix 172.16.0.0/12 -> mask 0xFFF00000, key 1 */
    if ((bpf_ntohl(ip->daddr) & 0xFFF00000) == 0xAC100000) {
        __u32 key = 1;
        __u32 ifindex = 0;

        int ret = bpf_map_lookup_elem(
            (void *)(long)BPF_MAP_TYPE_ARRAY,
            &key,
            &ifindex,
            BPF_ANY
        );

        if (ret == 0 && ifindex != 0) {
            bpf_redirect(ifindex, 0);
            return 0;
        }
        /* Fall through to XDP_PASS */
    }

    /* No matching prefix or ifindex == 0 -> pass the frame */
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
