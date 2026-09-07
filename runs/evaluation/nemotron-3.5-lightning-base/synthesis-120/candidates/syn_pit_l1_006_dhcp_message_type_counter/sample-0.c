#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>

/* DHCP header starts after UDP header.
 * We use a flexible array to inspect the DHCP options area.
 * The DHCP message type option (53) is typically at offset 236 from
 * the start of the DHCP data, which is offset 236 from the UDP payload start.
 * Total offset from packet start: ETH_HLEN + sizeof(struct iphdr) + sizeof(struct udphdr) + 236
 */

#define DHCP_MAGIC_COOKIE 0x63825363u
#define DHCP_OPTIONS_OFFSET 236
#define DHCP_OPTION 53

struct dhcp_hdr {
    __be32 magic_cookie;
    /* options follow */
};

/* Per-CPU map to count DHCP message types.
 * Slots: 0=Discover(1), 1=Offer(2), 2=Request(3), 3=Ack(5)
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} dhcp_type_map SEC(".maps");

static __always_inline int
process_dhcp(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    /* 1. Validate Ethernet frame */
    struct eth_hdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    /* 2. Validate IPv4 */
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;

    /* 3. Validate UDP */
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + sizeof(*ip);
    if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp) > data_end)
        return XDP_PASS;

    /* 4. Check DHCP ports (67 server, 68 client) */
    __u16 src_port = ntohs(udp->source);
    __u16 dst_port = ntohs(udp->dest);
    if (!((src_port == 67 && dst_port == 68) ||
          (src_port == 68 && dst_port == 67)))
        return XDP_PASS;

    /* 5. Validate DHCP minimum size and Magic Cookie offset */
    /* DHCP header starts after UDP header.
     * We need at least 240 bytes (236 options offset + 4 cookie bytes)
     * from the start of the DHCP data to verify the cookie.
     */
    if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp) + DHCP_OPTIONS_OFFSET + sizeof(__be32) > data_end)
        return XDP_PASS;

    /* Point to DHCP data start (first byte after UDP header) */
    struct dhcp_hdr *dhcp = (void *)udp + 1; /* +1 to skip UDP header */
    /* Actually, (void *)udp + 1 is UB if udp is at end.
     * Use offset arithmetic safely:
     */
    __u8 *dhcp_data = (void *)udp + 1;
    if (dhcp_data + sizeof(__be32) > data_end)
        return XDP_PASS;

    /* Verify Magic Cookie at offset 236 from DHCP data start */
    if (dhcp_data[DHCP_OPTIONS_OFFSET] != (__u8)(DHCP_MAGIC_COOKIE & 0xFF))
        return XDP_PASS;
    if (dhcp_data[DHCP_OPTIONS_OFFSET + 1] != (__u8)((DHCP_MAGIC_COOKIE >> 8) & 0xFF))
        return XDP_PASS;
    if (dhcp_data[DHCP_OPTIONS_OFFSET + 2] != (__u8)((DHCP_MAGIC_COOKIE >> 16) & 0xFF))
        return XDP_PASS;
    if (dhcp_data[DHCP_OPTIONS_OFFSET + 3] != (__u8)((DHCP_MAGIC_COOKIE >> 24) & 0xFF))
        return XDP_PASS;

    /* 6. Verify Magic Cookie 32-bit value */
    __be32 *cookie_ptr = (__be32 *)(dhcp_data + DHCP_OPTIONS_OFFSET);
    if (*cookie_ptr != cpu_to_be32(DHCP_MAGIC_COOKIE))
        return XDP_PASS;

    /* 7. Parse DHCP Option 53 (Message Type).
     * Option 53 is located at offset 236 from DHCP data start.
     * Option format: 1 byte type, 1 byte length, then value.
     * We assume Option 53 is present and properly aligned at that offset.
     * We only read the value byte.
     */
    __u8 *option53_ptr = dhcp_data + DHCP_OPTIONS_OFFSET + 4; /* after cookie */
    /* Option 53 structure: Code(1) Len(1) Val(1) */
    /* We need at least 3 bytes from option53_ptr */
    if (option53_ptr + 3 > data_end)
        return XDP_PASS;

    __u8 option_code = option53_ptr[0];
    __u8 option_len  = option53_ptr[1];
    __u8 option_val  = option53_ptr[2];

    if (option_code != DHCP_OPTION)
        return XDP_PASS;

    /* Option length must be at least 1 to have a value */
    if (option_len < 1)
        return XDP_PASS;

    /* Map slot assignment:
     * 1 -> Discover   -> slot 0
     * 2 -> Offer      -> slot 1
     * 3 -> Request    -> slot 2
     * 5 -> Ack        -> slot 3
     */
    __u32 key = 0;
    __u64 *val;

    switch (option_val) {
        case 1: /* Discover */
            key = 0;
            break;
        case 2: /* Offer */
            key = 1;
            break;
        case 3: /* Request */
            key = 2;
            break;
        case 5: /* Ack */
            key = 3;
            break;
        default:
            return XDP_PASS; /* Ignore other message types */
    }

    val = bpf_map_lookup_elem(&dhcp_type_map, &key);
    if (val) {
        (*val)++;
    } else {
        /* Map should exist, but handle gracefully */
    }

    return XDP_PASS;
}

SEC("xdp")
int xdp_dhcp_counter(struct xdp_md *ctx)
{
    return process_dhcp(ctx);
}

char _license[] SEC("license") = "GPL";
