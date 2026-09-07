#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>

/* WireGuard header definition (simplified for this use case)
 * WireGuard protocol structure:
 *   - 2 bytes: Message Type (4 for data packets)
 *   - 4 bytes: Receiver Index
 *   - Remaining bytes: Payload (encrypted data, keys, etc.)
 * Total fixed header: 6 bytes
 */
struct wg_header {
    __be16 msg_type;   /* WireGuard message type */
    __be32 receiver_idx; /* 32-bit receiver index */
} __attribute__((packed));

/* XDP program entry point */
SEC("xdp")
int xdp_wg_router(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct eth_hdr *eth;
    struct iphdr *ip;
    struct udphdr *udp;
    struct wg_header *wg;

    /* 1. Validate Ethernet frame minimum size */
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    eth = data;

    /* 2. Validate IPv4 protocol */
    /* Check Ethernet type == IPv4 (0x0800) */
    if (eth->h_proto != bpf_htonl(ETH_P_IP))
        return XDP_PASS;

    ip = data + sizeof(*eth);

    /* Ensure IPv4 header fits within the packet */
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;

    /* Verify IPv4 total length field allows UDP payload */
    /* ip->tot_len is network byte order, convert to host order */
    if (ntohs(ip->tot_len) < sizeof(*udp) + sizeof(*wg))
        return XDP_PASS;

    /* 3. Validate UDP protocol and port 51820 */
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    udp = (void *)(ip + 1);

    /* Ensure UDP header fits */
    if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp) > data_end)
        return XDP_PASS;

    /* Verify UDP destination port is 51820 */
    if (udp->dest != bpf_htons(51820))
        return XDP_PASS;

    /* 4. Validate WireGuard Type 4 header */
    wg = (void *)(udp + 1);

    /* Ensure WireGuard header fits */
    if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp) + sizeof(*wg) > data_end)
        return XDP_PASS;

    /* Verify WireGuard message type is 4 */
    if (wg->msg_type != bpf_htonl(4))
        return XDP_PASS;

    /* 5. Extract and evaluate Receiver Index */
    /* receiver_idx is in network byte order (big-endian) */
    __be32 receiver_idx_be = wg->receiver_idx;
    __u32 receiver_idx = ntohl(receiver_idx_be);

    /* Route based on Receiver Index */
    if (receiver_idx == 0x11111111) {
        /* Redirect to peer interface ifindex 25 */
        return bpf_redirect(25, 0);
    } else if (receiver_idx == 0x22222222) {
        /* Redirect to peer interface ifindex 26 */
        return bpf_redirect(26, 0);
    }

    /* 6. Pass all other traffic (including other Receiver Indexes) */
    return XDP_PASS;
}

char LICENSE[] = "GPL";
__attribute__((section("xdp"))) struct xdp_program *xdp_prog = (struct xdp_program *)LICENSE;
