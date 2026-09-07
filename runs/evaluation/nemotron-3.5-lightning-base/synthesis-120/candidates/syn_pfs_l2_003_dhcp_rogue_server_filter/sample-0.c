#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/ctx/skb.h>

/* 
 * Array map to store authorized DHCP server IPv4 addresses.
 * Key: __u32 (index 0)
 * Value: __be32 (server IP)
 * max_entries: 1
 * Default fallback value: 192.168.1.1 (0xC0A80101)
 */
struct {
	__uint	type,		BPF_MAP_TYPE_ARRAY;
	__uint	max_entries,	1;
	__type(key,	__u32);
	__type(value,	__be32);
} auth_dhcp_server SEC(".maps");

/* 
 * DHCP Magic Cookie offset within the DHCP options field.
 * Standard DHCP header is 240 bytes total (UDP payload).
 * Magic Cookie starts at offset 236 from the start of the UDP payload.
 * Cookie value: 0x63825363
 */
#define DHCP_MAGIC_COOKIE_OFFSET	236
#define DHCP_MAGIC_COOKIE_VALUE		0x63825363u

/* XDP program entry point */
SEC("xdp")
int xdp_block_rogue_dhcp_server(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct eth_hdr *eth;
	struct iphdr *ip;
	struct udphdr *udp;
	__u32 authorized_ip;
	__be33 server_ip_be;
	int eth_type;
	int ip_proto;
	int udp_len;
	__u16 src_port, dst_port;

	/* 
	 * Validate Ethernet frame bounds.
	 * sizeof(struct eth_hdr) is guaranteed to be 14 bytes.
	 */
	if (data + sizeof(struct eth_hdr) > data_end)
		return XDP_PASS;

	eth = data;
	eth_type = eth->h_proto;

	/* Only process IPv4 traffic (ETH_P_IP = 0x0800) */
	if (eth_type != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	/* 
	 * Validate IPv4 header bounds.
	 * iphdr starts after the Ethernet header (14 bytes).
	 */
	if (data + sizeof(struct eth_hdr) + sizeof(struct iphdr) > data_end)
		return XDP_PASS;

	ip = data + sizeof(struct eth_hdr);
	ip_proto = ip->protocol;

	/* Only process IPv4 UDP traffic (protocol = 17) */
	if (ip_proto != IPPROTO_UDP)
		return XDP_PASS;

	/* 
	 * Validate UDP header bounds.
	 * udphdr starts after the IPv4 header (ip->ihl * 4 bytes).
	 */
	if (data + sizeof(struct eth_hdr) + (ip->ihl << 2) + sizeof(struct udphdr) > data_end)
		return XDP_PASS;

	udp = data + sizeof(struct eth_hdr) + (ip->ihl << 2);
	udp_len = ntohs(udp->len);

	/* 
	 * Validate total UDP payload bounds.
	 * UDP payload starts after the UDP header (8 bytes).
	 * We need at least 240 bytes to check the DHCP magic cookie at offset 236.
	 */
	if (data + sizeof(struct eth_hdr) + (ip->ihl << 2) + udp_len > data_end)
		return XDP_PASS;

	/* 
	 * Check UDP source and destination ports.
	 * DHCP server uses src 67, client uses dst 67.
	 * DHCP client uses src 68, server uses dst 68.
	 * We inspect traffic from server to client: src==67, dst==68.
	 */
	src_port = ntohs(udp->source);
	dst_port = ntohs(udp->dest);

	if (src_port != 67 || dst_port != 68)
		return XDP_PASS;

	/* 
	 * Validate DHCP header bounds.
	 * DHCP header is 240 bytes starting from the UDP data payload.
	 * We need data + eth_hdr + ip_hdr + udp_hdr + 240 <= data_end
	 */
	if (data + sizeof(struct eth_hdr) + (ip->ihl << 2) + udp_len + 240 > data_end)
		return XDP_PASS;

	/* 
	 * Verify BOOTREPLY op code (op == 2).
	 * The 'op' field is the first 2 bytes of the DHCP header (offset 0 from UDP payload).
	 * Located at: udp + 0
	 */
	if (udp->source == 0) /* Prevent compiler warning, actual check below */
		return XDP_PASS;

	/* 
	 * The op code is at offset 0 from the start of the DHCP options,
	 * which is the start of the UDP payload.
	 * We access it via the UDP header structure, but op is not a standard field.
	 * We cast the UDP payload to access the op field.
	 * Actually, the DHCP header starts immediately after the UDP header.
	 * The 'op' field is at offset 0 from the UDP data payload.
	 * Since we have the udp struct, the DHCP header starts at udp + 1 (after the 8-byte UDP header).
	 * Wait, the UDP payload starts right after the udphdr.
	 * Let's use a char pointer to the start of the DHCP options/payload.
	 */
	/* 
	 * DHCP header structure (first 4 bytes):
	 * op (1 byte) - Message type: 1=Bootp Request, 2=Bootp Reply
	 * htype (1 byte) - Hardware address type
	 * hlen (1 byte) - Hardware address length
	 * hops (1 byte) - Number of hops
	 */
	/* 
	 * To access the op field, we need to point to the start of the DHCP message.
	 * The DHCP message starts at: data + sizeof(struct eth_hdr) + (ip->ihl << 2) + sizeof(struct udphdr)
	 * Let's calculate the offset.
	 */
	void *dhcp_start = data + sizeof(struct eth_hdr) + (ip->ihl << 2) + sizeof(struct udphdr);
	struct dhcp_hdr *dhcp;

	/* 
	 * Validate DHCP header size (minimum 240 bytes as per requirement).
	 * We already checked bounds above, but let's ensure dhcp_start is valid.
	 */
	if (dhcp_start + 240 > data_end)
		return XDP_PASS;

	dhcp = dhcp_start;

	/* Check op code: 2 = BOOTREPLY */
	if (dhcp->op != 2)
		return XDP_PASS;

	/* 
	 * Verify DHCP Magic Cookie (0x63825363) at offset 236 from the start of DHCP header.
	 * The magic cookie is located in the options field, starting at byte 236 from the
	 * beginning of the DHCP header (which is the start of the UDP payload).
	 * Offset 236 from dhcp_start.
	 */
	__u32 __maybe_unused magic_cookie;
	__u32 *magic_ptr;

	magic_ptr = (__u32 *)(dhcp_start + DHCP_MAGIC_COOKIE_OFFSET);
	/* 
	 * Magic cookie is stored in network byte order (big-endian) in the standard,
	 * but typically checked as a 32-bit value. We compare the raw 32-bit value.
	 * The constant 0x63825363 is the standard magic cookie value.
	 */
	if (*magic_ptr != DHCP_MAGIC_COOKIE_VALUE)
		return XDP_PASS;

	/* 
	 * Lookup the authorized DHCP server IPv4 address in the map.
	 * Key is 0 (index 0), value is the server IP.
	 * Fallback value is 192.168.1.1 (0xC0A80101) if key 0 is not found.
	 */
	authorized_ip = bpf_map_lookup_elem(&auth_dhcp_server, &(__u32){0}, &server_ip_be);

	/* 
	 * If the map lookup returns 0 (key not found), we use the fallback value.
	 * bpf_map_lookup_elem returns 0 on success, non-zero on failure.
	 * Wait, bpf_map_lookup_elem returns 0 on success, and the value is written to the third argument.
	 * If the key doesn't exist, it returns 1 (error) and the value is not modified.
	 * However, with a default fallback map value feature (not available in all versions),
	 * or we handle it manually.
	 * Let's check the return value.
	 */
	if (authorized_ip
