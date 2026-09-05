#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>

/* 
 * Per-CPU array map to tally inner EtherType frequencies.
 * max_entries 4: slot 0 = inner IPv4 (0x0800),
 *                 slot 1 = inner IPv6 (0x86DD),
 *                 slot 2 = inner ARP (0x0806),
 *                 slot 3 = other protocols.
 */
struct {
	__uint	type,		BPF_MAP_TYPE_PERCPU_ARRAY;
	__uint	max_entries,	4;
	__uint(map_flags),	0;
} vxlan_inner_proto_map SEC(".maps");

/* 
 * XDP program entry point.
 * Inspects VXLAN tunnel traffic (UDP port 4789),
 * parses outer headers, VXLAN header, and inner Ethernet header,
 * and tallies inner EtherType frequencies into the per-CPU map.
 */
SEC("xdp")
int xdp_vxlan_inner_l3_distribution(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct eth_hdr *eth;
	struct iphdr *ip;
	struct udphdr *udp;
	struct vxlan_hdr *vxlan;
	struct eth_hdr *inner_eth;
	__u16 inner_eth_type;
	__u32 key = 0, index;

	/* 
	 * Validate outer Ethernet header.
	 * sizeof(struct eth_hdr) is typically 14 bytes.
	 */
	if (data + sizeof(*eth) > data_end)
		return XDP_PASS;

	eth = data;

	/* 
	 * Validate IPv4 outer header.
	 * Check that there is enough data for the IPv4 header.
	 */
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	ip = data + sizeof(*eth);
	if (data + sizeof(*ip) > data_end)
		return XDP_PASS;

	/* 
	 * Validate UDP header.
	 * Check UDP destination port for VXLAN (4789).
	 */
	if (ip->protocol != IPPROTO_UDP)
		return XDP_PASS;

	udp = (void *)ip + ip_hl(ip) * 4;
	if (data + sizeof(*udp) > data_end)
		return XDP_PASS;

	/* 
	 * Validate VXLAN destination port (UDP port 4789).
	 * VXLAN header is 8 bytes following the UDP header.
	 */
	if (bpf_ntohs(udp->dest) != 4789)
		return XDP_PASS;

	vxlan = (void *)udp + sizeof(*udp);
	if (data + sizeof(*udp) + sizeof(*vxlan) > data_end)
		return XDP_PASS;

	/* 
	 * Validate inner Ethernet header.
	 * VXLAN payload starts after the 8-byte VXLAN header.
	 * The inner Ethernet header follows immediately.
	 */
	inner_eth = (void *)vxlan + sizeof(*vxlan);
	if (data + sizeof(*udp) + sizeof(*vxlan) + sizeof(*inner_eth) > data_end)
		return XDP_PASS;

	/* 
	 * Extract inner EtherType.
	 * inner_eth->h_proto is network byte order, compare with constants.
	 */
	inner_eth_type = inner_eth->h_proto;

	/* 
	 * Tally into per-CPU array map.
	 * Map type is BPF_MAP_TYPE_PERCPU_ARRAY, so we use a 32-bit key
	 * and the BPF helper bpf_map_update_elem will handle per-CPU indexing
	 * when the map is updated from XDP context.
	 * However, to be safe and explicit for per-CPU arrays, we can
	 * use the CPU index as part of the key or rely on the map's
	 * per-CPU nature. Here we use key=0 and the map infrastructure
	 * will update the correct per-CPU slot. Note: standard practice
	 * for per-CPU arrays in XDP often involves reading/writing
	 * with the CPU id, but bpf_map_update_elem with key=0 on a
	 * per-CPU array updates the current CPU's slot. For this
	 * simplification, we use key=0.
	 */
	if (inner_eth_type == bpf_htons(ETH_P_IP)) {
		/* slot 0: inner IPv4 */
		key = 0;
		bpf_map_update_elem(&vxlan_inner_proto_map, &key, &((__u32){1}), BPF_ANY);
	} else if (inner_eth_type == bpf_htons(ETH_P_IPV6)) {
		/* slot 1: inner IPv6 */
		key = 1;
		bpf_map_update_elem(&vxlan_inner_proto_map, &key, &((__u32){1}), BPF_ANY);
	} else if (inner_eth_type == bpf_htons(ETH_P_ARP)) {
		/* slot 2: inner ARP */
		key = 2;
		bpf_map_update_elem(&vxlan_inner_proto_map, &key, &((__u32){1}), BPF_ANY);
	} else {
		/* slot 3: other protocols */
		key = 3;
		bpf_map_update_elem(&vxlan_inner_proto_map, &key, &((__u32){1}), BPF_ANY);
	}

	/* 
	 * Always return XDP_PASS as required.
	 * The program has performed the inspection and tallying.
	 */
	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
