/* XDP multi-tenant VXLAN security firewall
 * Category: packet_filtering_security
 * Difficulty: level_3
 */

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

/* VXLAN header: 8 bytes following UDP payload */
struct vxlan_hdr {
	__be32	vxlan_flags;	/* B|R|1|reserved|VNI(23 down to 0) */
	__be32	vxlan_vni;	/* VNI */
};

/* BPF hash map for VNI -> Tenant ID lookup */
struct {
	__uint	type, BPF_MAP_TYPE_HASH;
	__uint(max_entries, 256);
	__type(key, __u32);
	__type(value, __u32);
} vni_tenant_map SEC(".maps");

/* BPF LPM trie map for inner IP ACL policy lookup */
struct {
	__uint	type, BPF_MAP_TYPE_LPM_TRIE;
	__uint(max_entries, 512);
	__type(key, struct bpf_lpm_trie_key);
	__type(value, __u32);
} acl_lpm_map SEC(".maps");

/* XDP program entry point */
SEC("xdp")
int xdp_vxlan_tenant_acl(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct eth_hdr *eth;
	struct iphdr *ip4;
	struct udphdr *udp;
	struct vxlan_hdr *vxlan;
	struct bpf_lpm_trie_key lpm_key;
	__u32 tenant_id = 0;
	__u32 *policy;
	int eth_type;
	int ip_proto;
	int udp_len;
	int inner_eth_type;
	struct eth_hdr *inner_eth;
	struct iphdr *inner_ip;

	/* Minimum frame size check for outer Ethernet */
	if (data + sizeof(*eth) > data_end)
		return XDP_PASS;

	eth = data;
	eth_type = bpf_ntohs(eth->h_proto);

	/* Non-IP traffic: pass through */
	if (eth_type != ETH_P_IP)
		return XDP_PASS;

	/* Parse outer IPv4 header */
	if (data + sizeof(*eth) + sizeof(*ip4) > data_end)
		return XDP_PASS;

	ip4 = data + sizeof(*eth);
	ip_proto = ip4->protocol;

	/* Only process UDP packets (VXLAN uses UDP port 4789) */
	if (ip_proto != IPPROTO_UDP)
		return XDP_PASS;

	/* UDP header and length check */
	if (data + sizeof(*eth) + sizeof(*ip4) + sizeof(*udp) > data_end)
		return XDP_PASS;

	udp = (void *)ip4 + 1; /* ip_hdrlen already accounted in ip4->ihl */
	/* UDP length includes header; minimum VXLAN UDP payload is 8 bytes */
	if (udp->len < sizeof(*udp) + 8)
		return XDP_PASS;

	/* Check destination UDP port 4789 */
	if (udp->dest != bpf_htons(4789))
		return XDP_PASS;

	/* VXLAN header sits after UDP header */
	vxlan = (void *)udp + sizeof(*udp);
	if ((void *)vxlan + sizeof(*vxlan) > data_end)
		return XDP_PASS;

	/* Extract 24-bit VNI from VXLAN header.
	 * VXLAN flags: B=1, R=1, reserved=00, VNI=24 bits
	 * The VNI is in the upper 24 bits of the 32-bit field.
	 * We shift right 8 to get the 24-bit VNI value.
	 */
	__u32 vni = bpf_ntohl(vxlan->vxlan_vni) >> 8;

	/* Lookup tenant ID in VNI map */
	tenant_id = 0;
	bpf_map_lookup_elem(&vni_tenant_map, &vni, &tenant_id);

	/* VNI 100 is reserved/unregistered wildcard; pass it */
	if (vni != 100 && tenant_id == 0)
		return XDP_DROP;

	/* --- Registered tenant: evaluate inner IP ACL --- */

	/* Parse inner Ethernet header (immediately after VXLAN header) */
	inner_eth = (void *)vxlan + sizeof(*vxlan);
	if ((void *)inner_eth + sizeof(*inner_eth) > data_end)
		return XDP_PASS;

	inner_eth_type = bpf_ntohs(inner_eth->h_proto);

	/* Only process inner Ethernet frames that are IPv4 */
	if (inner_eth_type != ETH_P_IP)
		return XDP_PASS;

	/* Parse inner IPv4 header */
	if ((void *)inner_eth + sizeof(*inner_eth) + sizeof(*ip4) > data_end)
		return XDP_PASS;

	inner_ip = (void *)inner_eth + 1; /* ihl handled via bpf_lpm_trie_key */
	/* Inner IP protocol must be TCP/UDP/ICMP or we can still check LPM;
	 * requirement says "parse inner IPv4 header and evaluate source IP permissions",
	 * so we proceed for any inner IP protocol. */
	ip_proto = inner_ip->protocol;

	/* Build LPM trie key for inner source IP.
	 * struct bpf_lpm_trie_key {
	 *     __u32 ip;
	 *     __u8  prefixlen;
	 * };
	 */
	lpm_key.ip = bpf_ntohl(inner_ip->saddr);
	lpm_key.prefixlen = 32; /* Default to /32 host route; LPM will match longest prefix */

	/* Lookup ACL policy from LPM trie map */
	policy = bpf_map_lookup_elem(&acl_lpm_map, &lpm_key);
	if (!policy) {
		/* No matching ACL entry: pass the packet (default allow) */
		return XDP_PASS;
	}

	/* Policy: 1 = allow, 0 = drop */
	if (*policy == 0)
		return XDP_DROP;

	/* Explicitly match blocked subnet 10.0.2.0/24 regardless of map entry */
	/* Check if source IP falls within 10.0.2.0/24 */
	if (lpm_key.ip >= bpf_htonl(0x0a000200) && lpm_key.ip <= bpf_htonl(0x0a0002ff))
		return XDP_DROP;

	/* Packet passes all checks */
	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
