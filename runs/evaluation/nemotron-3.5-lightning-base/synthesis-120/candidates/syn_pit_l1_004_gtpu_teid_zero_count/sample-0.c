#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>

/* Per-CPU array map to store split counters.
 * max_entries 2: slot 0 for control packets (TEID == 0), slot 1 for user data (TEID != 0) */
struct {
	__uint	type,		BPF_MAP_TYPE_PERCPU_ARRAY;
	__uint	max_entries,	2;
	__type(type, __u32);
} gtpu_teid_split_map SEC(".maps");

/* XDP program entry point */
SEC("xdp")
int xdp_gtpu_teid_split(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct eth_hdr *eth;
	struct iphdr *ip;
	struct udphdr *udp;
	struct gtp_hdr *gtp;
	__u32 *counter;
	__u32 idx;
	__u16 protocol;

	/* 1. Validate Ethernet frame minimum size */
	if (data + sizeof(*eth) > data_end)
		return XDP_PASS;

	eth = data;
	protocol = eth->h_proto;

	/* 2. Validate IPv4 protocol */
	if (protocol != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	if (data + sizeof(*eth) + sizeof(*ip) > data_end)
		return XDP_PASS;

	ip = data + sizeof(*eth);

	/* 3. Validate IPv4 IHL (minimum 5 dwords = 20 bytes) */
	if (ip->ihl < 5)
		return XDP_PASS;

	/* 4. Verify IPv4 total length allows UDP header */
	if (data + sizeof(*eth) + ip->ihl * 4 + sizeof(*udp) > data_end)
		return XDP_PASS;

	/* 5. Verify protocol is UDP */
	if (ip->protocol != IPPROTO_UDP)
		return XDP_PASS;

	/* 6. Validate UDP header bounds */
	udp = (void *)ip + ip->ihl * 4;
	if (data + sizeof(*eth) + ip->ihl * 4 + sizeof(*udp) > data_end)
		return XDP_PASS;

	/* 7. Verify UDP destination port 2152 (GTP-U) */
	if (udp->dest != bpf_htons(2152))
		return XDP_PASS;

	/* 8. Validate GTP-U header bounds (minimum 8 bytes) */
	if (data + sizeof(*eth) + ip->ihl * 4 + sizeof(*udp) + 8 > data_end)
		return XDP_PASS;

	gtp = (void *)udp + sizeof(*udp);

	/* 9. Inspect the 32-bit TEID field */
	__u32 teid = gtp->teid;

	/* 10. Select per-CPU counter index:
	 *     - slot 0: control packets (teid == 0)
	 *     - slot 1: user data packets (teid != 0) */
	if (teid == 0)
		idx = 0;
	else
		idx = 1;

	/* 11. Increment the per-CPU counter */
	counter = bpf_map_lookup_elem(&gtpu_teid_split_map, &idx);
	if (counter)
		(*counter)++;

	/* 12. Always pass the packet to the network stack */
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
