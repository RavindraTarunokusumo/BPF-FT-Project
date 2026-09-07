/* XDP program: pit_l3_tcp_flow_outcomes
 *
 * Maintains per-flow packet and byte totals plus SYN, FIN, and RST
 * observation flags for IPv4 TCP traffic in a BPF hash map.
 *
 * Map name: tcp_flow_map
 * Key:   { __u32 saddr; __u32 daddr; __u16 sport; __u16 dport; }
 * Val:   { __u64 packets; __u64 bytes; __u32 syn_seen; __u32 fin_seen; __u32 rst_seen; }
 * Max entries: 32768
 *
 * Returns XDP_PASS for all packets.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>

/* Key structure for the hash map */
struct tcp_flow_key {
	__u32 saddr;	/* source IP address */
	__u32 daddr;	/* destination IP address */
	__u16 sport;	/* source port */
	__u16 dport;	/* destination port */
};

/* Value structure stored in the hash map */
struct tcp_flow_val {
	__u64 packets;	/* total packets seen in this flow */
	__u64 bytes;	/* total bytes seen in this flow */
	__u32 syn_seen;	/* 1 if SYN flag observed */
	__u32 fin_seen;	/* 1 if FIN flag observed */
	__u32 rst_seen;	/* 1 if RST flag observed */
};

/* Map definition:
 * type: BPF_MAP_TYPE_HASH
 * key:  struct tcp_flow_key
 * val:  struct tcp_flow_val
 * max_entries: 32768
 */
SEC("xdp")
int xdp_tcp_flow_outcomes(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct eth_hdr *eth;
	struct iphdr *ip;
	struct tcphdr *tcp;
	struct tcp_flow_key key = {};
	struct tcp_flow_val *val;
	int ret;

	/* 1. Verify Ethernet frame minimum size */
	if (data + sizeof(*eth) > data_end)
		return XDP_PASS;

	eth = data;

	/* 2. Verify IPv4 protocol */
	if (eth->h_proto != htons(ETH_P_IP))
		return XDP_PASS;

	ip = data + sizeof(*eth);
	if (data + sizeof(*ip) > data_end)
		return XDP_PASS;

	/* 3. Verify IPv4 protocol is TCP */
	if (ip->protocol != IPPROTO_TCP)
		return XDP_PASS;

	/* 4. Verify IPv4 IHL and total header size */
	if (ip->ihl < 5)
		return XDP_PASS;
	if (data + (ip->ihl * 4) > data_end)
		return XDP_PASS;

	/* 5. Parse TCP header */
	tcp = (struct tcphdr *)(ip + 1); /* ip + ip->ihl */
	if (data + (ip->ihl * 4) + sizeof(*tcp) > data_end)
		return XDP_PASS;

	/* 6. Build the 4-tuple key (network byte order as stored) */
	key.saddr = ip->saddr;
	key.daddr = ip->daddr;
	key.sport = tcp->source;
	key.dport = tcp->dest;

	/* 7. Lookup or insert entry in tcp_flow_map */
	val = bpf_map_lookup_elem(tcp_flow_map, &key);
	if (!val) {
		/* Initialize a new entry */
		val = bpf_map_update_elem(tcp_flow_map, &key, &zero_val, BPF_ANY);
		if (!val)
			return XDP_PASS; /* update failed, but continue */
		/* zero_val is a static zero-initialized struct tcp_flow_val */
	}

	/* 8. Update flow statistics */
	val->packets++;
	val->bytes += (unsigned long)ctx->data_end - (unsigned long)data; /* wire_len */

	/* 9. Set flag bits based on TCP flags */
	/* TCP flags are in offset 13 of the TCP header (bits 0-3 of byte 13) */
	if (tcp->syn)
		val->syn_seen = 1;
	if (tcp->fin)
		val->fin_seen = 1;
	if (tcp->rst)
		val->rst_seen = 1;

	return XDP_PASS;
}

/* Zero-initialized value for new flow entries */
const struct tcp_flow_val zero_val = {
	.packets	= 0,
	.bytes		= 0,
	.syn_seen	= 0,
	.fin_seen	= 0,
	.rst_seen	= 0,
};

char LICENSE[] SEC("license") = "GPL";
