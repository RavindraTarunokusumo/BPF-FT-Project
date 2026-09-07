/* XDP IPv4 5-tuple flow counter program
 *
 * Counts valid IPv4 TCP and UDP packets keyed by 5-tuple (saddr, daddr, sport, dport, proto).
 * Returns XDP_PASS for all traffic.
 *
 * Compile with:
 *   clang -target bpf -O2 -c flow_counter_kern.c -o flow_counter_kern.o
 *   llvm-strip --strip-debug --strip-unneeded flow_counter_kern.o
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* 5-tuple key matching the required struct layout */
struct flow_key {
	__u32 saddr;		/* source IP address   */
	__u32 daddr;		/* destination IP address */
	__u16 sport;		/* source port         */
	__u16 dport;		/* destination port    */
	__u8  proto;		/* IP protocol         */
	__u8  pad[3];		/* padding to 20 bytes total */
};

/* Map definition: BPF_MAP_TYPE_HASH with max_entries 65536 */
SEC("xdp")
int xdp_flow_counter(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth;
	struct iphdr *ip;
	int eth_type;
	int iphdr_len;
	__u32 saddr, daddr;
	__u16 sport, dport;
	__u8 proto;
	struct flow_key key = { .pad = { 0, 0, 0 } }; /* zero-initialize padding */
	__u64 *val, default_val = 1;
	int ret;

	/* 1. Parse Ethernet header and verify IPv4 type */
	if (data + sizeof(*eth) > data_end)
		return XDP_PASS;

	eth = data;
	eth_type = bpf_ntohs(eth->h_proto);

	if (eth_type != ETH_P_IP)
		return XDP_PASS;	/* non-IPv4 -> pass without map update */

	/* 2. Parse IPv4 header, verify bounds and IHL */
	if (data + sizeof(*eth) + sizeof(*ip) > data_end)
		return XDP_PASS;

	ip = data + sizeof(*eth);

	/* IHL is in 4-byte units; minimum is 5 (20 bytes) */
	iphdr_len = ip->ihl * 4;
	if (iphdr_len < sizeof(*ip) || iphdr_len > data_end - (void *)ip)
		return XDP_PASS;

	/* 3. Check protocol: only TCP (6) and UDP (17) */
	proto = ip->protocol;
	if (proto != IPPROTO_TCP && proto != IPPROTO_UDP)
		return XDP_PASS;

	/* 4. Extract 5-tuple fields safely within IPv4 payload bounds */
	/* TCP/UDP header starts after IPv4 header */
	void *transport = (void *)ip + iphdr_len;
	if (transport > data_end - sizeof(struct tcphdr) && proto == IPPROTO_TCP)
		return XDP_PASS;
	if (transport > data_end - sizeof(struct udphdr) && proto == IPPROTO_UDP)
		return XDP_PASS;

	if (proto == IPPROTO_TCP) {
		struct tcphdr *tcp = transport;
		if (transport + sizeof(*tcp) > data_end)
			return XDP_PASS;
		sport = bpf_ntohs(tcp->source);
		dport = bpf_ntohs(tcp->dest);
	} else { /* IPPROTO_UDP */
		struct udphdr *udp = transport;
		if (transport + sizeof(*udp) > data_end)
			return XDP_PASS;
		sport = bpf_ntohs(udp->source);
		dport = bpf_ntohs(udp->dest);
	}

	/* 5. Populate key fields (host byte order for map lookup) */
	saddr = bpf_ntohl(ip->saddr);
	daddr = bpf_ntohl(ip->daddr);

	key.saddr = saddr;
	key.daddr = daddr;
	key.sport = sport;
	key.dport = dport;
	key.proto = proto;

	/* 6. Lookup/update the hash map */
	val = bpf_map_lookup_elem(flow_counter_map, &key);
	if (val) {
		/* Increment existing counter */
		(*val)++;
	} else {
		/* Insert with count = 1 */
		bpf_map_update_elem(flow_counter_map, &key, &default_val, BPF_ANY);
	}

	return XDP_PASS;
}

/* Define the XDP map */
struct {
	__uint	type,		BPF_MAP_TYPE_HASH;
	__uint	max_entries,	65536;
	__type(key,	struct flow_key);
	__type(val,	__u64);
} flow_counter_map SEC(".maps");

char _license[] SEC("license") = "GPL";
