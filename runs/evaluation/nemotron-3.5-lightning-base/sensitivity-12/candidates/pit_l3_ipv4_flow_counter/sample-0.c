/**
 * @file pit_l3_ipv4_flow_counter.c
 * @brief XDP program counting valid IPv4 TCP/UDP packets in a hash map keyed by 5-tuple.
 *
 * This program inspects incoming packets, identifies valid IPv4 TCP or UDP frames,
 * and maintains a per-flow packet counter in a BPF hash map keyed by the 5-tuple
 * (saddr, daddr, sport, dport, proto). Non-TCP/UDP and non-IPv4 traffic is passed
 * through without modification.
 */

#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/errno.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>

/* Define the 5-tuple key structure matching the specification */
struct flow_key {
	__u32 saddr;		/* Source IP address */
	__u32 daddr;		/* Destination IP address */
	__u16 sport;		/* Source port */
	__u16 dport;		/* Destination port */
	__u8  proto;		/* Protocol (TCP/UDP) */
	__u8  pad[3];		/* Padding to align key to 16 bytes */
};

/* Define the hash map */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(struct flow_key));
	__uint(value_size, sizeof(__u64));
	__uint(max_entries, 65536);
} flow_counter_map SEC(".maps");

/* XDP entry point */
SEC("xdp")
int xdp_flow_counter(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct eth_hdr *eth;
	struct iphdr *ip;
	__u16 sport, dport;
	__u8 proto;
	struct flow_key key = { }; /* Zeroed key */
	__u64 *count, init_val = 1;

	/* 1. Verify Ethernet frame boundaries */
	if (data + sizeof(*eth) > data_end)
		return XDP_PASS;

	eth = data;

	/* 2. Verify IPv4 protocol and bounds */
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	if (data + sizeof(*eth) + sizeof(*ip) > data_end)
		return XDP_PASS;

	ip = data + sizeof(*eth);

	/* 3. Check IPv4 IHL: must be at least 5 (20 bytes) */
	if (ip->ihl < 5)
		return XDP_PASS;

	/* 4. Verify we have enough data for the IPv4 header */
	if (data + sizeof(*eth) + (ip->ihl * 4) > data_end)
		return XDP_PASS;

	/* 5. Check protocol: only count TCP and UDP */
	proto = ip->protocol;
	if (proto != IPPROTO_TCP && proto != IPPROTO_UDP)
		return XDP_PASS;

	/* 6. Extract source and destination addresses (network byte order) */
	key.saddr = ip->saddr;
	key.daddr = ip->daddr;
	key.proto = proto;

	/* 7. Extract ports safely from transport layer */
	/* TCP/UDP header starts after IPv4 header */
	void *transport = data + sizeof(*eth) + (ip->ihl * 4);

	/* Ensure transport header fits within packet */
	if (transport + sizeof(__u16) > data_end)
		return XDP_PASS;

	if (proto == IPPROTO_TCP) {
		/* TCP: source port at offset 0, dest port at offset 2 */
		if (transport + 4 > data_end)
			return XDP_PASS;
		sport = bpf_ntohs(*(__u16 *)transport);
		dport = bpf_ntohs(*(__u16 *)(transport + 2));
	} else { /* IPPROTO_UDP */
		/* UDP: source port at offset 0, dest port at offset 2 */
		if (transport + 8 > data_end)
			return XDP_PASS; /* minimum UDP header is 8 bytes */
		sport = bpf_ntohs(*(__u16 *)transport);
		dport = bpf_ntohs(*(__u16 *)(transport + 2));
	}

	key.sport = sport;
	key.dport = dport;

	/* 8. Lookup/update the flow counter in the hash map */
	count = bpf_map_lookup_elem(&flow_counter_map, &key);
	if (count) {
		/* Key exists: increment counter */
		__sync_add_and_fetch(count, 1);
	} else {
		/* Key absent: insert with count = 1 */
		__sync_add_and_fetch(&init_val, 1); /* init_val is 1, but we need to store it */
		bpf_map_update_elem(&flow_counter_map, &key, &init_val, BPF_ANY);
	}

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
