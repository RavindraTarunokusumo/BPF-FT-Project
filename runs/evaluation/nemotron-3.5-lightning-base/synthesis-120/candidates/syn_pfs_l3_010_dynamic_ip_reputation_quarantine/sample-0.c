#include <linux/bpf.h>
#include <linux/if/ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* 
 * Per-source IP reputation state stored in BPF hash map.
 * bad_event_count: Number of abnormal TCP flag detections (SYN+FIN or NULL).
 * quarantine_until_ns: Epoch nanoseconds until which the source is quarantined.
 */
struct ip_reputation {
	__u32 bad_event_count;
	__u64 quarantine_until_ns;
};

/* 
 * Hash map to track IP reputation.
 * Key: source IPv4 address (__be32).
 * Value: struct ip_reputation.
 * max_entries: 1024.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(__be32));
	__uint(value_size, sizeof(struct ip_reputation));
	__uint(max_entries, 1024);
} quarantine_map SEC(".maps");

/* 
 * XDP program entry point.
 * Implements dynamic IP reputation quarantine:
 * - Active quarantine: drop all traffic from quarantined sources.
 * - Abnormal TCP flag detection: SYN+FIN or NULL flags.
 * - Quarantine enforcement: 3 bad events -> 60s quarantine.
 */
SEC("xdp")
int xdp_quarantine_prog(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct eth_hdr *eth;
	struct iphdr *ip;
	struct tcphdr *tcp;
	__be32 src_ip;
	struct ip_reputation *rep;
	__u64 now = bpf_ktime_get_ns();
	int drop = 0;

	/* 
	 * Verify we have enough data for an Ethernet frame.
	 * Required minimum: Ethernet header (14 bytes).
	 */
	if (data + sizeof(*eth) > data_end)
		return XDP_PASS;

	eth = data;

	/* 
	 * Only process IPv4 traffic (ETH_P_IP = 0x0800).
	 * Non-IPv4 traffic is passed through.
	 */
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	/*
	 * Verify we have enough data for the IPv4 header.
	 * IPv4 header minimum size is 20 bytes (ihl=5).
	 */
	if (data + sizeof(*eth) + sizeof(*ip) > data_end)
		return XDP_PASS;

	ip = data + sizeof(*eth);

	/* 
	 * Verify IPv4 version (4 bits at the start of ip_hl).
	 * ip_hl is 4 bits: version (4 bits) << 4 | ihl (4 bits).
	 */
	if (ip->version != 4)
		return XDP_PASS;

	/* 
	 * Extract source IP address from the IPv4 header.
	 * ip_src is in network byte order; convert to host byte order for map lookup.
	 */
	src_ip = ip->saddr;

	/*
	 * Check if the source IP is currently in active quarantine.
	 * Look up the reputation state from the hash map.
	 * If found and quarantine_until_ns > now, drop the packet.
	 */
	rep = bpf_map_lookup_elem(&quarantine_map, &src_ip);
	if (rep) {
		if (rep->quarantine_until_ns > now) {
			/* Active quarantine: drop all traffic */
			return XDP_DROP;
		}
		/* 
		 * Quarantine expired: remove the entry from the map
		 * to allow future traffic (optional cleanup).
		 */
		bpf_map_delete_elem(&quarantine_map, &src_ip);
	}

	/*
	 * Only process TCP packets.
	 * Verify we have enough data for the TCP header.
	 * TCP header starts after the IPv4 header (ihl * 4 bytes).
	 */
	if (data + sizeof(*eth) + (ip->ihl * 4) + sizeof(*tcp) > data_end)
		return XDP_PASS;

	tcp = data + sizeof(*eth) + (ip->ihl * 4);

	/*
	 * Detect abnormal TCP flags:
	 * - SYN+FIN simultaneously (tcp_flags & (TH_SYN | TH_FIN) == (TH_SYN | TH_FIN))
	 * - NULL flags (no flags set: tcp_flags == 0)
	 */
	if ((tcp->syn && tcp->fin) || tcp->syn == 0 && tcp->fin == 0 && tcp->rst == 0 && tcp->psh == 0 && tcp->ack == 0) {
		/*
		 * Increment bad_event_count for the source IP.
		 * If the IP is not in the map, bpf_map_update_elem will
		 * implicitly create/initialize the value to zero.
		 */
		if (rep) {
			rep->bad_event_count++;
		} else {
			/*
			 * First abnormal event: initialize the struct.
			 * We must provide a complete struct ip_reputation value
			 * to bpf_map_update_elem when the key does not exist,
			 * because the map does not auto-initialize values.
			 */
			struct ip_reputation new_rep = {
				.bad_event_count = 1,
				.quarantine_until_ns = 0,
			};
			bpf_map_update_elem(&quarantine_map, &src_ip, &new_rep, BPF_ANY);
			rep = &new_rep;
		}

		/*
		 * Check if bad_event_count has reached the threshold (3).
		 * If so, enforce a 60-second quarantine.
		 * 60 seconds in nanoseconds: 60 * 1_000_000_000 = 60,000,000,000
		 */
		if (rep->bad_event_count >= 3) {
			rep->quarantine_until_ns = now + 60000000000ULL;
			return XDP_DROP;
		}
		/*
		 * bad_event_count < 3: drop the current abnormal packet,
		 * but do not yet quarantine the source.
		 * The source will be quarantined only after the 3rd event.
		 */
		return XDP_DROP;
	}

	/*
	 * Compliant packet (normal TCP flags or non-TCP/IPv4):
	 * Pass the packet through.
	 */
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
