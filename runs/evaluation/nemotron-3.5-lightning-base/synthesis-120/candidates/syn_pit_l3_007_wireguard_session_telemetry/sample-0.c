#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* WireGuard packet type definitions (RFC 3948 / wg-docs) */
#define WIREGUARD_HANDSHAKE 1
#define WIREGUARD_DATA     2
#define WIREGUARD_INIT     3
#define WIREGUARD_DATA_VER 4

/* WireGuard packet header structure (first 4 bytes after UDP header) */
struct wg_header {
	__u8	type;
	__u8	reserved[3];
};

/* Session statistics structure stored in BPF hash map */
struct wg_session_stat {
	__u64	last_seen_ns;
	__u64	total_packets;
	__u64	total_bytes;
};

/* BPF hash map for session telemetry */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, struct wg_session_stat);
} wg_session_map SEC(".maps");

/* XDP program entry point */
SEC("xdp")
int xdp_wg_session_telemetry(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct eth_hdr *eth;
	struct iphdr *ip;
	struct udphdr *udp;
	struct wg_header *wg;
	__u32 receiver_idx;
	struct wg_session_stat *stat;
	__u64 *last_seen;
	int eth_type;

	/* 1. Parse Ethernet header */
	if (data + sizeof(*eth) > data_end)
		return XDP_PASS;

	eth = data;
	eth_type = bpf_ntohl(eth->h_proto);

	/* Only process IPv4 packets */
	if (eth_type != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	data += sizeof(*eth);
	if (data + sizeof(*ip) > data_end)
		return XDP_PASS;

	ip = data;

	/* 2. Parse IPv4 header and verify protocol is UDP */
	if (ip->protocol != IPPROTO_UDP)
		return XDP_PASS;

	data += sizeof(*ip);
	if (data + sizeof(*udp) > data_end)
		return XDP_PASS;

	udp = data;

	/* 3. Verify UDP destination port is 51820 (WireGuard) */
	if (bpf_ntohs(udp->dest) != 51820)
		return XDP_PASS;

	data += sizeof(*udp);
	if (data + 4 > data_end)
		return XDP_PASS;

	/* 4. Parse WireGuard Type field (byte 0 of payload) */
	wg = data;
	if (wg->type != WIREGUARD_DATA_VER)
		return XDP_PASS;

	/* 5. Extract 32-bit Receiver Index (bytes 1-4 of WireGuard header) */
	/* WireGuard Data packet layout after type byte:
	 * Byte 0: type (already verified as 4)
	 * Bytes 1-4: Receiver Index (32-bit unsigned integer)
	 */
	receiver_idx = bpf_ntohl(*(__u32 *)(wg + 1));

	/* 6. Lookup or create session statistics in the hash map */
	stat = bpf_map_lookup_elem(&wg_session_map, &receiver_idx);
	if (!stat) {
		/* First packet for this receiver index - initialize stats */
		stat = bpf_map_lookup_elem(&wg_session_map, &receiver_idx);
		if (!stat) {
			struct wg_session_stat init_stat = {
				.last_seen_ns = bpf_ktime_get_ns(),
				.total_packets = 1,
				.total_bytes = 0, /* will be updated below */
			};
			bpf_map_update_elem(&wg_session_map, &receiver_idx,
					    &init_stat, BPF_ANY);
			stat = bpf_map_lookup_elem(&wg_session_map, &receiver_idx);
			if (!stat)
				return XDP_PASS; /* map update failed, but pass packet */
		}
	}

	/* 7. Update session statistics */
	stat->last_seen_ns = bpf_ktime_get_ns();
	stat->total_packets++;

	/* 8. Calculate wire bytes: UDP payload length (excluding UDP header)
	 * We compute: total packet length - IP header - UDP header
	 * ip->tot_len includes IP header, so we subtract ip_hlen + udp_hlen */
	{
		__u16 ip_hdr_len = ip->ihl * 4;
		__u16 udp_payload_len = bpf_ntohs(udp->len) - sizeof(*udp) - ip_hdr_len;
		if (udp_payload_len > 0) {
			stat->total_bytes += udp_payload_len;
		}
	}

	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
