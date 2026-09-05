/* XDP program: Count valid IPv4 TCP packets by TCP control flags.
 *
 * Map: tcp_flag_counters (BPF_MAP_TYPE_PERCPU_ARRAY)
 *   Key: __u32  [0=SYN, 1=FIN, 2=RST, 3=Other]
 *   Val: __u64  count
 *   Max entries: 4
 *
 * Precedence: SYN (0x02) -> 0, FIN (0x01) -> 1, RST (0x04) -> 2, else -> 3.
 * Only valid IPv4 TCP packets with a parseable TCP header are counted.
 * All packets return XDP_PASS.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>

/* Per-CPU array map: key=flag index (0..3), val=64-bit counter */
struct {
	__uint	type, BPF_MAP_TYPE_PERCPU_ARRAY;
	__uint	max_entries, 4;
	__type(key, __u32);
	__type(value, __u64);
} tcp_flag_counters SEC(".maps");

/* XDP entry point */
SEC("xdp")
int xtcp_flag_counter(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct eth_hdr *eth;
	struct iphdr *ip;
	struct tcphdr *tcp;
	__u32 key;
	__u64 *val;

	/* 1. Verify Ethernet frame bounds */
	if (data + sizeof(*eth) > data_end)
		return XDP_PASS;

	eth = data;

	/* 2. Verify IPv4 protocol (ETH_P_IP = 0x0800) */
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	/* 3. Verify IPv4 header bounds and IHL */
	if (data + sizeof(*ip) > data_end)
		return XDP_PASS;

	ip = data + sizeof(*eth);
	/* ihl is in 4-byte units; minimum is 5 (20 bytes) */
	if (ip->ihl < 5)
		return XDP_PASS;

	if (data + (ip->ihl * 4) > data_end)
		return XDP_PASS;

	/* 4. Verify IPv4 protocol == TCP */
	if (ip->protocol != IPPROTO_TCP)
		return XDP_PASS;

	/* 5. Verify TCP header bounds */
	tcp = (void *)ip + ip->ihl * 4;
	if (data + (ip->ihl * 4) + sizeof(*tcp) > data_end)
		return XDP_PASS;

	/* 6. Inspect TCP flags at offset 13 (bits 0..3 of flags field) */
	__u16 tcp_flags = tcp->th_flags;

	/* 7. Apply precedence: SYN -> 0, FIN -> 1, RST -> 2, else -> 3 */
	if (tcp_flags & TH_SYN) {
		key = 0;
	} else if (tcp_flags & TH_FIN) {
		key = 1;
	} else if (tcp_flags & TH_RST) {
		key = 2;
	} else {
		key = 3;
	}

	/* 8. Lookup slot in per-CPU array and increment */
	val = bpf_map_lookup_elem(tcp_flag_counters, &key);
	if (val) {
		(*val)++;
	}

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
