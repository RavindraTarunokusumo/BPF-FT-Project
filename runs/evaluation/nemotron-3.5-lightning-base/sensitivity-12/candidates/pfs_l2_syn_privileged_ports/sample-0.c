/*
 * pfs_l2_syn_privileged_ports
 * XDP program to drop initial IPv4 TCP SYN packets targeting
 * privileged destination ports (1-1023).
 *
 * Author: kernel eBPF systems programmer
 * License: GPL
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/errno.h>

/* Helper macro to safely access header fields with bounds checking.
 * Ensures we do not read past the packet buffer. */
#define BPF_PROG_LOAD(sec)                                                \
	__attribute__((section(sec), used))

struct xdp_md {
	void *data;
	void *data_end;
};

/* XDP action return values */
#define XDP_PASS 0
#define XDP_DROP 1

SEC("xdp")
int pfs_l2_syn_privileged_ports(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth;
	struct iphdr *ip;
	struct tcphdr *tcp;

	/* 1. Verify Ethernet frame bounds */
	if (data + sizeof(*eth) > data_end)
		return XDP_PASS;

	eth = data;

	/* 2. Verify Ethernet protocol is IPv4 (ETH_P_IP) */
	if (eth->h_proto != bpf_htonl(ETH_P_IP))
		return XDP_PASS;

	/* 3. Verify IP header fits within packet bounds */
	if (data + sizeof(*eth) + sizeof(*ip) > data_end)
		return XDP_PASS;

	ip = data + sizeof(*eth);

	/* 4. Verify IP protocol is TCP */
	if (ip->protocol != IPPROTO_TCP)
		return XDP_PASS;

	/* 5. Verify TCP header fits within packet bounds using variable IHL.
	 *    ip->ihl is the number of 32-bit words; multiply by 4 to get bytes. */
	if (data + sizeof(*eth) + (ip->ihl * 4) + sizeof(*tcp) > data_end)
		return XDP_PASS;

	tcp = data + sizeof(*eth) + (ip->ihl * 4);

	/* 6. Verify this is an initial SYN packet:
	 *    - SYN flag set (0x02)
	 *    - ACK flag unset (0x10)
	 *    - Check at offset 13 of TCP header: ((flags & 0x12) == 0x02)
	 *      Bit 0x02 = SYN, Bit 0x10 = ACK. masking with 0x12 checks both.
	 */
	if (((tcp->th_flags & 0x12) != 0x02))
		return XDP_PASS;

	/* 7. Check destination port range: 1 <= dport <= 1023 */
	if (ntohs(tcp->dest) < 1 || ntohs(tcp->dest) > 1023)
		return XDP_PASS;

	/* 8. Drop the packet */
	return XDP_DROP;
}

char LICENSE[] SEC("license") = "GPL";
