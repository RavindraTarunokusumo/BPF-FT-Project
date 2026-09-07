#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_transform(struct xdp_md *ctx) {
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;

	/* Verify that the Ethernet header fits */
	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;

	/* Only process IPv4 frames */
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	/* Verify that the IPv4 header fits */
	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return XDP_PASS;

	/* Verify that the outer protocol is GRE (IPPROTO_GRE == 47) */
	if (ip->protocol != 47)
		return XDP_PASS;

	/* Adjust the head by the fixed constant 24 (20 bytes outer IPv4 + 4 bytes GRE) */
	if (bpf_xdp_adjust_head(ctx, 24))
		return XDP_DROP;

	/* After adjust_head the Ethernet header is at the new data pointer.
	 * The inner Ethernet frame now starts at 'data'.
	 * The program can now read/process the inner frame as needed.
	 */
	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
