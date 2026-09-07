#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <bpf/ctx/sk_buff.h>

/* Per-CPU array map to store MPLS depth counters.
 * max_entries 2: slot 0 for single-label (BOS=1), slot 1 for stacked (BOS=0) */
struct {
	__uint	type,		BPF_TYPE_PERCPU_HASH;
	__uint	max_entries,	2;
	__uint	flags,		BPF_F_NO_PREALLOC;
} mpls_depth_map SEC(".maps");

/* XDP program entry point */
SEC("xdp")
int xdp_mpls_depth_counter(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	struct eth_hdr *eth;
	struct mpls_hdr *mpls;

	/* 1. Validate Ethernet header bounds */
	eth = data;
	if (data + sizeof(*eth) > data_end)
		return XDP_PASS;

	/* 2. Check EtherType for MPLS unicast (0x8847) */
	if (eth->h_proto != bpf_htons(0x8847))
		return XDP_PASS;

	/* 3. Validate 4-byte MPLS label header bounds */
	mpls = data + sizeof(*eth);
	if (data + sizeof(*eth) + sizeof(*mpls) > data_end)
		return XDP_PASS;

	/* 4. Inspect BOS bit (bit 8 = 0x00000100)
	 *    BOS == 1 -> single-label frame -> slot 0
	 *    BOS == 0 -> stacked multi-label frame -> slot 1 */
	if (mpls->label & BPF_MPLS_BOS) {
		/* BOS set: single-label frame */
		bpf_map_update_elem(&mpls_depth_map, 0, (int []){ 1 }, BPF_ANY);
	} else {
		/* BOS clear: stacked multi-label frame */
		bpf_map_update_elem(&mpls_depth_map, 1, (int []){ 1 }, BPF_ANY);
	}

	/* 5. Always return XDP_PASS */
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
