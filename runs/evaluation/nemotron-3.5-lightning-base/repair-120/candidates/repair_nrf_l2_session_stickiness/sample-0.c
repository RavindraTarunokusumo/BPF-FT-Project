#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

/* DEVMAP with exactly 2 entries (indices 0 and 1) */
struct {
	__uint(type, BPF_MAP_TYPE_DEVMAP);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 2);
} backend_map SEC(".maps");

SEC("xdp")
int xdp_forward(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;

	/* Verify Ethernet frame boundaries */
	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;

	/* Only process IPv4 frames */
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	/* Verify IP header boundaries */
	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return XDP_PASS;

	/* Hash the 5-tuple (src/dst IPs) and constrain to 0 or 1 */
	__u32 hash = ip->saddr ^ ip->daddr;
	__u32 key = hash & 1;

	/* Redirect through the DEVMAP using the masked key */
	return bpf_redirect_map(&backend_map, key, 0);
}

char LICENSE[] SEC("license") = "GPL";
