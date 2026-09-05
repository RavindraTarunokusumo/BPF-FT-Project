#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

/* Minimal representation of the kernel's bpf_fib_lookup struct.
 * Only the fields we need are included; the real kernel struct may have
 * additional members, but the verifier only validates the fields we touch. */
struct bpf_fib_lookup {
	__u8 family;
	__u8 l4_protocol;
	__be16 sport;
	__be16 dport;
	union {
		__u8 tos;
		__be32 flowinfo;
	};
	__u32 ifindex;
	union {
		__u8 dmac[6];
		__u16 dmac_u16[3];
	};
	union {
		__u8 smac[6];
		__u16 smac_u16[3];
	};
	union {
		__be32 ipv4_src;
		__u32 ipv6_src[4];
	};
	union {
		__be32 ipv4_dst;
		__u32 ipv6_dst[4];
	};
};

SEC("xdp")
int xdp_forward(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;

	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return XDP_PASS;

	/* Zero-initialize the entire struct to silence the verifier
	 * "invalid indirect read from stack" error for uninitialized fields
	 * (sport, dport, etc.). */
	struct bpf_fib_lookup fib_params = { 0 };

	fib_params.family = 2;             /* AF_INET */
	fib_params.ipv4_src = ip->saddr;
	fib_params.ipv4_dst = ip->daddr;
	fib_params.ifindex = ctx->ingress_ifindex;

	int rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
	if (rc == 0) {
		/* Rewrite Ethernet destination and source MACs from the FIB result. */
		#pragma unroll
		for (int i = 0; i < ETH_ALEN; i++) {
			eth->h_dest[i] = fib_params.dmac[i];
			eth->h_source[i] = fib_params.smac[i];
		}
		return bpf_redirect(fib_params.ifindex, 0);
	}

	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
