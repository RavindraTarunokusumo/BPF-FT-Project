#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/types.h>

/* GENEVE header definition from linux/if_geneve.h */
struct genevehdr {
	__be16		flags1;
	__be16		flags2;
	__be32		vni;
	/* followed by options */
};

SEC("xdp")
int xdp_geneve_strip_opts(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth;
	struct iphdr *ip;
	struct udphdr *udp;
	struct genevehdr *gen;

	/* 1. Validate Ethernet frame boundaries */
	eth = data;
	if (data + sizeof(*eth) > data_end)
		return XDP_PASS;

	/* 2. Validate IPv4 protocol */
	if (eth->h_proto != htons(ETH_P_IP))
		return XDP_PASS;

	ip = data + sizeof(*eth);
	if (data + sizeof(*eth) + sizeof(*ip) > data_end)
		return XDP_PASS;

	/* 3. Validate IPv4 header length and protocol */
	if (ip->ihl < 5 || ip->protocol != IPPROTO_UDP)
		return XDP_PASS;

	/* 4. Validate UDP header boundaries */
	if (data + sizeof(*eth) + ip->ihl * 4 + sizeof(*udp) > data_end)
		return XDP_PASS;

	udp = data + sizeof(*eth) + ip->ihl * 4;

	/* 5. Check UDP destination port 6081 (GENEVE) */
	if (udp->dest != htons(6081))
		return XDP_PASS;

	/* 6. Validate GENEVE header boundaries */
	if (data + sizeof(*eth) + ip->ihl * 4 + sizeof(*udp) + sizeof(*gen) > data_end)
		return XDP_PASS;

	gen = (struct genevehdr *)(udp + 1);

	/* 7. Strip options by zeroing opt_len (if present) */
	if (gen->opt_len > 0)
		gen->opt_len = 0;

	/* 8. Always pass the packet */
	return XDP_PASS;
}

char LICENSE[] = "GPL";
