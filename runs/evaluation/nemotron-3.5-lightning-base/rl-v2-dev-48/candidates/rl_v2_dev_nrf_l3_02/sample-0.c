#include <linux/bpf.h>
#include <linux/if/ether.h>
#include <linux/ip.h>
#include <linux/in.h>

/* Route table entry structure */
struct route_entry {
	__u32 prefixlen;
	__u32 data;
};

/* LPM trie key structure */
struct route_lpm_key {
	__u32 prefixlen;
	__u32 data;
};

/* Route table map */
struct {
	__uint	type,		BPF_MAP_TYPE_LPM_TRIE;
	__uint	key_size,	sizeof(struct route_lpm_key);
	__uint	value_size,	sizeof(struct route_entry);
	__uint	max_entries,	256;
	__uint	flags,	BPF_F_NO_PREALLOC;
} dev_route_table_2 SEC(".maps");

/* Default gateway MAC address (52:54:00:00:00:fe) */
static const unsigned char def_gw_mac[6] = { 0x52, 0x54, 0x00, 0x00, 0x00, 0xfe };

/* XDP program entry point */
SEC("xdp")
int xdp_route_forward(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct eth_hdr *eth;
	struct iphdr *ip;
	int eth_type;

	/* Verify Ethernet header bounds */
	if (data + sizeof(*eth) > data_end)
		return XDP_PASS;

	eth = data;
	eth_type = bpf_ntohs(eth->h_proto);

	/* Only process IPv4 packets */
	if (eth_type != ETH_P_IP)
		return XDP_PASS;

	/* Verify IPv4 header bounds */
	if (data + sizeof(*eth) + sizeof(*ip) > data_end)
		return XDP_PASS;

	ip = (struct iphdr *)(eth + 1);

	/* Lookup destination address in the LPM trie route table */
	struct route_lpm_key key = {
		.prefixlen = ip->daddr ? 32 : 0,  /* fallback to default route */
		.data	 = ip->daddr
	};

	struct route_entry *entry;

	entry = bpf_lpm_lookup(&dev_route_table_2, &key, sizeof(key), 0);

	if (entry) {
		/* Route hit: rewrite destination MAC to route gateway */
		bpf_eth_addr_assign(eth->h_dst, (void *)(entry->data));
	} else {
		/* Route miss: rewrite destination MAC to default gateway */
		bpf_eth_addr_assign(eth->h_dst, (void *)def_gw_mac);
	}

	return XDP_TX;
}

char _license[] SEC("license") = "GPL";
