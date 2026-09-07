#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/errno.h>
#include <linux/types.h>

/* GRE header definition (RFC 2890) */
struct grehdr {
	__be16		flags;
	__be16		protocol;
	/* followed by key, sequence, checksum, etc. */
};

/* Map definition: per-CPU array of 3 u64 counters */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 3);
	__type_key, __u32;
	__type_val, __u64;
} gre_flags_freq_map SEC(".maps");

/* XDP program entry point */
SEC("xdp")
int xdp_gre_flags_telemetry(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct eth_hdr *eth;
	struct iphdr *ip;
	struct grehdr *gre;
	__u32 key = 0;
	__u64 *val;

	/* 1. Validate Ethernet frame minimum size */
	if (data + sizeof(*eth) > data_end)
		return XDP_PASS;

	eth = data;

	/* 2. Validate IPv4 protocol */
	/* Check IPv4 protocol field (offset 9 from eth->h_dest) */
	if (data + sizeof(*eth) + sizeof(*ip) > data_end)
		return XDP_PASS;

	ip = data + sizeof(*eth);
	/* ip->protocol is at offset sizeof(struct eth_hdr) + 9 */
	if (ip->protocol != IPPROTO_GRE)
		return XDP_PASS;

	/* 3. Validate GRE header bounds */
	/* GRE header starts immediately after IPv4 header (offset 20) */
	if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*gre) > data_end)
		return XDP_PASS;

	gre = data + sizeof(*eth) + sizeof(*ip);

	/* 4. Inspect GRE flags word (__be16, network byte order) */
	__be16 gre_flags = gre->flags;
	__u16 flags_val = bpf_ntohs(gre_flags);

	/* 5. Independently increment the three slots */
	/* Slot 0: Key bit (0x2000) */
	if (flags_val & 0x2000) {
		key = 0;
		val = bpf_map_lookup_elem(&gre_flags_freq_map, &key);
		if (val) {
			(*val)++;
		}
	}

	/* Slot 1: Sequence bit (0x1000) */
	if (flags_val & 0x1000) {
		key = 1;
		val = bpf_map_lookup_elem(&gre_flags_freq_map, &key);
		if (val) {
			(*val)++;
		}
	}

	/* Slot 2: Checksum bit (0x8000) */
	if (flags_val & 0x8000) {
		key = 2;
		val = bpf_map_lookup_elem(&gre_flags_freq_map, &key);
		if (val) {
			(*val)++;
		}
	}

	/* 6. Always pass the packet */
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
