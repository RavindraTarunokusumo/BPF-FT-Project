/* XDP Telemetry Program for VLAN Dual-Stack Packet Counting
 *
 * Categories (Slot):
 *   0: Untagged IPv4   (EtherType 0x0800)
 *   1: Single-VLAN IPv4 (802.1Q with inner EtherType 0x0800)
 *   2: Single-VLAN IPv6 (802.1Q with inner EtherType 0x86DD)
 *   3: Other (untagged IPv6, ARP, QinQ, non-IP)
 *
 * Map: vlan_telemetry_map (BPF_MAP_TYPE_PERCPU_ARRAY)
 *      Key: __u32 (slot index 0..3)
 *      Val: struct { __u64 packets; __u64 bytes; }
 *      Max entries: 4
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>

/* Map definition */
struct vlan_telemetry_entry {
	__u64 packets;
	__u64 bytes;
};

BPF_PERCPU_ARRAY(vlan_telemetry_map, struct vlan_telemetry_entry, 4);

/* Helper: load 2 bytes in native endianness from a pointer */
static __always_inline __u16 load_u16(const void *ptr)
{
	return *(const __u16 *)ptr;
}

SEC("xdp")
int xdp_vlan_telemetry(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct eth_hdr *eth;
	__u16 h_proto;
	struct vlan_hdr *vlan;
	__u16 inner_ethertype;
	struct vlan_telemetry_entry *entry;
	__u64 pkt_len;

	/* Validate Ethernet frame boundaries */
	if (data + sizeof(*eth) > data_end)
		return XDP_PASS;

	eth = data;
	h_proto = load_u16(eth->h_proto);

	/* 1. Untagged IPv4 */
	if (h_proto == bpf_htons(ETH_P_IP)) {
		entry = bpf_map_lookup_elem(&vlan_telemetry_map, &(__u){0});
		if (entry) {
			pkt_len = data_end - data;
			entry->packets += 1;
			entry->bytes += pkt_len;
		}
		return XDP_PASS;
	}

	/* 2. VLAN tagged (802.1Q) */
	if (h_proto == bpf_htons(ETH_P_8021Q)) {
		/* Check if there is enough room for the VLAN header */
		if (data + sizeof(*eth) + sizeof(*vlan) > data_end)
			return XDP_PASS;

		vlan = data + sizeof(*eth);
		inner_ethertype = load_u16(vlan->h_vlan_encapsulated_proto);

		/* Slot 1: Single-VLAN IPv4 */
		if (inner_ethertype == bpf_htons(ETH_P_IP)) {
			entry = bpf_map_lookup_elem(&vlan_telemetry_map, &(__u){1});
			if (entry) {
				pkt_len = data_end - data;
				entry->packets += 1;
				entry->bytes += pkt_len;
			}
			return XDP_PASS;
		}

		/* Slot 2: Single-VLAN IPv6 */
		if (inner_ethertype == bpf_htons(ETH_P_IPV6)) {
			entry = bpf_map_lookup_elem(&vlan_telemetry_map, &(__u){2});
			if (entry) {
				pkt_len = data_end - data;
				entry->packets += 1;
				entry->bytes += pkt_len;
			}
			return XDP_PASS;
		}

		/* Slot 3: VLAN with non-IP payload (QinQ, etc.) */
		entry = bpf_map_lookup_elem(&vlan_telemetry_map, &(__u){3});
		if (entry) {
			pkt_len = data_end - data;
			entry->packets += 1;
			entry->bytes += pkt_len;
		}
		return XDP_PASS;
	}

	/* 3. All other traffic (untagged IPv6, ARP, non-IP, etc.) -> Slot 3 */
	entry = bpf_map_lookup_elem(&vlan_telemetry_map, &(__u){3});
	if (entry) {
		pkt_len = data_end - data;
		entry->packets += 1;
		entry->bytes += pkt_len;
	}
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
