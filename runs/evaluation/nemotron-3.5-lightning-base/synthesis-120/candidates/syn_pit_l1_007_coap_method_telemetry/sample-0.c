#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>

/* CoAP header: 4 bytes
 * Byte 0: Version (2 bits) + Type (2 bits) + Token Length (4 bits)
 * Byte 1: Code (Request/Response)
 * Byte 2: Message ID high
 * Byte 3: Message ID low
 */
#define COAP_PORT 5683

/* Per-CPU array map to count CoAP request methods.
 * max_entries 4 corresponds to codes 1..4 (GET..DELETE).
 * Index = Code - 1.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 4);
	__type(key, __u32);
	__type(value, __u64);
} coap_method_map SEC(".maps");

/* XDP program entry point */
SEC("xdp")
int xdp_coap_method_telemetry(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct eth_hdr *eth;
	struct iphdr *ip;
	struct udphdr *udp;
	__u16 coap_code;
	__u32 *value;

	/* 1. Validate Ethernet frame minimum size */
	if (data + sizeof(*eth) > data_end)
		return XDP_PASS;

	eth = data;

	/* 2. Validate IPv4 protocol */
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	ip = data + sizeof(*eth);
	if (data + sizeof(*eth) + sizeof(*ip) > data_end)
		return XDP_PASS;

	/* 3. Validate IPv4 protocol is UDP */
	if (ip->protocol != IPPROTO_UDP)
		return XDP_PASS;

	/* 4. Validate UDP header bounds and extract ports */
	if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp) > data_end)
		return XDP_PASS;

	udp = data + sizeof(*eth) + sizeof(*ip);

	/* 5. Verify UDP destination port is CoAP (5683) */
	if (udp->dest != bpf_htons(COAP_PORT))
		return XDP_PASS;

	/* 6. Parse the 4-byte CoAP header located right after UDP header */
	if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp) + 4 > data_end)
		return XDP_PASS;

	/* CoAP header starts at udp + 1 (byte offset 0 = Version/Type/TokenLen) */
	/* Code field is at byte offset 1 within the CoAP header */
	coap_code = ((__u8 *)(udp + 1))[1];

	/* 7. Only process CoAP request codes 1..4 (GET..DELETE) */
	if (coap_code >= 1 && coap_code <= 4) {
		/* Increment the per-CPU counter for this method.
		 * Map index = code - 1 (slot 0 = GET=1, slot 1 = POST=2, ...)
		 */
		value = bpf_map_lookup_elem(&coap_method_map, &coap_code);
		if (value) {
			(*value)++;
		}
	}

	/* 8. Always pass the packet to the next handler */
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
