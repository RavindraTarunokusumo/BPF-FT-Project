#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

/* Per-CPU array map to store connection churn counters.
 * max_entries 2: slot 0 = new SYN connections, slot 1 = terminated connections */
struct {
	__uint	type, BPF_MAP_TYPE_PERCPU_ARRAY;
	__uint	max_entries, 2;
	__type(__u64);
} churn_monitor_map SEC(".maps");

SEC("xdp")
int xdp_churn_monitor(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	/* Validate Ethernet frame boundary */
	struct eth_hdr *eth = data;
	if (data + sizeof(*eth) > data_end)
		return XDP_PASS;

	/* Only process IPv4 traffic */
	if (eth->h_proto != htons(ETH_P_IP))
		return XDP_PASS;

	/* Validate IPv4 header boundary */
	struct iphdr *ip = data + sizeof(*eth);
	if (data + sizeof(*eth) + sizeof(*ip) > data_end)
		return XDP_PASS;

	/* Only process TCP protocol */
	if (ip->protocol != IPPROTO_TCP)
		return XDP_PASS;

	/* Validate TCP header boundary */
	struct tcphdr *tcp = (void *)ip + ip->ihl * 4;
	if (data + sizeof(*eth) + ip->ihl * 4 + sizeof(*tcp) > data_end)
		return XDP_PASS;

	/* Count newly initiated TCP connections (SYN with ACK=0) in slot 0 */
	if (tcp->syn && !tcp->ack) {
		bpf_map_update_elem(&churn_monitor_map, &(__u64){0}, &(__u64){1},
				    BPF_ANY);
	}

	/* Count terminated connections (FIN or RST) in slot 1 */
	if (tcp->fin || tcp->rst) {
		bpf_map_update_elem(&churn_monitor_map, &(__u64){1}, &(__u64){1},
				    BPF_ANY);
	}

	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
