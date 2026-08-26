#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int xdp_blocklist_prog(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Check Ethernet header bounds
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_PASS;

    struct ethhdr *eth = data;
    // Check Ethernet type is IPv4
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // Check IP header bounds
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
        return XDP_PASS;

    struct iphdr *ip = (struct iphdr *)((void *)eth + sizeof(struct ethhdr));
    // Extract source IP
    __be32 src_ip = ip->saddr;

    // Prepare key for LPM trie lookup (prefixlen=32, IP in host byte order)
    struct {
        __u32 prefixlen;
        __u32 ip;
    } key = {
        .prefixlen = 32,
        .ip = bpf_ntohl(src_ip)
    };

    // Lookup in blocklist_lpm_map
    __u32 *rule_id = bpf_lpm_trie_lookup_elem(&blocklist_lpm_map, &key);
    if (rule_id) {
        // Update rule counter in rule_counter_map
        __u64 *counter = bpf_map_lookup_elem(&rule_counter_map, rule_id);
        if (counter) {
            *counter += 1;
        }
        return XDP_DROP;
    }

    return XDP_PASS;
}

// Define LPM trie blocklist map
struct bpf_map_def SEC("maps/blocklist_lpm_map") = {
    .type = BPF_MAP_TYPE_LPM_TRIE,
    .key_size = 8,
    .value_size = sizeof(__u32),
    .max_entries = 1024,
    .flags = BPF_F_NO_PREALLOC
};

// Define rule counter array map
struct bpf_map_def SEC("maps/rule_counter_map") = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 64
};

char _license[] SEC("license") = "GPL";
