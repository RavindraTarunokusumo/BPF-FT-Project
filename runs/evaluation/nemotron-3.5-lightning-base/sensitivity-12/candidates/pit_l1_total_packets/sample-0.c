#include <linux/bpf.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/pkt_cls.h>

/* Map definition:
 * Type: BPF_MAP_TYPE_PERCPU_ARRAY
 * Key: __u32 (0)
 * Val: __u64 (packet_count)
 * Max entries: 1
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 1);
} total_packet_counter SEC(".maps");

/* XDP entry point */
SEC("xdp")
int xdp_total_packets(struct xdp_md *ctx)
{
    __u32 key = 0;
    __u64 *counter;

    /* Lookup the per-CPU counter for key 0 */
    counter = bpf_map_lookup_elem(&total_packet_counter, &key, 0);
    if (counter) {
        /* Increment the counter if found */
        (*counter)++;
    }

    /* Return XDP_PASS for every packet */
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
