/* XDP telemetry program: pit_l1_total_packets
 * Category: packet_inspection_telemetry
 * Difficulty: level_1
 *
 * This program increments a per-CPU 64-bit total-packet counter
 * for every received packet and returns XDP_PASS.
 */

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if.h>

/* Map definition:
 * Type: BPF_MAP_TYPE_PERCPU_ARRAY
 * Key: __u32 (0)
 * Value: __u64 (packet_count)
 * Max entries: 1
 */
SEC("xdp")
int pit_l1_total_packets(struct xdp_md *ctx)
{
    /* Lookup key 0 in the per-CPU array map */
    __u64 *counter;
    __u32 key = 0;

    counter = bpf_map_lookup_elem(bpf_map_fd_from_name("total_packet_counter"), &key, NULL);
    if (counter) {
        /* Increment the per-CPU counter */
        (*counter)++;
    }

    /* Pass the packet to the next network stack */
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
