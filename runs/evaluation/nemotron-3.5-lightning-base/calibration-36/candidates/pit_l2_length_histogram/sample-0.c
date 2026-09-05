/* Copyright (c) 2024, Red Hat Inc. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */
#include <linux/bpf.h>
#include <linux/if/ether.h>
#include <bpf/bpf_helpers.h>

/* Per-CPU array map holding the wire length histogram buckets.
 * Key: __u32 (slot index 0..3)
 * Val: __u64 (counter for that slot)
 */
SEC("xdp")
int xdp_length_histogram(struct xdp_md *ctx)
{
    /* Pointers to the start and end of the packet data in the XDP context.
     * We compute the wire length as the difference between these two pointers.
     * Using (void *)(long) cast to avoid warnings about pointer arithmetic
     * on void pointers. */
    void *data   = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Calculate the packet length in bytes. */
    __u64 pkt_len = (unsigned long)data_end - (unsigned long)data;

    /* Determine the bucket slot based on wire length. */
    __u32 slot = 0;

    if (pkt_len < 64) {
        slot = 0;
    } else if (pkt_len < 128) {
        slot = 1;
    } else if (pkt_len < 512) {
        slot = 2;
    } else {
        slot = 3;
    }

    /* Lookup the per-CPU array map using the computed slot index.
     * The map 'length_histogram' has max_entries=4, key=__u32, val=__u64.
     * We use bpf_map_lookup_elem which returns a pointer to the value
     * at the given key in the map. Since the map is PERCPU_ARRAY, the
     * returned pointer points to the local CPU's value. */
    __u64 *counter = bpf_map_lookup_elem(/* map */ &length_histogram,
                                          /* key */ &slot,
                                          /* elem */ NULL);

    /* If the lookup succeeds (returns 0), increment the counter.
     * Note: bpf_map_lookup_elem returns 0 on success, -errno on failure.
     * For a PERCPU_ARRAY with valid keys (0..3), lookup should always succeed
     * if the map is properly loaded, but we check the return value for safety. */
    if (counter) {
        (*counter)++;
    }

    /* Always pass the packet to the next network stack handler. */
    return XDP_PASS;
}

/* Map definition.
 * type: BPF_MAP_TYPE_PERCPU_ARRAY
 * key_size: sizeof(__u32) = 4 bytes
 * value_size: sizeof(__u64) = 8 bytes
 * max_entries: 4 (one bucket per slot) */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 4);
} length_histogram SEC(".maps");

char _license[] SEC("license") = "GPL";
