/* XDP multi-vector guard program
 * Category: packet_filtering_security
 * Difficulty: level_3
 *
 * Protects privileged ports, blocks prohibited UDP, and rejects malformed IPv4 packets.
 * Precedence: malformed_len (2) > privileged_syn (0) > blocked_udp (1)
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>

/* Map: Blocked UDP ports hash map.
 * Key: __u16 dport
 * Val: __u8 flag (reserved for future use)
 * Max entries: 256 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u16));
    __uint(value_size, sizeof(__u8));
    __uint(max_entries, 256);
} blocked_udp_ports SEC(".maps");

/* Map: Drop reason counters.
 * Key: __u32 index (0=privileged_syn, 1=blocked_udp, 2=malformed_len)
 * Val: __u64 count
 * Max entries: 3 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 3);
} drop_reasons SEC(".maps");

/* XDP entry point */
SEC("xdp")
int xdp_multi_vector_guard(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct eth_hdr *eth;
    struct iphdr *ip;
    __u16 dport;
    __u32 index;
    __u64 *cnt;
    __u8 flag;

    /* 1. Verify Ethernet frame bounds */
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    eth = data;

    /* 2. Accept non-IPv4 frames */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    /* 3. Verify IPv4 header bounds */
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;

    ip = data + sizeof(*eth);

    /* 4. Evaluate malformed IPv4 length (highest precedence) */
    if (ip->ihl < 5 || bpf_ntohs(ip->tot_len) < 20) {
        /* Increment drop_reasons[2] */
        index = 2;
        cnt = bpf_map_lookup_elem(&drop_reasons, &index);
        if (cnt) {
            *cnt = *cnt + 1;
        }
        return XDP_DROP;
    }

    /* 5. Evaluate privileged TCP SYN (second precedence) */
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp;

        /* Verify TCP header bounds */
        if (data + sizeof(*eth) + ip->ihl * 4 + sizeof(*tcp) > data_end)
            return XDP_PASS;

        tcp = data + sizeof(*eth) + ip->ihl * 4;

        /* Check TCP SYN flag: (flags & 0x12) == 0x02 */
        /* 0x12 = ACK + SYN bits; 0x02 = SYN bit only */
        if ((tcp->syn && tcp->ack) || (!tcp->syn && !tcp->ack)) {
            /* General case: check raw flags if needed, but standard check is (flags & 0x12) == 0x02 */
            if ((tcp->flags & 0x12) == 0x02) {
                /* Verify destination port in network byte order */
                dport = bpf_ntohs(tcp->dest);
                if (dport >= 1 && dport <= 1023) {
                    /* Increment drop_reasons[0] */
                    index = 0;
                    cnt = bpf_map_lookup_elem(&drop_reasons, &index);
                    if (cnt) {
                        *cnt = *cnt + 1;
                    }
                    return XDP_DROP;
                }
            }
        } else {
            /* Packet has both SYN and ACK (SYN-ACK) or other flag combos;
               condition (flags & 0x12) == 0x02 requires only SYN set, ACK clear.
               Here we explicitly check the bitmask condition. */
            if ((tcp->flags & 0x12) == 0x02) {
                dport = bpf_ntohs(tcp->dest);
                if (dport >= 1 && dport <= 1023) {
                    index = 0;
                    cnt = bpf_map_lookup_elem(&drop_reasons, &index);
                    if (cnt) {
                        *cnt = *cnt + 1;
                    }
                    return XDP_DROP;
                }
            }
        }
        /* If not a privileged SYN, fall through to UDP check */
    }

    /* 6. Evaluate blocked UDP (lowest precedence among the three) */
    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp;

        /* Verify UDP header bounds */
        if (data + sizeof(*eth) + ip->ihl * 4 + sizeof(*udp) > data_end)
            return XDP_PASS;

        udp = data + sizeof(*eth) + ip->ihl * 4;

        dport = bpf_ntohs(udp->dest);

        /* Lookup in blocked_udp_ports hash map */
        flag = 0;
        if (bpf_map_lookup_elem(&blocked_udp_ports, &dport) == 0) {
            /* Key found */
            /* Increment drop_reasons[1] */
            index = 1;
            cnt = bpf_map_lookup_elem(&drop_reasons, &index);
            if (cnt) {
                *cnt = *cnt + 1;
            }
            return XDP_DROP;
        }
        /* Key not found -> continue to pass */
    }

    /* 7. No drop rule matched -> pass */
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
