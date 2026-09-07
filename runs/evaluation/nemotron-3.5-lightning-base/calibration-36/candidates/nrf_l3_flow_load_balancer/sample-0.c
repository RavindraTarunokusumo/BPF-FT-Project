/* XDP 5-tuple flow load balancer
 *
 * Maps:
 *   - backend_maps: BPF_MAP_TYPE_ARRAY (key: u32 [0|1], val: u8[6], max_entries: 2)
 *   - backend_devmap: BPF_MAP_TYPE_DEVMAP (key: u32, val: u32, max_entries: 2)
 *
 * Behaviour:
 *   - Only processes IPv4 TCP/UDP packets.
 *   - Computes a 1-bit flow hash:
 *         hash = (saddr ^ daddr ^ (sport << 16 | dport) ^ proto) & 1
 *   - Looks up the backend MAC at key 'hash' in backend_macs and overwrites
 *     eth->h_dest.
 *   - Redirects the packet via bpf_redirect_map(&backend_devmap, hash, 0).
 *   - Returns XDP_PASS for non-IPv4 or non-TCP/UDP traffic.
 */

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

/* Map definitions */
struct {
    __uint_type__(type, BPF_MAP_TYPE_ARRAY);
    __uint_type__(key_size, sizeof(__u32));
    __uint_type__(value_size, sizeof(__u8) * 6);
    __uint_type__(max_entries, 2);
    __type__(values, __u8[6]);
} backend_maps SEC(".maps");

struct {
    __uint_type__(type, BPF_MAP_TYPE_DEVMAP);
    __uint_type__(key_size, sizeof(__u32));
    __uint_type__(value_size, sizeof(__u32));
    __uint_type__(max_entries, 2);
} backend_devmap SEC(".maps");

/* XDP entry point */
SEC("xdp")
int xdp_flow_load_balancer(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Verify we have at least an Ethernet header */
    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    /* Only process IPv4 */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    /* Verify we have at least an IPv4 header */
    struct iphdr *ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;

    /* Verify transport protocol is TCP or UDP */
    if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    /* Verify we have enough room for the transport header.
     * For TCP: ip_hl*4 bytes of IPv4 header + sizeof(struct tcphdr)
     * For UDP: ip_hl*4 bytes of IPv4 header + sizeof(struct udphdr)
     * We use a generic check: iphdr->ihl * 4 gives the IPv4 header length.
     * The minimum L4 header size is sizeof(struct udphdr) (8 bytes).
     * We'll just ensure data + ip_hdr + min_l4 <= data_end later when reading ports. */
    __u32 ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr) || data + sizeof(*eth) + ip_hdr_len > data_end)
        return XDP_PASS;

    /* Pointer to transport header */
    void *transport = data + sizeof(*eth) + ip_hdr_len;
    struct tcphdr *tcp = transport;
    struct udphdr *udp = transport;

    __u16 sport = 0, dport = 0;

    if (ip->protocol == IPPROTO_TCP) {
        /* Verify TCP header fits */
        if (transport + sizeof(*tcp) > data_end)
            return XDP_PASS;
        sport = tcp->source;
        dport = tcp->dest;
    } else { /* IPPROTO_UDP */
        if (transport + sizeof(*udp) > data_end)
            return XDP_PASS;
        sport = udp->source;
        dport = udp->dest;
    }

    /* Compute 5-tuple flow hash:
     *   hash = (saddr ^ daddr ^ (sport << 16 | dport) ^ proto) & 1
     * Note: sport << 16 | dport packs the ports into a 32-bit value. */
    __u32 saddr = ip->saddr;
    __u32 daddr = ip->daddr;
    __u32 packed_ports = ((__u32)sport << 16) | dport;
    __u32 proto = ip->protocol;
    __u32 hash = (saddr ^ daddr ^ packed_ports ^ proto) & 1;

    /* Lookup backend MAC from backend_maps at key 'hash' */
    __u8 *mac = bpf_map_lookup_elem(&backend_maps, &hash);
    if (mac) {
        /* Copy the 6-byte MAC address to the destination Ethernet address */
        bpf_eth_addr_copy(eth->h_dest, mac);
    }

    /* Redirect packet via the DEVMAP using the computed hash as index */
    bpf_redirect_map(&backend_devmap, hash, 0);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
