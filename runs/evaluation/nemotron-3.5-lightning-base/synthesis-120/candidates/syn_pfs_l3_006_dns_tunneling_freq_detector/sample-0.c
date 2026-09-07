#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* Define the per-client statistics structure */
struct dns_client_stat {
    __u64 window_start_ns;   /* Timestamp marking the start of the current 1-second window */
    __u64 total_bytes;       /* Cumulative DNS query payload bytes within the current window */
};

/* Define the BPF hash map for per-client tracking */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __be32);
    __type(value, struct dns_client_stat);
} dns_tunnel_map SEC(".maps");

/* XDP program entry point */
SEC("xdp")
int xdp_dns_tunnel_detector(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    /* Parse Ethernet header */
    struct eth_hdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* IPv4 only */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    /* Must be UDP and destination port 53 */
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    struct udphdr *udp = (struct udphdr *)(ip + 1);
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    /* Check UDP destination port 53 */
    if (bpf_ntohs(udp->dest) != 53)
        return XDP_PASS;

    /* Verify there is enough room for at least 4 bytes to read QR bit */
    if (udp + 1 > data_end - 4)
        return XDP_PASS;

    /* Pointer to the DNS header (first 4 bytes after UDP header) */
    __u16 *dns_hdr = udp + 1;

    /* Check QR bit: QR == 0 means Query */
    /* DNS header fields are in network byte order (big-endian).
       The first 2 bits of the first byte are OPCODE (3 bits) and QR (1 bit).
       We check if bit 15 (the QR bit in the first 2 bytes) is 0. */
    if (*dns_hdr & bpf_htons(0x8000))
        return XDP_PASS; /* Response (QR == 1), pass */

    /* This is a DNS query targeting UDP port 53 with QR == 0 */
    __be32 client_ip = ip->saddr;

    /* Look up or insert per-client statistics */
    struct dns_client_stat *stat;
    stat = bpf_map_lookup_elem(dns_tunnel_map, &client_ip, &stat);
    if (!stat) {
        /* First time seeing this client; initialize stat */
        struct dns_client_stat init = {
            .window_start_ns = bpf_ktime_get_ns(),
            .total_bytes = 0,
        };
        stat = &init;
        bpf_map_update_elem(dns_tunnel_map, &client_ip, stat, BPF_ANY);
    }

    /* Get current timestamp */
    __u64 now_ns = bpf_ktime_get_ns();

    /* Check if we are still within the same 1-second window */
    if (now_ns - stat->window_start_ns >= 1000000000) {
        /* Start a new window; reset counters */
        stat->window_start_ns = now_ns;
        stat->total_bytes = 0;
    }

    /* Calculate DNS query payload length.
       DNS header is 12 bytes (8 bytes header + 4 bytes fields).
       UDP header is 8 bytes.
       Total frame IP+UDP+DNS = iphdr->ihl*4 + udphdr->len.
       Payload = total - (ip_hdr_size + udp_hdr_size).
       We only count the DNS query payload (octets after the 12-byte DNS header). */
    __u16 ip_hdr_size = ip->ihl * 4;
    if (ip_hdr_size < sizeof(struct iphdr) || ip_hdr_size > (udp - data))
        return XDP_PASS; /* Malformed IP header */

    __u16 udp_hdr_size = sizeof(struct udphdr);
    __u16 total_frame_len = (udp - data) + udp->len; /* bytes from eth start to end of UDP */
    /* Actually, total_frame_len is not directly available; we compute payload as:
       data_end - (data + ip_hdr_size + udp_hdr_size + 12) */
    void *dns_payload = (void *)(udp + 1) + 12; /* after DNS header */
    if (dns_payload > data_end)
        return XDP_PASS; /* Malformed DNS */

    __u64 dns_payload_len = data_end - dns_payload;
    if (dns_payload_len > 0xFFFFFFFF)
        dns_payload_len = 0xFFFFFFFF; /* cap to __u32 */

    /* Accumulate bytes into the current window */
    stat->total_bytes += dns_payload_len;

    /* Enforce the 500-byte threshold within the 1-second window */
    if (stat->total_bytes > 500) {
        /* Drop subsequent queries exceeding the limit */
        return XDP_DROP;
    }

    /* Query is within limits; allow it through */
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
