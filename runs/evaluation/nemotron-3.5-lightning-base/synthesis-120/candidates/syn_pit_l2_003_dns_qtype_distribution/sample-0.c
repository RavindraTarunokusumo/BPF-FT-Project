/* XDP program: DNS QTYPE distribution telemetry
 * Category: packet_inspection_telemetry
 * Difficulty: level_2
 *
 * Inspects DNS query traffic (UDP port 53, QR == 0).
 * Parses the DNS question section to extract the 16-bit QTYPE
 * and records counts into a per-CPU array map.
 *
 * Compilation: clang -target bpf -O2 -c dns_qtype_dist.c -o dns_qtype_dist.o
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>

/* DNS header structure (big-endian wire format) */
struct dns_header {
    __be16 id;          /* Query identification number */
    __be16 flags;       /* Flags */
    __be16 qdcount;     /* Number of question entries */
    __be16 ancount;     /* Number of answer entries */
    __be16 nscount;     /* Number of authority entries */
    __be16 arcount;     /* Number of additional entries */
} __attribute__((packed));

/* DNS question entry */
struct dns_question {
    __be16 qtype;       /* Query type */
    __be16 qclass;      /* Query class */
} __attribute__((packed));

/* Per-CPU array map to store QTYPE distribution */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 6);
    __type(key, __u32);
    __type(value, __u64);
} dns_qtype_dist_map SEC(".maps");

/* Helper: load 16-bit big-endian value from pointer */
static __always_inline __be16 load_be16(const void *ptr)
{
    const __u8 *p = ptr;
    return (p[0] << 8) | p[1];
}

/* XDP program entry point */
SEC("xdp")
int xdp_dns_qtype_dist(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Parse Ethernet header */
    struct eth_hdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    /* Only process IPv4 */
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    /* Parse IPv4 header */
    struct iphdr *ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;

    /* Only process UDP */
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    /* Parse UDP header */
    struct udphdr *udp = (void *)ip + sizeof(*ip);
    if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp) > data_end)
        return XDP_PASS;

    /* Only process DNS queries on port 53 */
    if (udp->source != htons(53) && udp->dest != htons(53))
        return XDP_PASS;

    /* Parse DNS header */
    struct dns_header *dns = (void *)udp + sizeof(*udp);
    if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp) +
        sizeof(*dns) > data_end)
        return XDP_PASS;

    /* Only process queries (QR == 0) */
    if (ntohs(dns->flags) & 0x8000)  /* QR bit is set in response */
        return XDP_PASS;

    /* Ensure at least one question entry */
    if (ntohs(dns->qdcount) < 1)
        return XDP_PASS;

    /* Pointer to the first DNS question */
    struct dns_question *q;
    void *q_start = (void *)(dns + 1);
    if (q_start > data_end)
        return XDP_PASS;

    q = q_start;
    if ((void *)q + sizeof(*q) > data_end)
        return XDP_PASS;

    /* Extract QTYPE (big-endian, convert to host byte order) */
    __be16 qtype_be = q->qtype;
    __u16 qtype = ntohs(qtype_be);

    /* QTYPE distribution slots:
     *  0: A (1)
     *  1: AAAA (28)
     *  2: CNAME (5)
     *  3: MX (15)
     *  4: TXT (16)
     *  5: OTHER
     */
    __u32 slot = 5; /* default: OTHER */
    switch (qtype) {
    case 1:  /* A */
        slot = 0;
        break;
    case 28: /* AAAA */
        slot = 1;
        break;
    case 5:  /* CNAME */
        slot = 2;
        break;
    case 15: /* MX */
        slot = 3;
        break;
    case 16: /* TXT */
        slot = 4;
        break;
    default:
        slot = 5;
        break;
    }

    /* Increment the per-CPU counter */
    __u32 key = 0;
    __u64 *val = bpf_map_lookup_elem(&dns_qtype_dist_map, &key);
    if (val) {
        (*val)++;
        bpf_map_update_elem(&dns_qtype_dist_map, &key, val, BPF_ANY);
    }

    /* Always pass the packet to the next handler */
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
