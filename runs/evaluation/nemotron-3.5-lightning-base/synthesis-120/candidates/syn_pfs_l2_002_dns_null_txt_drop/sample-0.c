/* XDP program: Drop DNS NULL (type 10) and TXT (type 16) queries to prevent DNS tunneling exfiltration.
 * Category: packet_filtering_security
 * Difficulty: level_2
 *
 * Inspects DNS query traffic on UDP destination port 53.
 * Parses the 12-byte DNS header, verifies QR == 0 (query) and qdcount >= 1.
 * Walks the variable-length QNAME wire format until the terminating null byte,
 * inspects the 16-bit QTYPE, and drops if qtype == 10 (NULL) or qtype == 16 (TXT).
 * All other queries, responses, non-DNS traffic, and malformed frames are passed.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>

/* DNS header offsets (12 bytes) */
#define DNS_HDR_IDX 0
#define DNS_HDR_QR  2   /* bit 15 of bytes 2-3 */
#define DNS_HDR_QDCOUNT 4

/* QTYPE offsets within the question section */
#define QTYPE_IDX  0

/* QTYPE values */
#define QTYPE_A       1
#define QTYPE_NS      2
#define QTYPE_MD      3
#define QTYPE_MF      4
#define QTYPE_CNAME   5
#define QTYPE_SOA     6
#define QTYPE_MB      7
#define QTYPE_MG      8
#define QTYPE_MR      9
#define QTYPE_NULL   10
#define QTYPE_PTR    12
#define QTYPE_HINFO  14
#define QTYPE_MINFO  15
#define QTYPE_MX     15
#define QTYPE_TXT    16
#define QTYPE_AAAA   28
#define QTYPE_ANY    255

/* Ethernet type for IPv4 */
#define ETH_P_IP 0x0800

/* XDP action helpers */
#define XDP_PASS 0
#define XDP_DROP 1

/* Structure pointing to the packet data after Ethernet header */
struct eth_hdr {
    unsigned char h_dest[6];
    unsigned char h_source[6];
    __be16 h_proto;
};

/* Structure pointing to the IP header */
struct iphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
    unsigned int ihl_version:4;
    unsigned int tos:8;
    unsigned int tot_len:16;
    unsigned int id:16;
    unsigned int frag_off:13;
    unsigned int frag_more:1;
    unsigned int frag_off2:2;
    unsigned int ttl:8;
    unsigned int protocol:8;
    unsigned int check:16;
    unsigned int saddr;
    unsigned int daddr;
#elif defined(__BIG_ENDIAN_BITFIELD)
    unsigned int version:4;
    unsigned int ihl:4;
    unsigned int tos:8;
    unsigned int tot_len:16;
    unsigned int id:16;
    unsigned int frag_off:13;
    unsigned int frag_more:1;
    unsigned int frag_off2:2;
    unsigned int ttl:8;
    unsigned int protocol:8;
    unsigned int check:16;
    unsigned int saddr;
    unsigned int daddr;
#else
#error  "Adjust your <asm/byteorder.h> defines"
#endif
};

/* Structure pointing to the UDP header */
struct udphdr {
    __be16 source;
    __be16 dest;
    __be16 len;
    __sum16 check;
};

/* DNS header structure (network byte order) */
struct dns_hdr {
    __be16 id;
    __be16 flags;
    __be16 qdcount;
    __be16 ancount;
    __be16 nscount;
    __be16 arcount;
};

/* XDP program entry point */
SEC("xdp")
int xdp_dns_null_txt_drop(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* --- Validate Ethernet header --- */
    struct eth_hdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    /* Only process IPv4 */
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    /* --- Validate IP header --- */
    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end)
        return XDP_PASS;

    /* Only process UDP */
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    /* --- Validate UDP header --- */
    struct udphdr *udp = (void *)ip + ip->ihl * 4;
    if ((void *)udp + sizeof(*udp) > data_end)
        return XDP_PASS;

    /* Check UDP destination port is 53 */
    if (udp->dest != htons(53))
        return XDP_PASS;

    /* --- Validate DNS payload bounds --- */
    void *dns_payload = (void *)udp + sizeof(*udp);
    if (dns_payload + 12 > data_end)
        return XDP_PASS;

    struct dns_hdr *dns = dns_payload;
    /* Verify DNS QR bit == 0 (query) */
    /* flags bytes 2-3, bit 15 is QR. Since we use __be16, we check the high bit */
    if (dns->flags & htons(0x8000))
        return XDP_PASS; /* response */

    /* Verify qdcount >= 1 */
    if (ntohs(dns->qdcount) < 1)
        return XDP_PASS;

    /* --- Walk QNAME until terminating null byte --- */
    /* QNAME starts right after the 12-byte DNS header */
    void *qname_start = dns + 1; /* points to first byte after header */
    void *qname_end = data_end;

    /* We need at least 1 byte for the length byte and the final null */
    if (qname_start >= qname_end)
        return XDP_PASS;

    /* Iterate through labels */
    while (1) {
        unsigned char label_len;

        /* Bounds check: need at least 1 byte for length */
        if (qname_start >= qname_end)
            return XDP_PASS;

        label_len = *(unsigned char *)qname_start;

        /* Termination condition: label_len == 0 */
        if (label_len == 0) {
            /* Consumed the null byte, qname is valid */
            qname_start = (void *)((unsigned char *)qname_start + 1);
            break;
        }

        /* Bounds check: need label_len bytes for the label + 1 byte for next length */
        if ((void *)((unsigned char *)qname_start + 1 + label_len) > qname_end)
            return XDP_PASS; /* malformed */

        /* Advance past this label */
        qname_start = (void *)((unsigned char *)qname_start + 1 + label_len);
    }

    /* Now qname_start points to the QTYPE field (16 bits) */
    if ((void *)qname_start + 2 > data_end)
        return XDP_PASS; /* not enough bytes for QTYPE */

    __be16 qtype_be = *(__be16 *)qname_start;
    __u16 qtype = ntohs(qtype_be);

    /* --- Inspect QTYPE and drop if NULL (10) or TXT (16) --- */
    if (qtype == 10 || qtype == 16)
        return XDP_DROP;

    /* Pass all other queries and responses */
    return XDP_PASS;
}

char LICENSE[] = "GPL";
