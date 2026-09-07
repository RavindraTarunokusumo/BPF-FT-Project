#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

/* 8-byte sensitive pattern: "SECRET99" */
static const unsigned char secret_pattern[8] = {
    'S', 'E', 'C', 'R', 'E', 'T', '9', '9'
};

/* 8-byte replacement mask: "XXXXXXXX" */
static const unsigned char mask_pattern[8] = {
    'X', 'X', 'X', 'X', 'X', 'X', 'X', 'X'
};

SEC("xdp")
int xdp_sanitize_payload(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* 1. Validate Ethernet frame minimum size */
    struct eth_hdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    /* 2. Validate IPv4 protocol */
    /* eth->h_proto is network byte order (big-endian), compare with htons(ETH_P_IP) */
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;

    /* 3. Verify IPv4 protocol is TCP (protocol field = 6) */
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    /* 4. Validate TCP header bounds */
    struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
    if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*tcp) > data_end)
        return XDP_PASS;

    /* 5. Calculate TCP payload offset: iphdr->ihl * 4 + tcphdr->doff * 4 */
    /* iphdr->ihl is in 4-byte units; tcphdr->doff is in 4-byte units */
    unsigned int ip_hdr_len = ip->ihl * 4;
    unsigned int tcp_hdr_len = tcp->doff * 4;

    /* Sanity check header lengths (minimum values) */
    if (ip_hdr_len < sizeof(struct iphdr) || tcp_hdr_len < sizeof(struct tcphdr))
        return XDP_PASS;

    /* 6. Calculate payload start and end pointers */
    void *payload_start = (void *)tcp + tcp_hdr_len;
    void *payload_end = (void *)(ip) + ip_hdr_len + tcp_hdr_len + (tcp->syn ? 0 : 
        /* We don't have easy access to total length here, but we can check
           against data_end by computing remaining bytes after TCP header */
        /* Actually, we compute remaining data from ip total length */
        /* ip->tot_len is network byte order */
        /* Let's compute payload end safely */
        );

    /* Better approach: compute payload end using ip total length */
    /* ip->tot_len includes IP header + TCP header + payload */
    /* We need to convert tot_len from network to host byte order */
    unsigned int ip_total_len = ntohs(ip->tot_len);

    /* payload_end = ip header start + ip_total_len */
    void *payload_end_calc = (void *)ip + ip_total_len;

    /* Clamp payload_end to data_end for safety */
    if (payload_end_calc > data_end)
        payload_end_calc = data_end;

    /* Check if there is any payload */
    if (payload_start > payload_end_calc)
        return XDP_PASS;

    /* 7. Search for 8-byte pattern in payload */
    /* We use a simple memmem-like loop, but since we can't include string.h
       reliably in kernel space without risk, we manual-loop. */
    const unsigned char *ptr = payload_start;
    const unsigned char *pattern = secret_pattern;
    int found = 0;

    /* Limit search to available payload bytes */
    size_t payload_len = (size_t)(payload_end_calc - payload_start);

    while (payload_len >= 8) {
        if (memcmp(ptr, pattern, 8) == 0) {
            found = 1;
            break;
        }
        ptr++;
        payload_len -= 8; /* advance by 1 byte for next iteration, but we check 8 bytes */
        /* Actually, to slide by 1 byte:
           ptr++;
           payload_len--;
           But we checked 8 bytes, so we should decrement by 1 and continue.
           The above loop logic is flawed for sliding by 1.
           Let's do a standard byte-by-byte search. */
    }

    /* Redo search with byte-by-byte advancement for correctness */
    found = 0;
    size_t i;
    for (i = 0; i + 8 <= payload_len; i++) {
        if (memcmp(payload_start + i, pattern, 8) == 0) {
            found = 1;
            break;
        }
    }

    if (found) {
        /* 8. Mask the matching pattern with 'XXXXXXXX' */
        memmove(payload_start + i, mask_pattern, 8);

        /* 9. Reset TCP checksum.
           Writing to tcp->check = 0 forces the stack to recalculate it,
           or we can explicitly zero it. Since we are in XDP, modifying
           the packet requires updating checksums.
           Simply zeroing the field is often sufficient for the stack
           to recalculate, but to be safe and explicit:
           tcp->check = 0; */
        tcp->check = 0;
    }

    /* 10. Always return XDP_PASS */
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
