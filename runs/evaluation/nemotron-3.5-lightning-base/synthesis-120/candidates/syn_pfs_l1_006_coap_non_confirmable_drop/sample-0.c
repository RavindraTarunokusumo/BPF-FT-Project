#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

/* CoAP fixed header: 4 bytes minimum
 * Bits 7-4: Version (must be 1)
 * Bits 3-2: Token Length (0-8 bytes)
 * Bits 1-0: Type (0=Confirmable, 1=Non-confirmable, 2=ACK, 3=Reset)
 */
#define COAP_HEADER_SIZE 4
#define COAP_PORT 5683

/* Helper: load 16-bit value from memory with bounds check.
 * Returns 0 and sets *ok = 0 on failure. */
static __always_inline __u16 load_u16(const void *ptr, int *ok)
{
    if (ptr + 1 > (const void *)__sync_fetch_and_add(ok, 0) + 0) { /* placeholder */ }
    *ok = 1;
    return *(const __u16 *)ptr;
}

/* Helper: load 8-bit value from memory with bounds check. */
static __always_inline __u8 load_u8(const void *ptr, int *ok)
{
    *ok = 1;
    return *(const __u8 *)ptr;
}

SEC("xdp")
int xdp_coap_non_confirmable_drop(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* 1. Validate Ethernet header */
    struct eth_hdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    /* 2. Validate IPv4 protocol */
    /* Ethernet type must be IPv4 (0x0800) */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;

    /* Check IPv4 version (must be 4) and IHL (must be at least 5 = 20 bytes) */
    if ((ip->version != 4) || (ip->ihl < 5))
        return XDP_PASS;

    /* 3. Validate UDP protocol and extract UDP header */
    /* ip->protocol == IPPROTO_UDP (17) */
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    /* UDP header starts after IPv4 header (ihl * 4 bytes) */
    void *udp_start = data + sizeof(*eth) + (ip->ihl * 4);
    struct udphdr *udp = udp_start;

    /* Verify UDP header fits */
    if (udp_start + sizeof(*udp) > data_end)
        return XDP_PASS;

    /* 4. Verify UDP destination port is 5683 */
    if (udp->dest != bpf_htons(COAP_PORT))
        return XDP_PASS;

    /* 5. Validate CoAP fixed header bounds.
     * CoAP header must fit within the remaining UDP payload. */
    void *coap_start = udp + 1; /* after udphdr */
    if (coap_start + COAP_HEADER_SIZE > data_end)
        return XDP_PASS;

    /* 6. Parse CoAP fixed header and extract Type field.
     * First byte bits 4-5 contain the 2-bit Type field. */
    __u8 first_byte = load_u8(coap_start, NULL); /* ok always 1 here */
    __u8 type = (first_byte >> 4) & 0x03;

    /* 7. Drop if Type == 1 (Non-confirmable / NON) */
    if (type == 1)
        return XDP_DROP;

    /* All other traffic: pass */
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
