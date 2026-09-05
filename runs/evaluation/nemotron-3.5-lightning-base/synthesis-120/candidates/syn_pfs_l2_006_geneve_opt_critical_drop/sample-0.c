#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>

/* GENEVE header definition (RFC 8604) */
struct geneve_hdr {
    __be16  flags;        /* bits: 0-15, bit 15 = Critical */
    __be16  protocol_type;
    __be32  vni;
    __be32  options_len;  /* length in 4-byte words, minus 1 */
};

/* XDP program entry point */
SEC("xdp")
int xdp_geneve_critical_drop(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct eth_hdr *eth;
    struct iphdr *ip;
    struct udphdr *udp;
    struct geneve_hdr *gen;

    /* 1. Validate Ethernet frame minimum size */
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    eth = data;

    /* 2. Validate IPv4 protocol */
    /* Accept only IPv4 (ETH_P_IP = 0x0800) */
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    /* 3. Validate IPv4 header */
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;

    ip = data + sizeof(*eth);
    /* Basic IPv4 header sanity: IHL >= 5 (20 bytes) */
    if (ip->ihl < 5)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    /* 4. Validate UDP header */
    if (data + sizeof(*eth) + ip->ihl * 4 + sizeof(*udp) > data_end)
        return XDP_PASS;

    udp = (void *)ip + ip->ihl * 4;
    /* Verify UDP destination port is GENEVE (6081) */
    if (udp->dest != htons(6081))
        return XDP_PASS;

    /* 5. Validate GENEVE header */
    if (data + sizeof(*eth) + ip->ihl * 4 + sizeof(*udp) + sizeof(*gen) > data_end)
        return XDP_PASS;

    gen = (void *)udp + sizeof(*udp);

    /* 6. Check global Critical flag in GENEVE base header */
    /* bit 15 of gen->flags is the Critical flag per RFC 8604 */
    if (gen->flags & cpu_to_be16(0x8000))
        return XDP_DROP;

    /* 7. Iterate through TLV options with strict bounds checking */
    /* gen->options_len is the number of 4-byte words minus 1 */
    /* Total options bytes = (options_len + 1) * 4 */
    __u32 options_len_words = be32_to_gen(gen->options_len);
    __u32 options_total_bytes = (options_len_words + 1) * 4;

    /* Bounds check: options area must fit within the packet */
    if (data + sizeof(*eth) + ip->ihl * 4 + sizeof(*udp) + sizeof(*gen) + options_total_bytes > data_end)
        return XDP_PASS;

    /* Pointer to the start of TLV options */
    __u8 *opt_ptr = (void *)(gen + 1);

    /* Iterate while there is at least one option header left */
    while ((void *)opt_ptr + sizeof(__u16) + sizeof(__u32) <= data_end - (opt_ptr - (void *)opt_ptr) + (void *)opt_ptr) {
        /* Ensure we have at least type (2 bytes) and length (4 bytes) */
        if (opt_ptr + 6 > data_end)
            break;

        __u16 opt_type = bpf_ntohs(*(__u16 *)opt_ptr);
        __u32 opt_len    = *(__u32 *)(opt_ptr + 2);

        /* Validate option length field: must be a multiple of 4 and not exceed remaining data */
        if (opt_len == 0 || (opt_len % 4) != 0)
            break;

        __u32 opt_total = opt_len; /* opt_len is already in 4-byte words? No, RFC says opt_len is the length in bytes minus 4? Let's check RFC 8604.
        Actually RFC 8604 Section 4.2: "Option Length: 8-bit field that contains the length of the Option Data field in bytes."
        Wait, standard TLV: Type (2 bytes), Length (2 bytes?), but GENEVE uses 4-byte aligned.
        Let's re-read typical GENEVE parsing in bpf.
        Usually: opt_type (2 bytes), opt_len (2 bytes) or opt_len (4 bytes)?
        The task says: "Parse the 8-byte GENEVE header and any variable-length TLV options (length specified by gen->opt_len * 4)."
        This implies gen->options_len field determines the total options length in 4-byte units.
        For TLV options inside:
        "Check option type bit 0x80 and drop if critical"
        Standard GENEVE TLV: 2-byte type, 2-byte length (in bytes?), then data.
        But the prompt says: "length specified by gen->opt_len * 4" for the whole options area.
        For individual TLV, we need to parse type and length.
        Let's assume standard 2-byte type, 2-byte length (in bytes, multiple of 4? or just bytes?).
        Actually, many implementations use: Type (2 bytes), Length (2 bytes) where Length is the length of the Option Data field in bytes.
        Let's stick to a safe parsing loop.
        We have opt_ptr pointing to the first option.
        We will read type and length.
        Let's assume type is 2 bytes at opt_ptr, length is 2 bytes at opt_ptr+2.
        The task says: "Check option type bit 0x80 and drop if critical".
        So we check (opt_type & 0x80).

        Let's define the TLV structure assumed:
        Offset 0: __be16 option_type
        Offset 2: __be16 option_length (length of the option data field in bytes)
        Offset 4: option data

        We must be careful with bounds.
        */
        __u16 opt_type_raw;
        __u16 opt_len_raw;

        /* Read type safely */
        if (opt_ptr + 4 > data_end)
            break;
        opt_type_raw = bpf_ntohs(*(__u16 *)opt_ptr);
        opt_len_raw    = *(__u16 *)(opt_ptr + 2);

        /* Option length validation: must be > 0 and a multiple of 4 (per GENEVE spec for data alignment usually, or just > 0).
        Also, total option size = 4 (header) + opt_len_raw.
        We must ensure opt_ptr + 4 + opt_len_raw <= data_end */
        if (opt_len_raw == 0 || (opt_len_raw % 4) != 0)
            break; /* or continue, but break is safer for malformed */

        __u32 opt_end = 4 + opt_len_raw;
        if (opt_ptr + opt_end > data_end)
            break;

        /* 8. Check Critical bit in option type (bit 7 / 0x80) */
        if (opt_type_raw & 0x80)
            return XDP_DROP;

        /* Move to next option */
        opt_ptr += opt_end;
    }

    /* 9. If we reach here, packet is not critical (or no options) */
    return XDP_PASS;
}

char LICENSE[] = "GPL";
