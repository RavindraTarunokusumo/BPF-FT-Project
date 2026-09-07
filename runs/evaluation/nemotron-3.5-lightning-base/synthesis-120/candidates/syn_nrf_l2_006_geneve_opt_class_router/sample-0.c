#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/types.h>

/* GENEVE header definition (RFC 8060)
 * The header is 4 bytes fixed, followed by options.
 * Option format: 2 bytes type, 2 bytes length, then value (length bytes)
 * Length includes the 4-byte header but not the option type/length fields.
 */
struct geneve_opt {
    __be16 option_type;
    __be16 option_len;
    /* option value follows */
};

struct geneve_hdr {
    __be16 flags;
    __be16 vni;
    /* options follow */
};

/* XDP program: GENEVE Option Class Router */
SEC("xdp")
int xdp_geneve_opt_router(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth;
    struct iphdr *ip;
    struct udphdr *udp;
    struct geneve_hdr *geneve;
    struct geneve_opt *opt;
    __u16 option_class;
    __u16 opt_len;

    /* 1. Validate minimum Ethernet frame size */
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    eth = data;

    /* 2. Validate IPv4 protocol */
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    ip = (struct iphdr *)(eth + 1);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;

    /* 3. Validate UDP protocol */
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    /* 4. Validate UDP header bounds */
    if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp) > data_end)
        return XDP_PASS;

    udp = (struct udphdr *)(ip + 1);

    /* 5. Verify UDP destination port is 6081 (GENEVE) */
    if (udp->dest != htons(6081))
        return XDP_PASS;

    /* 6. Validate GENEVE header bounds */
    if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp) + sizeof(*geneve) > data_end)
        return XDP_PASS;

    geneve = (struct geneve_hdr *)(udp + 1);

    /* 7. Validate minimum GENEVE header size (4 bytes) */
    if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp) + 4 > data_end)
        return XDP_PASS;

    /* 8. Check for at least one option present.
     * GENEVE header is 4 bytes. Options start immediately after.
     * We need at least 2 bytes for option type/length header.
     */
    if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp) + 4 + 2 > data_end)
        return XDP_PASS;

    opt = (struct geneve_opt *)(geneve + 1);

    /* 9. Read option type (first 2 bytes) */
    if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp) + 4 +
        2 + ntohs(opt->option_len) > data_end)
        return XDP_PASS;

    option_class = ntohs(opt->option_type);

    /* 10. Route based on Option Class */
    /* Option Class 0x0100 (Linux) -> ifindex 20 */
    if (option_class == 0x0100) {
        return bpf_redirect(20, 0);
    }
    /* Option Class 0x0102 (AWS) -> ifindex 21 */
    if (option_class == 0x0102) {
        return bpf_redirect(21, 0);
    }

    /* 11. Pass all other traffic (optionless GENEVE, other classes, non-GENEVE) */
    return XDP_PASS;
}

char LICENSE[] = "GPL";
