#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>

/* NTP header definition (RFC 5905).
 * The stratum byte is at offset 1 from the start of the NTP header.
 * We define the struct packed to ensure no padding. */
struct ntp_header {
    __be8  li_vn_mode;   /* offset 0   */
    __be8  stratum;      /* offset 1   */
    __be8  poll;         /* offset 2   */
    __be8  precision;    /* offset 3   */
    __be32 root_delay;   /* offset 4   */
    __be32 root_disp;    /* offset 8   */
    __be32 ref_id;       /* offset 12  */
    __be64 ref_ts;       /* offset 16  */
    __be64 orig_ts;      /* offset 24  */
    __be64 recv_ts;      /* offset 32  */
    __be64 trans_ts;     /* offset 40  */
} __attribute__((packed));

/* Per-CPU array map to hold stratum counters.
 * max_entries 4: 0=Stratum1, 1=Stratum2, 2=Stratum3-15, 3=Unsynchronized/Reserved */
struct {
    __u64 values[4];
} ntp_stratum_map __attribute__((section("maps")));

static __always_inline int
classify_stratum(__u8 stratum, struct bpf_map *map)
{
    __u64 *slot, val = 1;
    int idx;

    if (stratum == 1)
        idx = 0; /* Stratum 1 (Primary Reference) */
    else if (stratum == 2)
        idx = 1; /* Stratum 2 (Secondary Reference) */
    else if (stratum >= 3 && stratum <= 15)
        idx = 2; /* Stratum 3-15 (Downstream servers) */
    else
        idx = 3; /* Stratum 0 or >= 16 (Unsynchronized / reserved) */

    slot = bpf_map_lookup_elem(map, &idx);
    if (!slot)
        return -1;
    *slot += val;
    return 0;
}

SEC("xdp")
int xdp_ntp_stratum_telemetry(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    /* Ethernet header check */
    struct eth_hdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* Only process IPv4 */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    /* IPv4 header check */
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    /* Must be UDP and destination port 123 */
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    /* UDP header check */
    struct udphdr *udp = (struct udphdr *)(ip + 1);
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    /* Verify UDP payload starts at least at NTP header size.
     * NTP header is 48 bytes; we need at least 2 bytes to read stratum. */
    if (udp->len < sizeof(struct ntp_header))
        return XDP_PASS;

    /* NTP header check */
    struct ntp_header *ntp = (struct ntp_header *)(udp + 1);
    if ((void *)(ntp + 1) > data_end)
        return XDP_PASS;

    /* Inspect Stratum field at byte offset 1 of NTP payload */
    __u8 stratum = ntp->stratum;

    /* Classify and increment histogram slot */
    (void)classify_stratum(stratum, &ntp_stratum_map);

    return XDP_PASS;
}

char LICENSE[] = "GPL";
