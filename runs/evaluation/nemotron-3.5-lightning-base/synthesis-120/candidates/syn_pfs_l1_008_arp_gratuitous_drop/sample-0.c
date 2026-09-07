#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* ARP over Ethernet (hardware format) */
struct arphdr_eth_ipv4 {
    __be16  ar_hrd;     /* format of hardware address */
    __be16  ar_pro;     /* format of protocol address */
    u8      ar_hln;     /* length of hardware address */
    u8      ar_pln;     /* length of protocol address */
    __be16  ar_op;      /* ARP opcode */
    u8      ar_sha[6];  /* sender hardware address */
    u8      ar_sip[4];  /* sender IP address */
    u8      ar_tha[6];  /* target hardware address */
    u8      ar_tip[4];  /* target IP address */
};

SEC("xdp")
int xdp_syn_pfs_l1_008_arp_gratuitous_drop(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    /* 1. Validate Ethernet header bounds */
    struct eth_hdr *eth;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    eth = data;

    /* 2. Check EtherType == ARP (0x0806) */
    if (eth->h_proto != bpf_htons(ETH_P_ARP))
        return XDP_PASS;

    /* 3. Validate ARP header bounds (28 bytes) */
    struct arphdr_eth_ipv4 *arp;
    if (data + sizeof(*eth) + sizeof(*arp) > data_end)
        return XDP_PASS;

    arp = data + sizeof(*eth);

    /* 4. Verify ARP sub-fields:
     *    - hardware format   : 1 (Ethernet)
     *    - protocol type     : 0x0800 (IPv4)
     *    - hardware addr len : 6 (MAC)
     *    - protocol addr len : 4 (IPv4)
     */
    if (arp->ar_hrd != bpf_htons(1))
        return XDP_PASS;
    if (arp->ar_pro != bpf_htons(ETH_P_IP))
        return XDP_PASS;
    if (arp->ar_hln != 6)
        return XDP_PASS;
    if (arp->ar_pln != 4)
        return XDP_PASS;

    /* 5. Check for Gratuitous ARP: ar_sip == ar_tip */
    if (arp->ar_sip[0] == arp->ar_tip[0] &&
        arp->ar_sip[1] == arp->ar_tip[1] &&
        arp->ar_sip[2] == arp->ar_tip[2] &&
        arp->ar_sip[3] == arp->ar_tip[3]) {
        bpf_printk("Gratuitous ARP detected: ar_sip == ar_tip, dropping\n");
        return XDP_DROP;
    }

    /* 6. Pass all other ARP traffic (requests, replies, non-matching) */
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
