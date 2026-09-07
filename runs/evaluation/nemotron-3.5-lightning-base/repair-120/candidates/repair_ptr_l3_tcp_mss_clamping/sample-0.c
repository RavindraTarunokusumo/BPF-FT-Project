#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_transform(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    
    /* Ethernet boundary check */
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    
    /* IPv4 header boundary check */
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    __u32 ip_len = (__u32)ip->ihl * 4;
    
    /* IPv4 header length validation and bounds check */
    if (ip_len < sizeof(struct iphdr) || (void *)ip + ip_len > data_end)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip_len;
    
    /* TCP header boundary check */
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    /* Process TCP SYN packets with options */
    if (tcp->syn && tcp->doff > 5) {
        __u8 *opt = (void *)(tcp + 1);
        
        /* Verify options data fits within the packet */
        if ((void *)(opt + 4) > data_end)
            return XDP_PASS;
        
        /* MSS option: kind=2, len=4 */
        if (opt[0] == 2 && opt[1] == 4) {
            __u16 *mss_val = (__u16 *)(opt + 2);
            
            if (bpf_ntohs(*mss_val) > 1220) {
                *mss_val = bpf_htons(1220);
                /* Recalculate TCP checksum after MSS option modification */
                bpf_l3_csum_replace(&ip->check, 0);
                bpf_l4_csum_replace(&tcp->check, 0, 
                                    (__u16 *)tcp, 
                                    tcp->doff * 4, 
                                    0);
            }
        }
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
