#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int xdp_rewrite_ip_dst(void *ctx) {
    void *data = (void *)ctx;
    void *data_end = (void *)bpf_get_data_end(ctx);

    // Check Ethernet header and IPv4 protocol
    struct ethhdr *eth = data;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    // Check if there's enough space for Ethernet and IPv4 headers
    if (data_end - data < ETH_HLEN + sizeof(struct iphdr)) {
        return XDP_PASS;
    }

    struct iphdr *ip = (struct iphdr *)(data + ETH_HLEN);

    // Check if IPv4 header is within bounds
    if ((void *)ip + sizeof(*ip) > data_end) {
        return XDP_PASS;
    }

    // Calculate sum of 16-bit words in IPv4 header (excluding checksum)
    uint32_t sum = 0;
    sum += ip->tot_len;
    sum += ip->id;
    sum += ip->frag_off;
    sum += ((uint16_t)ip->ttl << 8) | ip->protocol;
    sum += (ip->saddr >> 16);
    sum += (ip->saddr & 0xFFFF);
    sum += (ip->daddr >> 16);
    sum += (ip->daddr & 0xFFFF);

    // New destination address (203.0.113.9 in network byte order)
    uint32_t new_daddr = bpf_htonl(0xCB007109);
    int delta = new_daddr - ip->daddr;
    uint32_t new_sum = sum + delta;
    uint16_t new_check = (uint16_t)(~new_sum);

    // Update destination address and checksum
    ip->daddr = new_daddr;
    ip->check = new_check;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
