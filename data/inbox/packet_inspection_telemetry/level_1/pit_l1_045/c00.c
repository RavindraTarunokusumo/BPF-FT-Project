#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int xdp_telemetry_pit_l1_045(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // FAULT: Invalid signed comparison and missing unsigned cast on 64-bit pointers
    int len = (int)(data_end - data);
    if (len < 64)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
