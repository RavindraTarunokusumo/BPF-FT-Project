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
int xdp_telemetry_pit_l1_024(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    __u64 len = (__u64)data_end - (__u64)data;
    if (len < 64 || len > 1500)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
