#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct packet_event {
    __u64 ts;
    __u32 len;
    __u32 ifindex;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events_rb SEC(".maps");

SEC("xdp")
int xdp_telemetry(struct xdp_md *ctx) {
    struct packet_event *evt = bpf_ringbuf_reserve(&events_rb, sizeof(*evt), 0);
    if (!evt) {
        return XDP_PASS;
    }
    evt->ts = bpf_ktime_get_ns();
    evt->len = (__u32)((long)ctx->data_end - (long)ctx->data);
    evt->ifindex = ctx->ingress_ifindex;

    bpf_ringbuf_submit(evt, 0);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
