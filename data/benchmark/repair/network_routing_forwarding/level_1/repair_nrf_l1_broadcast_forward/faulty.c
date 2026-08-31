#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_forward(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Verifier error: comparing pointer to scalar 0
    if (eth->h_dest == 0)
        return XDP_PASS;

    if (eth->h_dest[0] == 0xFF && eth->h_dest[1] == 0xFF &&
        eth->h_dest[2] == 0xFF && eth->h_dest[3] == 0xFF &&
        eth->h_dest[4] == 0xFF && eth->h_dest[5] == 0xFF) {
        return bpf_redirect(5, 0);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
