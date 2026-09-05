#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* Define the knock state structure */
struct knock_state {
    __u32 stage;
    __u64 last_knock_ns;
};

/* Define the BPF hash map for client authentication state */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __be32);
    __type(value, struct knock_state);
} knock_map SEC(".maps");

/* Constants for port knocking sequence and timeouts */
#define KNOCK_STAGE_1 1
#define KNOCK_STAGE_2 2
#define KNOCK_STAGE_3 3
#define KNOCK_TIMEOUT_NS 10000000000ULL /* 10 seconds */

/* XDP program entry point */
SEC("xdp")
int xdp_port_knock_auth(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct eth_hdr *eth = data;
    struct iphdr *ip;
    struct udphdr *udp;
    struct tcphdr *tcp;
    __be32 src_ip;
    __u16 src_port, dst_port;
    int protocol;
    struct knock_state *kstate;
    __u64 now_ns;
    int bpf_ret;

    /* Parse Ethernet header */
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    eth = data;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    /* Parse IP header */
    ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end)
        return XDP_PASS;

    protocol = ip->protocol;
    src_ip = ip->saddr;

    /* Handle UDP packets for port knocking */
    if (protocol == IPPROTO_UDP) {
        udp = (void *)ip + sizeof(*ip);
        if ((void *)udp + sizeof(*udp) > data_end)
            return XDP_PASS;

        src_port = udp->source;
        dst_port = udp->dest;

        /* Step 1: UDP port 7000 -> stage 1 */
        if (dst_port == bpf_htons(7000)) {
            kstate = bpf_map_lookup_elem(&knock_map, &src_ip);
            if (!kstate) {
                /* First knock: create entry with stage 1 */
                kstate = bpf_map_lookup_elem(&knock_map, &src_ip);
                if (!kstate) {
                    kstate = bpf_map_update_elem(&knock_map, &src_ip,
                                                  (void *)&(struct knock_state){
                                                      .stage = KNOCK_STAGE_1,
                                                      .last_knock_ns = bpf_ktime_get_ns(),
                                                  }, BPF_ANY);
                    if (IS_ERR(kstate))
                        return XDP_PASS;
                } else {
                    /* Update existing entry to stage 1 and reset timer */
                    kstate->stage = KNOCK_STAGE_1;
                    kstate->last_knock_ns = bpf_ktime_get_ns();
                }
            } else {
                /* If already at stage 1 or higher, reset to stage 1 */
                kstate->stage = KNOCK_STAGE_1;
                kstate->last_knock_ns = bpf_ktime_get_ns();
            }
            return XDP_PASS;
        }

        /* Step 2: UDP port 8000 -> stage 1 -> 2 (must follow stage 1 within timeout) */
        if (dst_port == bpf_htons(8000)) {
            kstate = bpf_map_lookup_elem(&knock_map, &src_ip);
            if (!kstate)
                return XDP_PASS; /* No prior knock, ignore */

            now_ns = bpf_ktime_get_ns();
            /* Check if stage 1 was set and within 10-second window */
            if (kstate->stage == KNOCK_STAGE_1 &&
                (now_ns - kstate->last_knock_ns) <= KNOCK_TIMEOUT_NS) {
                kstate->stage = KNOCK_STAGE_2;
                kstate->last_knock_ns = now_ns;
            } else {
                /* Stage mismatch or timeout: reset to stage 1 */
                kstate->stage = KNOCK_STAGE_1;
                kstate->last_knock_ns = now_ns;
            }
            return XDP_PASS;
        }

        /* Step 3: UDP port 9000 -> stage 2 -> 3 (must follow stage 2 within timeout) */
        if (dst_port == bpf_htons(9000)) {
            kstate = bpf_map_lookup_elem(&knock_map, &src_ip);
            if (!kstate)
                return XDP_PASS; /* No prior knock, ignore */

            now_ns = bpf_ktime_get_ns();
            /* Check if stage 2 was set and within 10-second window */
            if (kstate->stage == KNOCK_STAGE_2 &&
                (now_ns - kstate->last_knock_ns) <= KNOCK_TIMEOUT_NS) {
                kstate->stage = KNOCK_STAGE_3;
                kstate->last_knock_ns = now_ns;
            } else {
                /* Stage mismatch or timeout: reset to stage 1 */
                kstate->stage = KNOCK_STAGE_1;
                kstate->last_knock_ns = now_ns;
            }
            return XDP_PASS;
        }
    }

    /* Handle TCP packets targeting destination port 22 (SSH) */
    if (protocol == IPPROTO_TCP) {
        tcp = (void *)ip + sizeof(*ip);
        if ((void *)tcp + sizeof(*tcp) > data_end)
            return XDP_PASS;

        if (tcp->dest == bpf_htons(22)) {
            kstate = bpf_map_lookup_elem(&knock_map, &src_ip);
            if (!kstate) {
                /* No authentication state: drop TCP port 22 */
                return XDP_DROP;
            }

            now_ns = bpf_ktime_get_ns();
            /* Check if client is in stage 3 and within 10-second window */
            if (kstate->stage == KNOCK_STAGE_3 &&
                (now_ns - kstate->last_knock_ns) <= KNOCK_TIMEOUT_NS) {
                return XDP_PASS; /* Authenticated: pass TCP SSH */
            } else {
                /* Not authenticated or timeout expired: drop */
                return XDP_DROP;
            }
        }
    }

    /* Pass all other traffic */
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
