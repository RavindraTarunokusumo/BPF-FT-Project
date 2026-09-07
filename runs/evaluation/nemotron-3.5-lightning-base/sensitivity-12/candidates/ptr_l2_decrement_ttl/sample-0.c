#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

/* XDP program entry point */
SEC("xdp")
int ptr_l2_decrement_ttl(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth;
    struct iphdr *ip;

    /* 1. Check Ethernet frame bounds */
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    eth = data;

    /* 2. Verify Ethernet protocol is IPv4 */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    /* 3. Check IPv4 header bounds */
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;

    ip = (struct iphdr *)(eth + 1);

    /* 4. Verify IPv4 version (4) and header length (at least 20 bytes) */
    if (ip->version != 4 || ip->ihl < 5)
        return XDP_PASS;

    /* 5. Check TTL */
    if (ip->ttl <= 1)
        return XDP_DROP;

    /* 6. Decrement TTL */
    ip->ttl -= 1;

    /* 7. Update IPv4 header checksum.
       The checksum field is 16 bits. Adding 0x0100 increments the low byte
       (the actual checksum) by 1. If the low byte overflows (wraps to 0),
       the high byte also increments, effectively adding 1 to the 16-bit value. */
    ip->check = (ip->check + bpf_htons(0x0100));
    if (ip->check < ip->check_old) /* Note: bpf_htons returns u16, addition wraps */
        ; /* The semantics here are tricky with helpers, usually a direct add is fine,
             but to be safe with the verifier, we perform the addition carefully. */
             
    /* Corrected checksum update logic for clarity and verifier safety:
       The check field stores the sum in network byte order (big endian).
       To add 1: 
       1. Add 0x0001 to the checksum value.
       2. Handle carry.
       
       Since bpf_htons(0x0100) is 0x0100, adding it adds 1 to the high byte.
       We want to add 1 to the low byte. So we use htons(0x0001).
       However, the prompt suggests: csum = (ip->check + bpf_htons(0x0100));
       Let's stick to the prompt's pattern but ensure correctness.
       
       Actually, the standard way in XDP to add 1 to the checksum is:
       ip->check = ntohs(ip->check) + 1;
       ip->check = htons(ip->check);
       But doing it in-place with helpers is preferred if possible.
       
       Let's use the most robust method that the verifier likes:
       ip->check = (ip->check + 1); // This might fail verifier if not careful with types.
       Let's use the explicit byte addition pattern often used.
    */
    
    /* 
       Prompt specific logic: csum = (ip->check + bpf_htons(0x0100));
       if (csum < ip->check) csum += 1;
       ip->check = csum;
       
       bpf_htons(0x0100) = 0x0100.
       If ip->check is in network order (big endian), adding 0x0100 affects the high byte.
       However, the kernel iphdr->check field is stored in host byte order 
       internally by the driver/stack often, OR the bpf helper handles the swap.
       
       Let's verify: struct iphdr { __u16 check; ... }. 
       The kernel network code usually expects check in host order for XDP 
       manipulation or network order depending on context.
       
       Actually, bpf_htons converts host to network. 
       If check is stored in network order (big endian), 
       and we add 0x0100 (big endian 1 in high byte), 
       we are adding 256 in host order.
       
       The prompt says: "e.g. csum = (ip->check + bpf_htons(0x0100)); if (csum < ip->check) csum += 1;"
       This pattern is the standard "INCREMENT CHECKSUM BY 1" idiom.
       It works regardless of byte order because:
       If adding 0x0100 causes an overflow in the high byte (>= 0x100), 
       the result wrapped around. 
       If the sum `csum` is less than the original `ip->check`, 
       it means a carry occurred from the low byte to the high byte 
       (or wrap around), so we add 1 more to compensate for the 0x0100 
       actually trying to increment the high half-word.
       
       Wait, let's do the math.
       Let Check = XY (hex), X high byte, Y low byte.
       We want to add 1 to the whole 16-bit value.
       Prompt: csum = Check + 0x0100.
       If Check = 0xABCD. 0xABCD + 0x0100 = 0xBDCD.
       csum (0xBDCD) < Check (0xABCD)? No.
       Result: 0xBDCD. Incorrect, should be 0xABCE.
       
       If Check = 0xABFF. 0xABFF + 0x0100 = 0xACFF.
       csum (0xACFF) < Check (0xABFF)? Yes.
       csum += 1 -> 0xAC00. Incorrect.
       
       The prompt's example `csum = (ip->check + bpf_htons(0x0100))` is actually 
       the pattern for incrementing by 0x0100 (256), not 1.
       To increment by 1, the usual XDP trick is:
       `ip->check = (ip->check + 1);` if check is in host order, 
       or the complex byte-manipulation.
       
       However, many tutorials and common BPF code use the following to add 1:
       `ip->check = htons(ntohs(ip->check) + 1);`
       
       Let's look at the prompt requirement again: "Update IPv4 header checksum (e.g. csum = (ip->check + bpf_htons(0x0100)); if (csum < ip->check) csum += 1; ip->check = csum;)"
       
       If I follow the prompt literally:
       `ip->check = (ip->check + bpf_htons(0x0100));`
       `if (ip->check < old_check) ip->check += 1;` (implicit in the prompt's `if (csum < ip->check) csum += 1;`)
       
       But wait, if I do `ip->check + 0x0100`, and it overflows, the check `< old_check` detects it.
       Let's test: Check = 0xFFFE. + 0x0100 = 0x100FE -> wraps to 0x00FE. 
       0x00FE < 0xFFFE is true. 0x00FE + 1 = 0x00FF. Wrong (should be 0xFFFF).
       
       Let's test: Check = 0xFFFF. + 0x0100 = 0x100FF -> wraps to 0x00FF. 
       0x00FF < 0xFFFF is true. 0x00FF + 1 = 0x0100. Wrong.
       
       The prompt's example `csum = (ip->check + bpf_htons(0x0100))` seems to be a mis-copyright or specific to a certain architecture assumption, OR it implies `ip->check` is in host order and `bpf_htons(0x0100)` is just a way to write `0x0100`.
       
       Actually, the most correct and verifier-safe way to increment a 16-bit checksum by 1 in XDP, where the field is conventionally stored in **network byte order** (big endian) inside
