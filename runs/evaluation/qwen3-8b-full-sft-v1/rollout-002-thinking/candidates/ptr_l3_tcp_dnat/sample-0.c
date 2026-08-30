<think>
Okay, I need to write an XDP program that does DNAT for TCP traffic. Let's start by recalling what DNAT means. DNAT changes the destination IP address and port of a packet. In this case, the target is to change the destination IP to 192.168.100.50 and the port to 8080. But I also have to handle the checksums correctly, which is a bit tricky.

First, the XDP program needs to check if the packet is IPv4 and TCP. So I'll start by checking the Ethernet header. The eth->h_proto should be ETH_P_IP. Then, in the IP header, the protocol field should be IPPROTO_TCP. If either of these checks fail, I return XDP_PASS.

Next, I need to parse the IP header. The IP header's IHL (Internet Header Length) field indicates the length of the IP header. Since IHL is in 32-bit words, I have to multiply by 4 to get the actual bytes. I need to make sure that the IP header is long enough to contain the TCP header. So, ip_hdr + ip_hdr->ihl * 4 should be within the packet's data. If not, it's an invalid packet, so return XDP_PASS.

Once I confirm the IP and TCP headers are valid, I'll modify the destination IP address and port. For the IP address, I set ip->daddr to 0xC0A86432. For the TCP port, I set tcp->dest to 8080. But here's the catch: changing the destination IP and port affects the checksums. The IP checksum covers the entire IP header, including the daddr. The TCP checksum includes a pseudo-header that includes the source and destination IPs, the protocol, and the TCP segment length. So, when I change the daddr and the port, I need to recompute both checksums.

Wait, how to handle the checksums? For the IP checksum, I can't just incrementally adjust it. Changing the daddr will alter the checksum. So I need to recalculate the IP checksum. Similarly, the TCP checksum includes the daddr and the new port, so I need to recompute that as well.

But how to do that in eBPF? Let's think. For the IP checksum, I can use the standard checksum algorithm. For the TCP checksum, I need to create a pseudo-header with the new daddr and port, then compute the checksum of the TCP header plus the pseudo-header.

But wait, the TCP checksum is computed over the pseudo-header (which includes the source IP, destination IP, protocol, TCP length) plus the TCP header. So when I change the destination IP and port, the pseudo-header changes, so the TCP checksum must be recomputed.

So the steps are:

1. Check Ethernet and IP headers.
2. Check if it's TCP.
3. Check IHL and TCP header bounds.
4. Modify daddr and dest port.
5. Recalculate IP checksum.
6. Recalculate TCP checksum using the new daddr and port.
7. Return XDP_PASS.

But how to handle the checksums in eBPF? Let's think about the IP checksum first. The IP header has a checksum field. To recalculate it, I can take the IP header (excluding the checksum field), compute the 16-bit checksum, and then store it back.

For the TCP checksum, the pseudo-header includes the source IP, destination IP, protocol (TCP), and the TCP segment length. So, the new daddr and port will affect the pseudo-header. So, I need to create a temporary buffer for the pseudo-header, add the TCP header, and compute the checksum.

But in eBPF, I can't allocate memory for temporary buffers. So I need to compute the checksum in-place. Let's see.

For the IP checksum:

- Take the IP header (excluding the checksum field) and compute the checksum. Then replace the checksum field with the new value.

For the TCP checksum:

- The pseudo-header is:
  - 16-bit source IP
  - 16-bit destination IP
  - 8-bit protocol
  - 16-bit TCP segment length
  - Then the TCP header (including source port, destination port, sequence number, etc.)

So, the TCP checksum is computed over the pseudo-header plus the TCP header. Since we're changing the destination IP and port, the pseudo-header changes. So, I need to compute the checksum of the modified pseudo-header plus the TCP header.

But how to do this in eBPF without allocating memory? Let's think. The TCP header starts at ip_hdr + ip_hdr->ihl * 4. Let's call that tcp_hdr. The pseudo-header is:

struct {
    __u32 src_addr;
    __u32 dst_addr;
    __u16 protocol;
    __u16 tcp_hdr_len;
} pseudo_hdr;

Then, the TCP header is tcp_hdr. So, the total data for checksum is pseudo_hdr + tcp_hdr.

But in eBPF, I can't create a new struct. So I need to compute the checksum by accessing the relevant fields directly.

So, for the TCP checksum:

- src_addr is ip_hdr->saddr
- dst_addr is the new daddr (0xC0A86432)
- protocol is IPPROTO_TCP (6)
- tcp_hdr_len is tcp_hdr->doff * 4

Then, the pseudo-header is these fields, followed by the TCP header.

So, I can compute the checksum by combining these fields and the TCP header.

But how to do that in eBPF? Let's think about the code.

First, for the IP checksum:

Original IP header is ip_hdr. We need to compute the checksum of the IP header (excluding the checksum field) and replace it.

So, the code for IP checksum:

__u32 csum = 0;
__u16 *p = (__u16 *)ip_hdr;
#define IP_HDR_LEN (ip_hdr->ihl * 4)
#define IP_HDR_END (p + IP_HDR_LEN)
while (p < IP_HDR_END - 1)
    csum += *p++;
p = (void *)ip_hdr + IP_HDR_LEN - 2;
if (p >= IP_HDR_END)
    csum += ( (__u16)ip_hdr->check ) + ( (__u16)ip_hdr->check >> 16 );
else
    csum += *p;
csum = (csum & 0xFFFF) + (csum >> 16);
ip_hdr->check = (__u16)csum;

Wait, but the IP header's checksum field is part of the data that's being checksummed. So, the code above would include the original checksum in the calculation, which is incorrect. So, the correct approach is to exclude the checksum field from the calculation.

So, the IP header's checksum is in the field ip_hdr->check. So, when computing the checksum, we need to exclude that field.

So, the code would be:

__u32 csum = 0;
__u16 *p = (__u16 *)ip_hdr;
#define IP_HDR_LEN (ip_hdr->ihl * 4)
#define IP_HDR_END (p + IP_HDR_LEN - 1)
while (p < IP_HDR_END)
    csum += *p++;
csum = (csum & 0xFFFF) + (csum >> 16);
ip_hdr->check = (__u16)csum;

Wait, but the IP_HDR_LEN is the length of the IP header. So, the IP header starts at ip_hdr, and the checksum is at ip_hdr + (ip_hdr->ihl * 4) - 2. Wait, the IP header is 20 bytes for the base case. The fields are:

struct iphdr {
    __u8  h_len;
    __u8  protocol;
    __u16 check;
    ...
};

Wait, the actual structure is:

struct iphdr {
    unsigned int ihl:4,
                version:4,
                ...
    __u16 check;
    ...
};

So, the check field is at offset 10 (assuming 32-bit alignment). So, the IP header's checksum is at ip_hdr + 10. So, when computing the checksum, we need to exclude that field.

So, the code for IP checksum would be:

__u32 csum = 0;
__u16 *p = (__u16 *)ip_hdr;
#define IP_HDR_LEN (ip_hdr->ihl * 4)
#define IP_HDR_END (p + IP_HDR_LEN - 1)
while (p < IP_HDR_END) {
    if (p + 1 <= IP_HDR_END)
        csum += *p++;
    else
        break;
}
// Now, subtract the original checksum
csum -= ip_hdr->check;
csum = (csum & 0xFFFF) + (csum >> 16);
ip_hdr->check = (__u16)csum;

Wait, but this approach would require that the IP header is at least 20 bytes. But since we've already checked that the IHL is valid (i.e., ip_hdr->ihl >= 5 and <= 15), then the IP_HDR_LEN is at least 20 bytes. So, the code can proceed.

But in eBPF, we can't use #define in the code. So, we need to compute the IP_HDR_LEN as ip_hdr->ihl * 4. Then, the IP_HDR_END is (void *)ip_hdr + ip_hdr->ihl * 4.

So, the code for IP checksum would be:

__u32 csum = 0;
__u16 *p = (__u16 *)ip_hdr;
__u32 ip_hdr_len = ip_hdr->ihl * 4;
if (ip_hdr_len < sizeof(struct iphdr))
    return XDP_PASS; // invalid header

__u8 *end = (void *)ip_hdr + ip_hdr_len;
while (p < (__u16 *)end - 1)
    csum += *p++;
// Now, subtract the original checksum
csum -= ip_hdr->check;
csum = (csum & 0xFFFF) + (csum >> 16);
ip_hdr->check = (__u16)csum;

But wait, the original checksum is part of the IP header. So, when we compute the checksum, we need to exclude it. So, the code above subtracts the original checksum from the sum, then computes the 1's complement.

But this is a bit tricky. Let me think again. The standard way to compute the checksum is to sum all 16-bit words, then take the 1's complement of the sum. So, the code for the IP checksum would be:

__u32 csum = 0;
__u16 *p = (__u16 *)ip_hdr;
__u32 ip_hdr_len = ip_hdr->ihl * 4;
if (ip_hdr_len < sizeof(struct iphdr))
    return XDP_PASS;

__u8 *end = (void *)ip_hdr + ip_hdr_len;
while (p < (__u16 *)end)
    csum += *p++;
csum = (csum & 0xFFFF) + (csum >> 16);
ip_hdr->check = (__u16)csum;

Wait, but this includes the original checksum in the sum. So, the code would be:

Original sum includes the original checksum. Then, after adding all words, we compute the 1's complement. But that's not correct. Because the checksum field is supposed to be zeroed out before computing the checksum.

So, the correct approach is to zero out the checksum field, compute the sum, then set the checksum to the 1's complement of the sum.

So, the code should be:

__u32 csum = 0;
__u16 *p = (__u16 *)ip_hdr;
__u32 ip_hdr_len = ip_hdr->ihl * 4;
if (ip_hdr_len < sizeof(struct iphdr))
    return XDP_PASS;

__u8 *end = (void *)ip_hdr + ip_hdr_len;
while (p < (__u16 *)end)
    csum += *p++;
// Now, subtract the original checksum
csum -= ip_hdr->check;
csum = (csum & 0xFFFF) + (csum >> 16);
ip_hdr->check = (__u16)csum;

But in eBPF, we can't modify the checksum field until after the calculation. So, the code would be:

// Save original checksum
__u16 old_csum = ip_hdr->check;
// Zero out checksum field
ip_hdr->check = 0;
// Compute checksum
__u32 csum = 0;
__u16 *p = (__u16 *)ip_hdr;
__u32 ip_hdr_len = ip_hdr->ihl * 4;
if (ip_hdr_len < sizeof(struct iphdr))
    return XDP_PASS;

__u8 *end = (void *)ip_hdr + ip_hdr_len;
while (p < (__u16 *)end)
    csum += *p++;
csum = (csum & 0xFFFF) + (csum >> 16);
ip_hdr->check = (__u16)csum;

But this approach would zero out the checksum field before computing, which is correct. However, in eBPF, we can't modify the ip_hdr->check until after the calculation. So, the code would be:

// Save original checksum
__u16 old_csum = ip_hdr->check;
// Zero out checksum field
ip_hdr->check = 0;
// Compute checksum
__u32 csum = 0;
__u16 *p = (__u16 *)ip_hdr;
__u32 ip_hdr_len = ip_hdr->ihl * 4;
if (ip_hdr_len < sizeof(struct iphdr))
    return XDP_PASS;

__u8 *end = (void *)ip_hdr + ip_hdr_len;
while (p < (__u16 *)end)
    csum += *p++;
csum = (csum & 0xFFFF) + (csum >> 16);
ip_hdr->check = (__u16)csum;

But this would overwrite the original checksum field.
