/* SPDX-License-Identifier: GPL-2.0 */
/*
 * This file contains parsing functions that are used in the packetXX XDP
 * programs. The functions are marked as __always_inline, and fully defined in
 * this header file to be included in the BPF program.
 *
 * Each helper parses a packet header, including doing bounds checking, and
 * returns the type of its contents if successful, and -1 otherwise.
 *
 * For Ethernet and IP headers, the content type is the type of the payload
 * (h_proto for Ethernet, nexthdr for IPv6), for ICMP it is the ICMP type field.
 * All return values are in host byte order.
 *
 * The versions of the functions included here are slightly expanded versions of
 * the functions in the packet01 lesson. For instance, the Ethernet header
 * parsing has support for parsing VLAN tags.
 */

#ifndef __PARSING_HELPERS_H
#define __PARSING_HELPERS_H

#include <stddef.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include "nsh.h"
#include "xdp_kern_helpers.h"

/* Notice, parse_ethhdr() will skip VLAN tags, by advancing nh->pos and returns
 * next header EtherType, BUT the ethhdr pointer supplied still points to the
 * Ethernet header. Thus, caller can look at eth->h_proto to see if this was a
 * VLAN tagged packet.
 */
static __always_inline int parse_ethhdr(struct hdr_cursor *nh, void *data_end,
                    struct ethhdr **ethhdr)
{
    struct ethhdr *eth = nh->pos;
    int hdrsize = sizeof(*eth);
        struct vlan_hdr *vlh;
        __u16 h_proto;
        int i;

    /* Byte-count bounds check; check if current pointer + size of header
     * is after data_end.
     */
    if (nh->pos + hdrsize > data_end) {
        return -1;
    }

    nh->pos += hdrsize;
    *ethhdr = eth;
        vlh = nh->pos;
        h_proto = eth->h_proto;

        /* Use loop unrolling to avoid the verifier restriction on loops;
         * support up to VLAN_MAX_DEPTH layers of VLAN encapsulation.
         */
        #pragma unroll
        for (i = 0; i < VLAN_MAX_DEPTH; i++) {
                if (!proto_is_vlan(h_proto)) {
                    break;
                }

                if (vlh + 1 > data_end) {
                    break;
                }

                h_proto = vlh->h_vlan_encapsulated_proto;
                vlh++;
        }

        nh->pos = vlh;
    return bpf_ntohs(h_proto);
}

static __always_inline int parse_arp_ethhdr(struct hdr_cursor *nh,
                                       void *data_end,
                                       struct arp_ethhdr **arphdr)
{
    struct arp_ethhdr *arph = nh->pos;

    if (arph + 1 > data_end) {
        return -1;
    }


    nh->pos = arph + 1;
    *arphdr = arph;

    return 0;
}

static __always_inline int parse_ip6hdr(struct hdr_cursor *nh,
                    void *data_end,
                    struct ipv6hdr **ip6hdr)
{
    struct ipv6hdr *ip6h = nh->pos;

    /* Pointer-arithmetic bounds check; pointer +1 points to after end of
     * thing being pointed to. We will be using this style in the remainder
     * of the tutorial.
     */
    if (ip6h + 1 > data_end)
        return -1;

    nh->pos = ip6h + 1;
    *ip6hdr = ip6h;

    return ip6h->nexthdr;
}

static __always_inline int parse_iphdr(struct hdr_cursor *nh,
                                       void *data_end,
                                       struct iphdr **iphdr)
{
    struct iphdr *iph = nh->pos;
    int hdrsize;

    if (iph + 1 > data_end) {
        return -1;
    }

    hdrsize = iph->ihl * 4;

    /* Variable-length IPv4 header, need to use byte-based arithmetic */
    if (nh->pos + hdrsize > data_end)
        return -1;

    nh->pos += hdrsize;
    *iphdr = iph;

    return iph->protocol;
}

static __always_inline int parse_icmp6hdr(struct hdr_cursor *nh,
                      void *data_end,
                      struct icmp6hdr **icmp6hdr)
{
    struct icmp6hdr *icmp6h = nh->pos;

    if (icmp6h + 1 > data_end)
        return -1;

    nh->pos   = icmp6h + 1;
    *icmp6hdr = icmp6h;

    return icmp6h->icmp6_type;
}

static __always_inline int parse_icmphdr(struct hdr_cursor *nh,
                                         void *data_end,
                                         struct icmphdr **icmphdr)
{
    struct icmphdr *icmph = nh->pos;

    if (icmph + 1 > data_end)
        return -1;

    nh->pos  = icmph + 1;
    *icmphdr = icmph;

    return icmph->type;
}

static __always_inline int parse_icmphdr_common(struct hdr_cursor *nh,
                        void *data_end,
                        struct icmphdr_common **icmphdr)
{
    struct icmphdr_common *h = nh->pos;

    if (h + 1 > data_end)
        return -1;

    nh->pos  = h + 1;
    *icmphdr = h;

    return h->type;
}

/*
 * parse_tcphdr: parse the udp header and return the length of the udp payload
 */
static __always_inline int parse_udphdr(struct hdr_cursor *nh,
                    void *data_end,
                    struct udphdr **udphdr)
{
    int len;
    struct udphdr *h = nh->pos;

    if (h + 1 > data_end)
        return -1;

    nh->pos  = h + 1;
    *udphdr = h;

    len = bpf_ntohs(h->len) - sizeof(struct udphdr);
    if (len < 0)
        return -1;

    return len;
}

/*
 * parse_tcphdr: parse and return the length of the tcp header
 */
static __always_inline int parse_tcphdr(struct hdr_cursor *nh,
                    void *data_end,
                    struct tcphdr **tcphdr)
{
    int len;
    struct tcphdr *h = nh->pos;

    if (h + 1 > data_end)
        return -1;

    len = h->doff * 4;
    if ((void *) h + len > data_end)
        return -1;

    nh->pos  = h + 1;
    *tcphdr = h;

    return len;
}

static __always_inline int parse_nshhdr(struct hdr_cursor *nh,
                                       void *data_end,
                                       struct nshhdr **nshhdr)
{
    struct nshhdr *nshh = nh->pos;
    int hdrsize = 4 * 2; // minimum size of a nsh header i.e, MD TYPE 2

    if (nshh + hdrsize > data_end)
        return -1;
        
    hdrsize = nsh_hdr_len(nshh) * 4;

    /* Variable-length IPv4 header, need to use byte-based arithmetic */
    if (nh->pos + hdrsize > data_end)
        return -1;

    nh->pos += hdrsize;
    *nshhdr = nshh;

    return nshh->np;
}

#endif /* __PARSING_HELPERS_H */
