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

#ifndef __PARSING_XF_KEY_HELPERS_H
#define __PARSING_XF_KEY_HELPERS_H

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
#include "flow.h"
#include "xdp_kern_helpers.h"

/* Notice, parse_ethhdr() will skip VLAN tags, by advancing nh->pos and returns
 * next header EtherType, BUT the ethhdr pointer supplied still points to the
 * Ethernet header. Thus, caller can look at eth->h_proto to see if this was a
 * VLAN tagged packet.
 */
static __always_inline int parse_xf_key_ethhdr(struct hdr_cursor *nh, void *data_end,
                    struct xf_key_ethernet **key_eth)
{
    if (nh->pos + sizeof(struct ethhdr) > data_end)
        return -1;
        
    struct ethhdr *ethh = nh->pos;
    int hdrsize = sizeof(*ethh);
    // return hdrsize;
    struct vlan_hdr *vlh;
    __u16 h_proto;
    int i;

    /* Byte-count bounds check; check if current pointer + size of header
     * is after data_end.
     */
    if (nh->pos + hdrsize > data_end)
        return -1;

    struct xf_key_ethernet eth;
    memcpy(eth.eth_dst, ethh->h_dest, 6);
    memcpy(eth.eth_src, ethh->h_source, 6);
    eth.h_proto = ethh->h_proto;
    *key_eth = &eth; /* The structs are the same */

    nh->pos += hdrsize;
    vlh = nh->pos;
    h_proto = ethh->h_proto;

    /* Use loop unrolling to avoid the verifier restriction on loops;
        * support up to VLAN_MAX_DEPTH layers of VLAN encapsulation.
        */
    #pragma unroll
    for (i = 0; i < VLAN_MAX_DEPTH; i++) {
            if (!proto_is_vlan(h_proto))
                    break;

            if (vlh + 1 > data_end)
                    break;

            h_proto = vlh->h_vlan_encapsulated_proto;
            vlh++;
    }

    nh->pos = vlh;
    return bpf_ntohs(h_proto);
}

static inline int parse_xf_key_arp(struct hdr_cursor *nh,
                    void *data_end,
                    struct xf_key_arp **key_arp)
{
    struct arp_ethhdr *arph = nh->pos;

    if (arph + 1 > data_end)
        return -1;

    struct xf_key_arp arp;
    memset(&arp, 0, sizeof(struct xf_key_arp));
    // arp.ar_op = arph->ar_op;
    arp.arp_sip = arph->ar_sip;
    arp.arp_tip = arph->ar_tip;
    
    memcpy(arp.arp_sha, arph->ar_sha, sizeof(arp.arp_sha));
    memcpy(arp.arp_tha, arph->ar_tha, sizeof(arp.arp_tha));

    nh->pos = arph + 1;
    
    *key_arp = &arp;
    return arph->ar_op;
}    

static inline int parse_xf_key_ip6hdr(struct hdr_cursor *nh,
                    void *data_end,
                    struct xf_key_ipv6 *key_ipv6)
{
    struct ipv6hdr *ip6h = nh->pos;

    /* Pointer-arithmetic bounds check; pointer +1 points to after end of
     * thing being pointed to. We will be using this style in the remainder
     * of the tutorial.
     */
    if (ip6h + 1 > data_end)
        return -1;

    key_ipv6->ipv6_proto = ip6h->nexthdr;
    key_ipv6->ipv6_tclass = ip6h->priority;
    key_ipv6->ipv6_hlimit = ip6h->hop_limit;
    key_ipv6->ipv6_frag = 0;

    memcpy(&key_ipv6->ipv6_dst, ip6h->daddr.s6_addr32, sizeof(key_ipv6->ipv6_dst));
    memcpy(&key_ipv6->ipv6_src, ip6h->saddr.s6_addr32, sizeof(key_ipv6->ipv6_src));

    nh->pos = ip6h + 1;

    return ip6h->nexthdr;
}

static __always_inline int parse_xf_key_iphdr(struct hdr_cursor *nh,
                                       void *data_end,
                                       struct xf_key_ipv4 *key_ipv4)
{
    struct iphdr *iph = nh->pos;
    
    int hdrsize;

    if (iph + 1 > data_end)
        return -1;

    hdrsize = iph->ihl * 4;

    /* Variable-length IPv4 header, need to use byte-based arithmetic */
    if (nh->pos + hdrsize > data_end)
            return -1;

    key_ipv4->ipv4_src = iph->saddr;
    key_ipv4->ipv4_dst = iph->daddr;
    key_ipv4->ipv4_proto = iph->protocol;
    key_ipv4->ipv4_tos = iph->tos;
    key_ipv4->ipv4_ttl = iph->ttl;

    nh->pos += hdrsize;

    return iph->protocol;
}

static __always_inline int parse_xf_key_icmp6hdr(struct hdr_cursor *nh,
                      void *data_end,
                      struct xf_key_icmpv6 **key_icmpv6)
{
    struct xf_key_icmpv6 *icmpv6 = nh->pos;

    if (icmpv6 + 1 > data_end)
        return -1;

    *key_icmpv6 = icmpv6;

    return 0;
}

static __always_inline int parse_xf_key_icmphdr(struct hdr_cursor *nh,
                                         void *data_end,
                                         struct xf_key_icmp **key_icmp)
{
    struct xf_key_icmp *icmp = nh->pos;

    if (icmp + 1 > data_end)
        return -1;

    *key_icmp = icmp;

    return 0;
}

/*
 * parse_tcphdr: parse the udp header and return the length of the udp payload
 */
static __always_inline int parse_xf_key_udphdr(struct hdr_cursor *nh,
                    void *data_end,
                    struct xf_key_udp **key_udp)
{
    struct xf_key_udp *udp = nh->pos;

    if (udp + 1 > data_end)
        return -1;

    *key_udp = udp;

    return 0;
}

/*
 * parse_tcphdr: parse and return the length of the tcp header
 */
static __always_inline int parse_xf_key_tcphdr(struct hdr_cursor *nh,
                    void *data_end,
                    struct xf_key_tcp **key_tcp)
{
    struct xf_key_tcp *tcp = nh->pos;

    if (tcp + 1 > data_end)
        return -1;

    *key_tcp = tcp;

    return 0;
}

static __always_inline int parse_xf_key_nsh_base(struct hdr_cursor *nh,
                                       void *data_end,
                                       struct xf_key_nsh_base **key_nsh_base)
{
    struct xf_key_nsh_base *nsh_base = nh->pos;

    if (nsh_base + 1 > data_end)
        return -1;

    *key_nsh_base = nsh_base;

    nh->pos  = nsh_base + 1;

    return 0;
}

static __always_inline int parse_xf_key_nsh_md1(struct hdr_cursor *nh,
                                       void *data_end,
                                       struct xf_key_nsh_md1 **key_nsh_md1)
{
    struct xf_key_nsh_md1 *md1ctx = nh->pos;

    if (md1ctx + 1 > data_end)
        return -1;
        
    
    *key_nsh_md1 = md1ctx;

    nh->pos = md1ctx + 1;

    return NSH_M_TYPE1_LEN - NSH_BASE_HDR_LEN;
}

/* Return value is the size of the metadata NOT padded to 4 bytes */
// static __always_inline int parse_xf_key_nsh_md2(struct hdr_cursor *nh,
//                                        void *data_end,
//                                        struct xf_key_nsh_md2 **key_nsh_md2)
// {
//     struct nsh_md2_tlv *md2tlv = nh->pos;

//     if (md2tlv + 1 > data_end)
//         return -1;
        
//     int hdrsize = md2tlv->length;

//     struct xf_key_nsh_md2 md2 = {
//         .md_class = md2tlv->md_class,
//         .type = md2tlv->type
//     };

//     *key_nsh_md2 = &md2;

//     nh->pos += hdrsize;

//     return hdrsize;
// }

#endif /* __PARSING_HELPERS_H */
