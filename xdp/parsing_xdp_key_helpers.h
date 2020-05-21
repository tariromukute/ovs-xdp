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

#ifndef __PARSING_XDP_KEY_HELPERS_H
#define __PARSING_XDP_KEY_HELPERS_H

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
static __always_inline int parse_xdp_key_ethhdr(struct hdr_cursor *nh, void *data_end,
                    struct xdp_key_ethernet **key_eth)
{
    struct ethhdr *ethh = nh->pos;
    int hdrsize = sizeof(struct ethhdr);
        struct vlan_hdr *vlh;
        __u16 h_proto;
        int i;

    /* Byte-count bounds check; check if current pointer + size of header
     * is after data_end.
     */
    if (nh->pos + hdrsize > data_end)
        return -1;

    struct xdp_key_ethernet eth;
    memcpy(eth.eth_dst, ethh->h_dest, sizeof(eth.eth_dst));
    memcpy(eth.eth_src, ethh->h_source, sizeof(eth.eth_src));
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

static inline int parse_xdp_key_arp(struct hdr_cursor *nh,
                    void *data_end,
                    struct xdp_key_arp **key_arp)
{
    struct arp_ethhdr *arph = nh->pos;

    if (arph + 1 > data_end)
        return -1;

    struct xdp_key_arp arp;
    memset(&arp, 0, sizeof(struct xdp_key_arp));
    arp.arp_op = arph->ar_op;
    arp.arp_sip = arph->ar_sip;
    arp.arp_tip = arph->ar_tip;
    
    memcpy(arp.arp_sha, arph->ar_sha, sizeof(arp.arp_sha));
    memcpy(arp.arp_tha, arph->ar_tha, sizeof(arp.arp_tha));

    nh->pos = arph + 1;
    
    return arph->ar_op;
}    

static inline int parse_xdp_key_ip6hdr(struct hdr_cursor *nh,
                    void *data_end,
                    struct xdp_key_ipv6 **key_ipv6)
{
    struct ipv6hdr *ip6h = nh->pos;

    /* Pointer-arithmetic bounds check; pointer +1 points to after end of
     * thing being pointed to. We will be using this style in the remainder
     * of the tutorial.
     */
    if (ip6h + 1 > data_end)
        return -1;

    struct xdp_key_ipv6 ipv6;
    memset(&ipv6, 0, sizeof(struct xdp_key_ipv6));
    ipv6.ipv6_proto = ip6h->nexthdr;
    ipv6.ipv6_tclass = ip6h->priority;
    ipv6.ipv6_hlimit = ip6h->hop_limit;
    ipv6.ipv6_frag = 0;

    memcpy(&ipv6.ipv6_dst, ip6h->daddr.s6_addr32, sizeof(ipv6.ipv6_dst));
    memcpy(&ipv6.ipv6_src, ip6h->saddr.s6_addr32, sizeof(ipv6.ipv6_src));
    // memcpy(&ipv6.ipv6_label, 0, sizeof(ipv6.ipv6_label)); /* TODO: fix this */

    nh->pos = ip6h + 1;
    *key_ipv6 = &ipv6;

    return ip6h->nexthdr;
}

static __always_inline int parse_xdp_key_iphdr(struct hdr_cursor *nh,
                                       void *data_end,
                                       struct xdp_key_ipv4 **key_ipv4)
{
    struct iphdr *iph = nh->pos;
    
    int hdrsize;

    if (iph + 1 > data_end)
        return -1;

    hdrsize = iph->ihl * 4;

    /* Variable-length IPv4 header, need to use byte-based arithmetic */
    if (nh->pos + hdrsize > data_end)
            return -1;

    struct xdp_key_ipv4 ipv4;
    memset(&ipv4, 0, sizeof(struct xdp_key_ipv4));
    ipv4.ipv4_src = iph->saddr;
    ipv4.ipv4_dst = iph->daddr;
    ipv4.ipv4_proto = iph->protocol;
    ipv4.ipv4_tos = iph->tos;
    ipv4.ipv4_ttl = iph->ttl;

    nh->pos += hdrsize;
    *key_ipv4 = &ipv4;

    return iph->protocol;
}

static __always_inline int parse_xdp_key_icmp6hdr(struct hdr_cursor *nh,
                      void *data_end,
                      struct xdp_key_icmpv6 **key_icmpv6)
{
    struct icmp6hdr *icmp6h = nh->pos;

    if (icmp6h + 1 > data_end)
        return -1;

    struct xdp_key_icmpv6 icmpv6 = {
        .icmpv6_type = icmp6h->icmp6_type,
        .icmpv6_code = icmp6h->icmp6_code 
    };
    *key_icmpv6 = &icmpv6;

    nh->pos = icmp6h + 1;

    return icmp6h->icmp6_type;
}

static __always_inline int parse_xdp_key_icmphdr(struct hdr_cursor *nh,
                                         void *data_end,
                                         struct xdp_key_icmp **key_icmp)
{
    struct icmphdr *icmph = nh->pos;

    if (icmph + 1 > data_end)
        return -1;

    struct xdp_key_icmp icmp = {
        .icmp_type = icmph->type,
        .icmp_code = icmph->code
    };
    *key_icmp = &icmp;
    nh->pos  = icmph + 1;

    return icmph->type;
}

/*
 * parse_tcphdr: parse the udp header and return the length of the udp payload
 */
static __always_inline int parse_xdp_key_udphdr(struct hdr_cursor *nh,
                    void *data_end,
                    struct xdp_key_udp **key_udp)
{
    int len;
    struct udphdr *h = nh->pos;

    if (h + 1 > data_end)
        return -1;
    

    len = bpf_ntohs(h->len) - sizeof(struct udphdr);
    if (len < 0)
        return -1;

    struct xdp_key_udp udp = {
        .udp_src = h->source,
        .udp_dst = h->dest
    };

    *key_udp = &udp;
    nh->pos  = h + 1;

    return len;
}

/*
 * parse_tcphdr: parse and return the length of the tcp header
 */
static __always_inline int parse_xdp_key_tcphdr(struct hdr_cursor *nh,
                    void *data_end,
                    struct xdp_key_tcp **key_tcp)
{
    int len;
    struct tcphdr *h = nh->pos;

    if (h + 1 > data_end)
        return -1;

    len = h->doff * 4;
    if ((void *) h + len > data_end)
        return -1;

    struct xdp_key_tcp tcp = {
        .tcp_src = h->source,
        .tcp_dst = h->dest
    };

    *key_tcp = &tcp;

    nh->pos  = h + 1;

    return len;
}

static __always_inline int parse_xdp_key_nsh_base(struct hdr_cursor *nh,
                                       void *data_end,
                                       struct xdp_key_nsh_base **key_nsh_base)
{
    struct nshhdr *nshh = nh->pos;
    
    if (nshh + 1 > data_end)
        return -1;

    int hdrsize = nsh_hdr_len(nshh) * 4;

    if (nh->pos + hdrsize > data_end)
        return -1;

    if (nshh->mdtype == NSH_M_TYPE1 && hdrsize != NSH_M_TYPE1_LEN) {
        return -1;
    } else if (nshh->mdtype == NSH_M_TYPE2 && hdrsize >= NSH_BASE_HDR_LEN) {
        return -1;
    }

    struct xdp_key_nsh_base base;
    memset(&base, 0, sizeof(struct xdp_key_nsh_base));
    base.flags = nsh_get_flags(nshh);
    base.ttl = nsh_get_ttl(nshh);
    base.mdtype = nshh->mdtype;
    base.np = nshh->np;
    base.path_hdr = nshh->path_hdr;

    *key_nsh_base = &base;
    nh->pos += NSH_BASE_HDR_LEN;

    return hdrsize;
}

static __always_inline int parse_xdp_key_nsh_md1(struct hdr_cursor *nh,
                                       void *data_end,
                                       struct xdp_key_nsh_md1 **key_nsh_md1)
{
    struct xdp_key_nsh_md1 *md1ctx = nh->pos;

    if (md1ctx + 1 > data_end)
        return -1;
        
    
    *key_nsh_md1 = md1ctx;

    nh->pos = md1ctx + 1;

    return NSH_M_TYPE1_LEN - NSH_BASE_HDR_LEN;
}

/* Return value is the size of the metadata NOT padded to 4 bytes */
// static __always_inline int parse_xdp_key_nsh_md2(struct hdr_cursor *nh,
//                                        void *data_end,
//                                        struct xdp_key_nsh_md2 **key_nsh_md2)
// {
//     struct nsh_md2_tlv *md2tlv = nh->pos;

//     if (md2tlv + 1 > data_end)
//         return -1;
        
//     int hdrsize = md2tlv->length;

//     struct xdp_key_nsh_md2 md2 = {
//         .md_class = md2tlv->md_class,
//         .type = md2tlv->type
//     };

//     *key_nsh_md2 = &md2;

//     nh->pos += hdrsize;

//     return hdrsize;
// }

#endif /* __PARSING_HELPERS_H */
