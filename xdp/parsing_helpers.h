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
#include "flow.h"

/* Header cursor to keep track of current parsing position */
struct hdr_cursor {
    void *pos;
};

/*
 *     struct vlan_hdr - vlan header
 *     @h_vlan_TCI: priority and VLAN ID
 *    @h_vlan_encapsulated_proto: packet type ID or len
 */
struct vlan_hdr {
    __be16    h_vlan_TCI;
    __be16    h_vlan_encapsulated_proto;
};

/*
 * Struct icmphdr_common represents the common part of the icmphdr and icmp6hdr
 * structures.
 */
struct icmphdr_common {
    __u8        type;
    __u8        code;
    __sum16        cksum;
};

/* Allow users of header file to redefine VLAN max depth */
#ifndef VLAN_MAX_DEPTH
#define VLAN_MAX_DEPTH 4
#endif

static __always_inline int proto_is_vlan(__u16 h_proto)
{
        return !!(h_proto == bpf_htons(ETH_P_8021Q) ||
                  h_proto == bpf_htons(ETH_P_8021AD));
}

/* Notice, parse_ethhdr() will skip VLAN tags, by advancing nh->pos and returns
 * next header EtherType, BUT the ethhdr pointer supplied still points to the
 * Ethernet header. Thus, caller can look at eth->h_proto to see if this was a
 * VLAN tagged packet.
 */
static __always_inline int parse_xdp_key_ethhdr(struct hdr_cursor *nh, void *data_end,
                    struct xdp_key_ethernet **key_eth)
{
    struct xdp_key_ethernet *eth = nh->pos;
    int hdrsize = sizeof(struct ethhdr);
        struct vlan_hdr *vlh;
        __u16 h_proto;
        int i;

    /* Byte-count bounds check; check if current pointer + size of header
     * is after data_end.
     */
    if (nh->pos + hdrsize > data_end)
        return -1;

    *key_eth = eth; /* The structs are the same */

    nh->pos += hdrsize;
    vlh = nh->pos;
    h_proto = eth->h_proto;

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

static __always_inline int parse_xdp_key_ip6hdr(struct hdr_cursor *nh,
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

    struct xdp_key_ipv6 ipv6 = {
        .ipv6_proto = ip6h->nexthdr,
        .ipv6_tclass = ip6h->priority,
        .ipv6_hlimit = ip6h->hop_limit
    };

    memcpy(&ipv6.ipv6_dst, &ip6h->daddr, sizeof(ipv6.ipv6_dst));
    memcpy(&ipv6.ipv6_src, &ip6h->saddr, sizeof(ipv6.ipv6_src));
    memcpy(&ipv6.ipv6_label, &ip6h->flow_lbl, sizeof(ipv6.ipv6_label)); /* TODO: fix this */

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

    nh->pos   = icmp6h + 1;

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

    struct xdp_key_nsh_base base = {
        .flags = nsh_get_flags(nshh),
        .ttl = nsh_get_ttl(nshh),
        .mdtype = nshh->mdtype,
        .np = nshh->np,
        .path_hdr = nshh->path_hdr
    };

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
static __always_inline int parse_xdp_key_nsh_md2(struct hdr_cursor *nh,
                                       void *data_end,
                                       struct xdp_key_nsh_md2 **key_nsh_md2)
{
    struct nsh_md2_tlv *md2tlv = nh->pos;

    if (md2tlv + 1 > data_end)
        return -1;
        
    int hdrsize = md2tlv->length;

    struct xdp_key_nsh_md2 md2 = {
        .md_class = md2tlv->md_class,
        .type = md2tlv->type
    };

    *key_nsh_md2 = &md2;

    nh->pos += hdrsize;

    return hdrsize;
}

#endif /* __PARSING_HELPERS_H */
