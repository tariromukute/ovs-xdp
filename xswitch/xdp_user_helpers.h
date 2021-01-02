#ifndef XDP_USER_HELPERS_H
#define XDP_USER_HELPERS_H 1

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <netinet/ether.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openvswitch/dynamic-string.h>

#include "flow.h"
#include "xf.h"

#ifndef HDR_LVL_MAX
#define HDR_LVL_MAX 1096
#endif

#ifndef HDR_MAX
#define HDR_MAX 4096
#endif

#ifndef NSH_M_TYPE1
#define NSH_M_TYPE1 0x01
#endif

#ifndef NSH_M_TYPE2
#define NSH_M_TYPE2 0x02
#endif

void format_key_to_hex(struct ds *ds, struct xdp_flow_key *key);
void xdp_flow_key_format(struct ds *ds, struct xf_key *key);
void xfa_buf_format(struct ds *ds, struct xfa_buf *act);
void xfu_stats_format(struct ds *ds, struct xfu_stats *stats);
int format_xdp_actions(const struct xdp_flow_actions *acts);
int format_xdp_key(struct xdp_flow_key *key, char buf[]);

static inline __u64 u8_arr_to_u64(const __u8 *addr, const int size)
{
    __u64 u = 0;
    int i;
    for (i = size; i >= 0; i--)
    {
        u = u << 8 | addr[i];
    }
    return u;
}

// static inline int struct_to_hex(const __u8 ptr[], const int size, char buf[])
// {

//     int i = 0;
//     for (i = 0; i < size; i++)
//     {

//     }
// }

void format_key_to_hex(struct ds *ds, struct xdp_flow_key *key)
{

    ds_put_cstr(ds, " eth_src: ");
    ds_put_hex(ds, &key->eth.eth_src, sizeof(ETH_ALEN));

    ds_put_cstr(ds, " eth_dst: ");
    ds_put_hex(ds, &key->eth.eth_dst, sizeof(ETH_ALEN));

    ds_put_cstr(ds, " h_proto: ");
    ds_put_hex(ds, &key->eth.h_proto, sizeof(__be16));

    ds_put_cstr(ds, "\n");

    if (ntohs(key->eth.h_proto) == ETH_P_IP)
    {
        ds_put_cstr(ds, " ipv4_src: ");
        ds_put_hex(ds, &key->iph.ipv4_src, sizeof(__be32));

        ds_put_cstr(ds, " ipv4_dst: ");
        ds_put_hex(ds, &key->iph.ipv4_dst, sizeof(__be32));

        ds_put_cstr(ds, " ipv4_proto: ");
        ds_put_hex(ds, &key->iph.ipv4_proto, sizeof(__u8));

        ds_put_cstr(ds, " ipv4_tos: ");
        ds_put_hex(ds, &key->iph.ipv4_tos, sizeof(__u8));

        ds_put_cstr(ds, " ipv4_ttl: ");
        ds_put_hex(ds, &key->iph.ipv4_ttl, sizeof(__u8));

        ds_put_cstr(ds, " ipv4_frag: ");
        ds_put_hex(ds, &key->iph.ipv4_frag, sizeof(__u8));

        ds_put_cstr(ds, "\n");

        /* Transport layer. */
        if (key->iph.ipv4_proto == IPPROTO_TCP)
        {
            ds_put_cstr(ds, " tcp_src: ");
            ds_put_hex(ds, &key->tcph.tcp_src, sizeof(__be16));

            ds_put_cstr(ds, " tcp_dst: ");
            ds_put_hex(ds, &key->tcph.tcp_dst, sizeof(__be16));

            ds_put_cstr(ds, "\n");
        }
        else if (key->iph.ipv4_proto == IPPROTO_UDP)
        {
            ds_put_cstr(ds, " udp_src: ");
            ds_put_hex(ds, &key->udph.udp_src, sizeof(__be16));

            ds_put_cstr(ds, " udp_dst: ");
            ds_put_hex(ds, &key->udph.udp_dst, sizeof(__be16));

            ds_put_cstr(ds, "\n");
        }
        else if (key->iph.ipv4_proto == IPPROTO_SCTP)
        {
            /* TODO: implement code */
        }
        else if (key->iph.ipv4_proto == IPPROTO_ICMP)
        {
            ds_put_cstr(ds, " icmp_type: ");
            ds_put_hex(ds, &key->icmph.icmp_type, sizeof(__u8));

            ds_put_cstr(ds, " icmp_code: ");
            ds_put_hex(ds, &key->icmph.icmp_code, sizeof(__u8));

            ds_put_cstr(ds, "\n");
        }
    }
    else if (ntohs(key->eth.h_proto) == ETH_P_ARP || bpf_ntohs(key->eth.h_proto) == ETH_P_RARP)
    {
        ds_put_cstr(ds, " arp_sip: ");
        ds_put_hex(ds, &key->arph.arp_sip, sizeof(__be32));

        ds_put_cstr(ds, " arp_tip: ");
        ds_put_hex(ds, &key->arph.arp_tip, sizeof(__be32));

        ds_put_cstr(ds, " ar_op: ");
        ds_put_hex(ds, &key->arph.ar_op, sizeof(__be16));

        ds_put_cstr(ds, " arp_sha: ");
        ds_put_hex(ds, &key->arph.arp_sha, sizeof(ETH_ALEN));

        ds_put_cstr(ds, " arp_tha: ");
        ds_put_hex(ds, &key->arph.arp_tha, sizeof(ETH_ALEN));

        ds_put_cstr(ds, "\n");
    }
    else if (ntohs(key->eth.h_proto) == ETH_P_MPLS_MC || bpf_ntohs(key->eth.h_proto) == ETH_P_MPLS_UC)
    {

        /* TODO: implement code */
    }
    else if (ntohs(key->eth.h_proto) == ETH_P_IPV6)
    {
        ds_put_cstr(ds, " ipv6_src: ");
        ds_put_hex(ds, &key->ipv6h.ipv6_src, sizeof(struct in6_addr));

        ds_put_cstr(ds, " ipv6_dst: ");
        ds_put_hex(ds, &key->ipv6h.ipv6_dst, sizeof(struct in6_addr));

        ds_put_cstr(ds, " ipv6_proto: ");
        ds_put_hex(ds, &key->ipv6h.ipv6_proto, sizeof(__u8));

        ds_put_cstr(ds, " ipv6_tclass: ");
        ds_put_hex(ds, &key->ipv6h.ipv6_tclass, sizeof(__u8));

        ds_put_cstr(ds, " ipv6_hlimit: ");
        ds_put_hex(ds, &key->ipv6h.ipv6_hlimit, sizeof(__u8));

        ds_put_cstr(ds, " ipv6_frag: ");
        ds_put_hex(ds, &key->ipv6h.ipv6_frag, sizeof(__u8));

        ds_put_cstr(ds, "\n");

        /* Transport layer. */
        if (key->ipv6h.ipv6_proto == IPPROTO_TCP)
        {
            ds_put_cstr(ds, " tcp_src: ");
            ds_put_hex(ds, &key->tcph.tcp_src, sizeof(__be16));

            ds_put_cstr(ds, " tcp_dst: ");
            ds_put_hex(ds, &key->tcph.tcp_dst, sizeof(__be16));

            ds_put_cstr(ds, "\n");
        }
        else if (key->ipv6h.ipv6_proto == IPPROTO_UDP)
        {
            ds_put_cstr(ds, " udp_src: ");
            ds_put_hex(ds, &key->udph.udp_src, sizeof(__be16));

            ds_put_cstr(ds, " udp_dst: ");
            ds_put_hex(ds, &key->udph.udp_dst, sizeof(__be16));

            ds_put_cstr(ds, "\n");
        }
        else if (key->ipv6h.ipv6_proto == IPPROTO_SCTP)
        {
            /* TODO: implement code */
        }
        else if (key->ipv6h.ipv6_proto == IPPROTO_ICMPV6)
        {
            ds_put_cstr(ds, " icmpv6_type: ");
            ds_put_hex(ds, &key->icmp6h.icmpv6_type, sizeof(__u8));

            ds_put_cstr(ds, " icmpv6_code: ");
            ds_put_hex(ds, &key->icmp6h.icmpv6_code, sizeof(__u8));

            ds_put_cstr(ds, "\n");
        }
    }
    else if (ntohs(key->eth.h_proto) == ETH_P_NSH)
    {
        ds_put_cstr(ds, " flags: ");
        ds_put_hex(ds, &key->nsh_base.flags, sizeof(__u8));

        ds_put_cstr(ds, " ttl: ");
        ds_put_hex(ds, &key->nsh_base.ttl, sizeof(__u8));

        ds_put_cstr(ds, " mdtype: ");
        ds_put_hex(ds, &key->nsh_base.mdtype, sizeof(__u8));

        ds_put_cstr(ds, " np: ");
        ds_put_hex(ds, &key->nsh_base.np, sizeof(__u8));

        ds_put_cstr(ds, " path_hdr: ");
        ds_put_hex(ds, &key->nsh_base.path_hdr, sizeof(__be32));

        ds_put_cstr(ds, "\n");

        if (key->nsh_base.mdtype == NSH_M_TYPE1)
        {
            /* TODO: implement code */
        }
        else if (key->nsh_base.mdtype == NSH_M_TYPE2)
        {

            /* TODO: implement code */
        }
    }

}

void xdp_flow_key_format(struct ds *ds, struct xf_key *key)
{

    ds_put_format(ds, "valid=(%d)", key->valid);
    
    __u64 eth_src = u8_arr_to_u64(key->eth.eth_src, 6);
    __u64 eth_dst = u8_arr_to_u64(key->eth.eth_dst, 6);
    char src[100], dst[100];
    ether_ntoa_r((struct ether_addr *)&eth_src, src);
    ether_ntoa_r((struct ether_addr *)&eth_dst, dst);
    ds_put_format(ds, "eth_src=(%s), eth_dst=(%s) h_proto=0x%x, ",
                    src,
                    dst,
                    ntohs(key->eth.h_proto));

    if (ntohs(key->eth.h_proto) == ETH_P_IP)
    {
        void *src_ptr = &key->iph.ipv4_src;
        void *dst_ptr = &key->iph.ipv4_dst;
        char src_buf[INET_ADDRSTRLEN];
        char dst_buf[INET_ADDRSTRLEN];

        ds_put_format(ds, "ip_src=(%s), ip_dst=(%s), proto=%u, ",
                    inet_ntop(AF_INET, src_ptr, src_buf, sizeof(src_buf)),
                    inet_ntop(AF_INET, dst_ptr, dst_buf, sizeof(dst_buf)),
                    key->iph.ipv4_proto);
        
        /* Transport layer. */
        if (key->iph.ipv4_proto == IPPROTO_TCP)
        {
            ds_put_format(ds, "tcp_src=%u, tcp_dst=%u, ",
                           key->tcph.tcp_src,
                           key->tcph.tcp_dst);
        }
        else if (key->iph.ipv4_proto == IPPROTO_UDP)
        {
            ds_put_format(ds, "udp_src=%u, udp_dst=%u, ",
                           key->udph.udp_src,
                           key->udph.udp_dst);
        }
        else if (key->iph.ipv4_proto == IPPROTO_SCTP)
        {
            /* TODO: implement code */
        }
        else if (key->iph.ipv4_proto == IPPROTO_ICMP)
        {
            ds_put_format(ds, "icmp_code=%u, icmp_type=%u, ",
                           key->icmph.icmp_code,
                           key->icmph.icmp_type);
        }
    }
    else if (ntohs(key->eth.h_proto) == ETH_P_ARP || bpf_ntohs(key->eth.h_proto) == ETH_P_RARP)
    {

        __u64 arp_sha = u8_arr_to_u64(key->arph.arp_sha, ETH_ALEN);
        __u64 arp_tha = u8_arr_to_u64(key->arph.arp_tha, ETH_ALEN);
        char sha[100], arp[100];
        ether_ntoa_r((struct ether_addr *)&arp_sha, sha);
        ether_ntoa_r((struct ether_addr *)&arp_tha, arp);
        void *src_ptr = &key->arph.arp_sip;
        void *dst_ptr = &key->arph.arp_tip;
        char src_buf[INET_ADDRSTRLEN];
        char dst_buf[INET_ADDRSTRLEN];

        ds_put_format(ds, "arp_sha=(%s), arp_tha=(%s) arp_op=0x%x, arp_sip=(%s), arp_tip=(%s)",
                       sha,
                       arp,
                        ntohs(key->arph.ar_op), // TODO: fix this
                    //    0,
                       inet_ntop(AF_INET, src_ptr, src_buf, sizeof(src_buf)),
                       inet_ntop(AF_INET, dst_ptr, dst_buf, sizeof(dst_buf)));
    }
    else if (ntohs(key->eth.h_proto) == ETH_P_MPLS_MC || bpf_ntohs(key->eth.h_proto) == ETH_P_MPLS_UC)
    {

        /* TODO: implement code */
    }
    else if (ntohs(key->eth.h_proto) == ETH_P_IPV6)
    {
        void *src_ptr = &key->ipv6h.ipv6_src.addr_b64;
        void *dst_ptr = &key->ipv6h.ipv6_dst.addr_b64;
        char src_buf[INET6_ADDRSTRLEN];
        char dst_buf[INET6_ADDRSTRLEN];

        ds_put_format(ds, "ipv6_src=(%s), ipv6_dst=(%s), proto=%u, ipv6_tclass=%u ipv6_hlimit=%u, ipv6_frag=%u,",
                       inet_ntop(AF_INET6, src_ptr, src_buf, sizeof(src_buf)),
                       inet_ntop(AF_INET6, dst_ptr, dst_buf, sizeof(dst_buf)),
                       key->ipv6h.ipv6_proto,
                       key->ipv6h.ipv6_tclass,
                       key->ipv6h.ipv6_hlimit,
                       key->ipv6h.ipv6_frag);

        /* Transport layer. */
        if (key->ipv6h.ipv6_proto == IPPROTO_TCP)
        {
            ds_put_format(ds, "tcp_src=%u, tcp_dst=%u, ",
                           key->tcph.tcp_src,
                           key->tcph.tcp_dst);
        }
        else if (key->ipv6h.ipv6_proto == IPPROTO_UDP)
        {
            ds_put_format(ds, "udp_src=%u, udp_dst=%u, ",
                           key->udph.udp_src,
                           key->udph.udp_dst);
        }
        else if (key->ipv6h.ipv6_proto == IPPROTO_SCTP)
        {
            /* TODO: implement code */
        }
        else if (key->ipv6h.ipv6_proto == IPPROTO_ICMPV6)
        {
            ds_put_format(ds, "icmpv6_code=%u, icmpv6_type=%u",
                           key->icmp6h.icmpv6_code,
                           key->icmp6h.icmpv6_type);
        }
    }
    else if (ntohs(key->eth.h_proto) == ETH_P_NSH)
    {
        ds_put_format(ds, "mdtype=%u, flags=%x, ttl=%u, np=%u path_hdr=0x%08x,",
                       key->nsh_base.mdtype,
                       key->nsh_base.flags,
                       key->nsh_base.ttl,
                       key->nsh_base.np,
                       ntohl(key->nsh_base.path_hdr));

        if (key->nsh_base.mdtype == NSH_M_TYPE1)
        {
            /* TODO: implement code */
        }
        else if (key->nsh_base.mdtype == NSH_M_TYPE2)
        {

            /* TODO: implement code */
        }
    }

}

void xfa_buf_format(struct ds *ds, struct xfa_buf *act)
{
    ds_put_format(ds, "rx_packets=(%d), rx_bytes=(%d)",
                    act->stats.rx_packets,
                    act->stats.rx_bytes);
}

void xfu_stats_format(struct ds *ds, struct xfu_stats *stats)
{
    ds_put_format(ds, "rx_packets=(%d), rx_bytes=(%d)",
                    stats->rx_packets,
                    stats->rx_bytes);
}

int format_xdp_key(struct xdp_flow_key *key, char buf[])
{
    char level2[HDR_LVL_MAX];
    char level3[HDR_LVL_MAX];
    char level4[HDR_LVL_MAX];
    __u64 eth_src = u8_arr_to_u64(key->eth.eth_src, 6);
    __u64 eth_dst = u8_arr_to_u64(key->eth.eth_dst, 6);
    char src[100], dst[100];
    ether_ntoa_r((struct ether_addr *)&eth_src, src);
    ether_ntoa_r((struct ether_addr *)&eth_dst, dst);
    int len = snprintf(level2, HDR_LVL_MAX, "eth_src=(%s), eth_dst=(%s) h_proto=0x%x,",
                       src,
                       dst,
                       ntohs(key->eth.h_proto));

    if (len < 0)
    {
        return EINVAL;
    }
    else if (len >= HDR_LVL_MAX)
    {
        return ENAMETOOLONG;
    }

    if (ntohs(key->eth.h_proto) == ETH_P_IP)
    {
        void *src_ptr = &key->iph.ipv4_src;
        void *dst_ptr = &key->iph.ipv4_dst;
        char src_buf[INET_ADDRSTRLEN];
        char dst_buf[INET_ADDRSTRLEN];

        len = snprintf(level3, HDR_LVL_MAX, "ip_src=(%s), ip_dst=(%s), proto=%u,",
                       inet_ntop(AF_INET, src_ptr, src_buf, sizeof(src_buf)),
                       inet_ntop(AF_INET, dst_ptr, dst_buf, sizeof(dst_buf)),
                       key->iph.ipv4_proto);

        if (len < 0)
        {
            return EINVAL;
        }
        else if (len >= HDR_LVL_MAX)
        {
            return ENAMETOOLONG;
        }
        /* Transport layer. */
        if (key->iph.ipv4_proto == IPPROTO_TCP)
        {
            len = snprintf(level4, HDR_LVL_MAX, "tcp_src=%u, tcp_dst=%u",
                           key->tcph.tcp_src,
                           key->tcph.tcp_dst);
            if (len < 0)
            {
                return EINVAL;
            }
            else if (len >= HDR_LVL_MAX)
            {
                return ENAMETOOLONG;
            }
        }
        else if (key->iph.ipv4_proto == IPPROTO_UDP)
        {
            len = snprintf(level4, HDR_LVL_MAX, "udp_src=%u, udp_dst=%u",
                           key->udph.udp_src,
                           key->udph.udp_dst);
            if (len < 0)
            {
                return EINVAL;
            }
            else if (len >= HDR_LVL_MAX)
            {
                return ENAMETOOLONG;
            }
        }
        else if (key->iph.ipv4_proto == IPPROTO_SCTP)
        {
            /* TODO: implement code */
        }
        else if (key->iph.ipv4_proto == IPPROTO_ICMP)
        {
            len = snprintf(level4, HDR_LVL_MAX, "icmp_code=%u, icmp_type=%u",
                           key->icmph.icmp_code,
                           key->icmph.icmp_type);
            if (len < 0)
            {
                return EINVAL;
            }
            else if (len >= HDR_LVL_MAX)
            {
                return ENAMETOOLONG;
            }
        }
    }
    else if (ntohs(key->eth.h_proto) == ETH_P_ARP || bpf_ntohs(key->eth.h_proto) == ETH_P_RARP)
    {

        __u64 arp_sha = u8_arr_to_u64(key->arph.arp_sha, ETH_ALEN);
        __u64 arp_tha = u8_arr_to_u64(key->arph.arp_tha, ETH_ALEN);
        char sha[100], arp[100];
        ether_ntoa_r((struct ether_addr *)&arp_sha, sha);
        ether_ntoa_r((struct ether_addr *)&arp_tha, arp);
        void *src_ptr = &key->arph.arp_sip;
        void *dst_ptr = &key->arph.arp_tip;
        char src_buf[INET_ADDRSTRLEN];
        char dst_buf[INET_ADDRSTRLEN];

        len = snprintf(level3, HDR_LVL_MAX, "arp_sha=(%s), arp_tha=(%s) arp_op=0x%x, arp_sip=(%s), arp_tip=(%s)",
                       sha,
                       arp,
                       //    ntohs(key->arph.arp_op), TODO: fix this
                       0,
                       inet_ntop(AF_INET, src_ptr, src_buf, sizeof(src_buf)),
                       inet_ntop(AF_INET, dst_ptr, dst_buf, sizeof(dst_buf)));
        if (len < 0)
        {
            return EINVAL;
        }
        else if (len >= HDR_LVL_MAX)
        {
            return ENAMETOOLONG;
        }
    }
    else if (ntohs(key->eth.h_proto) == ETH_P_MPLS_MC || bpf_ntohs(key->eth.h_proto) == ETH_P_MPLS_UC)
    {

        /* TODO: implement code */
    }
    else if (ntohs(key->eth.h_proto) == ETH_P_IPV6)
    {
        void *src_ptr = &key->ipv6h.ipv6_src.addr_b64;
        void *dst_ptr = &key->ipv6h.ipv6_dst.addr_b64;
        char src_buf[INET6_ADDRSTRLEN];
        char dst_buf[INET6_ADDRSTRLEN];

        len = snprintf(level3, HDR_LVL_MAX, "ipv6_src=(%s), ipv6_dst=(%s), proto=%u, ipv6_tclass=%u ipv6_hlimit=%u, ipv6_frag=%u,",
                       inet_ntop(AF_INET6, src_ptr, src_buf, sizeof(src_buf)),
                       inet_ntop(AF_INET6, dst_ptr, dst_buf, sizeof(dst_buf)),
                       key->ipv6h.ipv6_proto,
                       key->ipv6h.ipv6_tclass,
                       key->ipv6h.ipv6_hlimit,
                       key->ipv6h.ipv6_frag);
        if (len < 0)
        {
            return EINVAL;
        }
        else if (len >= HDR_LVL_MAX)
        {
            return ENAMETOOLONG;
        }
        /* Transport layer. */
        if (key->ipv6h.ipv6_proto == IPPROTO_TCP)
        {
            len = snprintf(level4, HDR_LVL_MAX, "tcp_src=%u, tcp_dst=%u",
                           key->tcph.tcp_src,
                           key->tcph.tcp_dst);
            if (len < 0)
            {
                return EINVAL;
            }
            else if (len >= HDR_LVL_MAX)
            {
                return ENAMETOOLONG;
            }
        }
        else if (key->ipv6h.ipv6_proto == IPPROTO_UDP)
        {
            len = snprintf(level4, HDR_LVL_MAX, "udp_src=%u, udp_dst=%u",
                           key->udph.udp_src,
                           key->udph.udp_dst);
            if (len < 0)
            {
                return EINVAL;
            }
            else if (len >= HDR_LVL_MAX)
            {
                return ENAMETOOLONG;
            }
        }
        else if (key->ipv6h.ipv6_proto == IPPROTO_SCTP)
        {
            /* TODO: implement code */
        }
        else if (key->ipv6h.ipv6_proto == IPPROTO_ICMPV6)
        {
            len = snprintf(level4, HDR_LVL_MAX, "icmpv6_code=%u, icmpv6_type=%u",
                           key->icmp6h.icmpv6_code,
                           key->icmp6h.icmpv6_type);
            if (len < 0)
            {
                return EINVAL;
            }
            else if (len >= HDR_LVL_MAX)
            {
                return ENAMETOOLONG;
            }
        }
    }
    else if (ntohs(key->eth.h_proto) == ETH_P_NSH)
    {
        len = snprintf(level3, HDR_LVL_MAX, "mdtype=%u, flags=%x, ttl=%u, np=%u path_hdr=0x%08x,",
                       key->nsh_base.mdtype,
                       key->nsh_base.flags,
                       key->nsh_base.ttl,
                       key->nsh_base.np,
                       ntohl(key->nsh_base.path_hdr));

        if (len < 0)
        {
            return EINVAL;
        }
        else if (len >= HDR_LVL_MAX)
        {
            return ENAMETOOLONG;
        }
        if (key->nsh_base.mdtype == NSH_M_TYPE1)
        {
            /* TODO: implement code */
        }
        else if (key->nsh_base.mdtype == NSH_M_TYPE2)
        {

            /* TODO: implement code */
        }
    }

    len = snprintf(buf, HDR_MAX, "%s %s %s", level2, level3, level4);

    if (len < 0)
    {
        return EINVAL;
    }
    else if (len >= HDR_LVL_MAX)
    {
        return ENAMETOOLONG;
    }
    return 0;
}

int format_xdp_actions(const struct xdp_flow_actions *acts)
{
    printf("func %s, action len: %d\n", __func__, acts->len);
    int size = acts->len;
    int offset = 0;
    // int len = 0;

    __u8 *pos = (__u8 *) acts->data;
    while (offset < size) {
        struct xdp_flow_action *act = (struct xdp_flow_action *) pos;
        int i = act->type;
        __u32 data;
        memcpy(&data, act->data, sizeof(__u32));
        printf("len: %d, i: %d, type: %d, action type: %s, action length: %d, act->len: %d, act->data: %u \n", 
                size, i, act->type, xdp_action_attr_list[act->type].name , xdp_action_attr_list[act->type].len, act->len,
                (__u32)*act->data);
        offset += act->len;
        pos += offset;
    }

    return 0;
}

#endif /* XDP_USER_HELPERS_H */