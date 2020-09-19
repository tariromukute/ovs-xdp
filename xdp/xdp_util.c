#include "xdp_util.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <netinet/ether.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "flow.h"

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

static int format_xdp_key(struct xdp_flow_key *key, char buf[])
{
    char level2[HDR_LVL_MAX];
    char level3[HDR_LVL_MAX];
    char level4[HDR_LVL_MAX];
    __u64 eth_src = u8_arr_to_u64(key->eth.eth_src, 6);
    __u64 eth_dst = u8_arr_to_u64(key->eth.eth_dst, 6);
    int len = snprintf(level2, HDR_LVL_MAX, "eth_src=(%s), eth_dst=(%s) h_proto=0x%x,",
                       ether_ntoa((struct ether_addr *)&eth_src),
                       ether_ntoa((struct ether_addr *)&eth_dst),
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
        void *src_ptr = &key->arph.arp_sip;
        void *dst_ptr = &key->arph.arp_tip;
        char src_buf[INET_ADDRSTRLEN];
        char dst_buf[INET_ADDRSTRLEN];

        len = snprintf(level3, HDR_LVL_MAX, "arp_sha=(%s), arp_tha=(%s) arp_op=0x%x, arp_sip=(%s), arp_tip=(%s)",
                       ether_ntoa((struct ether_addr *)&arp_sha),
                       ether_ntoa((struct ether_addr *)&arp_tha),
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

static int format_xdp_actions(struct xdp_flow_actions *acts)
{
    printf("func %s, action len: %d\n", __func__, acts->len);
    int size = acts->len;
    int offset = 0;
    // int len = 0;

    __u8 *pos = acts->data;
    while (offset < size) {
        struct xdp_flow_action *act = (struct xdp_flow_action *) pos;
        int i = act->type;
        printf("len: %d, i: %d, type: %d, action type: %s, action length: %d \n", size, i, act->type, xdp_action_attr_list[act->type].name , xdp_action_attr_list[act->type].len);
        offset += act->len;
        pos += offset;
    }

    return 0;
}

void xdp_flow_format(struct *xdp_flow, struct ds *ds)
{

}