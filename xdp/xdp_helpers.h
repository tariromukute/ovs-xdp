#ifndef XDP_HELPERS_H
#define XDP_HELPERS_H

#include <stddef.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <bpf/bpf_endian.h>

/* Header cursor to keep track of current parsing position */
struct hdr_cursor {
	void *pos;
};

/*
 * 	struct vlan_hdr - vlan header
 * 	@h_vlan_TCI: priority and VLAN ID
 *	@h_vlan_encapsulated_proto: packet type ID or len
 */
struct vlan_hdr {
	__be16	h_vlan_TCI;
	__be16	h_vlan_encapsulated_proto;
};

/*
 * Struct icmphdr_common represents the common part of the icmphdr and icmp6hdr
 * structures.
 */
struct icmphdr_common {
	__u8		type;
	__u8		code;
	__sum16		cksum;
};

struct arp_ethhdr {
	__be16      ar_hrd;	/* format of hardware address   */
	__be16      ar_pro;	/* format of protocol address   */
	__u8        ar_hln;	/* length of hardware address   */
	__u8        ar_pln;	/* length of protocol address   */
	__be16      ar_op;	/* ARP opcode (command)     */

	/* Ethernet+IPv4 specific members. */
	__u8       ar_sha[ETH_ALEN];	/* sender hardware address  */
	__be32              ar_sip;		/* sender IP address        */
	__u8       ar_tha[ETH_ALEN];	/* target hardware address  */
	__be32              ar_tip;		/* target IP address        */
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

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

#define bpf_printk(fmt, ...)                       \
    ({                                             \
        char ____fmt[] = fmt;                      \
        bpf_trace_printk(____fmt, sizeof(____fmt), \
                         ##__VA_ARGS__);           \
    })

static inline __u64 ether_addr_to_u64(const __u8 *addr)
{
    __u64 u = 0;
    int i;
    for (i = ETH_ALEN; i >= 0; i--) {
        u = u << 8 | addr[i];
    }
    return u;
}

static inline __u64 u8_arr_to_u64(const __u8 *addr, const int size)
{
    __u64 u = 0;
    int i;
    for (i = size; i >= 0; i--) {
        u = u << 8 | addr[i];
    }
    return u;
}

static inline __u32 u8_arr_to_u32(const __u8 *addr, const int size)
{
    __u32 u = 0;
    int i;
    for (i = size; i >= 0; i--) {
        u = u << 8 | addr[i];
    }
    return u;
}

static void __always_inline log_flow_key(struct xdp_flow_key *key)
{
    bpf_printk("line: xdp_key_ethernet: eth_src: %llu, eth_dst: %llu, h_proto: %u :line\n",
               u8_arr_to_u64(key->eth.eth_src, ETH_ALEN),
               u8_arr_to_u64(key->eth.eth_dst, ETH_ALEN),
               bpf_ntohs(key->eth.h_proto));
    if (bpf_ntohs(key->eth.h_proto) == ETH_P_IP)
    {
        bpf_printk("line: xdp_key_ipv4: ipv4_src: %lu, ipv4_dst: %lu, h_proto: %u :line\n",
                   key->iph.ipv4_src,
                   key->iph.ipv4_dst,
                   key->iph.ipv4_proto);
        /* Transport layer. */
        if (key->iph.ipv4_proto == IPPROTO_TCP)
        {
            bpf_printk("line: xdp_key_tcp: tcp_src: %u tcp_dst: %u :line\n",
                   key->tcph.tcp_src,
                   key->tcph.tcp_dst);
        }
        else if (key->iph.ipv4_proto == IPPROTO_UDP)
        {
            bpf_printk("line: xdp_key_udp: udp_src: %u udp_dst: %u :line\n",
                   key->udph.udp_src,
                   key->udph.udp_dst);
        }
        else if (key->iph.ipv4_proto == IPPROTO_SCTP)
        {
            /* TODO: implement code */
        }
        else if (key->iph.ipv4_proto == IPPROTO_ICMP)
        {
            bpf_printk("line: xdp_key_icmp: icmp_code: %u icmp_type: %u :line\n",
                   key->icmph.icmp_code,
                   key->icmph.icmp_type);
        }
    }
    else if (bpf_ntohs(key->eth.h_proto) == ETH_P_ARP || bpf_ntohs(key->eth.h_proto) == ETH_P_RARP)
    {
        bpf_printk("line: xdp_key_arp: arp_sha: %llu arp_tha: %llu arp_op: %u \n",
                    u8_arr_to_u64(key->arph.arp_sha, ETH_ALEN),
                    u8_arr_to_u64(key->arph.arp_tha, ETH_ALEN),
                    bpf_ntohs(key->arph.arp_op));

        bpf_printk("xdp_key_arp: arp_sip: %lu arp_tip: %lu :line\n",
                    key->arph.arp_sip,
                    key->arph.arp_tip);
        /* TODO: implement code */
    }
    else if (bpf_ntohs(key->eth.h_proto) == ETH_P_MPLS_MC || bpf_ntohs(key->eth.h_proto) == ETH_P_MPLS_UC)
    {

        /* TODO: implement code */
    }
    else if (bpf_ntohs(key->eth.h_proto) == ETH_P_IPV6)
    {
        /* TODO: implement code */
        bpf_printk("line: xdp_key_ipv6: ipv6_src: %llu-%llu\n",
                   key->ipv6h.ipv6_src.addr_b64[0],
                   key->ipv6h.ipv6_src.addr_b64[1]);
        bpf_printk("xdp_key_ipv6: ipv6_dst: %llu-%llu ipv6_proto: %u\n",
                   key->ipv6h.ipv6_dst.addr_b64[0],
                   key->ipv6h.ipv6_dst.addr_b64[1],
                   key->ipv6h.ipv6_proto);
        bpf_printk("xdp_key_ipv6: ipv6_tclass: %u ipv6_hlimit: %u ipv6_frag: %u :line\n",
                   key->ipv6h.ipv6_tclass,
                   key->ipv6h.ipv6_hlimit,
                   key->ipv6h.ipv6_frag);

        /* Transport layer. */
        if (key->ipv6h.ipv6_proto == IPPROTO_TCP)
        {
            bpf_printk("line: xdp_key_tcp: tcp_src: %u tcp_dst: %u :line\n",
                   key->tcph.tcp_src,
                   key->tcph.tcp_dst);
        }
        else if (key->ipv6h.ipv6_proto == IPPROTO_UDP)
        {
            bpf_printk("line: xdp_key_udp: udp_src: %u udp_dst: %u :line\n",
                   key->udph.udp_src,
                   key->udph.udp_dst);
        }
        else if (key->ipv6h.ipv6_proto == IPPROTO_SCTP)
        {
            /* TODO: implement code */
        }
        else if (key->ipv6h.ipv6_proto == IPPROTO_ICMPV6)
        {
            bpf_printk("line: xdp_key_icmpv6: icmpv6_code: %u icmpv6_type: %u :line\n",
                   key->icmp6h.icmpv6_code,
                   key->icmp6h.icmpv6_type);
        }
    }
    else if (bpf_ntohs(key->eth.h_proto) == ETH_P_NSH)
    {
        bpf_printk("line: xdp_key_nsh_base: mdtype: %u flags: %u ttl: %u \n",
                   key->nsh_base.mdtype,
                   key->nsh_base.flags,
                   key->nsh_base.ttl);

        bpf_printk("xdp_key_nsh_base: np: %u path_hdr: %u :line\n",
                   key->nsh_base.np,
                   bpf_ntohl(key->nsh_base.path_hdr));

        if (key->nsh_base.mdtype == NSH_M_TYPE1)
        {
            bpf_printk("line: xdp_key_nsh_md1: context: %llu-%llu :line\n",
                   key->nsh_md1.context.ctx_b64[0],
                   key->nsh_md1.context.ctx_b64[1]);
        }
        else if (key->nsh_base.mdtype == NSH_M_TYPE2)
        {

            /* TODO: implement code */
        }
    }
}
    
#endif /* XDP_HELPERS_H */