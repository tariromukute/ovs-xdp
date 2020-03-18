#ifndef FLOW_H
#define FLOW_H 1

#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/if_arp.h>

#include "nsh.h"

struct pkt_metadata_t {
    u32 recirc_id; /* 32 bits */
    u32 dp_hash; /* 32 bits */
    u32 skb_priority; /* 32 bits */
    u32 pkt_mark; /* 32 bits */
    u16 ct_state; /* 16 bits */
    u16 ct_zone; /* 16 bits */
    u32 ct_mark; /* 32 bits */
    char ct_label[16]; /* 128 bits */
    u32 in_port; /* 32 bits ifindex */
};

struct vlan_hdr {
	__be16	h_vlan_TCI;
	__be16	h_vlan_encapsulated_proto;
};

struct xdp_flow_key {
    u32 valid;
    struct ethhdr eth;
    struct mpls mpls;
    union {
        struct iphdr iph;
        struct ipv6hdr ipv6h;
        struct arphdr arph;
        struct nshhdr nshh;
    };
    union {
        struct tcphdr tcph;
        struct udphdr udph;
        struct icmphdr icmph;
        struct icmpv6hdr icmpv6h;
    };
    struct vlan_hdr vlanh;
    struct pkt_metadata_t md;
};

#define MAX_UFID_LENGTH 16 /* 128 bits */

struct xdp_flow_id {
    u32 ufid_len;
    u32 ufid[MAX_UFID_LENGTH / 4];
};
#endif /* flow.h */