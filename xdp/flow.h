#ifndef XDP_FLOW_H
#define XDP_FLOW_H 1

#include <linux/bpf.h>
#include <linux/openvswitch.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <linux/mpls.h>
#include <crypt.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <net/if_arp.h>
#include "bpf_endian.h"
#include "nsh.h"

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

#define bpf_printk(fmt, ...)                                    \
({                                                              \
        char ____fmt[] = fmt;                                   \
        bpf_trace_printk(____fmt, sizeof(____fmt),              \
                         ##__VA_ARGS__);                        \
})

struct xdp_flow_key {
    __u32 valid;
    struct ethhdr eth;
    struct mpls_label mpls;
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
        struct icmp6hdr icmp6h;
    };
    struct vlan_hdr *vlanh;
    // struct pkt_metadata_t md;
};

#define MAX_UFID_LENGTH 16 /* 128 bits */

struct xdp_flow_id {
    __u32 ufid_len;
    __u32 ufid[MAX_UFID_LENGTH / 4];
};

struct xdp_flow_stats {
    __u64 packet_count;        /* Number of packets matched. */
    __u64 byte_count;            /* Number of bytes matched. */
    unsigned long used;        /* Last used time (in jiffies). */
    __be16 tcp_flags;        /* Union of seen TCP flags. */
};

#define MAX_OVS_ACTION_SIZE 24 /* 128 bits */

struct xdp_flow_action {
    __u8 type; /* Determine the type of attr - enum ovs_action_attr*/
    __u8 len; /* len of the whole xdp_flow_action as a multiple of u8 */
    __u8 data[MAX_OVS_ACTION_SIZE]; /* contains the attr, where data points at the start*/
};

#define MAX_ACTION_SIZE (MAX_OVS_ACTION_SIZE) * 4 /* We consider the maximum number of actions that can be applied to single flow */

struct xdp_flow_actions {
    __u8 len;
    __u8 data[MAX_ACTION_SIZE];
};

struct xdp_flow {
    struct xdp_flow_key key;
    // struct xdp_flow_id id;
    struct xdp_flow_stats stats;
    struct xdp_flow_actions actions;
};

/* NOTE: Adding the actions to the metadata was resulting stack limit when trying
 * to copy data. The per-cpu array was being recommended for that so went with that
 * design instead. TODO maybe to check the performance difference of reading an array
 * vs getting data from the *ctx. If there is a significant difference then might 
 * consider redisigning e.g, trying to add the actions to the flow_metadata instead of
 * the key*/
struct flow_metadata {
    __u8 type; // type of header, won't need this in current implentatiom it is always action attributes
    __u8 len; // length of the 
    __u8 pos; // the pos of the action attribute being processed
    __u8 offset; // Multiple of __u8 from the position of data
    struct xdp_flow_key key;
};

struct xdp_upcall {
    __u8 type;
    __u8 subtype;
    __u32 ifindex;
    __u32 pkt_len;
    struct xdp_flow_key key;  
    /* Follwed by pkt_len of packet data */
};

struct ovs_len_tbl {
    char *name;
    const struct ovs_len_tbl *next;
};

static const struct ovs_len_tbl
ovs_action_attr_list[OVS_ACTION_ATTR_MAX + 1] = {
    [OVS_ACTION_ATTR_UNSPEC] = { .name = "OVS_ACTION_ATTR_UNSPEC"},
    [OVS_ACTION_ATTR_OUTPUT] =  { .name = "OVS_ACTION_ATTR_OUTPUT"},
    [OVS_ACTION_ATTR_USERSPACE] =  { .name = "OVS_ACTION_ATTR_USERSPACE"},
    [OVS_ACTION_ATTR_SET] = { .name = "OVS_ACTION_ATTR_SET"},
    [OVS_ACTION_ATTR_PUSH_VLAN] = { .name = "OVS_ACTION_ATTR_PUSH_VLAN"} ,
    [OVS_ACTION_ATTR_POP_VLAN] =  { .name = "OVS_ACTION_ATTR_POP_VLAN"},
    [OVS_ACTION_ATTR_SAMPLE] =  { .name = "OVS_ACTION_ATTR_SAMPLE"},
    [OVS_ACTION_ATTR_RECIRC] =  { .name = "OVS_ACTION_ATTR_RECIRC"},
    [OVS_ACTION_ATTR_HASH] =  { .name = "OVS_ACTION_ATTR_HASH"},
    [OVS_ACTION_ATTR_PUSH_MPLS] =  { .name = "OVS_ACTION_ATTR_PUSH_MPLS"},
    [OVS_ACTION_ATTR_POP_MPLS] = { .name = "OVS_ACTION_ATTR_POP_MPLS"} ,
    [OVS_ACTION_ATTR_SET_MASKED] =  { .name = "OVS_ACTION_ATTR_SET_MASKED"},
    [OVS_ACTION_ATTR_CT] = { .name = "OVS_ACTION_ATTR_CT"},
    [OVS_ACTION_ATTR_TRUNC] = { .name = "OVS_ACTION_ATTR_TRUNC"} ,
    [OVS_ACTION_ATTR_PUSH_ETH] =  { .name = "OVS_ACTION_ATTR_PUSH_ETH"},
    [OVS_ACTION_ATTR_POP_ETH] =  { .name = "OVS_ACTION_ATTR_POP_ETH"},
    [OVS_ACTION_ATTR_CT_CLEAR] =  { .name = "OVS_ACTION_ATTR_CT_CLEAR"},
    [OVS_ACTION_ATTR_PUSH_NSH] =  { .name = "OVS_ACTION_ATTR_PUSH_NSH"},
    [OVS_ACTION_ATTR_POP_NSH] =  { .name = "OVS_ACTION_ATTR_POP_NSH"},
    [OVS_ACTION_ATTR_METER] =  { .name = "OVS_ACTION_ATTR_METER"},
    [OVS_ACTION_ATTR_CLONE] =  { .name = "OVS_ACTION_ATTR_CLONE"},
};

enum sw_flow_mac_proto {
    MAC_PROTO_NONE = 0,
    MAC_PROTO_ETHERNET,
};

#define XDP_FLOW_KEY_INVALID    0x80

static inline __u8 ovs_key_mac_proto(const struct xdp_flow_key *key)
{
    return key->eth.h_proto & ~XDP_FLOW_KEY_INVALID;
}

static inline __u16 __ovs_mac_header_len(__u8 mac_proto)
{
    return mac_proto == MAC_PROTO_ETHERNET ? ETH_HLEN : 0;
}

static inline __u16 ovs_mac_header_len(const struct xdp_flow_key *key)
{
    return __ovs_mac_header_len(ovs_key_mac_proto(key));
}

static inline bool ovs_identifier_is_ufid(const struct xdp_flow_id *sfid)
{
    return sfid->ufid_len;
}

static inline bool ovs_identifier_is_key(const struct xdp_flow_id *sfid)
{
    return !ovs_identifier_is_ufid(sfid);
}

void ovs_flow_stats_update(struct xdp_flow *, __be16 tcp_flags,
               const struct xdp_md *);
void ovs_flow_stats_get(const struct xdp_flow *, struct ovs_flow_stats *,
            unsigned long *used, __be16 *tcp_flags);
void ovs_flow_stats_clear(struct xdp_flow *);
__u64 ovs_flow_used_time(unsigned long flow_jiffies);

/* Update the non-metadata part of the flow key using ctx. */
int ovs_flow_key_update(struct xdp_md *ctx, struct xdp_flow_key *key);
// int ovs_flow_key_extract(const struct ip_tunnel_info *tun_info,
//              struct xdp_md *ctx,
//              struct xdp_flow_key *key);
// /* Extract key from packet coming from userspace. */
// int ovs_flow_key_extract_userspace(struct net *net, const struct nlattr *attr,
//                    struct xdp_md *ctx,
//                    struct xdp_flow_key *key, bool log);
#endif /* flow.h */