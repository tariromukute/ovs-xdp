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
#include <linux/mpls.h>
// #include <net/if_arp.h>
#include <linux/openvswitch.h>
#include <linux/bpf.h>
// #include <linux/jiffies.h>
#include <stdbool.h>
// #include <net/mpls.h>

#include "nsh.h"

enum sw_flow_mac_proto {
    MAC_PROTO_NONE = 0,
    MAC_PROTO_ETHERNET,
};

#define XDP_FLOW_KEY_INVALID    0x80

struct pkt_metadata_t {
    __u32 recirc_id; /* 32 bits */
    __u32 dp_hash; /* 32 bits */
    __u32 ctx_priority; /* 32 bits */
    __u32 pkt_mark; /* 32 bits */
    __u16 ct_state; /* 16 bits */
    __u16 ct_zone; /* 16 bits */
    __u32 ct_mark; /* 32 bits */
    char ct_label[16]; /* 128 bits */
    __u32 in_port; /* 32 bits ifindex */
};

struct vlan_hdr {
    __be16    h_vlan_TCI;
    __be16    h_vlan_encapsulated_proto;
};

struct xdp_flow_key {
    __u32 valid;
    struct ethhdr *eth;
    struct mpls *mpls;
    union {
        struct iphdr *iph;
        struct ipv6hdr *ipv6h;
        struct arphdr *arph;
        struct nshhdr *nshh;
    };
    union {
        struct tcphdr *tcph;
        struct udphdr *udph;
        struct icmphdr *icmph;
        struct icmpv6hdr *icmpv6h;
    };
    struct vlan_hdr *vlanh;
    struct pkt_metadata_t *md;
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

#define MAX_OVS_ACTION_SIZE 16 /* 128 bits */

struct xdp_flow_action {
    enum ovs_action_attr type; /* Determine the type of attr */
    __u8 act_data[MAX_OVS_ACTION_SIZE]; /* Contains the data*/
};

#define MAX_ACTION_SIZE (MAX_OVS_ACTION_SIZE/4) * 4 /* We consider the maximum number of actions that can be applied to single flow */

struct xdp_flow_actions {
    __u16 len;
    __u64 data[MAX_ACTION_SIZE];
};

struct xdp_flow {
    struct xdp_flow_key key;
    struct xdp_flow_id id;
    struct xdp_flow_actions actions;
    struct xdp_flow_stats stats;
};

static inline __u8 ovs_key_mac_proto(const struct xdp_flow_key *key)
{
    return key->eth->h_proto & ~XDP_FLOW_KEY_INVALID;
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