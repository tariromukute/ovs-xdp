#ifndef XDP_FLOW_H
#define XDP_FLOW_H 1

#include <linux/bpf.h>
#include <crypt.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <bpf/bpf_endian.h>

enum xdp_packet_cmd {
    XDP_PACKET_CMD_UNSPEC,

    /* Kernel-to-user notifications. */
    XDP_PACKET_CMD_MISS,    /* Flow table miss. */
    XDP_PACKET_CMD_ACTION,  /* OVS_ACTION_ATTR_USERSPACE action. */

    /* Userspace commands. */
    XDP_PACKET_CMD_EXECUTE  /* Apply actions to a packet. */
};

enum proto_valid {
    ETHER_VALID = 1 << 0,
    MPLS_VALID = 1 << 1,
    IPV4_VALID = 1 << 2,
    IPV6_VALID = 1 << 3,
    ARP_VALID = 1 << 4,
    TCP_VALID = 1 << 5,
    UDP_VALID = 1 << 6,
    ICMP_VALID = 1 << 7,
    VLAN_VALID = 1 << 8,
    CVLAN_VALID = 1 << 9,
    ICMPV6_VALID = 1 << 10,
};

/* Keys */

struct xdp_key_ethernet {
    __u8     eth_src[6];
    __u8     eth_dst[6];
    __be16     h_proto;
};

struct xdp_key_mpls {
    __be32 mpls_lse;
};

struct xdp_key_ipv4 {
    __be32 ipv4_src;
    __be32 ipv4_dst;
    __u8   ipv4_proto;
    __u8   ipv4_tos;
    __u8   ipv4_ttl;
    __u8   ipv4_frag;    /* One of OVS_FRAG_TYPE_*. */
};

struct xdp_key_ipv6 {
    union {
        __be32 addr_b32[4];
        __be64 addr_b64[2];
    } ipv6_src;
    union {
        __be32 addr_b32[4];
        __be64 addr_b64[2];
    } ipv6_dst;
    // __be32 ipv6_label;    /* 20-bits in least-significant bits. */
    __u8   ipv6_proto;
    __u8   ipv6_tclass;
    __u8   ipv6_hlimit;
    __u8   ipv6_frag;    /* One of OVS_FRAG_TYPE_*. */
    // __be32 pad;
};

struct xdp_key_tcp {
    __be16 tcp_src;
    __be16 tcp_dst;
};

struct xdp_key_udp {
    __be16 udp_src;
    __be16 udp_dst;
};

struct xdp_key_sctp {
    __be16 sctp_src;
    __be16 sctp_dst;
};

struct xdp_key_icmp {
    __u8 icmp_type;
    __u8 icmp_code;
};

struct xdp_key_icmpv6 {
    __u8 icmpv6_type;
    __u8 icmpv6_code;
};

struct xdp_key_arp {
    __be32 arp_sip;
    __be32 arp_tip;
    __be16 ar_op;
    __u8   arp_sha[6];
    __u8   arp_tha[6];
};

struct xdp_key_nd {
    __be32    nd_target[4];
    __u8    nd_sll[6];
    __u8    nd_tll[6];
};

#define XDP_CT_LABELS_LEN_32    4
#define XDP_CT_LABELS_LEN    (XDP_CT_LABELS_LEN_32 * sizeof(__u32))
struct xdp_key_ct_labels {
    union {
        __u8    ct_labels[XDP_CT_LABELS_LEN];
        __u32    ct_labels_32[XDP_CT_LABELS_LEN_32];
    };
};

/* XDP_KEY_ATTR_CT_STATE flags */
#define XDP_CS_F_NEW               0x01 /* Beginning of a new connection. */
#define XDP_CS_F_ESTABLISHED       0x02 /* Part of an existing connection. */
#define XDP_CS_F_RELATED           0x04 /* Related to an establishXDPconnection. */
#define XDP_CS_F_REPLY_DIR         0x08 /* Flow is in the reply direction. */
#define XDP_CS_F_INVALID           0x10 /* Could not track connection. */
#define XDP_CS_F_TRACKED           0x20 /* Conntrack has occurred. */
#define XDP_CS_F_SRC_NAT           0x40 /* Packet's source address/port was mangled by NAT. */
#define XDP_CS_F_DST_NAT           0x80 /* Packet's destination address/port was mangled by NAT. */

#define XDP_CS_F_NAT_MASK (XDP_CS_F_SRC_NAT | XDP_CS_F_DST_NAT)

struct xdp_key_ct_tuple_ipv4 {
    __be32 ipv4_src;
    __be32 ipv4_dst;
    __be16 src_port;
    __be16 dst_port;
    __u8   ipv4_proto;
};

struct xdp_key_ct_tuple_ipv6 {
    __be32 ipv6_src[4];
    __be32 ipv6_dst[4];
    __be16 src_port;
    __be16 dst_port;
    __u8   ipv6_proto;
};

enum xdp_nsh_key_attr {
    XDP_NSH_KEY_ATTR_UNSPEC,
    XDP_NSH_KEY_ATTR_BASE,  /* struct ovs_nsh_key_base. */
    XDP_NSH_KEY_ATTR_MD1,   /* struct ovs_nsh_key_md1. */
    XDP_NSH_KEY_ATTR_MD2,   /* variable-length octets for MD type 2. */
    __XDP_NSH_KEY_ATTR_MAX
};

#define XDP_NSH_KEY_ATTR_MAX (__XDP_NSH_KEY_ATTR_MAX - 1)

struct xdp_key_nsh_base {
    __u8 flags;
    __u8 ttl;
    __u8 mdtype;
    __u8 np;
    __be32 path_hdr;
};

#define NSH_MD1_CONTEXT_SIZE 4

struct xdp_key_nsh_md1 {
    union {
        __be32 ctx_b32[NSH_MD1_CONTEXT_SIZE];
        __be64 ctx_b64[NSH_MD1_CONTEXT_SIZE / 2];
    } context;    
};

struct xdp_key_nsh_md2 {
    __be16 md_class;
    __u8 type;
};

enum xdp_key_attr {
    XDP_KEY_ATTR_UNSPEC,
    XDP_KEY_ATTR_ENCAP,    /* Nested set of encapsulated attributes. */
    XDP_KEY_ATTR_PRIORITY,  /* u32 skb->priority */
    XDP_KEY_ATTR_IN_PORT,   /* u32 OVS dp port number */
    XDP_KEY_ATTR_ETHERNET,  /* struct ovs_key_ethernet */
    XDP_KEY_ATTR_VLAN,    /* be16 VLAN TCI */
    XDP_KEY_ATTR_ETHERTYPE,    /* be16 Ethernet type */
    XDP_KEY_ATTR_IPV4,      /* struct ovs_key_ipv4 */
    XDP_KEY_ATTR_IPV6,      /* struct ovs_key_ipv6 */
    XDP_KEY_ATTR_TCP,       /* struct ovs_key_tcp */
    XDP_KEY_ATTR_UDP,       /* struct ovs_key_udp */
    XDP_KEY_ATTR_ICMP,      /* struct ovs_key_icmp */
    XDP_KEY_ATTR_ICMPV6,    /* struct ovs_key_icmpv6 */
    XDP_KEY_ATTR_ARP,       /* struct ovs_key_arp */
    XDP_KEY_ATTR_ND,        /* struct ovs_key_nd */
    XDP_KEY_ATTR_SKB_MARK,  /* u32 skb mark */
    XDP_KEY_ATTR_TUNNEL,    /* Nested set of ovs_tunnel attributes */
    XDP_KEY_ATTR_SCTP,      /* struct ovs_key_sctp */
    XDP_KEY_ATTR_TCP_FLAGS,    /* be16 TCP flags. */
    XDP_KEY_ATTR_DP_HASH,   /* u32 hash value. Value 0 indicates the hash
                   is not computed by the datapath. */
    XDP_KEY_ATTR_RECIRC_ID, /* u32 recirc id */
    XDP_KEY_ATTR_MPLS,      /* array of struct ovs_key_mpls.
                 * The implementation may restrict
                 * the accepted length of the array. */
    XDP_KEY_ATTR_CT_STATE,    /* u32 bitmask of OVS_CS_F_* */
    XDP_KEY_ATTR_CT_ZONE,    /* u16 connection tracking zone. */
    XDP_KEY_ATTR_CT_MARK,    /* u32 connection tracking mark */
    XDP_KEY_ATTR_CT_LABELS,    /* 16-octet connection tracking labels */
    XDP_KEY_ATTR_CT_ORIG_TUPLE_IPV4,   /* struct ovs_key_ct_tuple_ipv4 */
    XDP_KEY_ATTR_CT_ORIG_TUPLE_IPV6,   /* struct ovs_key_ct_tuple_ipv6 */
    XDP_KEY_ATTR_NSH,       /* Nested set of ovs_nsh_key_* */

#ifdef __KERNEL__
    /* Only used within kernel data path. */
    XDP_KEY_ATTR_TUNNEL_INFO,  /* struct ovs_tunnel_info */
#endif

#ifndef __KERNEL__
    /* Only used within userspace data path. */
    XDP_KEY_ATTR_PACKET_TYPE,  /* be32 packet type */
#endif

    __XDP_KEY_ATTR_MAX
};

/* Actions */

struct xdp_action_trunc {
    __u32 max_len; /* Max packet size in bytes. */
};

/**
 * struct ovs_action_push_mpls - %OVS_ACTION_ATTR_PUSH_MPLS action argument.
 * @mpls_lse: MPLS label stack entry to push.
 * @mpls_ethertype: Ethertype to set in the encapsulating ethernet frame.
 *
 * The only values @mpls_ethertype should ever be given are %ETH_P_MPLS_UC and
 * %ETH_P_MPLS_MC, indicating MPLS unicast or multicast. Other are rejected.
 */
struct xdp_action_push_mpls {
    __be32 mpls_lse;
    __be16 mpls_ethertype; /* Either %ETH_P_MPLS_UC or %ETH_P_MPLS_MC */
};

/**
 * struct ovs_action_push_vlan - %OVS_ACTION_ATTR_PUSH_VLAN action argument.
 * @vlan_tpid: Tag protocol identifier (TPID) to push.
 * @vlan_tci: Tag control identifier (TCI) to push.  The CFI bit must be set
 * (but it will not be set in the 802.1Q header that is pushed).
 *
 * The @vlan_tpid value is typically %ETH_P_8021Q or %ETH_P_8021AD.
 * The only acceptable TPID values are those that the kernel module also parses
 * as 802.1Q or 802.1AD headers, to prevent %OVS_ACTION_ATTR_PUSH_VLAN followed
 * by %OVS_ACTION_ATTR_POP_VLAN from having surprising results.
 */
struct xdp_action_push_vlan {
    __be16 vlan_tpid;    /* 802.1Q or 802.1ad TPID. */
    __be16 vlan_tci;    /* 802.1Q TCI (VLAN ID and priority). */
};

/* Data path hash algorithm for computing Datapath hash.
 *
 * The algorithm type only specifies the fields in a flow
 * will be used as part of the hash. Each datapath is free
 * to use its own hash algorithm. The hash value will be
 * opaque to the user space daemon.
 */
enum xdp_hash_alg {
    XDP_HASH_ALG_L4,
};

/*
 * struct xdp_action_hash - %OVS_ACTION_ATTR_HASH action argument.
 * @hash_alg: Algorithm used to compute hash prior to recirculation.
 * @hash_basis: basis used for computing hash.
 */
struct xdp_action_hash {
    __u32  hash_alg;     /* One of ovs_hash_alg. */
    __u32  hash_basis;
};

/*
 * struct xdp_action_push_eth - %OVS_ACTION_ATTR_PUSH_ETH action argument.
 * @addresses: Source and destination MAC addresses.
 * @eth_type: Ethernet type
 */
struct xdp_action_push_eth {
    struct xdp_key_ethernet addresses;
};

enum xdp_action_attr {
    XDP_ACTION_ATTR_UNSPEC,
    XDP_ACTION_ATTR_OUTPUT,          /* u32 port number. */
    XDP_ACTION_ATTR_USERSPACE,    /* Nested OVS_USERSPACE_ATTR_*. */
    XDP_ACTION_ATTR_SET,          /* One nested OVS_KEY_ATTR_*. */
    XDP_ACTION_ATTR_PUSH_VLAN,    /* struct ovs_action_push_vlan. */
    XDP_ACTION_ATTR_POP_VLAN,     /* No argument. */
    XDP_ACTION_ATTR_SAMPLE,       /* Nested OVS_SAMPLE_ATTR_*. */
    XDP_ACTION_ATTR_RECIRC,       /* u32 recirc_id. */
    XDP_ACTION_ATTR_HASH,          /* struct ovs_action_hash. */
    XDP_ACTION_ATTR_PUSH_MPLS,    /* struct ovs_action_push_mpls. */
    XDP_ACTION_ATTR_POP_MPLS,     /* __be16 ethertype. */
    XDP_ACTION_ATTR_SET_MASKED,   /* One nested OVS_KEY_ATTR_* including
                       * data immediately followed by a mask.
                       * The data must be zero for the unmasked
                       * bits. */
    XDP_ACTION_ATTR_CT,           /* Nested OVS_CT_ATTR_* . */
    XDP_ACTION_ATTR_TRUNC,        /* u32 struct ovs_action_trunc. */
    XDP_ACTION_ATTR_PUSH_ETH,     /* struct ovs_action_push_eth. */
    XDP_ACTION_ATTR_POP_ETH,      /* No argument. */
    XDP_ACTION_ATTR_CT_CLEAR,     /* No argument. */
    XDP_ACTION_ATTR_PUSH_NSH,     /* Nested OVS_NSH_KEY_ATTR_*. */
    XDP_ACTION_ATTR_POP_NSH,      /* No argument. */
    XDP_ACTION_ATTR_METER,        /* u32 meter ID. */
    XDP_ACTION_ATTR_CLONE,        /* Nested OVS_CLONE_ATTR_*.  */

    __XDP_ACTION_ATTR_MAX,          /* Nothing past this will be accepted
                       * from userspace. */

};

#define XDP_ACTION_ATTR_MAX (__XDP_ACTION_ATTR_MAX - 1)

#define XDP_ACTION_ATTR_UPCALL __XDP_ACTION_ATTR_MAX
#define TAIL_TABLE_SIZE XDP_ACTION_ATTR_UPCALL + 1

struct xdp_len_tbl {
    char *name;
    const struct xdp_len_tbl *next;
};

// static int
// odp_action_len(uint16_t type)
// {
//     if (type > OVS_ACTION_ATTR_MAX) {
//         return -1;
//     }

//     switch ((enum ovs_action_attr) type) {
//     case OVS_ACTION_ATTR_OUTPUT: return sizeof(uint32_t);
//     case OVS_ACTION_ATTR_TRUNC: return sizeof(struct ovs_action_trunc);
//     case OVS_ACTION_ATTR_TUNNEL_PUSH: return ATTR_LEN_VARIABLE;
//     case OVS_ACTION_ATTR_TUNNEL_POP: return sizeof(uint32_t);
//     case OVS_ACTION_ATTR_METER: return sizeof(uint32_t);
//     case OVS_ACTION_ATTR_USERSPACE: return ATTR_LEN_VARIABLE;
//     case OVS_ACTION_ATTR_PUSH_VLAN: return sizeof(struct ovs_action_push_vlan);
//     case OVS_ACTION_ATTR_POP_VLAN: return 0;
//     case OVS_ACTION_ATTR_PUSH_MPLS: return sizeof(struct ovs_action_push_mpls);
//     case OVS_ACTION_ATTR_POP_MPLS: return sizeof(ovs_be16);
//     case OVS_ACTION_ATTR_RECIRC: return sizeof(uint32_t);
//     case OVS_ACTION_ATTR_HASH: return sizeof(struct ovs_action_hash);
//     case OVS_ACTION_ATTR_SET: return ATTR_LEN_VARIABLE;
//     case OVS_ACTION_ATTR_SET_MASKED: return ATTR_LEN_VARIABLE;
//     case OVS_ACTION_ATTR_SAMPLE: return ATTR_LEN_VARIABLE;
//     case OVS_ACTION_ATTR_CT: return ATTR_LEN_VARIABLE;
//     case OVS_ACTION_ATTR_CT_CLEAR: return 0;
//     case OVS_ACTION_ATTR_PUSH_ETH: return sizeof(struct ovs_action_push_eth);
//     case OVS_ACTION_ATTR_POP_ETH: return 0;
//     case OVS_ACTION_ATTR_CLONE: return ATTR_LEN_VARIABLE;
//     case OVS_ACTION_ATTR_PUSH_NSH: return ATTR_LEN_VARIABLE;
//     case OVS_ACTION_ATTR_POP_NSH: return 0;

//     case OVS_ACTION_ATTR_UNSPEC:
//     case __OVS_ACTION_ATTR_MAX:
//         return ATTR_LEN_INVALID;
//     }

//     return ATTR_LEN_INVALID;
// }

static const struct xdp_len_tbl
xdp_action_attr_list[TAIL_TABLE_SIZE] = {
    [XDP_ACTION_ATTR_UNSPEC] = { .name = "OVS_ACTION_ATTR_UNSPEC"},
    [XDP_ACTION_ATTR_OUTPUT] =  { .name = "OVS_ACTION_ATTR_OUTPUT"},
    [XDP_ACTION_ATTR_USERSPACE] =  { .name = "OVS_ACTION_ATTR_USERSPACE"},
    [XDP_ACTION_ATTR_SET] = { .name = "OVS_ACTION_ATTR_SET"},
    [XDP_ACTION_ATTR_PUSH_VLAN] = { .name = "OVS_ACTION_ATTR_PUSH_VLAN"} ,
    [XDP_ACTION_ATTR_POP_VLAN] =  { .name = "OVS_ACTION_ATTR_POP_VLAN"},
    [XDP_ACTION_ATTR_SAMPLE] =  { .name = "OVS_ACTION_ATTR_SAMPLE"},
    [XDP_ACTION_ATTR_RECIRC] =  { .name = "OVS_ACTION_ATTR_RECIRC"},
    [XDP_ACTION_ATTR_HASH] =  { .name = "OVS_ACTION_ATTR_HASH"},
    [XDP_ACTION_ATTR_PUSH_MPLS] =  { .name = "OVS_ACTION_ATTR_PUSH_MPLS"},
    [XDP_ACTION_ATTR_POP_MPLS] = { .name = "OVS_ACTION_ATTR_POP_MPLS"} ,
    [XDP_ACTION_ATTR_SET_MASKED] =  { .name = "OVS_ACTION_ATTR_SET_MASKED"},
    [XDP_ACTION_ATTR_CT] = { .name = "OVS_ACTION_ATTR_CT"},
    [XDP_ACTION_ATTR_TRUNC] = { .name = "OVS_ACTION_ATTR_TRUNC"} ,
    [XDP_ACTION_ATTR_PUSH_ETH] =  { .name = "OVS_ACTION_ATTR_PUSH_ETH"},
    [XDP_ACTION_ATTR_POP_ETH] =  { .name = "OVS_ACTION_ATTR_POP_ETH"},
    [XDP_ACTION_ATTR_CT_CLEAR] =  { .name = "OVS_ACTION_ATTR_CT_CLEAR"},
    [XDP_ACTION_ATTR_PUSH_NSH] =  { .name = "OVS_ACTION_ATTR_PUSH_NSH"},
    [XDP_ACTION_ATTR_POP_NSH] =  { .name = "OVS_ACTION_ATTR_POP_NSH"},
    [XDP_ACTION_ATTR_METER] =  { .name = "OVS_ACTION_ATTR_METER"},
    [XDP_ACTION_ATTR_CLONE] =  { .name = "OVS_ACTION_ATTR_CLONE"},
    [XDP_ACTION_ATTR_UPCALL] = { .name = "OVS_ACTION_ATTR_UPCALL" }
};

/* NOTE: In modern compilers, data structures are aligned by default to access memory 
 * efficiently. Structure members are aligned to memory address that multiples their 
 * size, and padding is added for the proper alignment. Because of this, the size of 
 * struct may often grow larger than expected. 
 * 
 * The BPF verifier in the kernel checks the stack boundary that a BPF program does not
 * access outside of boundary or uninitialized stack area. Using struct with the padding
 * as a map value, will cause invalid indirect read from stack failure on bpf_prog_load().
 * ref: https://docs.cilium.io/en/v1.7/bpf/ 
 * 
 * Therefore for safe operations we are going to use buffers for storing and manipulating
 * these structs. The struct pointer will point to the buffer. The buffer will have a padded
 * size. Without this was getting some inconsistency when reading a point to a struct across
 * differnt functions WITHOUT the use of buffers. */
#define DIFF_LOWER_PAD(LEN, POW)         \
    (int)(LEN -  ((LEN >> POW) << POW))

#define DIFF_UPPER_PAD(LEN, POW)         \
    (int) ((1 << POW) - DIFF_LOWER_PAD(LEN, POW)) % (1 << POW)

#define PADDED_LEN_u64(LEN)             \
    (int) (LEN + DIFF_UPPER_PAD(LEN, 3))

#define PADDED_LEN_u32(LEN)             \
    (int) (LEN + DIFF_UPPER_PAD(LEN, 2))

#define PADDED_LEN_u16(LEN)             \
    (int) (LEN + DIFF_UPPER_PAD(LEN, 1))

struct xdp_flow_key {
    __u32 valid;
    struct xdp_key_ethernet eth;
    struct xdp_key_mpls mpls;
    union {
        struct xdp_key_ipv4 iph;
        struct xdp_key_ipv6 ipv6h;
        struct xdp_key_arp arph;
        struct xdp_key_nsh_base nsh_base;
    };
    union {
        struct xdp_key_tcp tcph;
        struct xdp_key_udp udph;
        struct xdp_key_icmp icmph;
        struct xdp_key_icmpv6 icmp6h;
        struct xdp_key_nsh_md1 nsh_md1;
        struct xdp_key_nsh_md2 nsh_md2;
    };
    struct vlan_hdr *vlanh;
};

#define XDP_FLOW_KEY_LEN_u64 PADDED_LEN_u64(sizeof(struct xdp_flow_key))

#define MAX_UFID_LENGTH 16 /* 128 bits */

struct xdp_flow_id {
    __u32 ufid_len;
    __u32 ufid[MAX_UFID_LENGTH / 4];
};

#define XDP_FLOW_ID_LEN_u64 PADDED_LEN_u64(sizeof(struct xdp_flow_id))

struct xdp_flow_stats {
    __u64 packet_count;        /* Number of packets matched. */
    __u64 byte_count;            /* Number of bytes matched. */
    unsigned long used;        /* Last used time (in jiffies). */
    __be16 tcp_flags;        /* Union of seen TCP flags. */
};

#define XDP_FLOW_STATS_LEN_u64 PADDED_LEN_u64(sizeof(struct xdp_flow_stats))

#define MAX_XDP_ACTION_SIZE 24 /* 128 bits */

struct xdp_flow_action {
    __u8 type; /* Determine the type of attr - enum ovs_action_attr*/
    __u8 len; /* len of the whole xdp_flow_action as a multiple of u8 */
    __u8 data[MAX_XDP_ACTION_SIZE]; /* contains the attr, where data points at the start*/
};

#define MAX_ACTION_SIZE (MAX_XDP_ACTION_SIZE) * 4 /* We consider the maximum number of actions that can be applied to single flow */

struct xdp_flow_actions {
    __u8 len;
    __u8 data[MAX_ACTION_SIZE];
};

#define XDP_FLOW_ACTIONS_LEN_u64 PADDED_LEN_u64(sizeof(struct xdp_flow_actions))

struct xdp_flow {
    struct xdp_flow_key key;
    // struct xdp_flow_id id;
    struct xdp_flow_stats stats;
    struct xdp_flow_actions actions;
};

#define XDP_FLOW_LEN_u64 PADDED_LEN_u64(sizeof(struct xdp_flow))

/* NOTE: Adding the actions to the metadata was resulting stack limit when trying
 * to copy data. The per-cpu array was being recommended for that so went with that
 * design instead. TODO maybe to check the performance difference of reading an array
 * vs getting data from the *ctx. If there is a significant difference then might 
 * consider redisigning e.g, trying to add the actions to the flow_metadata instead of
 * the key */
struct flow_metadata {
    __u8 type; // type of header, won't need this in current implentatiom it is always action attributes
    __u8 len; // length of the 
    __u8 pos; // the pos of the action attribute being processed
    __u8 offset; // Multiple of __u8 from the position of data
    struct xdp_flow_key key;
};

#define XDP_FLOW_METADATA_KEY_LEN_u64 PADDED_LEN_u64(sizeof(struct flow_metadata))

struct xdp_upcall {
    __u8 type;
    __u8 subtype;
    __u32 ifindex;
    __u32 pkt_len;
    struct xdp_flow_key key;  
    /* Follwed by pkt_len of packet data */
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
    return mac_proto == MAC_PROTO_ETHERNET ? 6 : 0;
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
void ovs_flow_stats_get(const struct xdp_flow *, struct xdp_flow_stats *,
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