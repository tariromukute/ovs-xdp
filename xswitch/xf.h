/* This file contains the struct definition and util functions for managing xdp flows (xf)
 * and their actions.
 */

#ifndef XF_H
#define XF_H 1

#include <linux/bpf.h>
#include <crypt.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <bpf/bpf_endian.h>

/* Adding the new xf structs and functions */
#define XFA_MAX_SIZE 24 /* 128 bits */
#define XFA_BUF_MAX_NUM 4
#define XFA_BUF_MAX_SIZE (XFA_MAX_SIZE) * XFA_BUF_MAX_NUM

enum xs_packet_cmd {
    XS_PACKET_CMD_UNSPEC,

    /* Kernel-to-user notifications. */
    XS_PACKET_CMD_MISS,    /* Flow table miss. */
    XS_PACKET_CMD_ACTION,  /* OVS_ACTION_ATTR_USERSPACE action. */

    /* Userspace commands. */
    XS_PACKET_CMD_EXECUTE  /* Apply actions to a packet. */
};

// enum xs_proto_valid {
//     ETH_VALID = 1 << 0,
//     MPLS_VALID = 1 << 1,
//     IPV4_VALID = 1 << 2,
//     IPV6_VALID = 1 << 3,
//     ARP_VALID = 1 << 4,
//     TCP_VALID = 1 << 5,
//     UDP_VALID = 1 << 6,
//     SCTP_VALID = 1 << 7,
//     ICMP_VALID = 1 << 8,
//     VLAN_VALID = 1 << 9,
//     CVLAN_VALID = 1 << 10,
//     ICMPV6_VALID = 1 << 11,
//     NSH_BASE_VALID = 1 << 12,
//     NSH_MD1_VALID = 1 << 13,
//     NSH_MD2_VALID = 1 << 14
// };

/* Keys */

struct xf_key_ethernet {
    __u8     eth_src[6];
    __u8     eth_dst[6];
    __be16     h_proto;
};

struct xf_key_mpls {
    __be32 mpls_lse;
};

struct xf_key_ipv4 {
    __be32 ipv4_src;
    __be32 ipv4_dst;
    __u8   ipv4_proto;
    __u8   ipv4_tos;
    __u8   ipv4_ttl;
    __u8   ipv4_frag;    /* One of OVS_FRAG_TYPE_*. */
};

struct xf_key_ipv6 {
    union {
        __be32 addr_b32[4];
        __be64 addr_b64[2];
    } ipv6_src;
    union {
        __be32 addr_b32[4];
        __be64 addr_b64[2];
    } ipv6_dst;
    // __be32 ipv6_label;    /* 20-bits in least-significant bits. */ /* TODO: when you enable it enbale the odp_ functions too */
    __u8   ipv6_proto;
    __u8   ipv6_tclass;
    __u8   ipv6_hlimit;
    __u8   ipv6_frag;    /* One of OVS_FRAG_TYPE_*. */
    // __be32 pad;
};

struct xf_key_tcp {
    __be16 tcp_src;
    __be16 tcp_dst;
};

struct xf_key_udp {
    __be16 udp_src;
    __be16 udp_dst;
};

struct xf_key_sctp {
    __be16 sctp_src;
    __be16 sctp_dst;
};

struct xf_key_icmp {
    __u8 icmp_type;
    __u8 icmp_code;
};

struct xf_key_icmpv6 {
    __u8 icmpv6_type;
    __u8 icmpv6_code;
};

struct xf_key_arp {
    __be32 arp_sip;
    __be32 arp_tip;
    __be16 ar_op;
    __u8   arp_sha[6];
    __u8   arp_tha[6];
    __u8 pad[2];
};

struct xf_key_nd {
    __be32    nd_target[4];
    __u8    nd_sll[6];
    __u8    nd_tll[6];
};

#define XF_CT_LABELS_LEN_32    4
#define XF_CT_LABELS_LEN    (XF_CT_LABELS_LEN_32 * sizeof(__u32))
struct xf_key_ct_labels {
    union {
        __u8    ct_labels[XF_CT_LABELS_LEN];
        __u32    ct_labels_32[XF_CT_LABELS_LEN_32];
    };
};

/* XF_KEY_ATTR_CT_STATE flags */
#define XF_CS_F_NEW               0x01 /* Beginning of a new connection. */
#define XF_CS_F_ESTABLISHED       0x02 /* Part of an existing connection. */
#define XF_CS_F_RELATED           0x04 /* Related to an establishXDPconnection. */
#define XF_CS_F_REPLY_DIR         0x08 /* Flow is in the reply direction. */
#define XF_CS_F_INVALID           0x10 /* Could not track connection. */
#define XF_CS_F_TRACKED           0x20 /* Conntrack has occurred. */
#define XF_CS_F_SRC_NAT           0x40 /* Packet's source address/port was mangled by NAT. */
#define XF_CS_F_DST_NAT           0x80 /* Packet's destination address/port was mangled by NAT. */

#define XF_CS_F_NAT_MASK (XF_CS_F_SRC_NAT | XF_CS_F_DST_NAT)

struct xf_key_ct_tuple_ipv4 {
    __be32 ipv4_src;
    __be32 ipv4_dst;
    __be16 src_port;
    __be16 dst_port;
    __u8   ipv4_proto;
};

struct xf_key_ct_tuple_ipv6 {
    __be32 ipv6_src[4];
    __be32 ipv6_dst[4];
    __be16 src_port;
    __be16 dst_port;
    __u8   ipv6_proto;
};

enum xf_nsh_key_attr {
    XF_NSH_KEY_ATTR_UNSPEC,
    XF_NSH_KEY_ATTR_BASE,  /* struct ovs_nsh_key_base. */
    XF_NSH_KEY_ATTR_MD1,   /* struct ovs_nsh_key_md1. */
    XF_NSH_KEY_ATTR_MD2,   /* variable-length octets for MD type 2. */
    __XF_NSH_KEY_ATTR_MAX
};

#define XF_NSH_KEY_ATTR_MAX (__XF_NSH_KEY_ATTR_MAX - 1)

struct xf_key_nsh_base {
    __u8 flags;
    __u8 ttl;
    __u8 mdtype;
    __u8 np;
    __be32 path_hdr;
};

#define NSH_MD1_CONTEXT_SIZE 4

struct xf_key_nsh_md1 {
    union {
        __be32 ctx_b32[NSH_MD1_CONTEXT_SIZE];
        __be64 ctx_b64[NSH_MD1_CONTEXT_SIZE / 2];
    } context;    
};

struct xf_key_nsh_md2 {
    __be16 md_class;
    __u8 type;
};

enum xf_key_attr {
    XF_KEY_ATTR_UNSPEC,
    XF_KEY_ATTR_ENCAP,    /* Nested set of encapsulated attributes. */
    XF_KEY_ATTR_PRIORITY,  /* u32 skb->priority */
    XF_KEY_ATTR_IN_PORT,   /* u32 OVS dp port number */
    XF_KEY_ATTR_ETHERNET,  /* struct ovs_key_ethernet */
    XF_KEY_ATTR_VLAN,    /* be16 VLAN TCI */
    XF_KEY_ATTR_ETHERTYPE,    /* be16 Ethernet type */
    XF_KEY_ATTR_IPV4,      /* struct ovs_key_ipv4 */
    XF_KEY_ATTR_IPV6,      /* struct ovs_key_ipv6 */
    XF_KEY_ATTR_TCP,       /* struct ovs_key_tcp */
    XF_KEY_ATTR_UDP,       /* struct ovs_key_udp */
    XF_KEY_ATTR_ICMP,      /* struct ovs_key_icmp */
    XF_KEY_ATTR_ICMPV6,    /* struct ovs_key_icmpv6 */
    XF_KEY_ATTR_ARP,       /* struct ovs_key_arp */
    XF_KEY_ATTR_ND,        /* struct ovs_key_nd */
    XF_KEY_ATTR_SKB_MARK,  /* u32 skb mark */
    XF_KEY_ATTR_TUNNEL,    /* Nested set of ovs_tunnel attributes */
    XF_KEY_ATTR_SCTP,      /* struct ovs_key_sctp */
    XF_KEY_ATTR_TCP_FLAGS,    /* be16 TCP flags. */
    XF_KEY_ATTR_DP_HASH,   /* u32 hash value. Value 0 indicates the hash
                   is not computed by the datapath. */
    XF_KEY_ATTR_RECIRC_ID, /* u32 recirc id */
    XF_KEY_ATTR_MPLS,      /* array of struct ovs_key_mpls.
                 * The implementation may restrict
                 * the accepted length of the array. */
    XF_KEY_ATTR_CT_STATE,    /* u32 bitmask of OVS_CS_F_* */
    XF_KEY_ATTR_CT_ZONE,    /* u16 connection tracking zone. */
    XF_KEY_ATTR_CT_MARK,    /* u32 connection tracking mark */
    XF_KEY_ATTR_CT_LABELS,    /* 16-octet connection tracking labels */
    XF_KEY_ATTR_CT_ORIG_TUPLE_IPV4,   /* struct ovs_key_ct_tuple_ipv4 */
    XF_KEY_ATTR_CT_ORIG_TUPLE_IPV6,   /* struct ovs_key_ct_tuple_ipv6 */
    XF_KEY_ATTR_NSH,       /* Nested set of ovs_nsh_key_* */

#ifdef __KERNEL__
    /* Only used within kernel data path. */
    XF_KEY_ATTR_TUNNEL_INFO,  /* struct ovs_tunnel_info */
#endif

#ifndef __KERNEL__
    /* Only used within userspace data path. */
    XF_KEY_ATTR_PACKET_TYPE,  /* be32 packet type */
#endif

    __XF_KEY_ATTR_MAX
};

/* Actions */

struct xf_action_trunc {
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
struct xf_action_push_mpls {
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
struct xf_action_push_vlan {
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
enum xf_hash_alg {
    XF_HASH_ALG_L4,
};

/*
 * struct xf_action_hash - %OVS_ACTION_ATTR_HASH action argument.
 * @hash_alg: Algorithm used to compute hash prior to recirculation.
 * @hash_basis: basis used for computing hash.
 */
struct xf_action_hash {
    __u32  hash_alg;     /* One of ovs_hash_alg. */
    __u32  hash_basis;
};

/*
 * struct xf_action_push_eth - %OVS_ACTION_ATTR_PUSH_ETH action argument.
 * @addresses: Source and destination MAC addresses.
 * @eth_type: Ethernet type
 */
struct xf_action_push_eth {
    struct xf_key_ethernet addresses;
};

enum xf_action_attr {
    XF_ACTION_ATTR_UNSPEC,
    XF_ACTION_ATTR_OUTPUT,          /* u32 port number. */
    XF_ACTION_ATTR_USERSPACE,    /* Nested OVS_USERSPACE_ATTR_*. */
    XF_ACTION_ATTR_SET,          /* One nested OVS_KEY_ATTR_*. */
    XF_ACTION_ATTR_PUSH_VLAN,    /* struct ovs_action_push_vlan. */
    XF_ACTION_ATTR_POP_VLAN,     /* No argument. */
    XF_ACTION_ATTR_SAMPLE,       /* Nested OVS_SAMPLE_ATTR_*. */
    XF_ACTION_ATTR_RECIRC,       /* u32 recirc_id. */
    XF_ACTION_ATTR_HASH,          /* struct ovs_action_hash. */
    XF_ACTION_ATTR_PUSH_MPLS,    /* struct ovs_action_push_mpls. */
    XF_ACTION_ATTR_POP_MPLS,     /* __be16 ethertype. */
    XF_ACTION_ATTR_SET_MASKED,   /* One nested OVS_KEY_ATTR_* including
                       * data immediately followed by a mask.
                       * The data must be zero for the unmasked
                       * bits. */
    XF_ACTION_ATTR_CT,           /* Nested OVS_CT_ATTR_* . */
    XF_ACTION_ATTR_TRUNC,        /* u32 struct ovs_action_trunc. */
    XF_ACTION_ATTR_PUSH_ETH,     /* struct ovs_action_push_eth. */
    XF_ACTION_ATTR_POP_ETH,      /* No argument. */
    XF_ACTION_ATTR_CT_CLEAR,     /* No argument. */
    XF_ACTION_ATTR_PUSH_NSH,     /* Nested OVS_NSH_KEY_ATTR_*. */
    XF_ACTION_ATTR_POP_NSH,      /* No argument. */
    XF_ACTION_ATTR_METER,        /* u32 meter ID. */
    XF_ACTION_ATTR_CLONE,        /* Nested OVS_CLONE_ATTR_*.  */
    XF_ACTION_ATTR_DROP,
    __XF_ACTION_ATTR_MAX,          /* Nothing past this will be accepted
                       * from userspace. */

};

#define XF_ACTION_ATTR_MAX (__XF_ACTION_ATTR_MAX - 1)

#define XF_ACTION_ATTR_UPCALL __XF_ACTION_ATTR_MAX
#define XF_PROG_NUM XF_ACTION_ATTR_UPCALL + 1

struct xf_len_tbl {
    char *name;
    __u32 len;
    const struct xf_len_tbl *next;
};

#define INVALID_ATTR_LEN  -1
#define VARIABLE_ATTR_LEN -2
#define NESTED_ATTR_LEN   -3

static const struct xf_len_tbl
xf_action_attr_list[XF_PROG_NUM] = {
    [XF_ACTION_ATTR_UNSPEC] = { .name = "XF_ACTION_ATTR_UNSPEC", .len = INVALID_ATTR_LEN },
    [XF_ACTION_ATTR_OUTPUT] =  { .name = "XF_ACTION_ATTR_OUTPUT", .len = sizeof(__u32)},
    [XF_ACTION_ATTR_USERSPACE] =  { .name = "XF_ACTION_ATTR_USERSPACE", .len = VARIABLE_ATTR_LEN },
    [XF_ACTION_ATTR_SET] = { .name = "XF_ACTION_ATTR_SET", .len = VARIABLE_ATTR_LEN },
    [XF_ACTION_ATTR_PUSH_VLAN] = { .name = "XF_ACTION_ATTR_PUSH_VLAN", .len = sizeof(struct xf_action_push_vlan) } ,
    [XF_ACTION_ATTR_POP_VLAN] =  { .name = "XF_ACTION_ATTR_POP_VLAN", .len = 0 },
    [XF_ACTION_ATTR_SAMPLE] =  { .name = "XF_ACTION_ATTR_SAMPLE", .len = VARIABLE_ATTR_LEN },
    [XF_ACTION_ATTR_RECIRC] =  { .name = "XF_ACTION_ATTR_RECIRC", .len = sizeof(__u32) },
    [XF_ACTION_ATTR_HASH] =  { .name = "XF_ACTION_ATTR_HASH", .len = sizeof(struct xf_action_hash) },
    [XF_ACTION_ATTR_PUSH_MPLS] =  { .name = "XF_ACTION_ATTR_PUSH_MPLS", .len = sizeof(struct xf_action_push_mpls) },
    [XF_ACTION_ATTR_POP_MPLS] = { .name = "XF_ACTION_ATTR_POP_MPLS", .len = sizeof(__be16) } ,
    [XF_ACTION_ATTR_SET_MASKED] =  { .name = "XF_ACTION_ATTR_SET_MASKED", .len = VARIABLE_ATTR_LEN },
    [XF_ACTION_ATTR_CT] = { .name = "XF_ACTION_ATTR_CT", .len = VARIABLE_ATTR_LEN },
    [XF_ACTION_ATTR_TRUNC] = { .name = "XF_ACTION_ATTR_TRUNC", .len = sizeof(struct xf_action_trunc) } ,
    [XF_ACTION_ATTR_PUSH_ETH] =  { .name = "XF_ACTION_ATTR_PUSH_ETH", .len = sizeof(struct xf_action_push_eth) },
    [XF_ACTION_ATTR_POP_ETH] =  { .name = "XF_ACTION_ATTR_POP_ETH", .len = 0 },
    [XF_ACTION_ATTR_CT_CLEAR] =  { .name = "XF_ACTION_ATTR_CT_CLEAR", .len = 0 },
    [XF_ACTION_ATTR_PUSH_NSH] =  { .name = "XF_ACTION_ATTR_PUSH_NSH", .len = VARIABLE_ATTR_LEN },
    [XF_ACTION_ATTR_POP_NSH] =  { .name = "XF_ACTION_ATTR_POP_NSH", .len = 0 },
    [XF_ACTION_ATTR_METER] =  { .name = "XF_ACTION_ATTR_METER", .len = sizeof(__u32) },
    [XF_ACTION_ATTR_CLONE] =  { .name = "XF_ACTION_ATTR_CLONE", .len = VARIABLE_ATTR_LEN },
    [XF_ACTION_ATTR_DROP] = { .name = "XF_ACTION_ATTR_DROP", .len = 0 },
    [XF_ACTION_ATTR_UPCALL] = { .name = "XF_ACTION_ATTR_UPCALL", .len =  INVALID_ATTR_LEN }
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

struct xf_flow_key {
    __u32 valid;
    struct xf_key_ethernet eth;
    struct xf_key_mpls mpls;
    union {
        struct xf_key_ipv4 iph;
        struct xf_key_ipv6 ipv6h;
        struct xf_key_arp arph;
        struct xf_key_nsh_base nsh_base;
    };
    union {
        struct xf_key_tcp tcph;
        struct xf_key_udp udph;
        struct xf_key_icmp icmph;
        struct xf_key_icmpv6 icmp6h;
        struct xf_key_nsh_md1 nsh_md1;
        struct xf_key_nsh_md2 nsh_md2;
    };
    // struct vlan_hdr *vlanh;
};

#define XF_FLOW_KEY_LEN_u64 PADDED_LEN_u64(sizeof(struct xf_flow_key))

/* Define logs */
#define LOG_MSG_SIZE 96

enum log_level {
    ERR = 1 << 0,
    INFO = 1 << 1,
    WARN = 1 << 2,
    DEBUG = 1 << 3
};

// #define LOG_ERR 0x0101
// #define LOG_INFO 0x0102
// #define LOG_WARN 0x0103
// #define LOG_DEBUG 0x0104
enum logging_print_level {
    LOG_WARN,
    LOG_INFO,
    LOG_DEBUG,
    LOG_VERBOSE,
    LOG_ERR,
    LOG_XF_KEY,
    LOG_XF_ACT,
    LOG_PKT
};

#define LOG_EXTRACTED_KEY 0x1001
#define LOG_RETRIEVED_ACTION 0x1002
#define LOG_RECEIVED_PKT 0x1003
#define LOG_UPCALLED_PKT 0x1004
#define LOG_MICRO_MISS_KEY 0x1005
#define LOG_MACRO_MISS_KEY 0x1006

struct xf_key {
    __u32 valid;
    struct xf_key_ethernet eth;
    struct xf_key_mpls mpls;
    union {
        struct xf_key_ipv4 iph;
        struct xf_key_ipv6 ipv6h;
        struct xf_key_arp arph;
        struct xf_key_nsh_base nsh_base;
    };
    union {
        struct xf_key_tcp tcph;
        struct xf_key_udp udph;
        struct xf_key_icmp icmph;
        struct xf_key_icmpv6 icmp6h;
        struct xf_key_nsh_md1 nsh_md1;
        struct xf_key_nsh_md2 nsh_md2;
    };
};

/* xdp flow header */
struct xf_hdr {
    __u32 type;
    __u32 len;
} __attribute__((packed));

#define XF_HDR_LEN sizeof(struct xf_hdr)

/* xdp flow action */
struct xf_act {
    struct xf_hdr hdr;
    __u8 data[XFA_MAX_SIZE];
};

/* xdp flow action cursor for keeping track of the action being executed */
struct xfa_cursor {
    __u32 len;
    __u32 num;
    __u32 cnt;
    __u32 offset;
};

struct xfa_hdr {
    __u32 len;
    __u32 num;
};

struct xfa_cur {
    __u32 cnt;
    __u32 offset;
};

/* xdp flow actions buffer for storing the list of action for a given flow */
struct xfa_buf {
    struct xfa_hdr hdr;
    __u8 data[XFA_BUF_MAX_SIZE];
};

struct xf_upcall {
    __u32 type;
    __u32 subtype;
    __u32 ifindex;
    __u32 pkt_len;
    struct xf_key key;  
    /* Follwed by pkt_len of packet data */
};

struct xf {
    struct xf_key key;
    struct xfa_buf actions;
};

/* extracts and returns the type of action being pointed to by the cursor (current action) */
static __always_inline int xfa_type(struct xfa_buf *acts, struct xfa_cur *cursor)
{
    __u32 pos = 0;
    if (pos + cursor->offset > XFA_BUF_MAX_SIZE)
        return -1;

    pos += cursor->offset;

    // Point cursor to current action header
    if (pos + sizeof (struct xf_hdr) > XFA_BUF_MAX_SIZE) {
        return -1;
    }

    struct xf_hdr *hdr = (struct xf_hdr *) &acts->data[pos];

    return (int)hdr->type;
}

/* extracts the length of the action being pointed to by the cursor (current action) */
static __always_inline int xfa_len(struct xfa_buf *acts, struct xfa_cur *cursor)
{
    __u32 pos = 0;
    if (pos + cursor->offset > XFA_BUF_MAX_SIZE)
        return -1;

    pos += cursor->offset;

    // Point cursor to current action header
    if (pos + sizeof (struct xf_hdr) > XFA_BUF_MAX_SIZE) {
        return -1;
    }

    struct xf_hdr *hdr = (struct xf_hdr *) &acts->data[pos];

    return hdr->len;
}

/* extracts the action being pointed to by the cursor (current action) */
static __always_inline int xfa_data(struct xfa_buf *acts, struct xfa_cur *cursor, void *act, __u32 size)
{
    __u32 pos = 0;
    if (pos + cursor->offset > XFA_BUF_MAX_SIZE)
        return -1;

    pos += cursor->offset;

    // Point cursor to current action header
    if (pos + sizeof (struct xf_hdr) > XFA_BUF_MAX_SIZE) {
        return -1;
    }

    struct xf_hdr *hdr = (struct xf_hdr *) &acts->data[pos];

    // check if the length is the same as size of act ptr
    if (hdr->len != size)
        return -1;

    // bound check access to act
    if (pos + sizeof (struct xf_hdr) + size > XFA_BUF_MAX_SIZE)
        return -1;

    pos += sizeof (struct xf_hdr);
    // memcpy(act, &acts->data[pos], size);

    return hdr->type;
}

/* advances to the cursor to point to the next action extracts the type of action  
 * returns -1 when there is no next */
static __always_inline int xfa_next(struct xfa_buf *acts, struct xfa_cur *cursor)
{
    if (!acts)
        return -1;

    __u32 pos = 0;
    if (pos + cursor->offset > XFA_BUF_MAX_SIZE)
        return -1;

    pos += cursor->offset;

    

    // struct xf_hdr *hdr = (struct xf_hdr *) &acts->data[pos];
    // if (hdr + 1 > &acts->data[XFA_BUF_MAX_SIZE -1])
    //     return -1;
    struct xf_hdr hdr;
    memset(&hdr, 0, sizeof(hdr));

    // Point cursor to current action header
    if (pos + sizeof (hdr) > XFA_BUF_MAX_SIZE) {
        return -1;
    }
    memcpy(&hdr, acts->data, sizeof(hdr));
    // acts->cursor.offset += hdr->len;
    cursor->cnt += 1;

    int ret = hdr.type;
    return ret; 
}

/* advances the cursor to the next action and puts the action in the buf and
 * returns the type of the action. The initial call will advance the cursor to
 * the first action in the buffer */
static __always_inline int xfa_next_data(struct xfa_buf *acts, struct xfa_cur *cursor, struct xf_act *act)
{
    if (cursor->cnt >= acts->hdr.num)
        return 0;

    // struct xfa_buf *acts = data;
    __u32 index = 0;
    if (index + cursor->offset > XFA_BUF_MAX_SIZE)
        return -1;
    

    index += cursor->offset;

    // Point cursor to current action header
    if (index + sizeof(struct xf_act) > XFA_BUF_MAX_SIZE) {
        return -1;
    }

    memset(act, 0, sizeof(struct xf_act));
    memcpy(act, acts->data + index, sizeof(struct xf_act));

    cursor->offset += act->hdr.len;
    cursor->cnt += 1;

    return act->hdr.type; 
}

/* puts an action into the xdp actions buffer */
static __always_inline int xfa_put(struct xfa_buf *acts, __u32 type, struct xfa_cur *cursor, void *data, __u32 size)
{
    __u32 len = XF_HDR_LEN + size;

    __u32 pos = 0;
    if (pos + acts->hdr.len > XFA_BUF_MAX_SIZE)
        return -1;

    pos += acts->hdr.len;

    // Point cursor to current action header
    if (pos + len > XFA_BUF_MAX_SIZE) {
        return -1;
    }

    struct xf_act act;
    memset(&act, 0, sizeof(struct xf_act));
    act.hdr.type = type;
    act.hdr.len = len;

    if (size > XFA_MAX_SIZE)
        return -1;

    if (data) {
        memcpy(act.data, data, size);
    }

    memcpy(&acts->data[pos], &act, len);

    acts->hdr.len += len;
    acts->hdr.num += 1;
    
    return acts->hdr.num;
}

#endif /* XF_H: XDP FLOW*/