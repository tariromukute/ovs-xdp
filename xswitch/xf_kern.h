/**
 * This files contains the struct definitions, BTF maps definitions and functions 
 * to be used in the xdp kern programs. The functions are marked as __always_inline, 
 * and fully defined in this header file to be included in the BPF program.
 *
 * The functions include bound checking and the maps use BTF definition approach
 */

#ifndef XDP_KERN_HEADERS_H
#define XDP_KERN_HEADERS_H 1

#include <linux/bpf.h>
#include <linux/in.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/netdevice.h>
#include "flow.h"
#include "xf.h"
#include "parsing_helpers.h"
#include "parsing_xf_key_helpers.h"

#define SAMPLE_SIZE 64ul
#define MAX_CPUS 128

#define bpf_printk(fmt, ...)                                    \
({                                                              \
        char ____fmt[] = fmt;                                   \
        bpf_trace_printk(____fmt, sizeof(____fmt),              \
                         ##__VA_ARGS__);                        \
})

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

#ifndef MIN
#define MIN(X, Y) ((X) < (Y) ? (X) : (Y))
#endif

#ifndef MAX
#define MAX(X, Y) ((X) > (Y) ? (X) : (Y))
#endif

/* map #0 */
struct micro_flow_map {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct xf_key));
    __uint(value_size, sizeof(struct xfa_buf));
    __uint(max_entries, 100);
    // __uint(pinning, LIBBPF_PIN_BY_NAME);
} xf_micro_map SEC(".maps");

/* map #1 */
// struct macro_flow_map {
//     __uint(type, BPF_MAP_TYPE_HASH);
//     __type(key, struct xf_key);
//     __type(value, struct xfa_buf);
//     __uint(max_entries, 100);
//     __uint(pinning, LIBBPF_PIN_BY_NAME);
// } _xf_macro_map SEC(".maps");

struct macro_flow_map {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct xf_key));
    __uint(value_size, sizeof(struct xfa_buf));
    __uint(max_entries, 100);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} _xf_macro_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct xfa_buf));
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} _xfa_buf_map SEC(".maps");

/* map #2 */
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, XDP_ACTION_ATTR_MAX);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} xf_tail_map SEC(".maps");

/* NOTE: loading a xdp program for afxdp depends on the map being
 * named 'xsks_map' */
/* map #3 */
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
    __uint(max_entries, 128);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} xsks_map SEC(".maps");

/* map #4 */
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, MAX_CPUS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} _perf_map SEC(".maps");

/* map #4 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(max_entries, 64);
    __uint(key_size, IFNAMSIZ);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __array(values, struct micro_flow_map);
} bridge SEC(".maps");

/* Note: High values of max_entries are resulting in program load error: 'Program too big' 
 * Trying to pin the map so that it's shared is also resulting in load time error. So for
 * now restricted to redirecting to fewer ifindex with values less than 64. */
/* TODO: Checking on how we can increase the max_entries or support map sharing */
struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
    __uint(max_entries, 128);
    // __uint(pinning, LIBBPF_PIN_BY_NAME);
} tx_port SEC(".maps");

static __always_inline int xfk_extract(struct hdr_cursor *nh, void *data_end, struct xf_key *key)
{
    int nh_type;
    struct xf_key_ethernet *eth;
    nh_type = parse_xf_key_ethhdr(nh, data_end, &eth);
    if (nh_type < 0)
    {
        goto out;
    }
    key->valid |= ETH_VALID;

    memcpy(&key->eth, eth, sizeof(key->eth));
    if (nh_type == ETH_P_IP)
    {
        struct xf_key_ipv4 iph;
        memset(&iph, 0, sizeof(struct xf_key_ipv4));
        nh_type = parse_xf_key_iphdr(nh, data_end, &iph);
        if (nh_type < 0)
        {
            goto out;
        }
        memcpy(&key->iph, &iph, sizeof(struct xf_key_ipv4));
        key->valid |= IPV4_VALID;

        /* Transport layer. */
        if (nh_type == IPPROTO_TCP)
        {
            struct xf_key_tcp *tcph;
            nh_type = parse_xf_key_tcphdr(nh, data_end, &tcph);
            if (nh_type < 0)
            {
                goto out;
            }

            
            memcpy(&key->tcph, tcph, sizeof(struct xf_key_tcp));
            key->valid |= TCP_VALID;

        }
        else if (nh_type == IPPROTO_UDP)
        {
            struct xf_key_udp *udph;
            nh_type = parse_xf_key_udphdr(nh, data_end, &udph);
            if (nh_type < 0)
            {
                goto out;
            }

            memcpy(&key->udph, udph, sizeof(struct xf_key_udp));
            key->valid |= UDP_VALID;
        }
        else if (nh_type == IPPROTO_SCTP)
        {
            /* TODO: implement code */
            // key->valid |= MPLS_VALID;
        }
        else if (nh_type == IPPROTO_ICMP)
        {
            struct xf_key_icmp *icmph;
            nh_type = parse_xf_key_icmphdr(nh, data_end, &icmph);
            if (nh_type < 0)
            {
                goto out;
            }
            memcpy(&key->icmph, icmph, sizeof(struct xf_key_icmp));
            key->valid |= ICMP_VALID;
        }
    }
    else if (nh_type == ETH_P_ARP || nh_type == ETH_P_RARP)
    {
        struct xf_key_arp *arph;
        nh_type = parse_xf_key_arp(nh, data_end, &arph);
        if (nh_type < 0)
        {
            goto out;
        }
        
        // memcpy(&key->arph, arph, sizeof(struct xf_key_arp));

        key->valid |= ARP_VALID;
    }
    else if (nh_type == ETH_P_MPLS_MC || nh_type == ETH_P_MPLS_UC)
    {

        /* TODO: implement code */
        // key->valid |= MPLS_VALID;
    }
    else if (nh_type == ETH_P_IPV6)
    {
        struct xf_key_ipv6 ip6h;
        memset(&ip6h, 0, sizeof(struct xf_key_ipv6));
        nh_type = parse_xf_key_ip6hdr(nh, data_end, &ip6h);
        if (nh_type < 0)
        {
            goto out;
        }

        memcpy(&key->ipv6h, &ip6h, sizeof(struct xf_key_ipv6));
        key->valid |= IPV6_VALID;

        /* Transport layer. */
        if (nh_type == IPPROTO_TCP)
        {
            struct xf_key_tcp *tcph;
            nh_type = parse_xf_key_tcphdr(nh, data_end, &tcph);
            if (nh_type < 0)
            {
                goto out;
            }

            // memcpy(&key->tcph, tcph, sizeof(struct xf_key_tcp)); // TODO: emiting this for now
            // key->valid |= TCP_VALID;
        }
        else if (nh_type == IPPROTO_UDP)
        {
            struct xf_key_udp *udph;
            nh_type = parse_xf_key_udphdr(nh, data_end, &udph);
            if (nh_type < 0)
            {
                goto out;
            }

            // memcpy(&key->udph, udph, sizeof(struct xf_key_udp)); // TODO: emiting this for now
            // key->valid |= UDP_VALID;
        }
        else if (nh_type == IPPROTO_SCTP)
        {
            /* TODO: implement code */
        }
        else if (nh_type == IPPROTO_ICMPV6)
        {
            struct xf_key_icmpv6 *icmp6h;
            nh_type = parse_xf_key_icmp6hdr(nh, data_end, &icmp6h);
            if (nh_type < 0)
            {
                goto out;
            }

            memcpy(&key->icmp6h, icmp6h, sizeof(struct xf_key_icmpv6));
            key->valid |= ICMPV6_VALID;
        }
    }
    else if (nh_type == ETH_P_NSH)
    {
        struct xf_key_nsh_base *nshh;
        nh_type = parse_xf_key_nsh_base(nh, data_end, &nshh);
        if (nh_type < 0)
        {
            goto out;
        }


        memcpy(&key->nsh_base, nshh, sizeof(struct xf_key_nsh_base));
        key->nsh_base.flags = nsh_get_flags((struct nshhdr *)nshh);
        key->nsh_base.ttl = nsh_get_ttl((struct nshhdr *)nshh);
        key->valid |= NSH_BASE_VALID;

        if (nshh->mdtype == NSH_M_TYPE1)
        {
            struct xf_key_nsh_md1 *md1h;
            nh_type = parse_xf_key_nsh_md1(nh, data_end, &md1h);
            if (nh_type < 0)
            {
                goto out;
            }

            memcpy(&key->nsh_md1, md1h, sizeof(struct xf_key_nsh_md1));
            key->valid |= NSH_MD1_VALID;
        }
        else if (nh_type != NSH_BASE_HDR_LEN && nshh->mdtype == NSH_M_TYPE1)
        {
            // struct xf_key_nsh_md2 *md2h;
            // nh_type = parse_xf_key_nsh_md2(nh, data_end, &md2h);
            // if (nh_type < 0)
            // {
            //     goto out;
            // }

            // memcpy(&key->nsh_md2, md2h, sizeof(struct xf_key_nsh_md2));
            // key->valid |= NSH_MD2_VALID;
        }
    }
    return 0;
out:
    return -1;
}

__u8 log_level = LOG_ERR;

/* Metadata will be in the perf event before the packet data. */
struct S {
    __u16 cookie;
    __u16 pkt_len;
    __u16 data_len; // the length of the data
    __u8 data[XFA_BUF_MAX_SIZE]; // the data being sent via perf
} __attribute__((packed));

static __always_inline int logger(struct xdp_md *ctx, __u16 log_type,
                                void *metadata, __u32 size)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    if (data_end > data) {
        struct S log;
        memset(&log, 0, sizeof(log));
        int data_len = (__u16)MIN(size, sizeof(log.data));
        /* The XDP perf_event_output handler will use the upper 32 bits
            * of the flags argument as a number of bytes to include of the
            * packet payload in the event data. If the size is too big, the
            * call to bpf_perf_event_output will fail and return -EFAULT.
            *
            * See bpf_xdp_event_output in net/core/filter.c.
            *
            * The BPF_F_CURRENT_CPU flag means that the event output fd
            * will be indexed by the CPU number in the event map.
            */
        
            
        // TODO: check if size is not too big
        if (size > sizeof(log.data))
            return -1;
        
        log.cookie = log_type;
        log.pkt_len = (__u16)MIN(data_end - data, SAMPLE_SIZE);
        log.data_len = data_len;

        memcpy(log.data, metadata, data_len);

        __u64 flags = BPF_F_CURRENT_CPU;
        __u16 sample_size;
        sample_size = 0; // MIN(log.pkt_len, SAMPLE_SIZE);
        flags |= (__u64)sample_size << 32;

        int ret = bpf_perf_event_output(ctx, &_perf_map, flags,
                        &log, sizeof(struct S));
        if (ret) {
            bpf_printk("Error: perf_event_output failed: %d\n", ret);
        }
    } else {
        bpf_printk("Error: Could not log data");
    }

    return 0;
}

#define SAMPLE_SIZE 64ul
// #define SAMPLE_SIZE sizeof(struct xdp_flow_key)
#define MAX_CPUS 128

/* Action header cursor to keep track of current parsing position */
struct act_cursor {
    __u8 type; /* Determine the type of attr - enum ovs_action_attr*/
    __u8 len; /* len of the whole xdp_flow_action as a multiple of u8 */
};

/* map #1 */
struct bpf_map_def SEC("maps") tail_table = {
    .type = BPF_MAP_TYPE_PROG_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = TAIL_TABLE_SIZE,
};

/* map #2 */
struct bpf_map_def SEC("maps") percpu_actions = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = XDP_FLOW_ACTIONS_LEN_u64,
    .max_entries = 1,
};

/* map #3 */
struct bpf_map_def SEC("maps") flow_table = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = XDP_FLOW_KEY_LEN_u64,
    .value_size = XDP_FLOW_ACTIONS_LEN_u64,
    .max_entries = 100,
};

/* map #4 */
struct bpf_map_def SEC("maps") flow_stats_table = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = XDP_FLOW_KEY_LEN_u64,
    .value_size = XDP_FLOW_STATS_LEN_u64,
    .max_entries = 100,
};

static __always_inline int parse_flow_metadata(struct hdr_cursor *nh,
                                       void *data_end,
                                       __u8 fmbuf[XDP_FLOW_METADATA_KEY_LEN_u64])
{
    // struct flow_metadata *fmh = nh->pos;

    if (nh->pos + XDP_FLOW_METADATA_KEY_LEN_u64 > data_end)
        return -1;

    memcpy(fmbuf, nh->pos, XDP_FLOW_METADATA_KEY_LEN_u64);
    nh->pos += XDP_FLOW_METADATA_KEY_LEN_u64;

    return 0;
}

/* This method updates the metadata which keeps track of the progress of the
   packet/flow processing. It increments the position (pos) of the action being
   processed from the previous to the current. Before doing so it checks if there 
   is still another action. It also updates the offset to be at the first byte of
   the action being processed. */
static __always_inline __u8 next_action(__u8 fmbuf[XDP_FLOW_METADATA_KEY_LEN_u64],
                                        void *data_end)
{
    struct xdp_flow_actions *actions;
    __u32 k = 0;
    actions = bpf_map_lookup_elem(&percpu_actions, &k);
    if (!actions) {
        return -1;
    }

    struct flow_metadata *fm = (struct flow_metadata *)fmbuf;
    
    /* NOTE: 2 is sizeof(struct act_cursor), for some reason putting causes the program
     * to fail to load. When you change the struct act_cursor also change the 2 below.  */
    int next_offset = fm->offset + 2;
    
    // check if there is another action
    if (next_offset > actions->len) {
        return -1;
    }

    // bound check
    if (fm->offset + 2 > MAX_ACTION_SIZE) {
        return -1;
    }

    __u8 pos = 0;
    // Move position to current action
    if (pos + fm->offset > MAX_ACTION_SIZE) {
        return -1;
    }
    pos += fm->offset;

    // Point cursor to current action header
    if (pos + sizeof (struct act_cursor) > MAX_ACTION_SIZE) {
        return -1;
    }
    struct act_cursor *cur = (struct act_cursor *) &actions->data[pos];
    
    // Advance the offset and position
    fm->offset += cur->len;
    fm->pos += 1;
    return cur->type;
}

static __always_inline void tail_action(struct xdp_md *ctx)
{
    /* TODO: Implement method */

    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    /* These keep track of the next header type and iterator pointer */
    struct hdr_cursor nh = { .pos = data };
    __u8 fmbuf[XDP_FLOW_METADATA_KEY_LEN_u64];
    memset(fmbuf, 0, XDP_FLOW_METADATA_KEY_LEN_u64);

    /* Parse xdp flow metadata */
    if (parse_flow_metadata(&nh, data_end, fmbuf) < 0) {
        bpf_printk("flow-metadata parse failed\n");
    } else {
        int flow_action = next_action(fmbuf, data_end);
        if (flow_action > 0 && flow_action <= XDP_ACTION_ATTR_MAX) {
            bpf_tail_call(ctx, &tail_table, flow_action);
        }    
    }

    // No more actions, exiting
}

static __always_inline int tail_action_prog__(struct xdp_md *ctx)
{
    /* read the current action from map */
    __u32 key = 0;
    struct xfa_buf *acts = bpf_map_lookup_elem(&_xfa_buf_map, &key);
    if (!acts)
        return -1;
    /* These keep track of the next header type and iterator pointer */
    struct xfa_cur cursor = { 0 };
    int xfa_type = xfa_next(acts, &cursor);
    if (xfa_type < 0)
        return -1;

    return xfa_type;
}

static __always_inline void tail_action_prog(struct xdp_md *ctx)
{
    
    int xfa_type = tail_action_prog__(ctx);

    if (xfa_type > 0 && xfa_type <= XDP_ACTION_ATTR_MAX) {
        bpf_tail_call(ctx, &xf_tail_map, xfa_type);
    }

    if (log_level & LOG_ERR) {
        char msg[LOG_MSG_SIZE] = "tail_action_prog tail program could not tail to next program";
        logger(ctx, LOG_ERR, msg, LOG_MSG_SIZE);
    }
}

static __always_inline __u8 has_next(struct xdp_md *ctx)
{
    /* TODO: Implement method */

    // if offset is less than len return true, if equal return false

    return 0;
}

#endif /* xdp_kern_headers.h */