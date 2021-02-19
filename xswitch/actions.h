/*
 * Example of using bpf tail calls (in XDP programs)
 */
#ifndef XF_ACTIONS_H
#define XF_ACTIONS_H 1
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/openvswitch.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// The parsing helper functions from the packet01 lesson have moved here
#include "parsing_helpers.h"
#include "rewrite_helpers.h"
#include "xf_kern.h"
#include "xf.h"

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

// static inline __u64 ether_addr_to_u64(const __u8 *addr)
// {
//     __u64 u = 0;
//     int i;

//     for (i = ETH_ALEN; i >= 0; i--)
//         u = u << 8 | addr[i];
//     return u;
// }

static __always_inline int xdp_unspec(struct xdp_md *ctx)
{
    int err = 0;
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_unspec action";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    return err;
}

#define IPV6_FLOWINFO_MASK bpf_htonl(0x0FFFFFFF)

/* from include/net/ip.h */
static __always_inline int ip_decrease_ttl(struct iphdr *iph)
{
    __u32 check = iph->check;
    check += bpf_htons(0x0100);
    iph->check = (__u16)(check + (check >= 0xFFFF));
    return --iph->ttl;
}

static __always_inline int xdp_output(struct xdp_md *ctx, __u32 ifindex)
{
    int action = XDP_PASS;
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_normal action";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }
    
    action = bpf_redirect_map(&tx_port, ifindex, 0);
    return action;
}

static __always_inline int xdp_normal(struct xdp_md *ctx)
{
    int action = XDP_PASS;
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_normal action";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    struct bpf_fib_lookup fib_params = {};
    struct ethhdr *eth = data;
    struct ipv6hdr *ip6h;
    struct iphdr *iph;
    struct arp_ethhdr *arph;
    __u16 h_proto;
    __u64 nh_off;
    int rc;

    nh_off = sizeof(*eth);
    if (data + nh_off > data_end) {
        action = XDP_DROP;
        goto out;
    }

    __u8 h_desta[ETH_ALEN];
    __u8 h_sourcea[ETH_ALEN];
    memcpy(h_desta, eth->h_dest, ETH_ALEN);
    memcpy(h_sourcea, eth->h_source, ETH_ALEN);
    h_proto = eth->h_proto;
    if (h_proto == bpf_htons(ETH_P_IP)) {
        iph = data + nh_off;

        if (iph + 1 > data_end) {
            action = XDP_DROP;
            goto out;
        }

        if (iph->ttl <= 1)
            goto out;

        fib_params.family    = AF_INET;
        fib_params.tos        = iph->tos;
        fib_params.l4_protocol    = iph->protocol;
        fib_params.sport    = 0;
        fib_params.dport    = 0;
        fib_params.tot_len    = bpf_ntohs(iph->tot_len);
        fib_params.ipv4_src    = iph->saddr;
        fib_params.ipv4_dst    = iph->daddr;

    } else if (h_proto == bpf_htons(ETH_P_IPV6)) {
        struct in6_addr *src = (struct in6_addr *) fib_params.ipv6_src;
        struct in6_addr *dst = (struct in6_addr *) fib_params.ipv6_dst;

        ip6h = data + nh_off;
        if (ip6h + 1 > data_end) {
            action = XDP_DROP;
            goto out;
        }

        if (ip6h->hop_limit <= 1)
            goto out;

        fib_params.family    = AF_INET6;
        fib_params.flowinfo    = *(__be32 *) ip6h & IPV6_FLOWINFO_MASK;
        fib_params.l4_protocol    = ip6h->nexthdr;
        fib_params.sport    = 0;
        fib_params.dport    = 0;
        fib_params.tot_len    = bpf_ntohs(ip6h->payload_len);
        *src            = ip6h->saddr;
        *dst            = ip6h->daddr;
    } else if (h_proto == bpf_htons(ETH_P_ARP) || h_proto == bpf_htons(ETH_P_RARP)) {
        arph = data + nh_off;
        if (arph + 1 > data_end) {
            action = XDP_DROP;
            goto out;
        }

        fib_params.family    = AF_INET;
        // fib_params.tos        = iph->tos;
        // fib_params.l4_protocol    = iph->protocol;
        fib_params.sport    = 0;
        fib_params.dport    = 0;
        // fib_params.tot_len    = bpf_ntohs(iph->tot_len);
        fib_params.ipv4_src    = arph->ar_sip;
        fib_params.ipv4_dst    = arph->ar_tip;
    } else {
        goto out;
    }

    fib_params.ifindex = ctx->ingress_ifindex;
    rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), BPF_FIB_LOOKUP_DIRECT);
    switch (rc) {
    case BPF_FIB_LKUP_RET_SUCCESS:         /* lookup successful */
        if (h_proto == bpf_htons(ETH_P_IP)) {
            // bound check to satisfy verifier
            if (iph + 1 > data_end) {
                action = XDP_DROP;
                goto out;
            }
            ip_decrease_ttl(iph);
        }
        else if (h_proto == bpf_htons(ETH_P_IPV6)) {
            // bound check to satisfy verifier
            if (ip6h + 1 > data_end) {
                action = XDP_DROP;
                goto out;
            }
            ip6h->hop_limit--;
        }
        
        __u8 h_dest[ETH_ALEN];
        __u8 h_source[ETH_ALEN];
        memcpy(h_dest, fib_params.dmac, ETH_ALEN);
        memcpy(h_source, fib_params.smac, ETH_ALEN);

      
        action = bpf_redirect_map(&tx_port, fib_params.ifindex, 0);
        break;
    case BPF_FIB_LKUP_RET_BLACKHOLE:    /* dest is blackholed; can be dropped */
    case BPF_FIB_LKUP_RET_UNREACHABLE:  /* dest is unreachable; can be dropped */
    case BPF_FIB_LKUP_RET_PROHIBIT:     /* dest not allowed; can be dropped */
        action = XDP_DROP;
        break;
    case BPF_FIB_LKUP_RET_NOT_FWDED:    /* packet is not forwarded */
    case BPF_FIB_LKUP_RET_FWD_DISABLED: /* fwding is not enabled on ingress */
    case BPF_FIB_LKUP_RET_UNSUPP_LWT:   /* fwd requires encapsulation */
    case BPF_FIB_LKUP_RET_NO_NEIGH:     /* no neighbor entry for nh */
    case BPF_FIB_LKUP_RET_FRAG_NEEDED:  /* fragmentation required to fwd */
        /* PASS */
        break;
    }

out:
    return action;
}

static __always_inline int xdp_userspace(struct xdp_md *ctx, void *action, __u32 size)
{
    int err = 0;
    // if (log_level & LOG_DEBUG) {
    //     char msg[LOG_MSG_SIZE] = "Executing xdp_userspace action";
    //     logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    // }

    return err;
}

static __always_inline int xdp_set(struct xdp_md *ctx, void *action, __u32 size)
{
    int err = 0;
    // if (log_level & LOG_DEBUG) {
    //     char msg[LOG_MSG_SIZE] = "Executing xdp_set action";
    //     logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    // }

    return err;
}


static __always_inline int xdp_push_vlan(struct xdp_md *ctx, 
                    struct xdp_action_push_vlan *action)
{
    // if (log_level & LOG_DEBUG) {
    //     char msg[LOG_MSG_SIZE] = "Executing xdp_push_vlan action";
    //     logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    // }

    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    struct ethhdr eth_cpy;
    struct vlan_hdr *vlh;

    if (eth + 1 > data_end)
        return -1;

    /* First copy the original Ethernet header */
    __builtin_memcpy(&eth_cpy, eth, sizeof(eth_cpy));

    /* Then add space in front of the packet */
    if (bpf_xdp_adjust_head(ctx, 0 - (int)sizeof(*vlh)))
        return -1;

    /* Need to re-evaluate data_end and data after head adjustment, and
     * bounds check, even though we know there is enough space (as we
     * increased it).
     */
    data_end = (void *)(long)ctx->data_end;
    eth = (void *)(long)ctx->data;

    if (eth + 1 > data_end)
        return -1;

    /* Copy back the Ethernet header in the right place, populate the VLAN
     * tag with the ID and proto, and set the outer Ethernet header to VLAN
     * type. */
    __builtin_memcpy(eth, &eth_cpy, sizeof(*eth));

    vlh = (void *)(eth +1);

    if (vlh + 1 > data_end)
        return -1;

    vlh->h_vlan_TCI = bpf_htons(action->vlan_tci);
    vlh->h_vlan_encapsulated_proto = eth->h_proto;

    eth->h_proto = bpf_htons(ETH_P_8021Q);
    return 0;
}                    

static __always_inline int xdp_pop_vlan(struct xdp_md *ctx)
{
    // if (log_level & LOG_DEBUG) {
    //     char msg[LOG_MSG_SIZE] = "Executing xdp_pop_vlan action";
    //     logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    // }

    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    struct ethhdr eth_cpy;
    struct vlan_hdr *vlh;
    __be16 h_proto;
    int vlid;

    if (!proto_is_vlan(eth->h_proto))
        return -1;

    /* Careful with the parenthesis here */
    vlh = (void *)(eth + 1);

    /* Still need to do bounds checking */
    if (vlh + 1 > data_end)
        return -1;

    /* Save vlan ID for returning, h_proto for updating Ethernet header */
    vlid = bpf_ntohs(vlh->h_vlan_TCI);
    h_proto = vlh->h_vlan_encapsulated_proto;

    /* Make a copy of the outer Ethernet header before we cut it off */
    __builtin_memcpy(&eth_cpy, eth, sizeof(eth_cpy));

    /* Actually adjust the head pointer */
    if (bpf_xdp_adjust_head(ctx, (int)sizeof(*vlh)))
        return -1;

    /* Need to re-evaluate data *and* data_end and do new bounds checking
     * after adjusting head
     */
    eth = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;
    if (eth + 1 > data_end)
        return -1;

    /* Copy back the old Ethernet header and update the proto type */
    __builtin_memcpy(eth, &eth_cpy, sizeof(*eth));
    eth->h_proto = h_proto;

    return vlid;
}

static __always_inline int xdp_sample(struct xdp_md *ctx, void *action, __u32 size)
{
    int err = 0;
    // if (log_level & LOG_DEBUG) {
    //     char msg[LOG_MSG_SIZE] = "Executing xdp_sample action";
    //     logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    // }

    return err;
}

static __always_inline int xdp_recirc(struct xdp_md *ctx, __u32 action)
{
    int err = 0;
    // if (log_level & LOG_DEBUG) {
    //     char msg[LOG_MSG_SIZE] = "Executing xdp_recirc action";
    //     logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    // }

    return err;
}

static __always_inline int xdp_hash(struct xdp_md *ctx,
                    struct xdp_action_hash *action)
{
    int err = 0;
    // if (log_level & LOG_DEBUG) {
    //     char msg[LOG_MSG_SIZE] = "Executing xdp_hash action";
    //     logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    // }

    return err;
}

static __always_inline int xdp_push_mpls(struct xdp_md *ctx,
                    struct xdp_action_push_mpls *action)
{
    int err = 0;
    // if (log_level & LOG_DEBUG) {
    //     char msg[LOG_MSG_SIZE] = "Executing xdp_push_mpls action";
    //     logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    // }

    return err;
}

static __always_inline int xdp_pop_mpls(struct xdp_md *ctx, __be16 action)
{
    int err = 0;
    // if (log_level & LOG_DEBUG) {
    //     char msg[LOG_MSG_SIZE] = "Executing xdp_pop_mpls action";
    //     logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    // }

    return err;
}

static __always_inline int xdp_set_masked(struct xdp_md *ctx, void *action, __u32 size)
{
    int err = 0;
    // if (log_level & LOG_DEBUG) {
    //     char msg[LOG_MSG_SIZE] = "Executing xdp_set_masked action";
    //     logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    // }

    return err;
}

static __always_inline int xdp_ct(struct xdp_md *ctx, void *action, __u32 size)
{
    int err = 0;
    // if (log_level & LOG_DEBUG) {
    //     char msg[LOG_MSG_SIZE] = "Executing xdp_ct action";
    //     logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    // }

    return err;
}

static __always_inline int xdp_trunc(struct xdp_md *ctx,
                    struct xdp_action_trunc *action)
{
    int err = 0;
    // if (log_level & LOG_DEBUG) {
    //     char msg[LOG_MSG_SIZE] = "Executing xdp_trunc action";
    //     logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    // }

    return err;
}                    

static __always_inline int xdp_push_eth(struct xdp_md *ctx, 
                    struct xdp_action_push_eth *action)
{
    int err = 0;
    // if (log_level & LOG_DEBUG) {
    //     char msg[LOG_MSG_SIZE] = "Executing xdp_push_eth action";
    //     logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    // }

    return err;   
}

static __always_inline int xdp_pop_eth(struct xdp_md *ctx)
{
    int err = 0;
    // if (log_level & LOG_DEBUG) {
    //     char msg[LOG_MSG_SIZE] = "Executing xdp_pop_eth action";
    //     logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    // }

    return err;
}

static __always_inline int xdp_ct_clear(struct xdp_md *ctx)
{
    int err = 0;
    // if (log_level & LOG_DEBUG) {
    //     char msg[LOG_MSG_SIZE] = "Executing xdp_ct_clear action";
    //     logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    // }

    return err;
}

static __always_inline int xdp_push_nsh(struct xdp_md *ctx, void *action, __u32 size)
{
    int err = 0;
    // if (log_level & LOG_DEBUG) {
    //     char msg[LOG_MSG_SIZE] = "Executing xdp_push_nsh action";
    //     logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    // }

    return err;
}

static __always_inline int xdp_pop_nsh(struct xdp_md *ctx)
{
    int err = 0;
    // if (log_level & LOG_DEBUG) {
    //     char msg[LOG_MSG_SIZE] = "Executing xdp_pop_nsh action";
    //     logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    // }

    return err;
}

static __always_inline int xdp_meter(struct xdp_md *ctx, __u32 action)
{
    int err = 0;
    // if (log_level & LOG_DEBUG) {
    //     char msg[LOG_MSG_SIZE] = "Executing xdp_meter action";
    //     logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    // }

    return err;
}

static __always_inline int xdp_clone(struct xdp_md *ctx, void *action, __u32 size)
{
    int err = 0;
    // if (log_level & LOG_DEBUG) {
    //     char msg[LOG_MSG_SIZE] = "Executing xdp_clone action";
    //     logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    // }

    return err;
}

static __always_inline int xdp_drop(struct xdp_md *ctx)
{
    int action = XDP_PASS;
    // if (log_level & LOG_DEBUG) {
    //     char msg[LOG_MSG_SIZE] = "Executing xdp_drop action";
    //     logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    // }

    return action;
}

static __always_inline int xdp_upcall(struct xdp_md *ctx,
                    struct xf_key *key)
{
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_upcall action";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    /* NOTE: for debug only. In production uncomment */
    if (log_level & LOG_DEBUG) {
        logger(ctx, LOG_XF_KEY, key, sizeof(struct xf_key));
    }

    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    int rxq_index = ctx->rx_queue_index;

    /* Record upcall stats */
    struct xfu_stats *stats = bpf_map_lookup_elem(&_xf_stats_map, key);
    if (stats) {
         /* Calculate packet length */
        __u64 bytes = data_end - data;

        /* BPF_MAP_TYPE_PERCPU_ARRAY returns a data record specific to current
        * CPU and XDP hooks runs under Softirq, which makes it safe to update
        * without atomic operations.
        */
        stats->rx_packets++;
        stats->rx_bytes += bytes;
    } else {
        struct xfu_stats s;
        memset(&s, 0, sizeof(struct xfu_stats));
        bpf_map_update_elem(&_xf_stats_map, key, &s, 0);
    }

    /* Add upcall information at the head of the packet */
    struct xf_upcall *up = data;
    struct xf_upcall upcall;
    memset(&upcall, 0, sizeof(upcall));
    upcall.type = XDP_PACKET_CMD_MISS;
    upcall.subtype = 0;
    upcall.ifindex = ctx->ingress_ifindex;
    upcall.pkt_len = data_end - data;
    __builtin_memcpy(&upcall.key, key, sizeof(*key));

    if (bpf_xdp_adjust_head(ctx, 0 - (int)sizeof(*up)))
        return -1;

    /* Need to re-evaluate data_end and data after head adjustment, and
    * bounds check, even though we know there is enough space (as we
    * increased it).
    */
    data_end = (void *)(long)ctx->data_end;
    up = (void *)(long)ctx->data;

    if (up + 1 > data_end)
    {
        return -1; // error should not occur, but if for some weird reason it does drop packet
    }

    memcpy(up, &upcall, sizeof(upcall));
    return rxq_index;  
}

/* Metadata will be in the perf event for upcall before the packet data. */
struct U {
    __u16 cookie;
    __u16 pkt_len;
} __attribute__((packed));

static __always_inline int xdp_upcall_perf(struct xdp_md *ctx,
                    struct xf_key *key)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    int ret = -1;
    // bpf_printk("doing xdp_upcall_perf\n");
    /* Record upcall stats */
    struct xfu_stats *stats = bpf_map_lookup_elem(&_xf_stats_map, key);
    if (stats) {
         /* Calculate packet length */
        __u64 bytes = data_end - data;

        /* BPF_MAP_TYPE_PERCPU_ARRAY returns a data record specific to current
        * CPU and XDP hooks runs under Softirq, which makes it safe to update
        * without atomic operations.
        */
        stats->rx_packets++;
        stats->rx_bytes += bytes;
    } else {
        struct xfu_stats s;
        memset(&s, 0, sizeof(struct xfu_stats));
        bpf_map_update_elem(&_xf_stats_map, key, &s, 0);
    }

    /* Add upcall information at the head of the packet */
    // struct xf_upcall upcall;
    // memset(&upcall, 0, sizeof(upcall));
    // upcall.type = XDP_PACKET_CMD_MISS;
    // upcall.subtype = 0;
    // upcall.ifindex = ctx->ingress_ifindex;
    // upcall.pkt_len = data_end - data;
    // __builtin_memcpy(&upcall.key, key, sizeof(*key));

    if (data_end > data) {
        
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
        
            
        __u64 flags = BPF_F_CURRENT_CPU;
        __u16 sample_size;
        int ret;
        struct U metadata;

        metadata.cookie = UPCALL_COOKIE;
        metadata.pkt_len = (__u16)(data_end - data);
        sample_size = MIN(metadata.pkt_len, MAX_FRAME_SIZE);

        flags |= (__u64)sample_size << 32;

        ret = bpf_perf_event_output(ctx, &_upcall_map, flags,
                        &metadata, sizeof(metadata));
        if (ret)
            bpf_printk("perf_event_output failed: %d\n", ret);
        
        if (!ret)
            return 0;
    }
    
    bpf_printk("xf loader failed\n");
    return ret;

    
}

#endif /* XF_ACTIONS_H */