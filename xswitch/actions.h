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
// 	__u64 u = 0;
// 	int i;

// 	for (i = ETH_ALEN; i >= 0; i--)
// 		u = u << 8 | addr[i];
// 	return u;
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

static __always_inline int xdp_output(struct xdp_md *ctx, __u32 port_no)
{
    int action = XDP_PASS;
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_output action";
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
    bpf_printk("eth->h_desta: %llx \n", ether_addr_to_u64(h_desta));
    bpf_printk("eth->h_sourcea: %llx \n", ether_addr_to_u64(h_sourcea));
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

        bpf_printk("iph->saddr: %lu \n", bpf_ntohl(iph->saddr));
        bpf_printk("iph->daddr: %lu \n", bpf_ntohl(iph->daddr));       
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
        bpf_printk("ETH_P_ARP\n");
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
    bpf_printk("ctx->ingress_ifindex: %d\n", ctx->ingress_ifindex);
    rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
    switch (rc) {
    case BPF_FIB_LKUP_RET_SUCCESS:         /* lookup successful */
        bpf_printk("BPF_FIB_LKUP_RET_SUCCESS\n");
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
        bpf_printk("eth->h_dest: %llx \n", ether_addr_to_u64(h_dest));
        bpf_printk("eth->h_source: %llx \n", ether_addr_to_u64(h_source));

        __u8 dmac[ETH_ALEN];
        __u8 smac[ETH_ALEN];
        memcpy(dmac, fib_params.dmac, ETH_ALEN);
        memcpy(smac, fib_params.smac, ETH_ALEN);
        bpf_printk("fib_params.dmac: %llx \n", u8_arr_to_u64(dmac, ETH_ALEN));
        bpf_printk("fib_params.smac: %llx \n", u8_arr_to_u64(smac, ETH_ALEN));
        bpf_printk("fib_params.ipv4_src: %lu \n", bpf_ntohl(fib_params.ipv4_src));
        bpf_printk("fib_params.ipv4_dst: %lu \n", bpf_ntohl(fib_params.ipv4_dst));
        bpf_printk("fib_params.ifindex: %d \n", fib_params.ifindex);

        memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
        memcpy(eth->h_source, fib_params.smac, ETH_ALEN);
        // action = bpf_redirect_map(&tx_port, fib_params.ifindex, 0);
        action = bpf_redirect(fib_params.ifindex, 0);
        break;
    case BPF_FIB_LKUP_RET_BLACKHOLE:    /* dest is blackholed; can be dropped */
    case BPF_FIB_LKUP_RET_UNREACHABLE:  /* dest is unreachable; can be dropped */
    case BPF_FIB_LKUP_RET_PROHIBIT:     /* dest not allowed; can be dropped */
        bpf_printk("BPF_FIB_LKUP_RET_PROHIBIT\n");
        action = XDP_DROP;
        break;
    case BPF_FIB_LKUP_RET_NOT_FWDED:    /* packet is not forwarded */
    case BPF_FIB_LKUP_RET_FWD_DISABLED: /* fwding is not enabled on ingress */
    case BPF_FIB_LKUP_RET_UNSUPP_LWT:   /* fwd requires encapsulation */
    case BPF_FIB_LKUP_RET_NO_NEIGH:     /* no neighbor entry for nh */
    case BPF_FIB_LKUP_RET_FRAG_NEEDED:  /* fragmentation required to fwd */
        bpf_printk("BPF_FIB_LKUP_RET_FRAG_NEEDED %d\n", rc);
        /* PASS */
        break;
    }

out:
    return action;
}
static __always_inline int xdp_userspace(struct xdp_md *ctx, void *action, __u32 size)
{
    int err = 0;
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_userspace action";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    return err;
}

static __always_inline int xdp_set(struct xdp_md *ctx, void *action, __u32 size)
{
    int err = 0;
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_set action";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    return err;
}


static __always_inline int xdp_push_vlan(struct xdp_md *ctx, 
                    struct xdp_action_push_vlan *action)
{
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_push_vlan action";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

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
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_pop_vlan action";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

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
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_sample action";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    return err;
}

static __always_inline int xdp_recirc(struct xdp_md *ctx, __u32 action)
{
    int err = 0;
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_recirc action";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    return err;
}

static __always_inline int xdp_hash(struct xdp_md *ctx,
                    struct xdp_action_hash *action)
{
    int err = 0;
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_hash action";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    return err;
}

static __always_inline int xdp_push_mpls(struct xdp_md *ctx,
                    struct xdp_action_push_mpls *action)
{
    int err = 0;
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_push_mpls action";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    return err;
}

static __always_inline int xdp_pop_mpls(struct xdp_md *ctx, __be16 action)
{
    int err = 0;
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_pop_mpls action";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    return err;
}

static __always_inline int xdp_set_masked(struct xdp_md *ctx, void *action, __u32 size)
{
    int err = 0;
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_set_masked action";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    return err;
}

static __always_inline int xdp_ct(struct xdp_md *ctx, void *action, __u32 size)
{
    int err = 0;
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_ct action";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    return err;
}

static __always_inline int xdp_trunc(struct xdp_md *ctx,
                    struct xdp_action_trunc *action)
{
    int err = 0;
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_trunc action";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    return err;
}                    

static __always_inline int xdp_push_eth(struct xdp_md *ctx, 
                    struct xdp_action_push_eth *action)
{
    int err = 0;
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_push_eth action";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    return err;   
}

static __always_inline int xdp_pop_eth(struct xdp_md *ctx)
{
    int err = 0;
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_pop_eth action";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    return err;
}

static __always_inline int xdp_ct_clear(struct xdp_md *ctx)
{
    int err = 0;
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_ct_clear action";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    return err;
}

static __always_inline int xdp_push_nsh(struct xdp_md *ctx, void *action, __u32 size)
{
    int err = 0;
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_push_nsh action";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    return err;
}

static __always_inline int xdp_pop_nsh(struct xdp_md *ctx)
{
    int err = 0;
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_pop_nsh action";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    return err;
}

static __always_inline int xdp_meter(struct xdp_md *ctx, __u32 action)
{
    int err = 0;
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_meter action";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    return err;
}

static __always_inline int xdp_clone(struct xdp_md *ctx, void *action, __u32 size)
{
    int err = 0;
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_clone action";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    return err;
}

static __always_inline int xdp_drop(struct xdp_md *ctx)
{
    int action = XDP_PASS;
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_drop action";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

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
    int index = ctx->ingress_ifindex;

    /* Add upcall information at the head of the packet */
    struct xf_upcall *up = data;
    struct xf_upcall upcall;
    memset(&upcall, 0, sizeof(upcall));
    upcall.type = XDP_PACKET_CMD_MISS;
    upcall.subtype = 0;
    upcall.ifindex = ctx->ingress_ifindex;
    bpf_printk("ctx->ingress_ifindex: %d, upcall.ifindex: %d\n", ctx->ingress_ifindex, upcall.ifindex);
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
    bpf_printk("Index %d\n", index);
    return index;  
}

#endif /* XF_ACTIONS_H */