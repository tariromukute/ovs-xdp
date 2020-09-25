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

static __always_inline int xdp_unspec(struct xdp_md *ctx)
{
    int err = 0;
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_unspec action";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    return err;
}

static __always_inline int xdp_output(struct xdp_md *ctx, __u32 port_no)
{
    int action = XDP_PASS;
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_unspec action";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    return action;
}
static __always_inline int xdp_userspace(struct xdp_md *ctx, void *action, __u32 size)
{
    int err = 0;
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_unspec action";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    return err;
}

static __always_inline int xdp_set(struct xdp_md *ctx, void *action, __u32 size)
{
    int err = 0;
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_unspec action";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    return err;
}


static __always_inline int xdp_push_vlan(struct xdp_md *ctx, 
                    struct xdp_action_push_vlan *action)
{
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_unspec action";
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
        char msg[LOG_MSG_SIZE] = "Executing xdp_unspec action";
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
        char msg[LOG_MSG_SIZE] = "Executing xdp_unspec action";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    return err;
}

static __always_inline int xdp_recirc(struct xdp_md *ctx, __u32 action)
{
    int err = 0;
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_unspec action";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    return err;
}

static __always_inline int xdp_hash(struct xdp_md *ctx,
                    struct xdp_action_hash *action)
{
    int err = 0;
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_unspec action";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    return err;
}

static __always_inline int xdp_push_mpls(struct xdp_md *ctx,
                    struct xdp_action_push_mpls *action)
{
    int err = 0;
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_unspec action";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    return err;
}

static __always_inline int xdp_pop_mpls(struct xdp_md *ctx, __be16 action)
{
    int err = 0;
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_unspec action";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    return err;
}

static __always_inline int xdp_set_masked(struct xdp_md *ctx, void *action, __u32 size)
{
    int err = 0;
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_unspec action";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    return err;
}

static __always_inline int xdp_ct(struct xdp_md *ctx, void *action, __u32 size)
{
    int err = 0;
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_unspec action";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    return err;
}

static __always_inline int xdp_trunc(struct xdp_md *ctx,
                    struct xdp_action_trunc *action)
{
    int err = 0;
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_unspec action";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    return err;
}                    

static __always_inline int xdp_push_eth(struct xdp_md *ctx, 
                    struct xdp_action_push_eth *action)
{
    int err = 0;
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_unspec action";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    return err;   
}

static __always_inline int xdp_pop_eth(struct xdp_md *ctx)
{
    int err = 0;
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_unspec action";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    return err;
}

static __always_inline int xdp_ct_clear(struct xdp_md *ctx)
{
    int err = 0;
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_unspec action";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    return err;
}

static __always_inline int xdp_push_nsh(struct xdp_md *ctx, void *action, __u32 size)
{
    int err = 0;
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_unspec action";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    return err;
}

static __always_inline int xdp_pop_nsh(struct xdp_md *ctx)
{
    int err = 0;
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_unspec action";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    return err;
}

static __always_inline int xdp_meter(struct xdp_md *ctx, __u32 action)
{
    int err = 0;
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_unspec action";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    return err;
}

static __always_inline int xdp_clone(struct xdp_md *ctx, void *action, __u32 size)
{
    int err = 0;
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_unspec action";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    return err;
}

static __always_inline int xdp_drop(struct xdp_md *ctx)
{
    int action = XDP_PASS;
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_unspec action";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    return action;
}

static __always_inline int xdp_upcall(struct xdp_md *ctx,
                    struct xf_key *key)
{
    if (log_level & LOG_INFO) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_unspec action";
        logger(ctx, LOG_INFO, msg, LOG_MSG_SIZE);
    }

    /* NOTE: for debug only. In production uncomment */
    if (log_level & LOG_DEBUG) {
        logger(ctx, LOG_EXTRACTED_KEY, key, sizeof(struct xf_key));
    }

    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    int index = ctx->rx_queue_index;

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
    return index;  
}

#endif /* XF_ACTIONS_H */