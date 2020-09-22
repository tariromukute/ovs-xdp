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

static __always_inline int xdp_unspec(void *pkt_data, struct xdp_md *ctx)
{
    int err = 0;
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_unspec action";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    return err;
}

static __always_inline int xdp_output(void *pkt_data, struct xdp_md *ctx, __u32 port_no)
{
    int action = XDP_PASS;
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_unspec action";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    return action;
}
static __always_inline int xdp_userspace(void *pkt_data, struct xdp_md *ctx, void *action, __u32 size)
{
    int err = 0;
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_unspec action";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    return err;
}

static __always_inline int xdp_set(void *pkt_data, struct xdp_md *ctx, void *action, __u32 size)
{
    int err = 0;
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_unspec action";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    return err;
}

static __always_inline int xdp_push_vlan(void *pkt_data, struct xdp_md *ctx, 
                    struct xdp_action_push_vlan *action)
{
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_unspec action";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    if (pkt_data > data_end)
        return -1;

    struct ethhdr *eth = pkt_data;
	struct vlan_hdr *vlh;

    __u32 mt_size = pkt_data - data; // the size of the metdata added to ctx

    if (data + mt_size + sizeof(struct ethhdr) > data_end)
        return -1;

    __u32 buf_size = mt_size + sizeof(struct ethhdr); // size of data to copy back

    __u8 buf[buf_size];

	/* First copy the metadata and Ethernet header */
	__builtin_memcpy(buf, data, buf_size);

	/* Then add space in front of the packet */
	if (bpf_xdp_adjust_head(ctx, 0 - (int)sizeof(*vlh)))
		return -1;

	/* Need to re-evaluate data_end and data after head adjustment, and
	 * bounds check, even though we know there is enough space (as we
	 * increased it).
	 */
	data_end = (void *)(long)ctx->data_end;
	data = (void *)(long)ctx->data;

	if (data + buf_size > data_end)
		return -1;

	/* Copy back the Ethernet header in the right place, populate the VLAN
	 * tag with the ID and proto, and set the outer Ethernet header to VLAN
	 * type. */
	__builtin_memcpy(data, buf, buf_size);

    if (pkt_data > data_end)
        return -1;
    
    eth = pkt_data;

	vlh = (void *)(eth +1);

	if (vlh + 1 > data_end)
		return -1;

	vlh->h_vlan_TCI = bpf_htons(action->vlan_tci);
	vlh->h_vlan_encapsulated_proto = eth->h_proto;

	eth->h_proto = bpf_htons(ETH_P_8021Q);
	return 0;
}                    

static __always_inline int xdp_pop_vlan(void *pkt_data, struct xdp_md *ctx)
{
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_unspec action";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    if (pkt_data > data_end)
        return -1;

    __u32 mt_size = pkt_data - data; // the size of the metdata added to ctx
    
    if (data + mt_size + sizeof(struct ethhdr) > data_end)
        return -1;
        
    __u32 buf_size = mt_size + sizeof(struct ethhdr); // size of data to copy back

    __u8 buf[buf_size];

    struct ethhdr *eth = pkt_data;
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

	/* Make a copy of the metadata and Ethernet header before we cut it off */
	__builtin_memcpy(buf, data, sizeof(buf_size));

	/* Actually adjust the head pointer */
	if (bpf_xdp_adjust_head(ctx, (int)sizeof(*vlh)))
		return -1;

	/* Need to re-evaluate data *and* data_end and do new bounds checking
	 * after adjusting head
	 */
	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	if (data + buf_size > data_end)
		return -1;


    if (pkt_data > data_end)
        return -1;
    
    eth = pkt_data;

	/* Copy back the old metadata and Ethernet header and update the proto type */
	__builtin_memcpy(data, buf, buf_size);
	eth->h_proto = h_proto;

	return vlid;
}

static __always_inline int xdp_sample(void *pkt_data, struct xdp_md *ctx, void *action, __u32 size)
{
    int err = 0;
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_unspec action";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    return err;
}

static __always_inline int xdp_recirc(void *pkt_data, struct xdp_md *ctx, __u32 action)
{
    int err = 0;
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_unspec action";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    return err;
}

static __always_inline int xdp_hash(void *pkt_data, struct xdp_md *ctx,
                    struct xdp_action_hash *action)
{
    int err = 0;
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_unspec action";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    return err;
}

static __always_inline int xdp_push_mpls(void *pkt_data, struct xdp_md *ctx,
                    struct xdp_action_push_mpls *action)
{
    int err = 0;
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_unspec action";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    return err;
}

static __always_inline int xdp_pop_mpls(void *pkt_data, struct xdp_md *ctx, __be16 action)
{
    int err = 0;
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_unspec action";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    return err;
}

static __always_inline int xdp_set_masked(void *pkt_data, struct xdp_md *ctx, void *action, __u32 size)
{
    int err = 0;
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_unspec action";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    return err;
}

static __always_inline int xdp_ct(void *pkt_data, struct xdp_md *ctx, void *action, __u32 size)
{
    int err = 0;
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_unspec action";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    return err;
}

static __always_inline int xdp_trunc(void *pkt_data, struct xdp_md *ctx,
                    struct xdp_action_trunc *action)
{
    int err = 0;
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_unspec action";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    return err;
}                    

static __always_inline int xdp_push_eth(void *pkt_data, struct xdp_md *ctx, 
                    struct xdp_action_push_eth *action)
{
    int err = 0;
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_unspec action";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    return err;   
}

static __always_inline int xdp_pop_eth(void *pkt_data, struct xdp_md *ctx)
{
    int err = 0;
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_unspec action";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    return err;
}

static __always_inline int xdp_ct_clear(void *pkt_data, struct xdp_md *ctx)
{
    int err = 0;
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_unspec action";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    return err;
}

static __always_inline int xdp_push_nsh(void *pkt_data, struct xdp_md *ctx, void *action, __u32 size)
{
    int err = 0;
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_unspec action";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    return err;
}

static __always_inline int xdp_pop_nsh(void *pkt_data, struct xdp_md *ctx)
{
    int err = 0;
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_unspec action";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    return err;
}

static __always_inline int xdp_meter(void *pkt_data, struct xdp_md *ctx, __u32 action)
{
    int err = 0;
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_unspec action";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    return err;
}

static __always_inline int xdp_clone(void *pkt_data, struct xdp_md *ctx, void *action, __u32 size)
{
    int err = 0;
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_unspec action";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    return err;
}

static __always_inline int xdp_drop(void *pkt_data, struct xdp_md *ctx)
{
    int action = XDP_PASS;
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_unspec action";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    return action;
}

static __always_inline int xdp_upcall(void *pkt_data, struct xdp_md *ctx,
                    struct xdp_flow_key *key)
{
    if (log_level & LOG_INFO) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_unspec action";
        logger(ctx, LOG_INFO, msg, LOG_MSG_SIZE);
    }

    /* NOTE: for debug only. In production uncomment */
    if (log_level & LOG_DEBUG) {
        logger(ctx, LOG_EXTRACTED_KEY, key, sizeof(struct xdp_flow_key));
    }

    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    if (pkt_data > data_end)
        return -1;

    // Upcall doesnt need actions metadata. Remove any metadata
    int mt_size = pkt_data - data;
    if (bpf_xdp_adjust_head(ctx, mt_size))
        return -1;

    // Re-evaluate and do bound checks
    data_end = (void *)(long)ctx->data_end;
    data = (void *)(long)ctx->data;

    /* Get the receive queue index and upcall via the XSK socket */
    int index = ctx->rx_queue_index;

    /* Add upcall information at the head of the packet */
    struct xdp_upcall upcall;
    memset(&upcall, 0, sizeof(struct xdp_upcall));
    upcall.type = XDP_PACKET_CMD_MISS;
    upcall.subtype = 0;
    upcall.ifindex = ctx->ingress_ifindex;
    upcall.pkt_len = data_end - data;
    memcpy(&upcall.key, key, sizeof(struct xdp_flow_key));

    if (bpf_xdp_adjust_head(ctx, 0 - (int)sizeof(struct xdp_upcall)))
        return -1;

    /* Need to re-evaluate data_end and data after head adjustment, and
    * bounds check, even though we know there is enough space (as we
    * increased it).
    */
    data_end = (void *)(long)ctx->data_end;
    struct xdp_upcall *up = (void *)(long)ctx->data;

    if (up + 1 > data_end)
    {
        return -1;
    }

    memcpy(up, &upcall, sizeof(*up));
    return index;  
}

#endif /* XF_ACTIONS_H */