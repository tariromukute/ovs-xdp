#include <linux/in.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <net/if_arp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "nsh.h" /* nsh was getting redefinition error with <openvswitch/nsh.h> in dpif */
// #include <openvswitch/nsh.h>
#include "flow.h"

#include "parsing_xdp_key_helpers.h"
#include "parsing_helpers.h"
#include "rewrite_helpers.h"
#include "xf_kern.h"
#include "xf.h"
#include "actions.h"

SEC("prog")
int xdp_ep_inline_actions(struct xdp_md *ctx)
{
    int action = XDP_PASS;
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    int err;

    struct xf_key key;
    memset(&key, 0, sizeof(struct xf_key));

    err = xfk_extract(data, data_end, &key);
    if (err)
        goto out;

    struct xfa_buf *acts = bpf_map_lookup_elem(&xf_micro_map, &key);
    if (!acts) /* If there are no flow actions, make an upcall */
    {
        free(acts);
        int index = ctx->rx_queue_index;


        // /* NOTE: if you don't put bpf_redirect_map in the program that you load to on the interface
        //  * and rather put it in a tail program e.g., bpf_tail_call(ctx, &tail_table, OVS_ACTION_ATTR_UPCALL)
        //  * and you create a xsk_socket for the interface. The xsk_socket seems to be created without an error
        //  * but on trying to do xsk_socket__fd(xsk_socket->xsk) you get a segmentation fault. This is resolved
        //  * by putting bpf_redirect_map(&xsks_map, index, 0) directly into the program loaded. However, calling
        //  * bpf_tail_call(ctx, &tail_table, OVS_ACTION_ATTR_UPCALL) i.e, invoking a tail program that will send
        //  * to a xsk_socket, before bpf_redirect_map(&xsks_map, index, 0) will still result in the packets being
        //  * delivered, i.e, being sent by the tail program and not the bpf_redirect_map TODO: check the libbpf or 
        //  * helper function why this is, it maybe due to some 'enforced' logic that can be changed */
        if (bpf_map_lookup_elem(&xsks_map, &index))
            return bpf_redirect_map(&xsks_map, index, 0);
        goto out;
    }

    bpf_printk("Tail ctx\n");
    struct xf_act act;
    memset(&act, 0, sizeof(struct xf_act));
    // int type = -1;
    // struct xf_act *actx = (struct xf_act *)&acts->data[0];
    // type = actx->hdr.type;
    int ret;

        int type = xfa_next_data(acts, &act);
        // if (type < 0) {
        //     action = XDP_ABORTED;
        //     break;
        // }
        switch(type) {
            case XDP_ACTION_ATTR_UNSPEC: {
                ret = xdp_unspec(ctx);
                if (ret) 
                    action = XDP_ABORTED;
                break;
            }
            case XDP_ACTION_ATTR_OUTPUT: {
                __u32 *port_no = (__u32 *)&act.data ;
                ret = xdp_output(ctx, *port_no);
                if (ret < 0)
                    action = XDP_ABORTED;
                action = ret;
                goto out; // output should be the last action where included
            }
            case XDP_ACTION_ATTR_USERSPACE: {
                void *xf_act = (void *) act.data;
                if (xdp_userspace(ctx, xf_act, act.hdr.len))
                    action = XDP_ABORTED;
                break;
            }
            case XDP_ACTION_ATTR_SET: {
                void *xf_act = (void *) act.data;
                if (xdp_set(ctx, xf_act, act.hdr.len))
                    action = XDP_ABORTED;
                break;
            }
            case XDP_ACTION_ATTR_PUSH_VLAN: {
                struct xdp_action_push_vlan *xf_act = (struct xdp_action_push_vlan *) act.data;
                if (xdp_push_vlan(ctx, xf_act))
                    action = XDP_ABORTED;
                break;
            }
            // case XDP_ACTION_ATTR_POP_VLAN: {
            //     if (xdp_pop_vlan(ctx) < 0)
            //         action = XDP_ABORTED;
            //     break;
            // }
            case XDP_ACTION_ATTR_SAMPLE: {
                void *xf_act = (void *) act.data;
                if (xdp_sample(ctx, xf_act, act.hdr.len))
                    action = XDP_ABORTED;
                break;
            }
            case XDP_ACTION_ATTR_RECIRC: {
                __u32 *recirc_id = (__u32 *) &act.data;
                ret = xdp_recirc(ctx, *recirc_id);
                if (ret < 0)
                    action = XDP_ABORTED;
                break;
            }
            case XDP_ACTION_ATTR_HASH: {
                struct xdp_action_hash *xf_act = (struct xdp_action_hash *) &act.data;
                if (xdp_hash(ctx, xf_act))
                    action = XDP_ABORTED;
                break;
            }
            case XDP_ACTION_ATTR_PUSH_MPLS: {
                struct xdp_action_push_mpls *xf_act = (struct xdp_action_push_mpls *) &act.data;
                if (xdp_push_mpls(ctx, xf_act))
                    action = XDP_ABORTED;
                break;
            }
            case XDP_ACTION_ATTR_POP_MPLS: {
                __be16 *xf_act = (__be16 *) &act.data;
                if (xdp_pop_mpls(ctx, *xf_act))
                    action = XDP_ABORTED;
                break;
            }
            case XDP_ACTION_ATTR_SET_MASKED: {
                void *xf_act = (void *) act.data;
                if (xdp_set_masked(ctx, xf_act, act.hdr.len))
                    action = XDP_ABORTED;
                break;
            }
            case XDP_ACTION_ATTR_CT: {
                void *xf_act = (void *) act.data;
                if (xdp_ct(ctx, xf_act, act.hdr.len))
                    action = XDP_ABORTED;
                break;
            }
            case XDP_ACTION_ATTR_TRUNC: {
                struct xdp_action_trunc *xf_act = (struct xdp_action_trunc *) &act.data;
                if (xdp_trunc(ctx, xf_act))
                    action = XDP_ABORTED;
                break;
            }
            case XDP_ACTION_ATTR_PUSH_ETH: {
                struct xdp_action_push_eth *xf_act = (struct xdp_action_push_eth *) &act.data;
                if (xdp_push_eth(ctx, xf_act))
                    action = XDP_ABORTED;
                break;
            }
            case XDP_ACTION_ATTR_POP_ETH: {
                if (xdp_pop_eth(ctx))
                    action = XDP_ABORTED;
                break;
            }
            case XDP_ACTION_ATTR_CT_CLEAR: {
                if (xdp_ct_clear(ctx))
                    action = XDP_ABORTED;
                break;
            }
            case XDP_ACTION_ATTR_PUSH_NSH: {
                void *xf_act = (void *) act.data;
                if (xdp_push_nsh(ctx, xf_act, act.hdr.len))
                    action = XDP_ABORTED;
                break;
            }
            case XDP_ACTION_ATTR_POP_NSH: {
                if (xdp_pop_nsh(ctx))
                    action = XDP_ABORTED;
                break;
            }
            case XDP_ACTION_ATTR_METER: {
                __u32 *meter_id = (__u32 *) &act.data;
                ret = xdp_meter(ctx, *meter_id);
                if (ret < 0)
                    action = XDP_ABORTED;
                break;
            }
            case XDP_ACTION_ATTR_CLONE: {
                void *xf_act = (void *) act.data;
                if (xdp_clone(ctx, xf_act, act.hdr.len))
                    action = XDP_ABORTED;
                break;
            }
            case XDP_ACTION_ATTR_DROP: {
                ret = xdp_drop(ctx);
                if (ret < 0)
                    action = XDP_ABORTED;
                action = XDP_DROP;
                break;
            }
            case __XDP_ACTION_ATTR_MAX:
            default: {
                action = XDP_ABORTED;
            } 
        }

        // One of the actions failed, otherwise the program work execute here
        if (action == XDP_ABORTED) {
            if (log_level & LOG_ERR) {
                char msg[LOG_MSG_SIZE] = "Error occured whilst applying actions to packet";
                logger(ctx, LOG_ERR, msg, LOG_MSG_SIZE);
            }
        }

    

out:
    bpf_printk("xdp_inline_actions exiting\n");
    return action;
}

char _license[] SEC("license") = "GPL";
