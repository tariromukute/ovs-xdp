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
int xdp_xs_inline_actions(struct xdp_md *ctx)
{
    int action = XDP_PASS;
    // void *data_end = (void *)(long)ctx->data_end;
    // void *data = (void *)(long)ctx->data;
    // struct hdr_cursor nh = { .pos = data };

    // int err;
    struct xf_key key;
    memset(&key, 0, sizeof(struct xf_key));

    // err = xfk_extract(&nh, data_end, &key);
    // if (err) {
    //     action = XDP_DROP;
    //     goto out;
    // }

    // // if arp deal with it
    if (key.valid & ARP_VALID) {
        action = XDP_PASS;
        goto out; // output should be the last action where included
    }
    struct xfa_buf *acts = bpf_map_lookup_elem(&_xf_macro_map, &key);
    if (!acts) /* If there are no flow actions, run output */
    {
        int ret = xdp_normal(ctx);
        if (ret < 0)
            action = XDP_ABORTED;
            
        action = ret;
        goto out;
    }

    /* Check that the number of actions is less that the maximum */
    __u32 num = acts->hdr.num;
    if (num > XFA_BUF_MAX_NUM) {
        action = XDP_DROP;
        goto out;
    }

    /* Initialise actions cursor */
    struct xfa_cur cursor = { 0 };

    /* NOTE: if we have the loop iterate for acts->cursor.num and first bound check if num < XFA_BUF_MAX_NUM
     * the verifier returns error 'The sequence of 8193 jumps is too complex' so just going to have the loop
     * run for XFA_BUF_MAX_NUM and it will terminate when all the actions have been found. */
    int index = 0;    
    for(index = 0; index < XFA_BUF_MAX_NUM; index++) {
        bpf_printk("Processing actions, loop num: %d cursor cnt %d, cursor total actions: %d", index, cursor.cnt, acts->hdr.num);
        struct xf_act a;
        memset(&a, 0, sizeof(struct xf_act));
        int ret = xfa_next_data(acts, &cursor, &a);

        if (ret < 0) {
            action = XDP_ABORTED;
            break;
        } else if (ret == 0) {
            break;            
        }

        bpf_printk("Processing action type: %d\n", a.hdr.type);
        switch(a.hdr.type) {
            case XDP_ACTION_ATTR_UNSPEC: {
                ret = xdp_unspec(ctx);
                if (ret) 
                    action = XDP_ABORTED;
                break;
            }
            case XDP_ACTION_ATTR_NORMAL: {
                __u32 *port_no = (__u32 *)&a.data ;
                ret = xdp_output(ctx, *port_no);
                if (ret < 0)
                    action = XDP_ABORTED;
                action = ret;
                // action = XDP_PASS;
                goto out; // output should be the last action where included
            }
            case XDP_ACTION_ATTR_OUTPUT: {
                __u32 *port_no = (__u32 *)&a.data ;
                ret = xdp_output(ctx, *port_no);
                if (ret < 0)
                    action = XDP_ABORTED;
                action = ret;
                // action = XDP_PASS;
                goto out; // output should be the last action where included
            }
            case XDP_ACTION_ATTR_USERSPACE: {
                void *xf_act = (void *) a.data;
                if (xdp_userspace(ctx, xf_act, a.hdr.len))
                    action = XDP_ABORTED;
                break;
            }
            case XDP_ACTION_ATTR_SET: {
                void *xf_act = (void *) a.data;
                if (xdp_set(ctx, xf_act, a.hdr.len))
                    action = XDP_ABORTED;
                break;
            }
            case XDP_ACTION_ATTR_PUSH_VLAN: {
                struct xdp_action_push_vlan *xf_act = (struct xdp_action_push_vlan *) a.data;
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
                void *xf_act = (void *) a.data;
                if (xdp_sample(ctx, xf_act, a.hdr.len))
                    action = XDP_ABORTED;
                break;
            }
            case XDP_ACTION_ATTR_RECIRC: {
                __u32 *recirc_id = (__u32 *) &a.data;
                ret = xdp_recirc(ctx, *recirc_id);
                if (ret < 0)
                    action = XDP_ABORTED;
                break;
            }
            case XDP_ACTION_ATTR_HASH: {
                struct xdp_action_hash *xf_act = (struct xdp_action_hash *) &a.data;
                if (xdp_hash(ctx, xf_act))
                    action = XDP_ABORTED;
                break;
            }
            case XDP_ACTION_ATTR_PUSH_MPLS: {
                struct xdp_action_push_mpls *xf_act = (struct xdp_action_push_mpls *) &a.data;
                if (xdp_push_mpls(ctx, xf_act))
                    action = XDP_ABORTED;
                break;
            }
            case XDP_ACTION_ATTR_POP_MPLS: {
                __be16 *xf_act = (__be16 *) &a.data;
                if (xdp_pop_mpls(ctx, *xf_act))
                    action = XDP_ABORTED;
                break;
            }
            case XDP_ACTION_ATTR_SET_MASKED: {
                void *xf_act = (void *) a.data;
                if (xdp_set_masked(ctx, xf_act, a.hdr.len))
                    action = XDP_ABORTED;
                break;
            }
            case XDP_ACTION_ATTR_CT: {
                void *xf_act = (void *) a.data;
                if (xdp_ct(ctx, xf_act, a.hdr.len))
                    action = XDP_ABORTED;
                break;
            }
            case XDP_ACTION_ATTR_TRUNC: {
                struct xdp_action_trunc *xf_act = (struct xdp_action_trunc *) &a.data;
                if (xdp_trunc(ctx, xf_act))
                    action = XDP_ABORTED;
                break;
            }
            case XDP_ACTION_ATTR_PUSH_ETH: {
                struct xdp_action_push_eth *xf_act = (struct xdp_action_push_eth *) &a.data;
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
                void *xf_act = (void *) a.data;
                if (xdp_push_nsh(ctx, xf_act, a.hdr.len))
                    action = XDP_ABORTED;
                break;
            }
            case XDP_ACTION_ATTR_POP_NSH: {
                if (xdp_pop_nsh(ctx))
                    action = XDP_ABORTED;
                break;
            }
            case XDP_ACTION_ATTR_METER: {
                __u32 *meter_id = (__u32 *) &a.data;
                ret = xdp_meter(ctx, *meter_id);
                if (ret < 0)
                    action = XDP_ABORTED;
                break;
            }
            case XDP_ACTION_ATTR_CLONE: {
                void *xf_act = (void *) a.data;
                if (xdp_clone(ctx, xf_act, a.hdr.len))
                    action = XDP_ABORTED;
                break;
            }
            case XDP_ACTION_ATTR_DROP: {
                ret = xdp_drop(ctx);
                action = XDP_DROP;
                if (ret < 0)
                    action = XDP_ABORTED;
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
            break;
        }
    } 

out:
    bpf_printk("xdp_inline_actions exiting with action %d\n", action);
    return action;
}

char _license[] SEC("license") = "GPL";
