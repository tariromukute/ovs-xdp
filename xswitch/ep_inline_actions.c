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
    bpf_printk("------------------------------------------------\n");
    int action = XDP_PASS;
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct hdr_cursor nh = { .pos = data };

    int err;
    struct xf_key key;
    memset(&key, 0, sizeof(struct xf_key));

    err = xfk_extract(&nh, data_end, &key);
    if (err) {
        bpf_printk("Error while extracting key\n");
        action = XDP_DROP;
        goto out;
    }

    bpf_printk("Flow key has valid: %d\n", key.valid);
    
    // // if arp deal with it
    // if (key.valid & ARP_VALID) {
    //     bpf_printk("Flow key is arp\n");
    //     __u32 port_no = 2 ;
    //     int ret = xdp_output(ctx, port_no);
    //     if (ret < 0)
    //         action = XDP_ABORTED;
            
    //     bpf_printk("action is: %d\n", ret);
    //     action = ret;
    //     // action = XDP_PASS;
    //     goto out; // output should be the last action where included
    // }
    struct xfa_buf *acts = bpf_map_lookup_elem(&_xf_macro_map, &key);
    if (!acts || key.valid & ARP_VALID) /* If there are no flow actions, make an upcall */
    {
        bpf_printk("Flow entry not found, doing upcall\n");
        int index = xdp_upcall(ctx, &key);
        if (index < 0) {
            goto out;
        }
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
    bpf_printk("Flow entry found, processing flow actions\n");

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
                ret = xdp_normal(ctx);
                if (ret < 0)
                    action = XDP_ABORTED;
                action = ret;
                goto out; // output should be the last action where included
            }
            case XDP_ACTION_ATTR_OUTPUT: {
                __u32 *ifindex = (__u32 *)&a.data;
                ret = xdp_output(ctx, *ifindex);
                if (ret < 0)
                    action = XDP_ABORTED;
                action = ret;
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
