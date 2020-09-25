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

// typedef int (tail_call_fn)(struct xdp_md *);

// SEC("XDP_ACTION_ATTR_OUTPUT")
// int output_prog(struct xdp_md *ctx)
// {
//     if (log_level & LOG_DEBUG) {
//         char msg[LOG_MSG_SIZE] = "Executing xdp_output_prog tail program";
//         logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
//     }

//     tail_action_prog(ctx);

//     if (log_level & LOG_ERR) {
//         char msg[LOG_MSG_SIZE] = "xdp_output_prog tail program could not tail to next program";
//         logger(ctx, LOG_ERR, msg, LOG_MSG_SIZE);
//     }
//     return XDP_DROP;
// }

// SEC("XDP_ACTION_ATTR_USERSPACE")
// int userspace_prog(struct xdp_md *ctx)
// {
//     if (log_level & LOG_DEBUG) {
//         char msg[LOG_MSG_SIZE] = "Executing xdp_userspace_prog tail program";
//         logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
//     }

//     tail_action_prog(ctx);

//     if (log_level & LOG_ERR) {
//         char msg[LOG_MSG_SIZE] = "xdp_userspace_prog tail program could not tail to next program";
//         logger(ctx, LOG_ERR, msg, LOG_MSG_SIZE);
//     }
//     return XDP_DROP;
// }

// struct {
// 	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
// 	__uint(max_entries, 2);
// 	__array(values, tail_call_fn);
// } jmp_table SEC(".maps") = {
//     .values = { &output_prog, &userspace_prog }
// };

SEC("prog")
int xdp_ep_tail_actions(struct xdp_md *ctx)
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
        // int index = xdp_upcall(ctx, &key);
        // if (index < 0) {
        //     goto out;
        // }
        // /* NOTE: if you don't put bpf_redirect_map in the program that you load to on the interface
        //  * and rather put it in a tail program e.g., bpf_tail_call(ctx, &tail_table, OVS_ACTION_ATTR_UPCALL)
        //  * and you create a xsk_socket for the interface. The xsk_socket seems to be created without an error
        //  * but on trying to do xsk_socket__fd(xsk_socket->xsk) you get a segmentation fault. This is resolved
        //  * by putting bpf_redirect_map(&xsks_map, index, 0) directly into the program loaded. However, calling
        //  * bpf_tail_call(ctx, &tail_table, OVS_ACTION_ATTR_UPCALL) i.e, invoking a tail program that will send
        //  * to a xsk_socket, before bpf_redirect_map(&xsks_map, index, 0) will still result in the packets being
        //  * delivered, i.e, being sent by the tail program and not the bpf_redirect_map TODO: check the libbpf or 
        //  * helper function why this is, it maybe due to some 'enforced' logic that can be changed */
        // if (bpf_map_lookup_elem(&xsks_map, &index))
        //     return bpf_redirect_map(&xsks_map, index, 0);

        goto out;
    }

    bpf_printk("Tail ctx\n");
    
    /* Add actions to the ctx for reading by the tail programs */
    __u32 k = 0;
    if (bpf_map_update_elem(&_xfa_buf_map, &k, acts, 0))
    {
        bpf_printk("Could not update percpu_actions map\n");
        goto out;
    } 
    int xfa_type = tail_action_prog__(ctx);
    if (xfa_type > 0 && xfa_type < XDP_ACTION_ATTR_MAX) {
        bpf_tail_call(ctx, &xf_tail_map, xfa_type);
        // action = XDP_DROP;
    }
    // bpf_tail_call(ctx, &jmp_table, 1);

    // bpf_tail_call(ctx, &tail_table, 1);
out:
    bpf_printk("xdp_process - tail failed\n");
    return action;
}

char _license[] SEC("license") = "GPL";