/*
 * Example of using bpf tail calls (in XDP programs)
 */
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/openvswitch.h>
#include "bpf_helpers.h"
#include "bpf_endian.h"
#include "tail_actions.h"

// The parsing helper functions from the packet01 lesson have moved here
#include "parsing_helpers.h"
#include "rewrite_helpers.h"

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

#define bpf_printk(fmt, ...)                                    \
({                                                              \
        char ____fmt[] = fmt;                                   \
        bpf_trace_printk(____fmt, sizeof(____fmt),              \
                         ##__VA_ARGS__);                        \
})

SEC("OVS_ACTION_ATTR_PUSH_ETH")
int xdp_action_attr_push_eth(struct xdp_md *ctx)
{
    int action = XDP_PASS;

    bpf_printk(" ==== OVS_ACTION_ATTR_PUSH_ETH === \n");    

    tail_action(ctx);

    bpf_printk(" == !! XDP:  reached fall-through action !! ==\n");
// out:
    return action;
}

SEC("OVS_ACTION_ATTR_POP_ETH")
int xdp_action_attr_pop_eth(struct xdp_md *ctx)
{
    int action = XDP_PASS;

    bpf_printk(" ==== OVS_ACTION_ATTR_POP_ETH === \n");    

    tail_action(ctx);

    bpf_printk(" == !! XDP:  reached fall-through action !! ==\n");
// out:
    return action;
}

SEC("OVS_ACTION_ATTR_OUTPUT")
int xdp_action_attr_output(struct xdp_md *ctx)
{
    int action = XDP_PASS;

    bpf_printk(" ==== OVS_ACTION_ATTR_OUTPUT === \n");    

    tail_action(ctx);

    bpf_printk(" == !! XDP:  reached fall-through action !! ==\n");
// out:
    return action;
}

SEC("OVS_ACTION_ATTR_UPCALL")
int xdp_action_attr_upcall(struct xdp_md *ctx)
{
    int action = XDP_PASS;

    bpf_printk(" === OVS_ACTION_ATTR_UPCALL === \n");
    int index = ctx->rx_queue_index;
    
    bpf_printk("rx_queue_index is: %d\n", index);

    /* A set entry here means that the correspnding queue_id
     * has an active AF_XDP socket bound to it. */
    if (bpf_map_lookup_elem(&xsks_map, &index))
        return bpf_redirect_map(&xsks_map, index, 0);

    bpf_printk("xsk redirect failed\n");
    return action;
}

char _license[] SEC("license") = "GPL";