#ifndef tail_action_prog_H
#define tail_action_prog_H 1

#include <linux/in.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <net/if_arp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
// #include <linux/bpf.h>
#include <linux/in.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "flow.h"
#include "parsing_helpers.h"
#include "xf_kern.h"
#include "xf.h"
#include "actions.h"


// /* NOTE: loading a xdp program for afxdp depends on the map being
//  * named 'xsks_map' */
// /* map #5 */
// struct bpf_map SEC("maps") xsks_map = {
//     .type = BPF_MAP_TYPE_XSKMAP,
//     .key_size = sizeof(int),
//     .value_size = sizeof(int),
//     .max_entries = 64,  /* Assume netdev has no more than 64 queues */
// };

// /* map #6 */
// struct bpf_map SEC("maps") _perf_map = {
//     .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
//     .key_size = sizeof(int),
//     .value_size = sizeof(__u32),
//     .max_entries = MAX_CPUS,
// };


#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"


SEC("XDP_ACTION_ATTR_UNSPEC")
int xdp_unspec_prog(struct xdp_md *ctx)
{
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_unspec_prog tail program";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    // tail_action_prog(ctx);

    if (log_level & LOG_ERR) {
        char msg[LOG_MSG_SIZE] = "xdp_unspec_prog tail program could not tail to next program";
        logger(ctx, LOG_ERR, msg, LOG_MSG_SIZE);
    }
    return XDP_DROP;
}

SEC("XDP_ACTION_ATTR_OUTPUT")
int xdp_output_prog(struct xdp_md *ctx)
{
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_output_prog tail program";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    tail_action_prog(ctx);

    if (log_level & LOG_ERR) {
        char msg[LOG_MSG_SIZE] = "xdp_output_prog tail program could not tail to next program";
        logger(ctx, LOG_ERR, msg, LOG_MSG_SIZE);
    }
    return XDP_DROP;
}

SEC("XDP_ACTION_ATTR_USERSPACE")
int xdp_userspace_prog(struct xdp_md *ctx)
{
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_userspace_prog tail program";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    tail_action_prog(ctx);

    if (log_level & LOG_ERR) {
        char msg[LOG_MSG_SIZE] = "xdp_userspace_prog tail program could not tail to next program";
        logger(ctx, LOG_ERR, msg, LOG_MSG_SIZE);
    }
    return XDP_DROP;
}

SEC("XDP_ACTION_ATTR_SET")
int xdp_set_prog(struct xdp_md *ctx)
{
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_set_prog tail program";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    tail_action_prog(ctx);

    if (log_level & LOG_ERR) {
        char msg[LOG_MSG_SIZE] = "xdp_set_prog tail program could not tail to next program";
        logger(ctx, LOG_ERR, msg, LOG_MSG_SIZE);
    }
    return XDP_DROP;
}

SEC("XDP_ACTION_ATTR_PUSH_VLAN")
int xdp_push_vlan_prog(struct xdp_md *ctx)
{
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_push_vlan_prog tail program";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    tail_action_prog(ctx);

    if (log_level & LOG_ERR) {
        char msg[LOG_MSG_SIZE] = "xdp_push_vlan_prog tail program could not tail to next program";
        logger(ctx, LOG_ERR, msg, LOG_MSG_SIZE);
    }
    return XDP_DROP;
}                    

SEC("XDP_ACTION_ATTR_POP_VLAN")
int xdp_pop_vlan_prog(struct xdp_md *ctx)
{
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_pop_vlan_prog tail program";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    tail_action_prog(ctx);

    if (log_level & LOG_ERR) {
        char msg[LOG_MSG_SIZE] = "xdp_pop_vlan_prog tail program could not tail to next program";
        logger(ctx, LOG_ERR, msg, LOG_MSG_SIZE);
    }
    return XDP_DROP;
}

SEC("XDP_ACTION_ATTR_SAMPLE")
int xdp_sample_prog(struct xdp_md *ctx)
{
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_sample_prog tail program";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    tail_action_prog(ctx);

    if (log_level & LOG_ERR) {
        char msg[LOG_MSG_SIZE] = "xdp_sample_prog tail program could not tail to next program";
        logger(ctx, LOG_ERR, msg, LOG_MSG_SIZE);
    }
    return XDP_DROP;
}

SEC("XDP_ACTION_ATTR_RECIRC")
int xdp_recirc_prog(struct xdp_md *ctx)
{
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_recirc_prog tail program";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    tail_action_prog(ctx);

    if (log_level & LOG_ERR) {
        char msg[LOG_MSG_SIZE] = "xdp_recirc_prog tail program could not tail to next program";
        logger(ctx, LOG_ERR, msg, LOG_MSG_SIZE);
    }
    return XDP_DROP;
}

SEC("XDP_ACTION_ATTR_HASH")
int xdp_hash_prog(struct xdp_md *ctx)
{
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_hash_prog tail program";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    tail_action_prog(ctx);

    if (log_level & LOG_ERR) {
        char msg[LOG_MSG_SIZE] = "xdp_hash_prog tail program could not tail to next program";
        logger(ctx, LOG_ERR, msg, LOG_MSG_SIZE);
    }
    return XDP_DROP;
}

SEC("XDP_ACTION_ATTR_PUSH_MPLS")
int xdp_push_mpls_prog(struct xdp_md *ctx)
{
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_push_mpls_prog tail program";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    tail_action_prog(ctx);

    if (log_level & LOG_ERR) {
        char msg[LOG_MSG_SIZE] = "xdp_push_mpls_prog tail program could not tail to next program";
        logger(ctx, LOG_ERR, msg, LOG_MSG_SIZE);
    }
    return XDP_DROP;
}

SEC("XDP_ACTION_ATTR_POP_MPLS")
int xdp_pop_mpls_prog(struct xdp_md *ctx)
{
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_pop_mpls_prog tail program";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    tail_action_prog(ctx);

    if (log_level & LOG_ERR) {
        char msg[LOG_MSG_SIZE] = "xdp_pop_mpls_prog tail program could not tail to next program";
        logger(ctx, LOG_ERR, msg, LOG_MSG_SIZE);
    }
    return XDP_DROP;
}

SEC("XDP_ACTION_ATTR_SET_MASKED")
int xdp_set_masked_prog(struct xdp_md *ctx)
{
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_set_masked_prog tail program";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    tail_action_prog(ctx);

    if (log_level & LOG_ERR) {
        char msg[LOG_MSG_SIZE] = "xdp_set_masked_prog tail program could not tail to next program";
        logger(ctx, LOG_ERR, msg, LOG_MSG_SIZE);
    }
    return XDP_DROP;
}

SEC("XDP_ACTION_ATTR_CT")
int xdp_ct_prog(struct xdp_md *ctx)
{
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_ct_prog tail program";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    tail_action_prog(ctx);

    if (log_level & LOG_ERR) {
        char msg[LOG_MSG_SIZE] = "xdp_ct_prog tail program could not tail to next program";
        logger(ctx, LOG_ERR, msg, LOG_MSG_SIZE);
    }
    return XDP_DROP;
}

SEC("XDP_ACTION_ATTR_TRUNC")
int xdp_trunc_prog(struct xdp_md *ctx)
{
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_trunc_prog tail program";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    tail_action_prog(ctx);

    if (log_level & LOG_ERR) {
        char msg[LOG_MSG_SIZE] = "xdp_trunc_prog tail program could not tail to next program";
        logger(ctx, LOG_ERR, msg, LOG_MSG_SIZE);
    }
    return XDP_DROP;
}                    

SEC("XDP_ACTION_ATTR_PUSH_ETH")
int xdp_push_eth_prog(struct xdp_md *ctx)
{
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_push_eth_prog tail program";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    tail_action_prog(ctx);

    if (log_level & LOG_ERR) {
        char msg[LOG_MSG_SIZE] = "xdp_push_eth_prog tail program could not tail to next program";
        logger(ctx, LOG_ERR, msg, LOG_MSG_SIZE);
    }
    return XDP_DROP;   
}

SEC("XDP_ACTION_ATTR_POP_ETH")
int xdp_pop_eth_prog(struct xdp_md *ctx)
{
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_pop_eth_prog tail program";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    tail_action_prog(ctx);

    if (log_level & LOG_ERR) {
        char msg[LOG_MSG_SIZE] = "xdp_pop_eth_prog tail program could not tail to next program";
        logger(ctx, LOG_ERR, msg, LOG_MSG_SIZE);
    }
    return XDP_DROP;
}

SEC("XDP_ACTION_ATTR_CT_CLEAR")
int xdp_ct_clear_prog(struct xdp_md *ctx)
{
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_ct_clear_prog tail program";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    tail_action_prog(ctx);

    if (log_level & LOG_ERR) {
        char msg[LOG_MSG_SIZE] = "xdp_ct_clear_prog tail program could not tail to next program";
        logger(ctx, LOG_ERR, msg, LOG_MSG_SIZE);
    }
    return XDP_DROP;
}

SEC("XDP_ACTION_ATTR_PUSH_NSH")
int xdp_push_nsh_prog(struct xdp_md *ctx)
{
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_push_nsh_prog tail program";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    tail_action_prog(ctx);

    if (log_level & LOG_ERR) {
        char msg[LOG_MSG_SIZE] = "xdp_push_nsh_prog tail program could not tail to next program";
        logger(ctx, LOG_ERR, msg, LOG_MSG_SIZE);
    }
    return XDP_DROP;
}

SEC("XDP_ACTION_ATTR_POP_NSH")
int xdp_pop_nsh_prog(struct xdp_md *ctx)
{
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_pop_nsh_prog tail program";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    tail_action_prog(ctx);

    if (log_level & LOG_ERR) {
        char msg[LOG_MSG_SIZE] = "xdp_pop_nsh_prog tail program could not tail to next program";
        logger(ctx, LOG_ERR, msg, LOG_MSG_SIZE);
    }
    return XDP_DROP;
}

SEC("XDP_ACTION_ATTR_METER")
int xdp_meter_prog(struct xdp_md *ctx)
{
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_meter_prog tail program";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    tail_action_prog(ctx);

    if (log_level & LOG_ERR) {
        char msg[LOG_MSG_SIZE] = "xdp_meter_prog tail program could not tail to next program";
        logger(ctx, LOG_ERR, msg, LOG_MSG_SIZE);
    }
    return XDP_DROP;
}

SEC("XDP_ACTION_ATTR_CLONE")
int xdp_clone_prog(struct xdp_md *ctx)
{
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_clone_prog tail program";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    tail_action_prog(ctx);

    if (log_level & LOG_ERR) {
        char msg[LOG_MSG_SIZE] = "xdp_clone_prog tail program could not tail to next program";
        logger(ctx, LOG_ERR, msg, LOG_MSG_SIZE);
    }
    return XDP_DROP;
}

SEC("XDP_ACTION_ATTR_DROP")
int xdp_drop_prog(struct xdp_md *ctx)
{
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_drop_prog tail program";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    tail_action_prog(ctx);

    if (log_level & LOG_ERR) {
        char msg[LOG_MSG_SIZE] = "xdp_drop_prog tail program could not tail to next program";
        logger(ctx, LOG_ERR, msg, LOG_MSG_SIZE);
    }
    return XDP_DROP;
}

SEC("XDP_ACTION_ATTR_UPCALL")
int xdp_upcall_prog(struct xdp_md *ctx)
{
    if (log_level & LOG_DEBUG) {
        char msg[LOG_MSG_SIZE] = "Executing xdp_upcall_prog tail program";
        logger(ctx, LOG_DEBUG, msg, LOG_MSG_SIZE);
    }

    tail_action_prog(ctx);

    if (log_level & LOG_ERR) {
        char msg[LOG_MSG_SIZE] = "xdp_upcall_prog tail program could not tail to next program";
        logger(ctx, LOG_ERR, msg, LOG_MSG_SIZE);
    }
    return XDP_DROP;   
}

#pragma GCC diagnostic pop

#endif /* tail_action_progs.h */