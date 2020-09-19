#ifndef TAIL_ACTION_H
#define TAIL_ACTION_H 1

#include <linux/bpf.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "flow.h"

#include "parsing_helpers.h"

#define SAMPLE_SIZE 64ul
// #define SAMPLE_SIZE sizeof(struct xdp_flow_key)
#define MAX_CPUS 128

/* Action header cursor to keep track of current parsing position */
struct act_cursor {
    __u8 type; /* Determine the type of attr - enum ovs_action_attr*/
    __u8 len; /* len of the whole xdp_flow_action as a multiple of u8 */
};

struct bpf_map_def SEC("maps") tail_table = {
    .type = BPF_MAP_TYPE_PROG_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = TAIL_TABLE_SIZE,
};

struct bpf_map_def SEC("maps") percpu_actions = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = XDP_FLOW_ACTIONS_LEN_u64,
    .max_entries = 1,
};

struct bpf_map_def SEC("maps") flow_table = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = XDP_FLOW_KEY_LEN_u64,
    .value_size = XDP_FLOW_ACTIONS_LEN_u64,
    .max_entries = 100,
};

struct bpf_map_def SEC("maps") flow_stats_table = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = XDP_FLOW_KEY_LEN_u64,
    .value_size = XDP_FLOW_STATS_LEN_u64,
    .max_entries = 100,
};

/* NOTE: loading a xdp program for afxdp depends on the map being
 * named 'xsks_map' */
struct bpf_map_def SEC("maps") xsks_map = {
    .type = BPF_MAP_TYPE_XSKMAP,
    .key_size = sizeof(int),
    .value_size = sizeof(int),
    .max_entries = 64,  /* Assume netdev has no more than 64 queues */
};

struct bpf_map_def SEC("maps") _perf_map = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(__u32),
    .max_entries = MAX_CPUS,
};

struct bpf_map_def SEC("maps") _ports = {
    .type = BPF_MAP_TYPE_ARRAY_OF_MAPS,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = MAX_CPUS,
};

struct bpf_map_def SEC("maps") port_flow = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = XDP_FLOW_KEY_LEN_u64,
    .value_size = XDP_FLOW_ACTIONS_LEN_u64,
    .max_entries = 100,
};

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

static __always_inline int parse_flow_metadata(struct hdr_cursor *nh,
                                       void *data_end,
                                       __u8 fmbuf[XDP_FLOW_METADATA_KEY_LEN_u64])
{
    // struct flow_metadata *fmh = nh->pos;

    if (nh->pos + XDP_FLOW_METADATA_KEY_LEN_u64 > data_end)
        return -1;

    memcpy(fmbuf, nh->pos, XDP_FLOW_METADATA_KEY_LEN_u64);
    nh->pos += XDP_FLOW_METADATA_KEY_LEN_u64;

    return 0;
}

/* This method updates the metadata which keeps track of the progress of the
   packet/flow processing. It increments the position (pos) of the action being
   processed from the previous to the current. Before doing so it checks if there 
   is still another action. It also updates the offset to be at the first byte of
   the action being processed. */
static __always_inline __u8 next_action(__u8 fmbuf[XDP_FLOW_METADATA_KEY_LEN_u64],
                                        void *data_end)
{
    struct xdp_flow_actions *actions;
    __u32 k = 0;
    actions = bpf_map_lookup_elem(&percpu_actions, &k);
    if (!actions) {
        // bpf_printk("Could not get percpu action\n");
        return -1;
    }

    struct flow_metadata *fm = (struct flow_metadata *)fmbuf;
    
    /* NOTE: 2 is sizeof(struct act_cursor), for some reason putting causes the program
     * to fail to load. When you change the struct act_cursor also change the 2 below.  */
    int next_offset = fm->offset + 2;
    
    // check if there is another action
    if (next_offset > actions->len) {
        return -1;
    }

    // bound check
    if (fm->offset + 2 > MAX_ACTION_SIZE) {
        return -1;
    }

    __u8 pos = 0;
    // Move position to current action
    if (pos + fm->offset > MAX_ACTION_SIZE) {
        return -1;
    }
    pos += fm->offset;

    // Point cursor to current action header
    if (pos + sizeof (struct act_cursor) > MAX_ACTION_SIZE) {
        return -1;
    }
    struct act_cursor *cur = (struct act_cursor *) &actions->data[pos];
    
    // Advance the offset and position
    fm->offset += cur->len;
    fm->pos += 1;
    return cur->type;
}

static __always_inline void tail_action(struct xdp_md *ctx)
{
    /* TODO: Implement method */

    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    /* These keep track of the next header type and iterator pointer */
    struct hdr_cursor nh = { .pos = data };
    __u8 fmbuf[XDP_FLOW_METADATA_KEY_LEN_u64];
    memset(fmbuf, 0, XDP_FLOW_METADATA_KEY_LEN_u64);

    /* Parse xdp flow metadata */
    if (parse_flow_metadata(&nh, data_end, fmbuf) < 0) {
        bpf_printk("flow-metadata parse failed\n");
    } else {
        struct flow_metadata *fm = (struct flow_metadata *)fmbuf;
        bpf_printk("flow_metadata before next_action pos %x\n", fm->pos);
        bpf_printk("flow_metadata before next_action offset %x\n", fm->offset);
        int flow_action = next_action(fmbuf, data_end);
        bpf_printk("flow_metadata after next_action pos %x\n", fm->pos);
        bpf_printk("flow_metadata after next_action offset %x\n", fm->offset);
        bpf_printk("flow_action is: %d\n", flow_action);
        if (flow_action > 0 && flow_action <= XDP_ACTION_ATTR_MAX) {
            bpf_tail_call(ctx, &tail_table, flow_action);
        }    
    }

    // No more actions, exiting
}

static __always_inline int add_actions(struct xdp_md *ctx, 
                struct xdp_flow_actions *acts, struct xdp_flow_id *id)
{
    /* TODO: Implement method */

    // get the length of the actions

    // create flow_metadata

    // get size of flow_metadata

    // tail grow the ctx by the size

    // add the flow_metadata to the ctx

    // return function with no error
    return 0;
}

static __always_inline int remove_actions(struct xdp_md *ctx)
{
    /* TODO: Implement method */

    // read the flow_metadata on the ctx

    // get the length of the flow_metadata

    // shrink the ctx by size of metadata

    // return success if no error
    return 0;
}

static __always_inline __u8 has_next(struct xdp_md *ctx)
{
    /* TODO: Implement method */

    // if offset is less than len return true, if equal return false

    return 0;
}

#pragma GCC diagnostic pop

#endif /* tail_actions.h */