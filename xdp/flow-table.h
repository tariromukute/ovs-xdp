/**
 * This is the kernel space program that keeps the flow table which
 * is a map. In our approach we have a micro table per interface which
 * are CPU 
 */

#ifndef FLOW_TABLE_H
#define FLOW_TABLE_H 1

#include <linux/bpf.h>

#include "flow.h"

// struct flow_table {
//     struct bpf_pinned_map map;
//     /* port_no */
//     /* bpf_map_def */
// };

struct bpf_map_def SEC("maps") flow_table = {
	.type = BPF_MAP_TYPE_LRU_PERCPU_HASH,
	.key_size = sizeof(struct xdp_flow_id),
	.value_size = sizeof(struct xdp_flow),
	.max_entries = 100,
};

int ovs_flow_init(void);
void ovs_flow_exit(void);

struct xdp_flow *ovs_flow_alloc(void);
void ovs_flow_free(struct xdp_flow *, bool deferred);

int ovs_flow_tbl_init();
int ovs_flow_tbl_count();
void ovs_flow_tbl_destroy();
int ovs_flow_tbl_flush();

int ovs_flow_tbl_insert(struct xdp_flow *flow);
void ovs_flow_tbl_remove(struct xdp_flow *flow);
int  ovs_flow_tbl_num_masks();
struct xdp_flow *ovs_flow_tbl_lookup(const struct xdp_flow_key *);
struct xdp_flow *ovs_flow_tbl_lookup_ufid(const struct xdp_flow_id *);


#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

int ovs_flow_init(void)
{
    /* TODO: implement method */
    return 0;
}

void ovs_flow_exit(void)
{
    /* TODO: implement method */
}


struct xdp_flow *ovs_flow_alloc(void)
{
    struct xdp_flow *flow;
    /* TODO: implement method */

    return flow;
}

void ovs_flow_free(struct xdp_flow *flow, bool deferred)
{
    /* TODO: implement method */
}


int ovs_flow_tbl_init()
{
    /* TODO: implement method */
    return 0;
}

int ovs_flow_tbl_count()
{
    /* TODO: implement method */
    return 0;
}

void ovs_flow_tbl_destroy()
{
    /* TODO: implement method */
}

int ovs_flow_tbl_flush()
{
    /* TODO: implement method */
    return 0;
}


int ovs_flow_tbl_insert(struct xdp_flow *flow)
{
    /* TODO: implement method */
    return 0;
}

void ovs_flow_tbl_remove(struct xdp_flow *flow)
{
    /* TODO: implement method */
}

int  ovs_flow_tbl_num_masks()
{
    /* TODO: implement method */
    return 0;
}

struct xdp_flow *ovs_flow_tbl_lookup(const struct xdp_flow_key *key)
{
    struct xdp_flow *flow;
    /* TODO: implement method */

    return flow;
}

struct xdp_flow *ovs_flow_tbl_lookup_ufid(const struct xdp_flow_id *id)
{
    struct xdp_flow *flow;
    /* TODO: implement method */

    return flow;
}
#pragma GCC diagnostic pop

#endif /* flow_table.h */                     