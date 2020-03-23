#include "flow.h"
#include "flow-table.h"

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


int ovs_flow_tbl_init(struct flow_table *tbl)
{
    /* TODO: implement method */
    return 0;
}

int ovs_flow_tbl_count(const struct flow_table *table)
{
    /* TODO: implement method */
    return 0;
}

void ovs_flow_tbl_destroy(struct flow_table *table)
{
    /* TODO: implement method */
}

int ovs_flow_tbl_flush(struct flow_table *flow_table)
{
    /* TODO: implement method */
    return 0;
}


int ovs_flow_tbl_insert(struct flow_table *table, struct xdp_flow *flow)
{
    /* TODO: implement method */
    return 0;
}

void ovs_flow_tbl_remove(struct flow_table *table, struct xdp_flow *flow)
{
    /* TODO: implement method */
}

int  ovs_flow_tbl_num_masks(const struct flow_table *table)
{
    /* TODO: implement method */
    return 0;
}

struct xdp_flow *ovs_flow_tbl_lookup(struct flow_table *tbl,
                    const struct xdp_flow_key *key)
{
    struct xdp_flow *flow;
    /* TODO: implement method */

    return flow;
}

struct xdp_flow *ovs_flow_tbl_lookup_ufid(struct flow_table *tbl,
                     const struct xdp_flow_id *id)
{
    struct xdp_flow *flow;
    /* TODO: implement method */

    return flow;
}
#pragma GCC diagnostic pop