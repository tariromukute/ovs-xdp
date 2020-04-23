#include "flow.h"
#include "flow-table.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

int ovs_flow_init()
{
    /* TODO: implement method */
    return 0;
}

void ovs_flow_exit()
{
    /* TODO: implement method */
}


struct xdp_flow *ovs_flow_alloc()
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