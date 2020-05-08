#include "flow.h"
#include "flow-table.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"


struct xdp_flow *xdp_flow_alloc()
{
    struct xdp_flow *flow = NULL;
    /* TODO: implement method */

    return flow;
}

int xdp_flow_map_count(int map_fd)
{
    /* TODO: implement method */
    return 0;
}

int xdp_flow_map_flush(int map_fd)
{
    /* TODO: implement method */
    return 0;
}


int xdp_flow_map_insert(int map_fd, struct xdp_flow *flow)
{
    /* TODO: implement method */
    return 0;
}

int xdp_flow_map_remove(int map_fd, struct xdp_flow_key *key)
{
    /* TODO: implement method */
    return 0;
}

int xdp_flow_map_num_masks(int map_fd)
{
    /* TODO: implement method */
    return 0;
}

int xdp_flow_map_next_key(int map_fd, struct xdp_flow_key *ckey, struct xdp_flow_key *nkey)
{
    nkey = NULL;

    return 0;
}

struct xdp_flow *xdp_flow_map_lookup(int map_fd, const struct xdp_flow_key *key)
{
    struct xdp_flow *flow = NULL;
    /* TODO: implement method */

    return flow;
}

struct xdp_flow *xdp_flow_map_lookup_ufid(int map_fd, const struct xdp_flow_id *id)
{
    struct xdp_flow *flow = NULL;
    /* TODO: implement method */

    return flow;
}
#pragma GCC diagnostic pop