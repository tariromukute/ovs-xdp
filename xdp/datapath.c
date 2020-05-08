#include "datapath.h"
#include "flow-table.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
int xdp_dp_downcall(struct datapath *dp, const struct xdp_flow_key *key,
            const struct dp_downcall_info *info)
{
    int err = 0;

    return err;
}

const char *xdp_dp_name(const struct datapath *dp)
{
    return "";
}

/* datapath crud */
int xdp_dp_create(struct datapath *dp)
{
    int err = 0;

    return err;
}

int xdp_dp_update(struct datapath *dp)
{
    int err = 0;

    return err;
}

int xdp_dp_delete(struct datapath *dp)
{
    int err = 0;

    return err;
}

int xdp_dp_fetch(struct datapath *dp)
{
    int err = 0;

    return err;
}

/* datapath port actions */
int xdp_dp_port_add(struct datapath *dp, struct xport *xport)
{
    int err = 0;

    return err;
}

int xdp_dp_port_del(struct datapath *dp, struct xport *xport)
{
    int err = 0;

    return err;
}

int xdp_dp_port_lookup(struct datapath *dp, struct xport *xport)
{
    int err = 0;

    return err;
}

int xdp_dp_port_next(struct datapath *dp, struct xport *xport)
{
    int err = 0;

    return err;
}

/* entry point flows */
int xdp_ep_flow_lookup(int map_fd, struct xdp_flow_key *key, struct xdp_flow *flow)
{
    int err = 0;

    flow = xdp_flow_map_lookup(map_fd, key);

    return err;
}

int xdp_ep_flow_insert(int map_fd, struct xdp_flow *flow)
{
    int err = 0;

    err = xdp_flow_map_insert(map_fd, flow);

    return err;
}

/* TODO: think need pointer to a pointer here for key */
int xdp_ep_flow_next(int map_fd, struct xdp_flow_key *key, struct xdp_flow *flow)
{
    int err = 0;

    struct xdp_flow_key nkey;

    err = xdp_flow_map_next_key(map_fd, key, &nkey);

    key = &nkey;

    return err;
}

int xdp_ep_flow_remove(int map_fd, struct xdp_flow_key *key)
{
    int err = 0;

    err = xdp_flow_map_remove(map_fd, key);

    return err;
}

int xdp_ep_flow_flush(int map_fd)
{
    int err = 0;

    err = xdp_flow_map_flush(map_fd);

    return err;
}

/* datapath flows */
int xdp_dp_flow_lookup(struct datapath *dp, struct xdp_flow_key *key, struct xdp_flow *flow)
{
    int err = 0;

    return err;
}

int xdp_dp_flow_insert(struct datapath *dp, struct xdp_flow *flow)
{
    int err = 0;

    return err;
}

int xdp_dp_flow_next(struct datapath *dp, struct xdp_flow_key *key, struct xdp_flow *flow)
{
    int err = 0;

    return err;
}

int xdp_dp_flow_remove(struct datapath *dp, struct xdp_flow_key *key)
{
    int err = 0;

    return err;
}

int xdp_dp_flow_flush(struct datapath *dp, struct xdp_flow_key *key)
{
    int err = 0;

    return err;
}
#pragma GCC diagnostic pop

