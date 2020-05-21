#ifndef XDP_DATAPATH_H
#define XDP_DATAPATH_H 1

#include <linux/kernel.h>
#include <linux/bpf.h>
#include <linux/if_xdp.h>
// #include <linux/netdevice.h>
// #include <net/net_namespace.h>
// #include <net/ip_tunnels.h>

#include "flow.h"
#include "flow-table.h"

struct xdp_datapath {
    char *name;
};

struct xdp_ep_stats {

};

struct xdp_dp_stats {

};

/* For getting the details of the entry point configured on a port*/
struct xdp_ep {
    char *mode; /* Native, Generic, Offloaded */
    int ep_id; /* Id for the ep, using the flow_map_fd as id may change in future */
    int prog_fd; /* The loaded xdp program */
    int devmap_fd; /* map with destination interfaces for batch flushing */
    int flow_map_fd; /* Flow table, shared map. TODO: if possible make it readonly reference */
    int stats_map_fd; /* table for stats on the performance of the ep */
};

struct xport {

};

struct ovs_xdp_md {

};

#define OVS_CB(xdp_md) ((struct ovs_xdp_md *)(xdp_md)->cb)

/**
 * struct dp_upcall - metadata to include with a packet to send to userspace
 * @cmd: One of %OVS_PACKET_CMD_*.
 * @userdata: If nonnull, its variable-length value is passed to userspace as
 * %OVS_PACKET_ATTR_USERDATA.
 * @portid: Netlink portid to which packet should be sent.  If @portid is 0
 * then no packet is sent and the packet is accounted in the datapath's @n_lost
 * counter.
 * @egress_tun_info: If nonnull, becomes %OVS_PACKET_ATTR_EGRESS_TUN_KEY.
 * @mru: If not zero, Maximum received IP fragment size.
 */
struct dp_downcall_info {
    struct ip_tunnel_info *egress_tun_info;
    const struct nlattr *userdata;
    const struct nlattr *actions;
    int actions_len;
    __u32 portid;
    __u8 cmd;
    __u16 mru;
};

int xdp_dp_downcall(struct xdp_datapath *, const struct xdp_flow_key *,
            const struct dp_downcall_info *);

const char *xdp_dp_name(const struct xdp_datapath *dp);

/* datapath crud */
int
xdp_dp_create(struct xdp_datapath *dp);

int
xdp_dp_update(struct xdp_datapath *dp);

int
xdp_dp_delete(struct xdp_datapath *dp);

int
xdp_dp_fetch(struct xdp_datapath *dp);

/* datapath port actions */
int
xdp_dp_port_add(struct xdp_datapath *dp, struct xport *xport);

int
xdp_dp_port_del(struct xdp_datapath *dp, struct xport *xport);

int
xdp_dp_port_lookup(struct xdp_datapath *dp, struct xport *xport);

int
xdp_dp_port_next(struct xdp_datapath *dp, struct xport *xport);

/* entry point flows */
int
xdp_ep_flow_lookup(int map_fd, struct xdp_flow_key *key, struct xdp_flow *flow);

int
xdp_ep_flow_insert(int map_fd, struct xdp_flow *flow);

int
xdp_ep_flow_next(int map_fd, struct xdp_flow_key *key, struct xdp_flow *flow);

int
xdp_ep_flow_remove(int map_fd, struct xdp_flow_key *key);

int
xdp_ep_flow_flush(int map_fd);

/* entry point flow stats */
int
xdp_ep_flow_stats_lookup(int map_fd, struct xdp_flow_key *key, struct xdp_flow *flow);

int
xdp_ep_flow_stats_next(int map_fd, struct xdp_flow_key *key, struct xdp_flow *flow);

int
xdp_ep_flow_stats_flush(int map_fd);

/* interface flows */
int
xdp_if_flow_lookup(int if_index, struct xdp_flow_key *key, struct xdp_flow *flow);

int
xdp_if_flow_insert(int if_index, struct xdp_flow *flow);

int
xdp_if_flow_next(int if_index, struct xdp_flow_key *key, struct xdp_flow *flow);

int
xdp_if_flow_remove(int if_index, struct xdp_flow_key *key);

int
xdp_if_flow_flush(int if_index);

/* interface flow stats */
int
xdp_if_flow_stats_lookup(int if_index, struct xdp_flow_key *key, struct xdp_flow *flow);

int
xdp_if_flow_stats_next(int if_index, struct xdp_flow_key *key, struct xdp_flow *flow);

int
xdp_if_flow_stats_flush(int if_index);

/* datapath flows */
int
xdp_dp_flow_lookup(struct xdp_datapath *dp, struct xdp_flow_key *key, struct xdp_flow *flow);

int
xdp_dp_flow_insert(struct xdp_datapath *dp, struct xdp_flow *flow);

int
xdp_dp_flow_next(struct xdp_datapath *dp, struct xdp_flow_key *key, struct xdp_flow *flow);

int
xdp_dp_flow_remove(struct xdp_datapath *dp, struct xdp_flow_key *key);

int
xdp_dp_flow_flush(struct xdp_datapath *dp, struct xdp_flow_key *key);

/* datapath flow stats */
int
xdp_dp_flow_stats_lookup(int map_fd, struct xdp_flow_key *key, struct xdp_flow *flow);

int
xdp_dp_flow_stats_next(int map_fd, struct xdp_flow_key *key, struct xdp_flow *flow);

int
xdp_dp_flow_stats_flush(int map_fd);



#endif /* xdp_datapath.h */