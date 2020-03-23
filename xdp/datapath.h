#ifndef DATAPATH_H
#define DATAPATH_H 1

#include <linux/kernel.h>
#include <linux/bpf.h>
#include <linux/if_xdp.h>
// #include <linux/netdevice.h>
// #include <net/net_namespace.h>
// #include <net/ip_tunnels.h>

#include "flow.h"
#include "flow-table.h"

struct datapath {

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
struct dp_upcall_info {
    struct ip_tunnel_info *egress_tun_info;
    const struct nlattr *userdata;
    const struct nlattr *actions;
    int actions_len;
    __u32 portid;
    __u8 cmd;
    __u16 mru;
};

void ovs_dp_process_packet(struct xdp_md *ctx, struct xdp_flow_key *key);
int ovs_dp_upcall(struct datapath *, struct xdp_md *,
          const struct xdp_flow_key *, const struct dp_upcall_info *,
          __u32 cutlen);

const char *ovs_dp_name(const struct datapath *dp);


int ovs_execute_actions(struct datapath *dp, struct xdp_md *ctx,
            const struct xdp_flow_actions *, struct xdp_flow_key *);

#endif /* datapath.h */