
#include "flow.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
void ovs_flow_stats_update(struct xdp_flow *flow, __be16 tcp_flags,
			   const struct xdp_md *ctx)
{
    /* TODO: implement method */
}

void ovs_flow_stats_get(const struct xdp_flow *flow, struct ovs_flow_stats *stats,
			unsigned long *used, __be16 *tcp_flags)
{
    /* TODO: implement method */
}

void ovs_flow_stats_clear(struct xdp_flow *flow)
{
    /* TODO: implement method */
}

__u64 ovs_flow_used_time(unsigned long flow_jiffies)
{
    /* TODO: implement method */
    return 0;
}


/* Update the non-metadata part of the flow key using ctx. */
int ovs_flow_key_update(struct xdp_md *ctx, struct xdp_flow_key *key)
{
    /* TODO: implement method */
    return 0;
}

// int ovs_flow_key_extract(const struct ip_tunnel_info *tun_info,
// 			 struct xdp_md *ctx,
// 			 struct xdp_flow_key *key)
// {
//     /* TODO: implement method */
//     return 0;
// }

// /* Extract key from packet coming from userspace. */
// int ovs_flow_key_extract_userspace(struct net *net, const struct nlattr *attr,
// 				   struct xdp_md *ctx,
// 				   struct xdp_flow_key *key, bool log)
// {
//     /* TODO: implement method */
//     return 0;
// }
#pragma GCC diagnostic pop