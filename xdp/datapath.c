#include "datapath.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
void ovs_dp_process_packet(struct xdp_md *ctx, struct xdp_flow_key *key)
{
    /* TODO: implement method */
}

int ovs_dp_upcall(struct datapath *dp, struct xdp_md *ctx,
		  const struct xdp_flow_key *key, const struct dp_upcall_info *info,
		  __u32 cutlen)
{
    /* TODO: implement method */
    return 0;
}

const char* ovs_dp_name(const struct datapath *dp)
{
    char *name = "";
    /* TODO: implement method */
    return name;
}

int ovs_execute_actions(struct datapath *dp, struct xdp_md *ctx,
			const struct xdp_flow_actions *act, struct xdp_flow_key *key)
{
    /* TODO: implement method */
    return 0;
}
#pragma GCC diagnostic pop

