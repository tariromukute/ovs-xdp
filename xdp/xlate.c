#include "xlate.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

size_t ovs_tun_key_attr_size(void)
{
    /* TODO: implement method */
    return 0;
}

size_t ovs_key_attr_size(void)
{
    /* TODO: implement method */
    return 0;
}


int ovs_nla_put_key(const struct xdp_flow_key *key, const struct xdp_flow_key *output,
            int attr, bool is_mask, struct xdp_md *ctx)
{
    /* TODO: implement method */
    return 0;
}

int parse_flow_nlattrs(const struct nlattr *attr, const struct nlattr *a[],
               __u64 *attrsp, bool log)
{
    /* TODO: implement method */
    return 0;
}

// int ovs_nla_get_flow_metadata(struct net *net,
//                   const struct nlattr *a[OVS_KEY_ATTR_MAX + 1],
//                   u64 attrs, struct xdp_flow_key *key, bool log)
// {
//     /* TODO: implement method */
//     return 0;
// }


int ovs_nla_put_identifier(const struct xdp_flow *flow, struct xdp_md *ctx)
{
    /* TODO: implement method */
    return 0;
}

// int ovs_nla_put_tunnel_info(struct xdp_md *ctx,
//                 struct ip_tunnel_info *tun_info)
// {
//     /* TODO: implement method */
//     return 0;
// }


bool ovs_nla_get_ufid(struct xdp_flow_id *id, const struct nlattr *nattr, bool log)
{
    /* TODO: implement method */
    return 0;
}

int ovs_nla_get_identifier(struct xdp_flow_id *sfid, const struct nlattr *ufid,
               const struct xdp_flow_key *key, bool log)
{
    /* TODO: implement method */
    return 0;
}

__u32 ovs_nla_get_ufid_flags(const struct nlattr *attr)
{
    /* TODO: implement method */
    return 0;
}


// int ovs_nla_copy_actions(struct net *net, const struct nlattr *attr,
//              const struct xdp_flow_key *key,
//              struct xdp_flow_actions **sfa, bool log)
// {
//     /* TODO: implement method */
//     return 0;
// }

int ovs_nla_add_action(struct xdp_flow_actions **sfa, int attrtype,
               void *data, int len, bool log)
{
    /* TODO: implement method */
    return 0;
}

int ovs_nla_put_actions(const struct nlattr *attr,
            int len, struct xdp_md *ctx)
{
    /* TODO: implement method */
    return 0;
}


void ovs_nla_free_flow_actions(struct xdp_flow_actions *act)
{
    /* TODO: implement method */
}

void ovs_nla_free_flow_actions_rcu(struct xdp_flow_actions *act)
{
    /* TODO: implement method */
}


int nsh_key_from_nlattr(const struct nlattr *attr, struct nshhdr *nsh,
            struct nshhdr *nsh_mask)
{
    /* TODO: implement method */
    return 0;
}

int nsh_hdr_from_nlattr(const struct nlattr *attr, struct nshhdr *nh,
            size_t size)
{
    /* TODO: implement method */
    return 0;
}
#pragma GCC diagnostic pop