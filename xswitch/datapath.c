#include <net/if.h>
#include <errno.h>
#include <stdio.h>
// #include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "datapath.h"
#include "flow-table.h"

static const char *pin_basedir = "/sys/fs/bpf";
static const char *stats_map = "stats_map";
static const char *flow_map = "flow_table";

#ifndef NAME_MAX
#define NAME_MAX 1096
#endif

#ifndef PATH_MAX
#define PATH_MAX	4096
#endif

/* NOTE: if a program without priviledges for bpf calls, calls these function that call
 * a bpf method e.g. bpf_obj_get, the method will just return a -1 as if there is
 * something wrong with the input (e.g. file doesn't exist) */

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
int xdp_dp_downcall(struct xdp_datapath *dp, const struct xdp_flow_key *key,
            const struct dp_downcall_info *info)
{
    int err = ENOENT;

    return err;
}

const char *xdp_dp_name(const struct xdp_datapath *dp)
{
    return "";
}

/* datapath crud */
int xdp_dp_create(struct xdp_datapath *dp)
{
    int err = ENOENT;

    return err;
}

int xdp_dp_update(struct xdp_datapath *dp)
{
    int err = ENOENT;

    return err;
}

int xdp_dp_delete(struct xdp_datapath *dp)
{
    int err = ENOENT;

    return err;
}

int xdp_dp_fetch(struct xdp_datapath *dp)
{
    int err = ENOENT;

    return err;
}

/* datapath port actions */
int xdp_dp_port_add(struct xdp_datapath *dp, struct xport *xport)
{
    int err = ENOENT;

    return err;
}

int xdp_dp_port_del(struct xdp_datapath *dp, struct xport *xport)
{
    int err = ENOENT;

    return err;
}

int xdp_dp_port_lookup(struct xdp_datapath *dp, struct xport *xport)
{
    int err = ENOENT;

    return err;
}

int xdp_dp_port_next(struct xdp_datapath *dp, struct xport *xport)
{
    int err = ENOENT;

    return err;
}

/* entry point flows */
int xdp_ep_flow_lookup(int map_fd, struct xdp_flow_key *key, struct xdp_flow **flowp)
{
    int err = 0;
    __u8 act_buf[XDP_FLOW_ACTIONS_LEN_u64] = { 0 };
    __u8 key_buf[XDP_FLOW_KEY_LEN_u64] = { 0 };
    memcpy(key_buf, key, sizeof(struct xdp_flow_key));

    err = xdp_flow_map_lookup(map_fd, key_buf, act_buf);
    if (err) {
        /* TODO: check error and return code */
        goto out;
    }
    struct xdp_flow flow;
    memcpy(&flow.actions, act_buf, sizeof(struct xdp_flow_actions));

    *flowp = &flow;
out:
    return err;
}

int xdp_ep_flow_insert(int map_fd, struct xdp_flow *flow)
{
    __u8 key_buf[XDP_FLOW_KEY_LEN_u64] = { 0 };
    memcpy(key_buf, &flow->key, sizeof(flow->key));
    int err = 0;

    err = xdp_flow_map_insert(map_fd, key_buf, &flow->actions);
    if (err) {
        /* TODO: check error and return code */
        goto out;
    }

out:
    return err;
}

/* TODO: think need pointer to a pointer here for key */
int xdp_ep_flow_next(int map_fd, struct xdp_flow_key *pkey, struct xdp_flow **flowp)
{
    // printf("%s \n", __func__);
    struct xdp_flow flow;
    memset(&flow, 0, sizeof(struct xdp_flow));

    __u8 key_buf[XDP_FLOW_KEY_LEN_u64] = { 0 };
    
    if (pkey)
        memcpy(key_buf, pkey, sizeof(*pkey));
    int err = 0;

    __u8 nkey_buf[XDP_FLOW_KEY_LEN_u64] = { 0 };

    err = xdp_flow_map_next_key(map_fd, key_buf, nkey_buf);
    if (err) {
        /* TODO: check error and return code */
        goto out;
    }

    memcpy(&flow.key, nkey_buf, sizeof(struct xdp_flow_key));

    __u8 act_buf[XDP_FLOW_ACTIONS_LEN_u64] = { 0 };
    err = xdp_flow_map_lookup(map_fd, nkey_buf, act_buf);
    if (err) {
        /* TODO: check error and return code */
        goto out;
    }
    memcpy(&flow.actions, act_buf, sizeof(struct xdp_flow_actions));
    *flowp = &flow;

out:
    return err;
}

int xdp_ep_flow_remove(int map_fd, struct xdp_flow_key *key)
{
    // printf("%s \n", __func__);
    __u8 key_buf[XDP_FLOW_KEY_LEN_u64] = { 0 };
    memcpy(key_buf, key, sizeof(*key));
    int err = 0;

    err = xdp_flow_map_remove(map_fd, key_buf);
    if (err) {
        /* TODO: check error and return code */
        goto out;
    }

out:
    return err;
}

int xdp_ep_flow_flush(int map_fd)
{
    int max_entries = 100; // for tail_actions.h, don't want to mix kernel and userspace code
    int err = 0;

    err = xdp_flow_map_flush(map_fd, max_entries);
    if (err) {
        /* TODO: check error and return code */
        goto out;
    }

out:
    return err;
}

/* entry point flow stats */
int
xdp_ep_flow_stats_lookup(int map_fd, struct xdp_flow_key *key, struct xdp_flow *flow)
{
    // printf("%s \n", __func__);
    int err = 0;
//     __u8 key_buf[XDP_FLOW_KEY_LEN_u64] = { 0 };
//     memcpy(key_buf, &flow->key, sizeof(flow->key));

//     err = xdp_flow_stats_map_lookup(map_fd, key_buf, &flow->stats);
//     if (err) {
//         /* TODO: check error and return code */
//         goto out;
//     }

// out:
    return err;
}

int
xdp_ep_flow_stats_next(int map_fd, struct xdp_flow_key *pkey, struct xdp_flow *flow)
{
    // printf("%s \n", __func__);
    int err = 0;
//     __u8 key_buf[XDP_FLOW_KEY_LEN_u64] = { 0 };
//     if (pkey)
//         memcpy(key_buf, pkey, sizeof(*pkey));

//     __u8 nkey_buf[XDP_FLOW_KEY_LEN_u64] = { 0 };

//     err = xdp_flow_map_next_key(map_fd, key_buf, nkey_buf);
//     if (err) {
//         /* TODO: check error and return code */
//         goto out;
//     }
//     memcpy(&flow->key, nkey_buf, sizeof(struct xdp_flow_key));

//     err = xdp_flow_stats_map_lookup(map_fd, nkey_buf, &flow->stats);
//     if (err) {
//         /* TODO: check error and return code */
//         goto out;
//     }

// out:
    return err;
}

int
xdp_ep_flow_stats_flush(int map_fd)
{
    int max_entries = 100; // for tail_actions.h, don't want to mix kernel and userspace code
    int err = 0;

    err = xdp_flow_map_flush(map_fd, max_entries);
    if (err) {
        /* TODO: check error and return code */
        goto out;
    }

out:
    return err;
}

/* interface flows */
int
xdp_if_flow_lookup(int if_index, struct xdp_flow_key *key, struct xdp_flow **flowp)
{
    // printf("%s \n", __func__);
    int err = 0;
    char ifname[NAME_MAX];
    if_indextoname(if_index, ifname);
    char buf[PATH_MAX];
    int len = snprintf(buf, PATH_MAX, "%s/%s/%s", pin_basedir, ifname, flow_map);
    if (len < 0) {
        err = -EINVAL;
        goto out;
    } else if(len >= PATH_MAX) {
        err = ENAMETOOLONG;
        goto out;
    }

    int map_fd = bpf_obj_get(buf);
    if (map_fd < 0) {
        err = ENOENT;
        goto out;
    }
    
    err = xdp_ep_flow_lookup(map_fd, key, flowp);
out:
    return err;
}

int
xdp_if_flow_insert(int if_index, struct xdp_flow *flow)
{
    int err = 0;
    char ifname[NAME_MAX];
    if_indextoname(if_index, ifname);
    char buf[PATH_MAX];
    int len = snprintf(buf, PATH_MAX, "%s/%s/%s", pin_basedir, ifname, stats_map);
    if (len < 0) {
        err = -EINVAL;
        goto out;
    } else if(len >= PATH_MAX) {
        err = ENAMETOOLONG;
        goto out;
    }

    int map_fd = bpf_obj_get(buf);
    if (map_fd < 0) {
        err = ENOENT;
        goto out;
    }

    err = xdp_ep_flow_insert(map_fd, flow);

out:
    return err;
}

int
xdp_if_flow_next(int if_index, struct xdp_flow_key *key, struct xdp_flow **flowp)
{
    // printf("%s \n", __func__);
    int err = 0;
    char ifname[NAME_MAX];
    if_indextoname(if_index, ifname);
    // printf("ifname %s\n", ifname);
    char buf[PATH_MAX];
    int len = snprintf(buf, PATH_MAX, "%s/%s/%s", pin_basedir, ifname, flow_map);
    if (len < 0) {
        err = -EINVAL;
        goto out;
    } else if(len >= PATH_MAX) {
        err = ENAMETOOLONG;
        goto out;
    }

    int map_fd = bpf_obj_get(buf);
    if (map_fd < 0) {
        err = ENOENT;
        goto out;
    }

    err = xdp_ep_flow_next(map_fd, key, flowp);

out:
    return err;
}

int
xdp_if_flow_remove(int if_index, struct xdp_flow_key *key)
{
    int err = 0;
    char ifname[NAME_MAX];
    if_indextoname(if_index, ifname);
    char buf[PATH_MAX];
    int len = snprintf(buf, PATH_MAX, "%s/%s/%s", pin_basedir, ifname, stats_map);
    if (len < 0) {
        err = -EINVAL;
        goto out;
    } else if(len >= PATH_MAX) {
        err = ENAMETOOLONG;
        goto out;
    }

    int map_fd = bpf_obj_get(buf);
    if (map_fd < 0) {
        err = ENOENT;
        goto out;
    }

    err = xdp_ep_flow_remove(map_fd, key);

out:
    return err;
}

int
xdp_if_flow_flush(int if_index)
{
    int err = 0;
    char ifname[NAME_MAX];
    if_indextoname(if_index, ifname);
    char buf[PATH_MAX];
    int len = snprintf(buf, PATH_MAX, "%s/%s/%s", pin_basedir, ifname, stats_map);
    if (len < 0) {
        err = -EINVAL;
        goto out;
    } else if(len >= PATH_MAX) {
        err = ENAMETOOLONG;
        goto out;
    }

    int map_fd = bpf_obj_get(buf);
    if (map_fd < 0) {
        err = ENOENT;
        goto out;
    }

    err = xdp_ep_flow_flush(map_fd);

out:
    return err;
}

/* interface flow stats */
int
xdp_if_flow_stats_lookup(int if_index, struct xdp_flow_key *key, struct xdp_flow *flow)
{
    // printf("%s \n", __func__);
    int err = 0;
    char ifname[NAME_MAX];
    if_indextoname(if_index, ifname);
    char buf[PATH_MAX];
    int len = snprintf(buf, PATH_MAX, "%s/%s/%s", pin_basedir, ifname, stats_map);
    if (len < 0) {
        err = -EINVAL;
        goto out;
    } else if(len >= PATH_MAX) {
        err = ENAMETOOLONG;
        goto out;
    }

    int map_fd = bpf_obj_get(buf);
    if (map_fd < 0) {
        err = ENOENT;
        goto out;
    }

    err = xdp_ep_flow_stats_lookup(map_fd, key, flow);

out:
    return err;
}

int
xdp_if_flow_stats_next(int if_index, struct xdp_flow_key *key, struct xdp_flow *flow)
{
    int err = 0;
    char ifname[NAME_MAX];
    if_indextoname(if_index, ifname);
    char buf[PATH_MAX];
    int len = snprintf(buf, PATH_MAX, "%s/%s/%s", pin_basedir, ifname, stats_map);
    if (len < 0) {
        err = -EINVAL;
        goto out;
    } else if(len >= PATH_MAX) {
        err = ENAMETOOLONG;
        goto out;
    }

    int map_fd = bpf_obj_get(buf);
    if (map_fd < 0) {
        err = ENOENT;
        goto out;
    }

    err = xdp_ep_flow_stats_next(map_fd, key, flow);

out:
    return err;
}

int
xdp_if_flow_stats_flush(int if_index)
{
    int err = 0;
    char ifname[NAME_MAX];
    if_indextoname(if_index, ifname);
    char buf[PATH_MAX];
    int len = snprintf(buf, PATH_MAX, "%s/%s/%s", pin_basedir, ifname, stats_map);
    if (len < 0) {
        err = -EINVAL;
        goto out;
    } else if(len >= PATH_MAX) {
        err = ENAMETOOLONG;
        goto out;
    }

    int map_fd = bpf_obj_get(buf);
    if (map_fd < 0) {
        err = ENOENT;
        goto out;
    }

    err = xdp_ep_flow_stats_flush(map_fd);

out:
    return err;
}

/* datapath flows */
int xdp_dp_flow_lookup(struct xdp_datapath *dp, struct xdp_flow_key *key, struct xdp_flow *flow)
{
    int err = ENOENT;

    return err;
}

int xdp_dp_flow_insert(struct xdp_datapath *dp, struct xdp_flow *flow)
{
    int err = ENOENT;

    return err;
}

int xdp_dp_flow_next(struct xdp_datapath *dp, struct xdp_flow_key *key, struct xdp_flow **flowp)
{
    int err = ENOENT;

    return err;
}

int xdp_dp_flow_remove(struct xdp_datapath *dp, struct xdp_flow_key *key)
{
    int err = ENOENT;

    return err;
}

int xdp_dp_flow_flush(struct xdp_datapath *dp, struct xdp_flow_key *key)
{
    int err = ENOENT;

    return err;
}

/* datapath flow stats */
int
xdp_dp_flow_stats_lookup(int map_fd, struct xdp_flow_key *key, struct xdp_flow *flow)
{
    int err = ENOENT;

    return err;
}

int
xdp_dp_flow_stats_next(int map_fd, struct xdp_flow_key *key, struct xdp_flow *flow)
{
    int err = ENOENT;

    return err;
}

int
xdp_dp_flow_stats_flush(int map_fd)
{
    int err = ENOENT;

    return err;
}

#pragma GCC diagnostic pop

