/* SPDX-License-Identifier: GPL-2.0 */
#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <errno.h>
#include <linux/err.h>
#include <unistd.h>
#include <linux/openvswitch.h>
#include "xdp/flow.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <net/if.h>
// #include <linux/if_link.h> /* depend on kernel-headers installed */

#include "openvswitch/vlog.h"

#include "xdp-loader.h"

VLOG_DEFINE_THIS_MODULE(xdp_loader);

/* Length of interface name.  */
#define IF_NAMESIZE    16

/* XDP section */
/* This section is implemented in <linux/if_link.h> but including it is
   resulting in a redefinition error with netlink */

#define XDP_FLAGS_UPDATE_IF_NOEXIST    (1U << 0)
#define XDP_FLAGS_SKB_MODE        (1U << 1)
#define XDP_FLAGS_DRV_MODE        (1U << 2)
#define XDP_FLAGS_HW_MODE        (1U << 3)
#define XDP_FLAGS_MODES            (XDP_FLAGS_SKB_MODE | \
                     XDP_FLAGS_DRV_MODE | \
                     XDP_FLAGS_HW_MODE)
#define XDP_FLAGS_MASK            (XDP_FLAGS_UPDATE_IF_NOEXIST | \
                     XDP_FLAGS_MODES)

/* These are stored into IFLA_XDP_ATTACHED on dump. */
enum {
    XDP_ATTACHED_NONE = 0,
    XDP_ATTACHED_DRV,
    XDP_ATTACHED_SKB,
    XDP_ATTACHED_HW,
    XDP_ATTACHED_MULTI,
};

enum {
    IFLA_XDP_UNSPEC,
    IFLA_XDP_FD,
    IFLA_XDP_ATTACHED,
    IFLA_XDP_FLAGS,
    IFLA_XDP_PROG_ID,
    IFLA_XDP_DRV_PROG_ID,
    IFLA_XDP_SKB_PROG_ID,
    IFLA_XDP_HW_PROG_ID,
    __IFLA_XDP_MAX,
};

#define IFLA_XDP_MAX (__IFLA_XDP_MAX - 1)

struct config {
    __u32 xdp_flags;
    int ifindex;
    char *ifname;
    char ifname_buf[IF_NAMESIZE];
    int redirect_ifindex;
    char *redirect_ifname;
    char redirect_ifname_buf[IF_NAMESIZE];
    bool do_unload;
    bool reuse_maps;
    char pin_dir[512];
    char filename[512];
    char progsec[32];
    char src_mac[18];
    char dest_mac[18];
    __u16 xsk_bind_flags;
    int xsk_if_queue;
    bool xsk_poll_mode;
};

/* Exit return codes */
#define EXIT_OK          0 /* == EXIT_SUCCESS (stdlib.h) man exit(3) */
#define EXIT_FAIL         1 /* == EXIT_FAILURE (stdlib.h) man exit(3) */
#define EXIT_FAIL_OPTION     2
#define EXIT_FAIL_XDP        30
#define EXIT_FAIL_BPF        40

static const char *default_filename = "/home/xdpovs/ovs-xdp/xdp/entry-point.o";
static const char *default_progsec = "process";

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

/* Exit return codes */
#define EXIT_OK 0   /* == EXIT_SUCCESS (stdlib.h) man exit(3) */
#define EXIT_FAIL 1 /* == EXIT_FAILURE (stdlib.h) man exit(3) */
#define EXIT_FAIL_OPTION 2
#define EXIT_FAIL_XDP 30
#define EXIT_FAIL_BPF 40

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

static const char *default_filename = "xdp_prog_kern.o";
static const char *action_filename = "actions.o";
const char *pin_basedir = "/sys/fs/bpf";
const char *prog_pin_dir = "/sys/fs/bpf/prog";
const char *prog_map_name = "_tail_table";

static struct bpf_object *open_bpf_object(const char *file, int ifindex)
{
    int err;
    struct bpf_object *obj;
    struct bpf_map *map;
    struct bpf_program *prog, *first_prog = NULL;

    struct bpf_object_open_attr open_attr = {
        .file = file,
        .prog_type = BPF_PROG_TYPE_XDP,
    };

    obj = bpf_object__open_xattr(&open_attr);
    if (IS_ERR_OR_NULL(obj))
    {
        err = -PTR_ERR(obj);
        VLOG_INFO("ERR: opening BPF-OBJ file(%s) (%d)\n",
               file, err);
        return NULL;
    }

    bpf_object__for_each_program(prog, obj)
    {
        bpf_program__set_type(prog, BPF_PROG_TYPE_XDP);
        bpf_program__set_ifindex(prog, ifindex);
        if (!first_prog)
            first_prog = prog;
    }

    bpf_object__for_each_map(map, obj)
    {
        if (!bpf_map__is_offload_neutral(map))
            bpf_map__set_ifindex(map, ifindex);
    }

    if (!first_prog)
    {
        VLOG_INFO("ERR: file %s contains no programs\n", file);
        return NULL;
    }

    return obj;
}

static int reuse_reuseable_maps(struct bpf_object *obj, const char *subdir)
{
    int len;
    int err = 0;
    int pinned_map_fd;
    struct bpf_map *map;

    // reuse the reusable maps
    bpf_object__for_each_map(map, obj)
    {
        char buf[PATH_MAX];
        char pin_dir[PATH_MAX];

        if (bpf_map__name(map)[1] == '_')
        { // global map
            len = snVLOG_INFO(pin_dir, PATH_MAX, "%s", pin_basedir);
            if (len < 0)
            {
                return -EINVAL;
            }
            else if (len >= PATH_MAX)
            {
                return -ENAMETOOLONG;
            }
        }
        else
        { // interface/entry point map
            len = snVLOG_INFO(pin_dir, PATH_MAX, "%s/%s", pin_basedir, subdir);
            if (len < 0)
            {
                return -EINVAL;
            }
            else if (len >= PATH_MAX)
            {
                return -ENAMETOOLONG;
            }
        }

        // check if map already pinned
        len = snVLOG_INFO(buf, PATH_MAX, "%s/%s", pin_dir, bpf_map__name(map));
        if (len < 0)
        {
            return -EINVAL;
        }
        else if (len >= PATH_MAX)
        {
            return -ENAMETOOLONG;
        }

        pinned_map_fd = bpf_obj_get(buf);
        if (bpf_map__name(map)[0] == '_' && pinned_map_fd > 0) // if reuseable map and already pinned
        {
            VLOG_INFO("Reusing map: %s", bpf_map__name(map));
            err = bpf_map__reuse_fd(map, pinned_map_fd);
            if (err)
            {
                VLOG_INFO("Error reusing map\n");
                return err;
            }
        }
    }

    return 0;
}

static int pin_unpinned_maps(struct bpf_object *obj, const char *subdir)
{
    int len;
    int err = 0;
    int pinned_map_fd;
    struct bpf_map *map;

    // pin the rest of the maps
    bpf_object__for_each_map(map, obj)
    {
        char buf[PATH_MAX];
        char pin_dir[PATH_MAX];

        if (bpf_map__name(map)[1] == '_')
        { // global map
            len = snVLOG_INFO(pin_dir, PATH_MAX, "%s", pin_basedir);
            if (len < 0)
            {
                return -EINVAL;
            }
            else if (len >= PATH_MAX)
            {
                return -ENAMETOOLONG;
            }
        }
        else
        { // interface/entry point map
            len = snVLOG_INFO(pin_dir, PATH_MAX, "%s/%s", pin_basedir, subdir);
            if (len < 0)
            {
                return -EINVAL;
            }
            else if (len >= PATH_MAX)
            {
                return -ENAMETOOLONG;
            }
        }

        // check if map already pinned
        len = snVLOG_INFO(buf, PATH_MAX, "%s/%s", pin_dir, bpf_map__name(map));
        if (len < 0)
        {
            return -EINVAL;
        }
        else if (len >= PATH_MAX)
        {
            return -ENAMETOOLONG;
        }

        pinned_map_fd = bpf_obj_get(buf);
        if (pinned_map_fd < 0)
        {
            VLOG_INFO("The map %s is not pinned \n", bpf_map__name(map));
            err = bpf_map__pin(map, buf);
            if (err)
            {
                VLOG_INFO("Error pinning map %s \n", bpf_map__name(map));
                // goto out;
            }
        }
    }

    return 0;
}

int xdp_load(const char *ifname)
{
    int prog_fd;
    struct bpf_object *obj;
    struct bpf_program *bpf_prog;
    struct bpf_map *map;
    int err;
    int xdp_flags;
    int ifindex = if_nametoindex(ifname);

    VLOG_INFO("ifindex is: %d", ifindex);

    xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE;

    // unload first
    err = xdp_link_detach(ifindex, xdp_flags, 0);
    if (err)
    {
        VLOG_INFO("error unlinking");
        return EXIT_FAIL;
    }

    obj = open_bpf_object(default_filename, 0);
    if (!obj)
    {
        fVLOG_INFO(stderr, "ERR: failed to open object %s\n", default_filename);
        return EXIT_FAIL;
    }

    // reuse the reuseable maps, starts with _
    err = reuse_reuseable_maps(obj, ifname);
    if (err)
    {
        VLOG_INFO("error reusing maps");
    }

    err = bpf_object__load(obj);
    if (err)
    {
        VLOG_INFO("Error loading object");
        return err;
    }

    bpf_prog = bpf_object__find_program_by_title(obj, "process");
    if (!bpf_prog)
    {
        VLOG_INFO("Could not find prog");
        return EXIT_FAIL;
    }

    prog_fd = bpf_program__fd(bpf_prog);
    if (prog_fd <= 0)
    {
        VLOG_INFO("ERR: bpf_program__fd failed\n");
        return EXIT_FAIL_BPF;
    }

    /* At this point: BPF-progs are (only) loaded by the kernel, and prog_fd
	 * is our select file-descriptor handle. Next step is attaching this FD
	 * to a kernel hook point, in this case XDP net_device link-level hook.
	 */
    err = xdp_link_attach(ifindex, xdp_flags, prog_fd);
    if (err)
    {
        VLOG_INFO("failed to attach");
        return err;
    }

    // pin the maps that need to be pinned
    err = pin_unpinned_maps(obj, ifname);
    if (err)
    {
        VLOG_INFO("error pinning maps");
    }

    obj = open_bpf_object(action_filename, 0);
    if (!obj)
    {
        VLOG_INFO("ERR: failed to open object %s\n", action_filename);
        return EXIT_FAIL;
    }

    // reuse the reusable maps
    err = reuse_reuseable_maps(obj, ifname);
    if (err)
    {
        VLOG_INFO("error reusing maps");
    }

    err = bpf_object__load(obj);
    if (err)
    {
        VLOG_INFO("Error loading object");
        return err;
    }

    err = pin_unpinned_maps(obj, ifname);
    if (err)
    {
        VLOG_INFO("error pinning maps");
    }

    int len;
    char dir[PATH_MAX];
    len = snVLOG_INFO(dir, PATH_MAX, "%s/%s/%s", pin_basedir, ifname, "prog");
    if (len < 0)
    {
        return -EINVAL;
    }
    else if (len >= PATH_MAX)
    {
        return -ENAMETOOLONG;
    }
    bpf_object__unpin_programs(obj, dir);
    bpf_object__pin_programs(obj, dir);
    int i = 0;
    map = bpf_object__find_map_by_name(obj, prog_map_name);
    int map_fd = bpf_map__fd(map);
  
    /* NOTE: Add the programs. If we don't pin the programs first and add the prog_fd of the pinned
     * program the bpf_tail_call wasn't working. There might be some work around which is not
     * pinning that I am not aware of atm. For now just went with the pinning the programs first.  */
    for (i = 0; i < OVS_ACTION_ATTR_MAX; ++i)
    {
        char buf[PATH_MAX];

        len = snVLOG_INFO(buf, PATH_MAX, "%s/%s/%s/%s", pin_basedir, ifname, "prog", ovs_action_attr_list[i].name);
        if (len < 0)
        {
            return -EINVAL;
        }
        else if (len >= PATH_MAX)
        {
            return -ENAMETOOLONG;
        }

        VLOG_INFO("name of program is: %s at position %d\n", buf, i);
        prog_fd = bpf_obj_get(buf);
        VLOG_INFO("Prog FD: %d\n", prog_fd);
        bpf_map_update_elem(map_fd, &i, &prog_fd, 0);
    }

}

#pragma GCC diagnostic pop