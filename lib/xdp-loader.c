/* SPDX-License-Identifier: GPL-2.0 */
#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

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

int xdp_link_attach(int ifindex, __u32 xdp_flags, int prog_fd);
int xdp_link_detach(int ifindex, __u32 xdp_flags, __u32 expected_prog_id);
struct bpf_object *__load_bpf_object_file(const char *filename, int ifindex);
struct bpf_object *__load_bpf_and_xdp_attach(struct config *cfg);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

int xdp_link_attach(int ifindex, __u32 xdp_flags, int prog_fd)
{
    VLOG_INFO("*** Called: %s ***", __func__);
    int err;

    /* libbpf provide the XDP net_device link-level hook attach helper */
    err = bpf_set_link_xdp_fd(ifindex, prog_fd, xdp_flags);
    if (err == -EEXIST && !(xdp_flags & XDP_FLAGS_UPDATE_IF_NOEXIST)) {
        /* Force mode didn't work, probably because a program of the
         * opposite type is loaded. Let's unload that and try loading
         * again.
         */
        VLOG_INFO("*** Doing unload and reloading ***");
        __u32 old_flags = xdp_flags;

        xdp_flags &= ~XDP_FLAGS_MODES;
        xdp_flags |= (old_flags & XDP_FLAGS_SKB_MODE) ? XDP_FLAGS_DRV_MODE : XDP_FLAGS_SKB_MODE;
        err = bpf_set_link_xdp_fd(ifindex, -1, xdp_flags);
        if (!err)
            err = bpf_set_link_xdp_fd(ifindex, prog_fd, old_flags);
    }
    if (err < 0) {
        switch (-err) {
        case EBUSY:
            break;
        case EEXIST:
            break;
        case EOPNOTSUPP:
            break;
        default:
            break;
        }
        return EXIT_FAIL_XDP;
    }

    return EXIT_OK;
}

int xdp_link_detach(int ifindex, __u32 xdp_flags, __u32 expected_prog_id)
{
    // __u32 curr_prog_id;
    // int err;

    // TODO: check how to get xdp_id, the method is not in libbpf so compile failing
    // err = bpf_get_link_xdp_id(ifindex, &curr_prog_id, xdp_flags);
    // if (err) {
    //     return EXIT_FAIL_XDP;
    // }

    // if (!curr_prog_id) {
    //     return EXIT_OK;
    // }

    // if (expected_prog_id && curr_prog_id != expected_prog_id) {
    //     return EXIT_FAIL;
    // }

    // if ((err = bpf_set_link_xdp_fd(ifindex, -1, xdp_flags)) < 0) {
    //     return EXIT_FAIL_XDP;
    // }

    return EXIT_OK;
}

struct bpf_object *__load_bpf_object_file(const char *filename, int ifindex)
{
    VLOG_INFO("*** Called: %s ***", __func__);
    int first_prog_fd = -1;
    struct bpf_object *obj;
    int err;

    struct bpf_prog_load_attr prog_load_attr = {
        .prog_type    = BPF_PROG_TYPE_XDP,
        .ifindex    = ifindex,
    };
    prog_load_attr.file = filename;

    /* Use libbpf for extracting BPF byte-code from BPF-ELF object, and
     * loading this into the kernel via bpf-syscall
     */
    err = bpf_prog_load_xattr(&prog_load_attr, &obj, &first_prog_fd);
    if (err) {
        VLOG_INFO("ERR: loading BPF-OBJ file(%s) (%d)",
            filename, err);
        return NULL;
    }

    return obj;
}

struct bpf_object *__load_bpf_and_xdp_attach(struct config *cfg)
{
    VLOG_INFO("*** Called: %s ***", __func__);
    struct bpf_program *bpf_prog;
    struct bpf_object *bpf_obj;
    int offload_ifindex = 0;
    int prog_fd = -1;
    int err;

    /* If flags indicate hardware offload, supply ifindex */
    if (cfg->xdp_flags & XDP_FLAGS_HW_MODE) {
        offload_ifindex = cfg->ifindex;
    }

    /* Load the BPF-ELF object file and get back libbpf bpf_object */
    bpf_obj = __load_bpf_object_file(cfg->filename, offload_ifindex);
    if (!bpf_obj) {
        VLOG_INFO("ERR: loading file: %s", cfg->filename);
        exit(EXIT_FAIL_BPF);
    }
    
    /* Find a matching BPF prog section name */
    bpf_prog = bpf_object__find_program_by_title(bpf_obj, cfg->progsec);
    if (!bpf_prog) {
        VLOG_INFO("ERR: finding progsec: %s", cfg->progsec);
        exit(EXIT_FAIL_BPF);
    }

    prog_fd = bpf_program__fd(bpf_prog);
    if (prog_fd <= 0) {
        VLOG_INFO("ERR: bpf_program__fd failed");
        exit(EXIT_FAIL_BPF);
    }

    err = xdp_link_attach(cfg->ifindex, cfg->xdp_flags, prog_fd);
    if (err) {
        VLOG_INFO("ERR: link attach (%d)", err);
        exit(err);
    }

    return bpf_obj;
}

int xdp_load(const char *ifname)
{
    VLOG_INFO("*** Called: %s ***", __func__);
    struct bpf_object *bpf_obj;

    if (!ifname) {
        VLOG_INFO("ERR: the dev name was not provided");
        return EXIT_FAIL_OPTION;
    }
    struct config cfg = {
        .xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE,
        .ifindex   = -1,
        .do_unload = false,
    };
   
    /* Set default BPF-ELF object file and BPF program name */
    strncpy(cfg.filename, default_filename, sizeof(cfg.filename));
    strncpy(cfg.progsec,  default_progsec,  sizeof(cfg.progsec));
    
    cfg.ifname = (char *)&cfg.ifname_buf;
    strncpy(cfg.ifname, ifname, IF_NAMESIZE);
    cfg.ifindex = if_nametoindex(cfg.ifname);
    if (cfg.ifindex == 0) {
        VLOG_INFO("ERR: --dev name (%s) unknown", ifname);
        return EXIT_FAIL_OPTION;
    }

    /* Required option */
    if (cfg.ifindex == -1) {
        VLOG_INFO("ERR: --dev name (%s) ifindex not found", ifname);
        return EXIT_FAIL_OPTION;
    }
    if (cfg.do_unload) {
        // return xdp_link_detach(cfg->ifindex, cfg->xdp_flags, 0);
    }

    bpf_obj = __load_bpf_and_xdp_attach(&cfg);
    if (!bpf_obj) {
        VLOG_INFO(" Failed - XDP prog attached on device:%s(ifindex:%d)",
            cfg.ifname, cfg.ifindex);
        return EXIT_FAIL_BPF;
    }

    VLOG_INFO("Success: Loaded BPF-object(%s) and used section(%s)",
            cfg.filename, cfg.progsec);
    VLOG_INFO(" - XDP prog attached on device:%s(ifindex:%d)",
            cfg.ifname, cfg.ifindex);
    
    /* Other BPF section programs will get freed on exit */
    return EXIT_OK;
}
#pragma GCC diagnostic pop