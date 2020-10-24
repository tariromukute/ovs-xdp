#include <net/if.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
// #include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <sys/mman.h>
#include "err.h"
#include "logging.h"
#include "xf_netdev.h"
#include "libxdp.h"
#include "util.h"
#include "datapath.h"
#include "flow-table.h"
#include "dynamic-string.h"

// static const char *action_filename = "actions.o";

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

int handle_multistring(const char *str, void *tgt)
{
    pr_info("handle_multistring");
    struct multistring *opt_set = tgt;
    void *ptr;

    ptr = reallocarray(opt_set->strings, sizeof(*opt_set->strings),
               opt_set->num_strings + 1);
    if (!ptr)
        return -errno;

    opt_set->strings = ptr;
    // opt_set->strings[opt_set->num_strings++] = str;
    strncpy(opt_set->strings[opt_set->num_strings++], str, PATH_MAX - 1);
    return 0;
}

int pinned_map_fd_by_name(struct loadopt *opt, const char *name)
{
    char buf[PATH_MAX];
    char pin_dir[PATH_MAX];

    strcpy(pin_dir, opt->pin_path);

    // check if map already pinned
    int len = snprintf(buf, PATH_MAX, "%s/%s", pin_dir, name);
    if (len < 0)
    {
        return -EINVAL;
    }
    else if (len >= PATH_MAX)
    {
        return -ENAMETOOLONG;
    }
    int fd = bpf_obj_get(buf);
    return fd;
}

/* program operations - load, unload, status etc */

/* Use this version of load to load a program with additional custom lower
 * priority programs. */
int
xdp_prog_load(struct xdp_ep *xdp_ep, struct xs_cfg *cfg)
{
    struct xdp_program **progs, *p;
    char errmsg[STRERR_BUFSIZE];
    int err = EXIT_SUCCESS, i;
    size_t num_progs;
    int ifindex = if_nametoindex(cfg->ifname);
    if (ifindex < 0)
        return EXIT_FAILURE;

    if (!cfg->path)
        return EXIT_FAILURE;

    struct iface iface = {
        .ifname = cfg->ifname,
        .ifindex = ifindex
    };

    struct loadopt opt = {
        .help = false,
        .mode = cfg->mode,
        .iface = iface,
        .section_name = "prog"
    };

    char file_name[PATH_MAX];
    struct multistring filenames;
    int x = 0;
    if (!cfg->filenames) {
        int len = snprintf(file_name, PATH_MAX, "%s/%s", cfg->path, default_filename);
        if (len < 0) {
            pr_warn("ERR: creating entry point path\n");
            return EXIT_FAIL_OPTION;
        }

        err = handle_multistring(file_name, &filenames);
        if (err)
            return EXIT_FAIL_OPTION;
    } else {
        int c = 0;
        for (c = 0; c < cfg->filenames->num_strings; c++) {
            err = handle_multistring(cfg->filenames->strings[c], &filenames);
            if (err)
                return EXIT_FAIL_OPTION;
        }
    }
    
    set_path_to_dispatcher(cfg->path);

    char buf[PATH_MAX];
    int len = snprintf(buf, PATH_MAX, "%s/%s", pin_basedir, cfg->brname);
    if (len < 0) {
        pr_info("ERR: creating pin dirname\n");
        return EXIT_FAIL_OPTION;
    }

    opt.pin_path = buf;

    DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts,
                .pin_root_path = opt.pin_path);

    num_progs = filenames.num_strings;
    if (!num_progs) {
        pr_warn("Need at least one filename to load\n");
        return EXIT_FAILURE;
    } else if (num_progs > 1 && opt.mode == XDP_MODE_HW) {
        pr_warn("Cannot attach multiple programs in HW mode\n");
        return EXIT_FAILURE;
    }

    progs = calloc(num_progs, sizeof(*progs));
    if (!progs) {
        pr_warn("Couldn't allocate memory\n");
        return EXIT_FAILURE;
    }

    pr_info("Loading %"PRIuSIZE" files on interface '%s'.\n",
         num_progs, opt.iface.ifname);

    /* libbpf spits out a lot of unhelpful error messages while loading.
     * Silence the logging so we can provide our own messages instead; this
     * is a noop if verbose logging is enabled.
     */
    silence_libbpf_logging();
    num_progs = 1;
retry:
    for (i = 0; i < num_progs && file_name != NULL; i++) {
        p = progs[i];
        if (p)
            xdp_program__close(p);
        
        p = xdp_program__open_file(file_name,
                       opt.section_name, &opts);

        if (IS_ERR(p)) {
            err = PTR_ERR(p);

            if (err == -EPERM && !double_rlimit())
                goto retry;

            libxdp_strerror(err, errmsg, sizeof(errmsg));
            pr_warn("Couldn't open file '%s': %s\n",
                file_name, errmsg);
            goto out;
        }

        xdp_program__print_chain_call_actions(p, errmsg, sizeof(errmsg));
        
        // if (!opt.pin_path) {
            struct bpf_map *map;

            bpf_object__for_each_map(map, xdp_program__bpf_obj(p)) {
                err = bpf_map__set_pin_path(map, NULL);
                if (err) {
                    pr_warn("Error clearing map pin path\n");
                    goto out;
                }
            }
        // }
        progs[i] = p;
    }

    err = xdp_program__attach_multi(progs, num_progs,
                    opt.iface.ifindex, opt.mode, 0);

    if (err) {
        if (err == -EPERM && !double_rlimit())
            goto retry;

        libbpf_strerror(err, errmsg, sizeof(errmsg));
        pr_warn("Couldn't attach XDP program on iface '%s': %s(%d)\n",
            opt.iface.ifname, errmsg, err);
        goto out;
    }

    // Get the fd
    xdp_ep->flow_map_fd = pinned_map_fd_by_name(&opt, macro_flow_map);
    xdp_ep->stats_map_fd = -1;
    xdp_ep->ep_id = xdp_ep->flow_map_fd;

out:
    for (i = 0; i < num_progs; i++)
        if (progs[i])
            xdp_program__close(progs[i]);
    free(progs);
    return err;
}

int xdp_prog_default_load(struct xdp_ep *xdp_ep, struct xs_cfg *cfg)
{
    pr_info("Called: %s", __func__);
    struct xdp_program **progs, *p;
    char errmsg[STRERR_BUFSIZE];
    int err = EXIT_SUCCESS, i;
    size_t num_progs = 1;
    int ifindex = if_nametoindex(cfg->ifname);
    if (ifindex < 0) {
        pr_warn("Invalid ifindex provided");
        return EXIT_FAILURE;
    }

    if (!cfg->path) {
        pr_warn("The path to the xdp program files is required");
        return EXIT_FAILURE;
    }

    struct iface iface = {
        .ifname = cfg->ifname,
        .ifindex = ifindex
    };

    char pin_path[PATH_MAX];
    if (try_snprintf(pin_path, PATH_MAX, "%s/%s", pin_basedir, cfg->brname_buf)) {
        pr_warn("Could not create pin_path");
        return EXIT_FAILURE;
    }

    struct loadopt opt = {
        .help = false,
        .mode = cfg->mode,
        .iface = iface,
        .section_name = "prog"
    };

    opt.pin_path = (char *)&pin_path;
    char file_name[PATH_MAX];
    int len = snprintf(file_name, PATH_MAX, "%s/%s", cfg->path, default_filename);
    if (len < 0) {
        pr_warn("ERR: creating entry point path\n");
        return EXIT_FAIL_OPTION;
    }
    pr_info("File being loaded %s", file_name);

    set_path_to_dispatcher(cfg->path);
    
    DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts,
                .pin_root_path = opt.pin_path);

    progs = calloc(num_progs, sizeof(*progs));
    if (!progs) {
        pr_warn("Couldn't allocate memory");
        return EXIT_FAILURE;
    }
    pr_warn("Loading %"PRIuSIZE" files on interface '%s'.",
         num_progs, opt.iface.ifname);
 
    /* libbpf spits out a lot of unhelpful error messages while loading.
     * Silence the logging so we can provide our own messages instead; this
     * is a noop if verbose logging is enabled.
     */
    silence_libbpf_logging();
retry:
    for (i = 0; i < num_progs; i++) {
        p = progs[i];
        if (p)
            xdp_program__close(p);
        
        p = xdp_program__open_file(file_name,
                       opt.section_name, &opts);

        if (IS_ERR(p)) {
            err = PTR_ERR(p);

            if (err == -EPERM && !double_rlimit())
                goto retry;

            libxdp_strerror(err, errmsg, sizeof(errmsg));
            pr_warn("Couldn't open file '%s': %s",
                file_name, errmsg);
            goto out;
        }

        xdp_program__print_chain_call_actions(p, errmsg, sizeof(errmsg));
        
        if (!opt.pin_path) {
            struct bpf_map *map;

            bpf_object__for_each_map(map, xdp_program__bpf_obj(p)) {
                err = bpf_map__set_pin_path(map, NULL);
                if (err) {
                    pr_warn("Failed to clear pinned map");
                    goto out;
                }
            }
        } else {
            struct bpf_map *map;
            bpf_object__for_each_map(map, xdp_program__bpf_obj(p)) {
                if (strcmp(macro_flow_map, bpf_map__name(map)) == 0)
                    xdp_ep->flow_map_fd = bpf_map__fd(map);

                if (strcmp(tx_port, bpf_map__name(map)) == 0) {
                    int m = 1;    
                    for (m = 1; m < 128; ++m) {
                        bpf_map_update_elem(bpf_map__fd(map), &m, &m, 0);
                    }
                }

            }
        }

        progs[i] = p;
    }


    err = xdp_program__attach_multi(progs, num_progs,
                    opt.iface.ifindex, opt.mode, 0);

    if (err) {
        if (err == -EPERM && !double_rlimit())
            goto retry;

        libbpf_strerror(err, errmsg, sizeof(errmsg));
        pr_warn("Couldn't attach XDP program on iface '%s': %s(%d)\n",
            opt.iface.ifname, errmsg, err);
        goto out;
    }

    // Get the fd
    // xdp_ep->flow_map_fd = pinned_map_fd_by_name(&opt, macro_flow_map);
    xdp_ep->stats_map_fd = -1;
    xdp_ep->ep_id = xdp_program__id(progs[0]);
out:
    for (i = 0; i < num_progs; i++)
        if (progs[i])
            xdp_program__close(progs[i]);
    free(progs);
    return err;
}

int
xdp_prog_unload(__u32 prog_id, char *ifname, char *brname)
{
    struct xdp_multiprog *mp = NULL;
    int err = EXIT_FAILURE;

    int ifindex = if_nametoindex(ifname);
    if (ifindex < 0)
        return EXIT_FAILURE;
   
    struct iface iface = {
        .ifname = ifname,
        .ifindex = ifindex
    };

    struct unloadopt opt = {
        .all = true,
        .prog_id = prog_id,
        .iface = iface
    };

    char pin_path[PATH_MAX];
    int len = snprintf(pin_path, PATH_MAX, "%s/%s", pin_basedir, brname);
    if (len < 0) {
        pr_warn("ERR: creating pin dirname\n");
        return EXIT_FAIL_OPTION;
    }

    DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts,
                .pin_root_path = pin_path);

    if (!opt.all && !opt.prog_id) {
        pr_warn("Need prog ID or --all\n");
        goto out;
    }

    if (!opt.iface.ifindex) {
        pr_warn("Must specify ifname\n");
        goto out;
    }

    mp = xdp_multiprog__get_from_ifindex(opt.iface.ifindex);
    if (IS_ERR_OR_NULL(mp)) {
        pr_warn("No XDP program loaded on %s\n", opt.iface.ifname);
        mp = NULL;
        goto out;
    }

    if (opt.all ||
        (xdp_multiprog__is_legacy(mp) &&
         (xdp_program__id(xdp_multiprog__main_prog(mp)) == opt.prog_id))) {
        err = xdp_multiprog__detach(mp);
        if (err) {
            pr_warn("Unable to detach XDP program\n");
            goto out;
        }
    } else {
        struct xdp_program *prog = NULL;

        while ((prog = xdp_multiprog__next_prog(prog, mp))) {
            if (xdp_program__id(prog) == opt.prog_id)
                break;
        }
        if (!prog) {
            pr_warn("Program with ID %u not loaded on %s\n",
                opt.prog_id, opt.iface.ifname);
            err = -ENOENT;
            goto out;
        }
        pr_debug("Detaching XDP program with ID %u from %s\n",
             xdp_program__id(prog), opt.iface.ifname);
        err = xdp_program__detach(prog, opt.iface.ifindex,
                      XDP_MODE_UNSPEC, 0);
        if (err) {
            pr_warn("Unable to detach XDP program\n");
            goto out;
        }
    }

out:
    xdp_multiprog__close(mp);
    return err ? EXIT_FAILURE : EXIT_SUCCESS;
}

int
xdp_prog_status(struct xs_cfg *cfg)
{
    int err = ENOENT;

    return err;
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

/* upcall sockets */
static struct xsk_umem_info *configure_xsk_umem(void *buffer, uint64_t size)
{
    struct xsk_umem_info *umem;
    int ret;

    umem = calloc(1, sizeof(*umem));
    if (!umem)
        return NULL;

    ret = xsk_umem__create(&umem->umem, buffer, size, &umem->fq, &umem->cq,
                   NULL);
    pr_info("xsk_umem__create fd %d", xsk_umem__fd(umem->umem));
    if (ret) {
        errno = -ret;
        return NULL;
    }

    umem->buffer = buffer;
    return umem;
}

static uint64_t xsk_alloc_umem_frame(struct xsk_socket_info *xsk)
{
    uint64_t frame;
    if (xsk->umem_frame_free == 0)
        return INVALID_UMEM_FRAME;

    frame = xsk->umem_frame_addr[--xsk->umem_frame_free];
    xsk->umem_frame_addr[xsk->umem_frame_free] = INVALID_UMEM_FRAME;
    return frame;
}

static void xsk_free_umem_frame(struct xsk_socket_info *xsk, uint64_t frame)
{
    assert(xsk->umem_frame_free < NUM_FRAMES);

    xsk->umem_frame_addr[xsk->umem_frame_free++] = frame;
}

static uint64_t xsk_umem_free_frames(struct xsk_socket_info *xsk)
{
    return xsk->umem_frame_free;
}

static int xsk_populate_fill_ring(struct xsk_umem_info *umem)
{
    int ret, i;
    __u32 idx;

    ret = xsk_ring_prod__reserve(&umem->fq,
                     XSK_RING_PROD__DEFAULT_NUM_DESCS * 2, &idx);
    if (ret != XSK_RING_PROD__DEFAULT_NUM_DESCS * 2) {
        pr_info("Could not reserve the requested number of descriptors");
        return -ret;
    }
        
    for (i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS * 2; i++)
        *xsk_ring_prod__fill_addr(&umem->fq, idx++) =
            i * opt_xsk_frame_size;
    xsk_ring_prod__submit(&umem->fq, XSK_RING_PROD__DEFAULT_NUM_DESCS * 2);

    return 0;
}

static struct xsk_umem_info *xsk_configure_umem__v2(void *buffer, __u64 size)
{
    struct xsk_umem_info *umem;
    struct xsk_umem_config cfg = {
        /* We recommend that you set the fill ring size >= HW RX ring size +
         * AF_XDP RX ring size. Make sure you fill up the fill ring
         * with buffers at regular intervals, and you will with this setting
         * avoid allocation failures in the driver. These are usually quite
         * expensive since drivers have not been written to assume that
         * allocation failures are common. For regular sockets, kernel
         * allocated memory is used that only runs out in OOM situations
         * that should be rare.
         */
        .fill_size = XSK_RING_PROD__DEFAULT_NUM_DESCS * 2,
        .comp_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
        .frame_size = opt_xsk_frame_size,
        .frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
        .flags = opt_umem_flags
    };
    int ret;

    umem = calloc(1, sizeof(*umem));
    if (!umem)
        return errno;

    ret = xsk_umem__create(&umem->umem, buffer, size, &umem->fq, &umem->cq,
                   &cfg);
    if (ret)
        return -ret;

    umem->buffer = buffer;
    return umem;
}

static struct xsk_socket_info *xsk_configure_socket(struct xs_cfg *cfg,
                            struct xsk_umem_info *umem)
{
    struct xsk_socket_config xsk_cfg;
    struct xsk_socket_info *xsk_info;
    uint32_t idx;
    // uint32_t prog_id = 0;
    int i;
    int ret;

    int ifindex = if_nametoindex(cfg->ifname);
    if (ifindex < 0) {
        pr_warn("Invalid ifname");
        return NULL;
    }

    xsk_info = calloc(1, sizeof(*xsk_info));
    if (!xsk_info) {
        pr_warn("Couldn't calloc xsk_info");
        return NULL;
    }

    xsk_info->umem = umem;
    xsk_cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
    xsk_cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
    /* Note: when loading multi program the create socket fails when the 
     * the xsk_socket__create tries to load program in xsk_setup_xdp_prog.
     * To take care of this error we will inhibit the program load and then
     * we will load the program ourselves. */
    xsk_cfg.libbpf_flags = 0;
    xsk_cfg.libbpf_flags |= XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD;
    xsk_cfg.xdp_flags = 0;
    xsk_cfg.bind_flags = 0;
    // xsk_cfg.bind_flags |= XDP_FLAGS_UPDATE_IF_NOEXIST;
    // ret = xsk_socket__create(&xsk_info->xsk, cfg->ifname,
    //              cfg->xsk_if_queue, umem->umem, &xsk_info->rx,
    //              &xsk_info->tx, &xsk_cfg);

    ret = xsk_socket__create_shared(&xsk_info->xsk, cfg->ifname,
                cfg->xsk_if_queue, umem->umem, 
                &xsk_info->rx,
                &xsk_info->tx,
                &umem->fq,
                &umem->cq,
                &xsk_cfg);

    if (ret) {
        pr_warn("Create socket failed with ret: %d", ret);
        goto err;
    }

    /* Get pinned xsks_map fd and set it up the socket in map*/
    char buf[PATH_MAX];
    if (try_snprintf(buf, PATH_MAX, "%s/%s/%s", pin_basedir, cfg->brname, xsks_map) < 0) {
        pr_warn("Creating the pin map failed");
        goto err;
    }

    int map_fd = bpf_obj_get(buf);
    if (map_fd < 0) {
        pr_warn("Could not get the map_fd of the pinned map");
        goto err;
    }

    if (!xsk_info->xsk)
        pr_info("xsk_info->xsk not defined");

    int xsk_fd = xsk_socket__fd(xsk_info->xsk);
    if (xsk_fd < 0) {
        pr_warn("Invalid xsk_fd returned");
        goto err;
    }

    ret = bpf_map_update_elem(map_fd, &ifindex,
                   &xsk_fd, 0);            
    if (ret) {
        pr_warn("Could not add the interface to the xsks_map");
        goto err;
    }

    /* Initialize umem frame allocation */

    for (i = 0; i < NUM_FRAMES; i++)
        xsk_info->umem_frame_addr[i] = i * FRAME_SIZE;

    xsk_info->umem_frame_free = NUM_FRAMES;

    /* Stuff the receive path with buffers, we assume we have enough */
    ret = xsk_ring_prod__reserve(&umem->fq,
                     XSK_RING_PROD__DEFAULT_NUM_DESCS,
                     &idx);

    if (ret != XSK_RING_PROD__DEFAULT_NUM_DESCS) {
        pr_warn("xsk_ring_prod__reserve did not reserve the requested number of descritors");
        goto err;
    }

    for (i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i ++)
        *xsk_ring_prod__fill_addr(&umem->fq, idx++) =
            xsk_alloc_umem_frame(xsk_info);

    xsk_ring_prod__submit(&umem->fq,
                  XSK_RING_PROD__DEFAULT_NUM_DESCS);

    return xsk_info;

err:
    errno = -ret;
    return NULL;
}

int xswitch_xsk__create_umem__v2(struct xsk_umem_info **umem) 
{
    void *bufs;
    struct xsk_umem_info *u;
    bufs = mmap(NULL, NUM_FRAMES * opt_xsk_frame_size,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS | opt_mmap_flags, -1, 0);
    if (bufs == MAP_FAILED) {
        pr_warn("ERROR: mmap failed\n");
        return -1;
    }

    /* Create sockets... */
    u = xsk_configure_umem__v2(bufs, NUM_FRAMES * opt_xsk_frame_size);
    
    int error = xsk_populate_fill_ring(u);
    if (error) {
        pr_warn("Failed to populate fill ring");
        return -1;
    }
    *umem = u;
    return 0;
}

int xswitch_xsk__create_umem(struct xsk_umem_info **umem)
{
    void *packet_buffer;
    uint64_t packet_buffer_size;
    struct xsk_umem_info *u;
    
    /* Allocate memory for NUM_FRAMES of the default XDP frame size */
    packet_buffer_size = NUM_FRAMES * FRAME_SIZE * 6;
    if (posix_memalign(&packet_buffer,
            getpagesize(), /* PAGE_SIZE aligned */
            packet_buffer_size)) {
        pr_warn("Can't allocate buffer memory");
        return errno;
    }

    /* Initialize shared packet_buffer for umem usage */
    u = configure_xsk_umem(packet_buffer, packet_buffer_size);
    if (u == NULL) {
        pr_warn("Can't create umem");
        return errno;
    }

    *umem = u;
    return 0;
}

int
xdp_xsk_create__v2(struct xsk_socket_info **sockp, struct xs_cfg *cfg, struct xsk_umem_info *umem)
{
    struct xsk_socket_config xsk_cfg;
    struct xsk_socket_info *xsk_info;
    struct xsk_ring_cons *rxr;
    struct xsk_ring_prod *txr;
    int ret;

    int ifindex = if_nametoindex(cfg->ifname);
    if (ifindex < 0) {
        pr_warn("Invalid ifname");
        return NULL;
    }

    xsk_info = calloc(1, sizeof(*xsk_info));
    if (!xsk_info)
        return errno;

    xsk_info->umem = umem;
    xsk_cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
    xsk_cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;

    /* Note: when loading multi program the create socket fails when the 
     * the xsk_socket__create tries to load program in xsk_setup_xdp_prog.
     * To take care of this error we will inhibit the program load and then
     * we will load the program ourselves. */
    xsk_cfg.libbpf_flags = 0;
    xsk_cfg.libbpf_flags |= XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD;
    xsk_cfg.xdp_flags = 0;
    xsk_cfg.bind_flags = 0;

    ret = xsk_socket__create_shared(&xsk_info->xsk, cfg->ifname,
                cfg->xsk_if_queue, umem->umem, 
                &xsk_info->rx,
                &xsk_info->tx,
                &umem->fq,
                &umem->cq,
                &xsk_cfg);

    if (ret) {
        pr_warn("Create socket failed with ret: %d", ret);
        goto err;
    }

    /* Get pinned xsks_map fd and set it up the socket in map*/
    char buf[PATH_MAX];
    if (try_snprintf(buf, PATH_MAX, "%s/%s/%s", pin_basedir, cfg->brname, xsks_map) < 0) {
        pr_warn("Creating the pin map failed");
        goto err;
    }

    int map_fd = bpf_obj_get(buf);
    if (map_fd < 0) {
        pr_warn("Could not get the map_fd of the pinned map");
        goto err;
    }

    if (!xsk_info->xsk) {
        pr_info("xsk_info->xsk not defined");
        goto err;
    }

    int xsk_fd = xsk_socket__fd(xsk_info->xsk);
    if (xsk_fd < 0) {
        pr_warn("Invalid xsk_fd returned");
        goto err;
    }

    ret = bpf_map_update_elem(map_fd, &ifindex,
                   &xsk_fd, 0);            
    if (ret) {
        pr_warn("Could not add the interface to the xsks_map");
        goto err;
    }

    *sockp = xsk_info;
    return 0;

err:
    errno = -ret;
    return -1;
}

int
xdp_xsk_create(struct xsk_socket_info **sockp, struct xs_cfg *cfg, struct xsk_umem_info *umem)
{
    struct xsk_socket_info *xsk_socket;
    
    int ifindex = if_nametoindex(cfg->ifname);
    if (ifindex < 0)
        return -ENODEV;

    if (umem == NULL) {
        pr_info("umem is still NULL");
        return -1;
    } else {
        pr_info("umem not null");
    }

    /* Open and configure the AF_XDP (xsk) socket */
    xsk_socket = xsk_configure_socket(cfg, umem);
    if (xsk_socket == NULL) {
        pr_warn("Can't setup AF_XDP socket");
        return errno;
    }
    *sockp = xsk_socket;

    return 0;
}

int
xdp_xsk_close(struct xsk_socket_info *sock)
{
    int err = ENOENT;

    return err;
}

void
xdp_xsk_destroy(struct xsk_socket_info *sock)
{
    xsk_socket__delete(sock->xsk);
    xsk_umem__delete(sock->umem->umem);
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
        pr_warn("Failed to insert into map");
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

/* arp table */
int
xswitch_arp__add_entry(char *dev, __be32 ip, __u8 mac[ETH_ALEN])
{
    int error = 0;
    // check if mac is valid

    // check if ip is valid

    // check if dev exists

    // add arp entry
    error = arp__add_entry(dev, ip, mac);
    if (error) {
        pr_warn("Failed to add arp entry");
        goto out;
    }

out:
    return error;
}

/* flows based on entry point */
int xswitch_ep_flow_lookup(int map_fd, struct xf_key *key, struct xf **flowp)
{
    int err = 0;
    struct xf_key xf_key;
    struct xfa_buf act_buf;
    memset(&act_buf, 0, sizeof(struct xfa_buf));
    memcpy(&xf_key, key, sizeof(struct xf_key));

    err = xf_map_lookup(map_fd, &xf_key, &act_buf);
    if (err) {
        /* TODO: check error and return code */
        pr_warn("Flow loop failed");
        goto out;
    }
    struct xf flow;
    memset(&flow, 0, sizeof(struct xf));
    memcpy(&flow.actions, &act_buf, sizeof(struct xfa_buf));

    *flowp = &flow;
out:
    return err;
}

int xswitch_ep_flow_insert(int map_fd, struct xf *flow)
{
    struct xf_key xf_key;
    memset(&xf_key, 0, sizeof(struct xf_key));
    memcpy(&xf_key, &flow->key, sizeof(flow->key));
    int err = 0;

    err = xf_map_insert(map_fd, &xf_key, &flow->actions);
    if (err) {
        pr_warn("Failed to insert into map, error %d", err);
        /* TODO: check error and return code */
        goto out;
    }

out:
    return err;
}


/* TODO: think need pointer to a pointer here for key */
int xswitch_ep_flow_next(int map_fd, struct xf_key *pkey, struct xf **flowp)
{
    // printf("%s \n", __func__);
    struct xf flow;
    memset(&flow, 0, sizeof(struct xf));

    struct xf_key xf_key;
    memset(&xf_key, 0, sizeof(struct xf_key));
    
    if (pkey)
        memcpy(&xf_key, pkey, sizeof(*pkey));
    int err = 0;

    struct xf_key nxf_key;
    memset(&nxf_key, 0, sizeof(struct xf_key));
    err = xf_map_next_key(map_fd, &xf_key, &nxf_key);
    if (err) {
        /* TODO: check error and return code */
        goto out;
    }

    memcpy(&flow.key, &nxf_key, sizeof(struct xf_key));

    struct xfa_buf act_buf;
    memset(&act_buf, 0, sizeof(struct xfa_buf));
    err = xf_map_lookup(map_fd, &nxf_key, &act_buf);
    if (err) {
        /* TODO: check error and return code */
        goto out;
    }
    memcpy(&flow.actions, &act_buf, sizeof(struct xfa_buf));
    *flowp = &flow;

out:
    return err;
}

int xswitch_ep_flow_remove(int map_fd, struct xf_key *key)
{
    struct xf_key xf_key;
    memset(&xf_key, 0, sizeof(struct xf_key));
    memcpy(&xf_key, key, sizeof(*key));
    int err = 0;

    err = xf_map_remove(map_fd, &xf_key);
    if (err) {
        /* TODO: check error and return code */
        goto out;
    }

out:
    return err;
}

int xswitch_ep_flow_flush(int map_fd)
{
    int max_entries = 100; // from xf_kern.h, don't want to mix kernel and userspace code
    int err = 0;

    err = xf_map_flush(map_fd, max_entries);
    if (err) {
        /* TODO: check error and return code */
        goto out;
    }

out:
    return err;
}

/* flows based on the bridge name */
/* NOTE: the change to use xdp dispatcher resulted in the fd for the flows map that is
 * assigned during load time to fail. Not sure yet what the reason is. So changed the 
 * design such that we get the fd from the pinned map before query. However, the pinned
 * map returns a different fd every time. Not sure yet if this affects the limit of fds
 * for the process running. TODO: check if we need to unlink the fd after the query. also
 * TODO: check if we change get a map_fd during program load that will remain valid for
 * the lifetime of the switch processes */
int 
xswitch_br__flow_lookup(char *brname, struct xf_key *key, struct xf **flowp)
{
    int err = 0;
    struct xf_key xf_key;
    struct xfa_buf act_buf;
    memset(&act_buf, 0, sizeof(struct xfa_buf));
    memcpy(&xf_key, key, sizeof(struct xf_key));

    char pin_path[PATH_MAX];
    if (try_snprintf(pin_path, PATH_MAX, "%s/%s/%s", pin_basedir, brname, macro_flow_map)) {
        pr_warn("Could not create pin_path");
        return EXIT_FAILURE;
    }
    
    int map_fd = bpf_obj_get(pin_path);
    if (map_fd < 0) {
        pr_warn("Could not find map pin path: %s, %d", pin_path, map_fd);
    }

    err = xf_map_lookup(map_fd, &xf_key, &act_buf);
    if (err) {
        /* TODO: check error and return code */
        pr_warn("Flow loop failed");
        goto out;
    }
    struct xf flow;
    memset(&flow, 0, sizeof(struct xf));
    memcpy(&flow.actions, &act_buf, sizeof(struct xfa_buf));

    *flowp = &flow;
out:
    if (map_fd >= 0)
        close(map_fd);
    return err;
}

int
xswitch_br__flow_insert(char *brname, struct xf *flow)
{
    struct xf_key xf_key;
    memset(&xf_key, 0, sizeof(struct xf_key));
    memcpy(&xf_key, &flow->key, sizeof(flow->key));
    int err = 0;

    char pin_path[PATH_MAX];
    if (try_snprintf(pin_path, PATH_MAX, "%s/%s/%s", pin_basedir, brname, macro_flow_map)) {
        pr_warn("Could not create pin_path");
        return EXIT_FAILURE;
    }
    
    int map_fd = bpf_obj_get(pin_path);
    if (map_fd < 0) {
        pr_warn("Could not find map pin path: %s, %d", pin_path, map_fd);
    }

    err = xf_map_insert(map_fd, &xf_key, &flow->actions);
    if (err) {
        pr_warn("Failed to insert into map, error %d", err);
        /* TODO: check error and return code */
        goto out;
    }

out:
    if (map_fd >= 0)
        close(map_fd);
    return err;
}

int
xswitch_br__flow_next(char *brname, struct xf_key *pkey, struct xf **flowp)
{
    struct xf flow;
    memset(&flow, 0, sizeof(struct xf));

    struct xf_key xf_key;
    memset(&xf_key, 0, sizeof(struct xf_key));
    
    if (pkey)
        memcpy(&xf_key, pkey, sizeof(*pkey));
    int err = 0;

    char pin_path[PATH_MAX];
    if (try_snprintf(pin_path, PATH_MAX, "%s/%s/%s", pin_basedir, brname, macro_flow_map)) {
        pr_warn("Could not create pin_path");
        return EXIT_FAILURE;
    }
    
    int map_fd = bpf_obj_get(pin_path);
    if (map_fd < 0) {
        pr_warn("Could not find map pin path: %s, %d", pin_path, map_fd);
    }

    struct xf_key nxf_key;
    memset(&nxf_key, 0, sizeof(struct xf_key));
    err = xf_map_next_key(map_fd, &xf_key, &nxf_key);
    if (err) {
        /* TODO: check error and return code */
        goto out;
    }

    memcpy(&flow.key, &nxf_key, sizeof(struct xf_key));

    struct xfa_buf act_buf;
    memset(&act_buf, 0, sizeof(struct xfa_buf));
    err = xf_map_lookup(map_fd, &nxf_key, &act_buf);
    if (err) {
        /* TODO: check error and return code */
        goto out;
    }
    memcpy(&flow.actions, &act_buf, sizeof(struct xfa_buf));
    *flowp = &flow;

out:
    if (map_fd >= 0)
        close(map_fd);
    return err;
}

int
xswitch_br__flow_remove(char *brname, struct xf_key *key)
{
    struct xf_key xf_key;
    memset(&xf_key, 0, sizeof(struct xf_key));
    memcpy(&xf_key, key, sizeof(*key));
    int err = 0;

    char pin_path[PATH_MAX];
    if (try_snprintf(pin_path, PATH_MAX, "%s/%s/%s", pin_basedir, brname, macro_flow_map)) {
        pr_warn("Could not create pin_path");
        return EXIT_FAILURE;
    }
    
    int map_fd = bpf_obj_get(pin_path);
    if (map_fd < 0) {
        pr_warn("Could not find map pin path: %s, %d", pin_path, map_fd);
    }

    err = xf_map_remove(map_fd, &xf_key);
    if (err) {
        /* TODO: check error and return code */
        goto out;
    }

out:
    if (map_fd >= 0)
        close(map_fd);
    return err;
}

int
xswitch_br__flow_flush(char *brname)
{
    int max_entries = 100; // from xf_kern.h, don't want to mix kernel and userspace code
    int err = 0;

    char pin_path[PATH_MAX];
    if (try_snprintf(pin_path, PATH_MAX, "%s/%s/%s", pin_basedir, brname, macro_flow_map)) {
        pr_warn("Could not create pin_path");
        return EXIT_FAILURE;
    }
    
    int map_fd = bpf_obj_get(pin_path);
    if (map_fd < 0) {
        pr_warn("Could not find map pin path: %s, %d", pin_path, map_fd);
    }

    err = xf_map_flush(map_fd, max_entries);
    if (err) {
        /* TODO: check error and return code */
        goto out;
    }

out:
    if (map_fd >= 0)
        close(map_fd);
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

