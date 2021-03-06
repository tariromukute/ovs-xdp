#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/xsk.h>
// #include <linux/if_link.h>
#include <net/if.h>
#include <errno.h>
#include <unistd.h>
#include <linux/openvswitch.h>
#include <sys/resource.h>
#include "flow.h"
#include "loader.h"
#include "datapath.h"

VLOG_DEFINE_THIS_MODULE(xdp_loader);
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
    char pin_dir[4096];
    char filename[512];
    char progsec[32];
    char src_mac[18];
    char dest_mac[18];
    __u16 xsk_bind_flags;
    int xsk_if_queue;
    bool xsk_poll_mode;
};

// static const char *default_filename = "entry-point.o";
static const char *action_filename = "actions.o";
// static const char *pin_basedir = "/sys/fs/bpf";
static const char *prog_map_name = "tail_table";
// static const char *stats_map = "stats_map";
// static const char *flow_map = "flow_table";
static const char *_ports_map = "_ports";
static const char *port_flow_map = "port_flow";
// static const char *_perf_map = "_perf_map";
// static const char *devmap = "devmap";
// static const char *xsks_map = "xsks_map";
static const char *prog_name = "process";


// static inline __u32 xsk_ring_prod__free(struct xsk_ring_prod *r)
// {
//     r->cached_cons = *r->consumer + r->size;
//     return r->cached_cons - r->cached_prod;
// }


static struct xsk_umem_info *configure_xsk_umem(void *buffer, uint64_t size)
{
    struct xsk_umem_info *umem;
    int ret;

    umem = calloc(1, sizeof(*umem));
    if (!umem)
        return NULL;

    ret = xsk_umem__create(&umem->umem, buffer, size, &umem->fq, &umem->cq,
                   NULL);
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

static struct xsk_socket_info *xsk_configure_socket(struct config *cfg,
                            struct xsk_umem_info *umem)
{
    struct xsk_socket_config xsk_cfg;
    struct xsk_socket_info *xsk_info;
    uint32_t idx;
    uint32_t prog_id = 0;
    int i;
    int ret;

    xsk_info = calloc(1, sizeof(*xsk_info));
    if (!xsk_info)
        return NULL;

    xsk_info->umem = umem;
    xsk_cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
    xsk_cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
    xsk_cfg.libbpf_flags = 0;
    xsk_cfg.xdp_flags = cfg->xdp_flags;
    xsk_cfg.bind_flags = cfg->xsk_bind_flags;
    ret = xsk_socket__create(&xsk_info->xsk, cfg->ifname,
                 cfg->xsk_if_queue, umem->umem, &xsk_info->rx,
                 &xsk_info->tx, &xsk_cfg);
    VLOG_INFO("--- Called: %s xsk_socket__create %d ---", __func__, ret);

    if (ret)
        goto error_exit;

    ret = bpf_get_link_xdp_id(cfg->ifindex, &prog_id, cfg->xdp_flags);
    VLOG_INFO("--- Called: %s bpf_get_link_xdp_id ret %d prog_id %d ---", __func__, ret, prog_id);
    if (ret)
        goto error_exit;

    /* Initialize umem frame allocation */

    for (i = 0; i < NUM_FRAMES; i++)
        xsk_info->umem_frame_addr[i] = i * FRAME_SIZE;

    xsk_info->umem_frame_free = NUM_FRAMES;

    /* Stuff the receive path with buffers, we assume we have enough */
    ret = xsk_ring_prod__reserve(&xsk_info->umem->fq,
                     XSK_RING_PROD__DEFAULT_NUM_DESCS,
                     &idx);

    VLOG_INFO("--- Called: %s xsk_ring_prod__reserve ret %d prog_id %d ---", __func__, ret, prog_id);
    if (ret != XSK_RING_PROD__DEFAULT_NUM_DESCS)
        goto error_exit;

    for (i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i ++)
        *xsk_ring_prod__fill_addr(&xsk_info->umem->fq, idx++) =
            xsk_alloc_umem_frame(xsk_info);

    xsk_ring_prod__submit(&xsk_info->umem->fq,
                  XSK_RING_PROD__DEFAULT_NUM_DESCS);

    return xsk_info;

error_exit:
    errno = -ret;
    return NULL;
}

int xsk_sock_create(struct xsk_socket_info **sockp, const char *ifname)
{
    struct xsk_socket_info *sock;
    void *packet_buffer;
    uint64_t packet_buffer_size;
    struct config cfg = {
        .xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE,
        .ifindex   = -1,
        .do_unload = false,
    };
    cfg.ifname = (char *)&cfg.ifname_buf;
    strncpy(cfg.ifname, ifname, IF_NAMESIZE);
    cfg.ifindex = if_nametoindex(cfg.ifname);
    struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
    struct xsk_umem_info *umem;
    /* Allow unlimited locking of memory, so all memory needed for packet
    * buffers can be locked.
    */
    if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
        VLOG_INFO("ERROR: setrlimit(RLIMIT_MEMLOCK)");
        return EXIT_FAIL;
    }
    /* Allocate memory for NUM_FRAMES of the default XDP frame size */
    packet_buffer_size = NUM_FRAMES * FRAME_SIZE;
    if (posix_memalign(&packet_buffer,
            getpagesize(), /* PAGE_SIZE aligned */
            packet_buffer_size)) {
        VLOG_INFO("ERROR: Can't allocate buffer memory");
        return EXIT_FAIL;
    }
    /* Initialize shared packet_buffer for umem usage */
    umem = configure_xsk_umem(packet_buffer, packet_buffer_size);
    if (umem == NULL) {
        VLOG_INFO("ERROR: Can't create umem");
        return EXIT_FAIL;
    }
    /* Open and configure the AF_XDP (xsk) socket */
    sock = xsk_configure_socket(&cfg, umem);
    if (sock == NULL) {
        VLOG_INFO("ERROR: Can't setup AF_XDP socket");
        return EXIT_FAIL;
    }
    *sockp = sock;
    return 0;
}

void xsk_sock_destroy(struct xsk_socket_info *sock)
{
    xsk_socket__delete(sock->xsk);
    xsk_umem__delete(sock->umem->umem);
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
int xsk_sock_close(struct xsk_socket_info *sock)
{
    // TODO: implement method

    return 0;
}
#pragma GCC diagnostic pop


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

static int reuse_maps(struct bpf_object *obj, struct config *cfg)
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

        if (bpf_map__name(map)[0] == '_') { // global map
            strcpy(pin_dir, pin_basedir);
        } else { // interface/entry point map
            strcpy(pin_dir, cfg->pin_dir);
        }

        // check if map already pinned
        len = snprintf(buf, PATH_MAX, "%s/%s", pin_dir, bpf_map__name(map));
        if (len < 0)
        {
            return -EINVAL;
        }
        else if (len >= PATH_MAX)
        {
            return -ENAMETOOLONG;
        }

        pinned_map_fd = bpf_obj_get(buf);
        if (pinned_map_fd > 0) // if reuse already pinned maps
        {
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

static int pin_unpinned_maps(struct bpf_object *obj, struct config *cfg)
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

        if (bpf_map__name(map)[0] == '_') { // global map
            strcpy(pin_dir, pin_basedir);
        } else { // interface/entry point map
            strcpy(pin_dir, cfg->pin_dir);
        }

        // check if map already pinned
        len = snprintf(buf, PATH_MAX, "%s/%s", pin_dir, bpf_map__name(map));
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
            err = bpf_map__pin(map, buf);
            if (err)
            {
                VLOG_INFO("Error pinning map %s \n", bpf_map__name(map));
            }
        }
    }

    return 0;
}

static struct bpf_object *load_attach_program(const char *filename, struct config *cfg)
{
    int prog_fd;
    struct bpf_object *obj;
    struct bpf_program *bpf_prog;
    int err = 0;
    // unload first
    err = link_detach(cfg->ifindex, cfg->xdp_flags, 0);
    if (err)
    {
        VLOG_INFO("error unlinking");
        return NULL;
    }
    obj = open_bpf_object(filename, 0);
    if (!obj)
    {
        VLOG_INFO("ERR: failed to open object %s\n", filename);
        return NULL;
    }
    // reuse the reuseable maps, starts with _
    err = reuse_maps(obj, cfg);
    if (err)
    {
        VLOG_INFO("error reusing maps");
        return NULL;
    }
    err = bpf_object__load(obj);
    if (err)
    {
        VLOG_INFO("Error loading object err: %d", err);
        return NULL;
    }
    bpf_prog = bpf_object__find_program_by_title(obj, cfg->progsec);
    if (!bpf_prog)
    {
        VLOG_INFO("Could not find prog");
        return NULL;
    }
    prog_fd = bpf_program__fd(bpf_prog);
    if (prog_fd <= 0)
    {
        VLOG_INFO("ERR: bpf_program__fd failed\n");
        return NULL;
    }
    /* At this point: BPF-progs are (only) loaded by the kernel, and prog_fd
     * is our select file-descriptor handle. Next step is attaching this FD
     * to a kernel hook point, in this case XDP net_device link-level hook.
     */
    err = link_attach(cfg->ifindex, cfg->xdp_flags, prog_fd);
    if (err)
    {
        VLOG_INFO("failed to attach");
        return NULL;
    }
    // pin the maps that need to be pinned
    err = pin_unpinned_maps(obj, cfg);
    if (err)
    {
        VLOG_INFO("error pinning maps");
        return NULL;
    }
    return obj;
}

static int load_update_prog_map(const char *filename, struct config *cfg)
{
    int prog_fd;
    struct bpf_object *obj;
    struct bpf_map *map;
    int err;
    obj = open_bpf_object(filename, 0);
    if (!obj)
    {
        VLOG_INFO("ERR: failed to open object %s\n", filename);
        return EXIT_FAIL;
    }

    // reuse the reusable maps
    err = reuse_maps(obj, cfg);
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

    err = pin_unpinned_maps(obj, cfg);
    if (err)
    {
        VLOG_INFO("error pinning maps");
    }

    int len;
    char dir[PATH_MAX];
    len = snprintf(dir, PATH_MAX, "%s/%s", cfg->pin_dir, "prog");
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
    if (!map) {
        VLOG_INFO("bpf_object__find_map_by_name failed\n");
    }
    int map_fd = bpf_map__fd(map);
    if (map_fd <= 0) {
        VLOG_INFO("bpf_map__fd failed\n");
    }


  
    /* NOTE: Add the programs. If we don't pin the programs first and add the prog_fd of the pinned
     * program the bpf_tail_call wasn't working. There might be some work around which is not
     * pinning that I am not aware of atm. For now just went with the pinning the programs first.  */
    for (i = 0; i < TAIL_TABLE_SIZE; ++i)
    {
        char buf[PATH_MAX];

        len = snprintf(buf, PATH_MAX, "%s/%s/%s", cfg->pin_dir, "prog", xdp_action_attr_list[i].name);
        if (len < 0)
        {
            return -EINVAL;
        }
        else if (len >= PATH_MAX)
        {
            return -ENAMETOOLONG;
        }

        prog_fd = bpf_obj_get(buf);
        err = bpf_map_update_elem(map_fd, &i, &prog_fd, 0);
        if (err) {
            // VLOG_INFO("Could not update prog map\n");
        }
    }

    return 0;
}

// static int pinned_map_fd_by_name(struct config *cfg, const char *name)
// {
//     char buf[PATH_MAX];
//     char pin_dir[PATH_MAX];

//     if (name[0] == '_') { // global map
//         strcpy(pin_dir, pin_basedir);
//     } else { // interface/entry point map
//         strcpy(pin_dir, cfg->pin_dir);
//     }

//     // check if map already pinned
//     int len = snprintf(buf, PATH_MAX, "%s/%s", pin_dir, name);
//     if (len < 0)
//     {
//         return -EINVAL;
//     }
//     else if (len >= PATH_MAX)
//     {
//         return -ENAMETOOLONG;
//     }

//     int fd = bpf_obj_get(buf);
//     return fd;
// }

// static bpf_map * pinned_map_by_name(struct config *cfg, const char *name)
// {
//     char buf[PATH_MAX];
//     char pin_dir[PATH_MAX];

//     if (name[0] == '_') { // global map
//         strcpy(pin_dir, pin_basedir);
//     } else { // interface/entry point map
//         strcpy(pin_dir, cfg->pin_dir);
//     }

//     // check if map already pinned
//     int len = snprintf(buf, PATH_MAX, "%s/%s", pin_dir, name);
//     // if (len < 0)
//     // {
//     //     return -EINVAL;
//     // }
//     // else if (len >= PATH_MAX)
//     // {
//     //     return -ENAMETOOLONG;
//     // }

//     return bpf_object__find_map_by_name();
// }

int xdp_load(struct xdp_ep *xdp_ep, const char *path, const char *ifname)
{
    int err = 0;
    struct config cfg = {
        .xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE,
        .ifindex   = -1,
        .do_unload = false,
    };
    strcpy(cfg.progsec, prog_name);
    cfg.ifname = (char *)&cfg.ifname_buf;
    strncpy(cfg.ifname, ifname, IF_NAMESIZE);
    // memcpy(cfg.ifname, ifname, sizeof(ifname));
    cfg.ifindex = if_nametoindex(cfg.ifname);


    int len = snprintf(cfg.pin_dir, PATH_MAX, "%s/%s", pin_basedir, cfg.ifname);
    if (len < 0) {
        VLOG_INFO("ERR: creating pin dirname\n");
        return EXIT_FAIL_OPTION;
    }

    char ep[PATH_MAX];
    len = snprintf(ep, PATH_MAX, "%s/%s", path, default_filename);
    if (len < 0) {
        VLOG_INFO("ERR: creating entry point path\n");
        return EXIT_FAIL_OPTION;
    }

    struct bpf_object *obj = load_attach_program(ep, &cfg);
    if (!obj) {
        VLOG_INFO("error loading program ifname: %s, ifindex %d, program name: %s \n", cfg.ifname, cfg.ifindex, cfg.progsec);

    }

    char actions[PATH_MAX];
    len = snprintf(actions, PATH_MAX, "%s/%s", path, action_filename);
    if (len < 0) {
        VLOG_INFO("ERR: creating actions path\n");
        return EXIT_FAIL_OPTION;
    }

    err = load_update_prog_map(actions, &cfg);
    if (err) {
        VLOG_INFO("error adding programs to prog map\n");
        return EXIT_FAIL_OPTION;
    }

    xdp_ep->flow_map_fd = pinned_map_fd_by_name(&cfg, flow_map);
    xdp_ep->stats_map_fd = pinned_map_fd_by_name(&cfg, stats_map);
    xdp_ep->ep_id = xdp_ep->flow_map_fd;

    // Added the inner map
    struct bpf_map *ports_map = bpf_object__find_map_by_name(obj, _ports_map);
    int port_flow_fd = pinned_map_fd_by_name(&cfg, port_flow_map);
    err = bpf_map__set_inner_map_fd(ports_map, port_flow_fd);
    if (err) {
        VLOG_INFO("---- Failed to add inner map, err: %d ----", err);
        return EXIT_FAIL_OPTION;
    }

    // Add value to map for testing;
    struct xdp_flow_key key;
    memset(&key, 0, sizeof(struct xdp_flow_key));
    __u8 act_buf[XDP_FLOW_ACTIONS_LEN_u64];

    memset(act_buf, 1, XDP_FLOW_ACTIONS_LEN_u64);
    err = bpf_map_update_elem(port_flow_fd, &key, act_buf, BPF_NOEXIST);
    if (err) {
        VLOG_INFO("---- Failed to add test data, err: %d ----", err);
        return EXIT_FAIL_OPTION;
    }

    VLOG_INFO("--- XDP INFO: xdp_ep->flow_map_fd: %d, xdp_ep->stats_map_fd: %d, xdp_ep->ep_id: %d ----", xdp_ep->flow_map_fd, xdp_ep->stats_map_fd, xdp_ep->ep_id);

    return 0; 

}
