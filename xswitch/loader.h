#ifndef XDP_LOADER_H
#define XDP_LOADER_H 1

#include <linux/types.h>
#include <asm/errno.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/xsk.h>
#include "datapath.h"
// #include <linux/if_link.h>

#include "openvswitch/vlog.h"

#ifdef  __cplusplus
extern "C" {
#endif

/* Exit return codes */
#define EXIT_OK 0   /* == EXIT_SUCCESS (stdlib.h) man exit(3) */
#define EXIT_FAIL 1 /* == EXIT_FAILURE (stdlib.h) man exit(3) */
#define EXIT_FAIL_OPTION 2
#define EXIT_FAIL_XDP 30
#define EXIT_FAIL_BPF 40

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

// #define NUM_FRAMES         4096
// #define FRAME_SIZE         XSK_UMEM__DEFAULT_FRAME_SIZE
// #define RX_BATCH_SIZE      64
// #define INVALID_UMEM_FRAME UINT64_MAX

/* XDP section */

#define XDP_FLAGS_UPDATE_IF_NOEXIST    (1U << 0)
#define XDP_FLAGS_SKB_MODE        (1U << 1)
#define XDP_FLAGS_DRV_MODE        (1U << 2)
#define XDP_FLAGS_HW_MODE        (1U << 3)
#define XDP_FLAGS_MODES            (XDP_FLAGS_SKB_MODE | \
                     XDP_FLAGS_DRV_MODE | \
                     XDP_FLAGS_HW_MODE)
#define XDP_FLAGS_MASK            (XDP_FLAGS_UPDATE_IF_NOEXIST | \
                     XDP_FLAGS_MODES)
                     
// struct xsk_umem_info {
//     struct xsk_ring_prod fq;
//     struct xsk_ring_cons cq;
//     struct xsk_umem *umem;
//     void *buffer;
// };

// struct stats_record {
//     uint64_t timestamp;
//     uint64_t rx_packets;
//     uint64_t rx_bytes;
//     uint64_t tx_packets;
//     uint64_t tx_bytes;
// };

// struct xsk_socket_info {
//     struct xsk_ring_cons rx;
//     struct xsk_ring_prod tx;
//     struct xsk_umem_info *umem;
//     struct xsk_socket *xsk;

//     uint64_t umem_frame_addr[NUM_FRAMES];
//     uint32_t umem_frame_free;

//     uint32_t outstanding_tx;

//     struct stats_record stats;
//     struct stats_record prev_stats;
// };

int link_detach(int ifindex, __u32 xdp_flags, __u32 expected_prog_id);
int link_attach(int ifindex, __u32 xdp_flags, int prog_fd);
int xsk_sock_create(struct xsk_socket_info **sockp, const char *ifname);
int xsk_sock_close(struct xsk_socket_info *sock);
void xsk_sock_destroy(struct xsk_socket_info *sock);
int xdp_load(struct xdp_ep *xdp_ep, const char *path, const char *ifname);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"


int link_detach(int ifindex, __u32 xdp_flags, __u32 expected_prog_id)
{
    __u32 curr_prog_id;
    int err;

    err = bpf_get_link_xdp_id(ifindex, &curr_prog_id, xdp_flags);
    if (err) {
        return EXIT_FAIL_XDP;
    }

    if (!curr_prog_id) {
        return EXIT_OK;
    }

    if (expected_prog_id && curr_prog_id != expected_prog_id) {
        return EXIT_FAIL;
    }

    if ((err = bpf_set_link_xdp_fd(ifindex, -1, xdp_flags)) < 0) {
        return EXIT_FAIL_XDP;
    }

    return EXIT_OK;
}

int link_attach(int ifindex, __u32 xdp_flags, int prog_fd)
{
    /* Next assignment this will move into ../common/ */
    int err;

    /* libbpf provide the XDP net_device link-level hook attach helper */
    err = bpf_set_link_xdp_fd(ifindex, prog_fd, xdp_flags);
    if (err == -EEXIST && !(xdp_flags & XDP_FLAGS_UPDATE_IF_NOEXIST)) {
        /* Force mode didn't work, probably because a program of the
         * opposite type is loaded. Let's unload that and try loading
         * again.
         */

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

#pragma GCC diagnostic pop

/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* <linux/err.h> not present therefore putting it's contents here */
#define MAX_ERRNO       4095

#define IS_ERR_VALUE(x) ((x) >= (unsigned long)-MAX_ERRNO)

static inline void * ERR_PTR(long error_)
{
    return (void *) error_;
}

static inline long PTR_ERR(const void *ptr)
{
    return (long) ptr;
}

static inline bool IS_ERR(const void *ptr)
{
    return IS_ERR_VALUE((unsigned long)ptr);
}

static inline bool IS_ERR_OR_NULL(const void *ptr)
{
    return (!ptr) || IS_ERR_VALUE((unsigned long)ptr);
}

#ifdef  __cplusplus
}
#endif

#endif /* loader.h */