#ifndef XDP_LOADER_H
#define XDP_LOADER_H 1

#include <linux/types.h>
#include <asm/errno.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>

#ifdef  __cplusplus
extern "C" {
#endif

/* Exit return codes */
#define EXIT_OK          0 /* == EXIT_SUCCESS (stdlib.h) man exit(3) */
#define EXIT_FAIL         1 /* == EXIT_FAILURE (stdlib.h) man exit(3) */
#define EXIT_FAIL_OPTION     2
#define EXIT_FAIL_XDP        30
#define EXIT_FAIL_BPF        40

// #define bpf_object__for_each_map(pos, obj)        \
//     for ((pos) = bpf_map__next(NULL, (obj));    \
//          (pos) != NULL;                \
//          (pos) = bpf_map__next((pos), (obj)))

int xdp_link_detach(int ifindex, __u32 xdp_flags, __u32 expected_prog_id);
int xdp_link_attach(int ifindex, __u32 xdp_flags, int prog_fd);
int xdp_load(const char *ifname);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"


int xdp_link_detach(int ifindex, __u32 xdp_flags, __u32 expected_prog_id)
{
    // __u32 curr_prog_id;
    // int err;

    // err = bpf_get_link_xdp_id(ifindex, &curr_prog_id, xdp_flags);
    // if (err) {
    //     fprintf(stderr, "ERR: get link xdp id failed (err=%d)\n",
    //         -err);
    //     return EXIT_FAIL_XDP;
    // }

    // if (!curr_prog_id) {
    //     if (verbose)
    //         printf("INFO: %s() no curr XDP prog on ifindex:%d\n",
    //                __func__, ifindex);
    //     return EXIT_OK;
    // }

    // if (expected_prog_id && curr_prog_id != expected_prog_id) {
    //     fprintf(stderr, "ERR: %s() "
    //         "expected prog ID(%d) no match(%d), not removing\n",
    //         __func__, expected_prog_id, curr_prog_id);
    //     return EXIT_FAIL;
    // }

    // if ((err = bpf_set_link_xdp_fd(ifindex, -1, xdp_flags)) < 0) {
    //     fprintf(stderr, "ERR: %s() link set xdp failed (err=%d)\n",
    //         __func__, err);
    //     return EXIT_FAIL_XDP;
    // }

    // if (verbose)
    //     printf("INFO: %s() removed XDP prog ID:%d on ifindex:%d\n",
    //            __func__, curr_prog_id, ifindex);

    return EXIT_OK;
}

int xdp_link_attach(int ifindex, __u32 xdp_flags, int prog_fd)
{
    /* Next assignment this will move into ../common/ */
    // int err;

    // /* libbpf provide the XDP net_device link-level hook attach helper */
    // err = bpf_set_link_xdp_fd(ifindex, prog_fd, xdp_flags);
    // if (err == -EEXIST && !(xdp_flags & XDP_FLAGS_UPDATE_IF_NOEXIST)) {
    //     /* Force mode didn't work, probably because a program of the
    //      * opposite type is loaded. Let's unload that and try loading
    //      * again.
    //      */

    //     __u32 old_flags = xdp_flags;

    //     xdp_flags &= ~XDP_FLAGS_MODES;
    //     xdp_flags |= (old_flags & XDP_FLAGS_SKB_MODE) ? XDP_FLAGS_DRV_MODE : XDP_FLAGS_SKB_MODE;
    //     err = bpf_set_link_xdp_fd(ifindex, -1, xdp_flags);
    //     if (!err)
    //         err = bpf_set_link_xdp_fd(ifindex, prog_fd, old_flags);
    // }

    // if (err < 0) {
    //     fprintf(stderr, "ERR: "
    //         "ifindex(%d) link set xdp fd failed (%d):\n",
    //         ifindex, -err);

    //     switch (-err) {
    //     case EBUSY:
    //     case EEXIST:
    //         fprintf(stderr, "Hint: XDP already loaded on device"
    //             " use --force to swap/replace\n");
    //         break;
    //     case EOPNOTSUPP:
    //         fprintf(stderr, "Hint: Native-XDP not supported"
    //             " use --skb-mode or --auto-mode\n");
    //         break;
    //     default:
    //         break;
    //     }
    //     return EXIT_FAIL_XDP;
    // }

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