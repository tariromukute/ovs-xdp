#include <errno.h>
#include <stdio.h>
#include <bpf/bpf.h>
#include "xf_map.h"
#include "err.h"
#include "util.h"
#include "logging.h"
#include "xdp_user_helpers.h"
#include "dynamic-string.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

int xf_map_count(int map_fd)
{
    void *key, *nkey = NULL;
    int cnt = 0;
    while (!bpf_map_get_next_key(map_fd, key, nkey)) {
        key = nkey;
        cnt ++;
    }
            
    return cnt;
}

int xf_map_flush(int map_fd, int max_entries)
{
    void *keyp, *nkeyp = NULL;
    __u8 *keys_buf;
    int error = 0;
    int key_size = sizeof(struct xf_key);
    keys_buf = malloc(max_entries * key_size);
    memset(keys_buf, 0, max_entries * key_size);

    __u32 cnt = 0;
    while (!bpf_map_get_next_key(map_fd, keyp, nkeyp)) {
        memcpy(&keys_buf[key_size * cnt], nkeyp, key_size);
        keyp = nkeyp;
        cnt++;
        if (cnt == max_entries)
            break;
    }

    error = bpf_map_delete_batch(map_fd, keys_buf, &cnt, 0);
    
    return error;
}


/* Buffer makes it more generic and enforces our solution for padding error */
int xf_map_insert(int map_fd, struct xf_key *xf_key, struct xfa_buf *xfas)
{
    int error = 0;
    // int fd = bpf_obj_get("/sys/fs/bpf/ovs-xdp/_xf_macro_map");
    // struct ds dsk = DS_EMPTY_INITIALIZER;
    // ds_put_hex(&dsk, xf_key, sizeof(struct xf_key));

    // struct ds ds = DS_EMPTY_INITIALIZER;
    // ds_put_hex(&ds, xfas, sizeof(struct xfa_buf));
    // pr_info("fd: %d, map_fd: %d, key is %s action is: %s", fd, map_fd, ds_cstr(&dsk), ds_cstr(&ds));
    // pr_info("fd: %d, map_fd: %d", fd, map_fd);

    error = bpf_map_update_elem(map_fd, xf_key, xfas, BPF_NOEXIST);
    if (error) {
        pr_warn("Error inserting flow");
    }

    return error;
}

int xf_map_remove(int map_fd, struct xf_key *xf_key)
{
    int error = 0;

    struct ds dsk = DS_EMPTY_INITIALIZER;
    ds_put_hex(&dsk, xf_key, sizeof(struct xf_key));

    pr_info("removing map_fd: %d, key is %s", map_fd, ds_cstr(&dsk));

    error = bpf_map_delete_elem(map_fd, xf_key);
    if (error) {
        pr_warn("Error removing flow");
    }

    return error;
}

int xf_map_num_masks(int map_fd)
{
    int err = ENOENT;

    return err;
}

int xf_map_next_key(int map_fd, struct xf_key *cxf_key, struct xf_key *bxf_key)
{
    int error = 0;

    error = bpf_map_get_next_key(map_fd, cxf_key, bxf_key);
    if (error) {
        if (errno == ENOENT)
            error = ENOENT;
    }

    return error;
}

int xf_map_lookup(int map_fd, const struct xf_key *xf_key, struct xfa_buf *xfas)
{
    int error = 0;

    error = bpf_map_lookup_elem(map_fd, xf_key, xfas);
    if (error) {
        struct ds ds = DS_EMPTY_INITIALIZER;
        xdp_flow_key_format(&ds, xf_key);
        pr_warn("Error looking up actions");
        pr_warn("key is %s", ds_cstr(&ds));
        ds_destroy(&ds);
    }

    return error;
}

int xf_map_count__by_name(char *map_name)
{
    int error = ENOENT;

    return error;
}

int xf_map_flush__by_name(char *map_name, int max_entries)
{
    int error = ENOENT;

    return error;
}


int xf_map_insert__by_name(char *map_name, struct xf_key *xf_key, struct xfa_buf *xfas)
{
    int error = ENOENT;

    return error;
}

int xf_map_remove__by_name(char *map_name, struct xf_key *xf_key)
{
    int error = ENOENT;

    return error;
}

int xf_map_num_masks__by_name(char *map_name)
{
    int error = ENOENT;

    return error;
}

int xf_map_next_key__by_name(char *map_name, struct xf_key *cxf_key, struct xf_key *bxf_key)
{
    int error = ENOENT;

    return error;
}

int xf_map_lookup__by_name(char *map_name, const struct xf_key *xf_key, struct xfa_buf *xfas)
{
    int error = ENOENT;

    return error;
}

#pragma GCC diagnostic pop