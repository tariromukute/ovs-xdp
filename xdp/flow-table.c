// #include <
#include <errno.h>
#include <stdio.h>
#include <bpf/bpf.h>
#include "flow-table.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"


int xdp_flow_map_count(int map_fd)
{
    void *key, *nkey = NULL;
    int cnt = 0;
    while (!bpf_map_get_next_key(map_fd, key, nkey)) {
        key = nkey;
        cnt ++;
    }
            
    return cnt;
}

int xdp_flow_map_flush(int map_fd, int max_entries)
{
    void *keyp, *nkeyp = NULL;
    __u8 *bufkeys;
    int error = 0;
    bufkeys = malloc(max_entries * XDP_FLOW_KEY_LEN_u64);
    memset(bufkeys, 0, max_entries * XDP_FLOW_KEY_LEN_u64);
    __u32 cnt = 0;
    while (!bpf_map_get_next_key(map_fd, keyp, nkeyp)) {
        memcpy(&bufkeys[XDP_FLOW_KEY_LEN_u64 * cnt], nkeyp, XDP_FLOW_KEY_LEN_u64);
        keyp = nkeyp;
        cnt++;
        if (cnt == max_entries)
            break;
    }

    error = bpf_map_delete_batch(map_fd, bufkeys, &cnt, 0);
    
    return error;
}


int xdp_flow_map_insert(int map_fd, __u8 key_buf[], struct xdp_flow_actions *actions)
{
    int error = 0;

    error = bpf_map_update_elem(map_fd, key_buf, actions, BPF_NOEXIST);
    if (error) {
        printf("Error inserting flow \n");
    }

    /* NOTE: the key is added to the stats map by the kernel program when the first flow comes */

    return error;
}

int xdp_flow_map_remove(int map_fd, __u8 key_buf[])
{
    int error = 0;

    error = bpf_map_delete_elem(map_fd, key_buf);
    if (error) {
        printf("Error removing flow\n");
    }

    return error;
}

int xdp_flow_map_num_masks(int map_fd)
{
    /* TODO: implement method */
    return 0;
}

int xdp_flow_map_next_key(int map_fd, __u8 ckey_buf[], __u8 nkey_buf[])
{
    printf("-- func %s --\n", __func__);
    int error = 0;

    error = bpf_map_get_next_key(map_fd, ckey_buf, nkey_buf);
    if (error) {
        printf("error %d errno %d-- xdp_flow_map_next_key\n", error, errno);
        if (errno == ENOENT)
            error = ENOENT;
    }
    printf("-- func %s -- end \n", __func__);
    return error;
}

int xdp_flow_map_lookup(int map_fd, const __u8 key_buf[], __u8 act_buf[])
{
    int error = 0;

    error = bpf_map_lookup_elem(map_fd, key_buf, act_buf);
    if (error) {
        printf("Error looking up actions\n");
    }
    printf("-- func %s --\n", __func__);
    return error;
}

struct xdp_flow_actions *xdp_flow_map_lookup_ufid(int map_fd, const struct xdp_flow_id *id)
{
    struct xdp_flow_actions *flow_actions = NULL;
    /* TODO: implement method */

    return flow_actions;
}

int xdp_flow_stats_map_lookup(int map_fd, const __u8 key_buf[], struct xdp_flow_stats *stats)
{
    int error = 0;

    error = bpf_map_lookup_elem(map_fd, key_buf, stats);
    if (error) {
        printf("Error looking up stats\n");
    }

    return error;
}
#pragma GCC diagnostic pop