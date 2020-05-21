/**
 * This is the kernel space program that keeps the flow table which
 * is a map. In our approach we have a micro table per interface which
 * are CPU 
 */

#ifndef FLOW_MAP_H
#define FLOW_MAP_H 1

#include <linux/bpf.h>
#include <stdbool.h>
#include "flow.h"

int xdp_flow_map_count(int map_fd);
int xdp_flow_map_flush(int map_fd, int max_entries);

/* Buffer makes it more generic and enforces our solution for padding error */
int xdp_flow_map_insert(int map_fd, __u8 key_buf[], struct xdp_flow_actions *actions);
int xdp_flow_map_remove(int map_fd, __u8 key_buf[]);
int xdp_flow_map_num_masks(int map_fd);
int xdp_flow_map_next_key(int map_fd, __u8 ckey_buf[], __u8 nkey_buf[]);
int xdp_flow_map_lookup(int map_fd, const __u8 key_buf[], struct xdp_flow_actions *actions);
struct xdp_flow_actions *xdp_flow_map_lookup_ufid(int map_fd, const struct xdp_flow_id *);

int xdp_flow_stats_map_lookup(int map_fd, const __u8 key_buf[], struct xdp_flow_stats *stats);


#endif /* flow_map.h */                     