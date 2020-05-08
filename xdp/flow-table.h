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

struct flow_table {
    // struct bpf_pinned_map map;
    /* port_no */
    /* bpf_map_def */
};

// struct bpf_map_def SEC("maps") flow_table = {
// 	.type = BPF_MAP_TYPE_LRU_PERCPU_HASH,
// 	.key_size = sizeof(struct xdp_flow_id),
// 	.value_size = sizeof(struct xdp_flow),
// 	.max_entries = 100,
// };

struct xdp_flow *xdp_flow_alloc(void);

int xdp_flow_map_count(int map_fd);
int xdp_flow_map_flush(int map_fd);

int xdp_flow_map_insert(int map_fd, struct xdp_flow *flow);
int xdp_flow_map_remove(int map_fd, struct xdp_flow_key *key);
int xdp_flow_map_num_masks(int map_fd);
int xdp_flow_map_next_key(int map_fd, struct xdp_flow_key *, struct xdp_flow_key *);
struct xdp_flow *xdp_flow_map_lookup(int map_fd, const struct xdp_flow_key *);
struct xdp_flow *xdp_flow_map_lookup_ufid(int map_fd, const struct xdp_flow_id *);


#endif /* flow_map.h */                     