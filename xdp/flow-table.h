#ifndef FLOW_TABLE_H
#define FLOW_TABLE_H 1

#include <linux/bpf.h>

#include "flow.h"

struct bpf_pinned_map {
    const char *name;
    const char *filename;
    int map_fd;
};

struct flow_table {
    struct bpf_pinned_map map;
    /* port_no */
    /* bpf_map_def */
};

int ovs_flow_init(void);
void ovs_flow_exit(void);

struct xdp_flow *ovs_flow_alloc(void);
void ovs_flow_free(struct xdp_flow *, bool deferred);

int ovs_flow_tbl_init(struct flow_table *);
int ovs_flow_tbl_count(const struct flow_table *table);
void ovs_flow_tbl_destroy(struct flow_table *table);
int ovs_flow_tbl_flush(struct flow_table *flow_table);

int ovs_flow_tbl_insert(struct flow_table *table, struct xdp_flow *flow);
void ovs_flow_tbl_remove(struct flow_table *table, struct xdp_flow *flow);
int  ovs_flow_tbl_num_masks(const struct flow_table *table);
struct xdp_flow *ovs_flow_tbl_lookup(struct flow_table *,
                    const struct xdp_flow_key *);
struct xdp_flow *ovs_flow_tbl_lookup_ufid(struct flow_table *,
                     const struct xdp_flow_id *);
#endif /* flow_table.h */                     