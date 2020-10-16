/**
 * This is the kernel space program that keeps the flow table which
 * is a map. In our approach we have a micro table per interface which
 * are CPU 
 */

#ifndef XF_MAP_H
#define XF_MAP_H 1

#include <linux/bpf.h>
#include <stdbool.h>
#include "xf.h"

int xf_map_count(int map_fd);
int xf_map_flush(int map_fd, int max_entries);

int xf_map_insert(int map_fd, struct xf_key *xf_key, struct xfa_buf *xfas);
int xf_map_remove(int map_fd, struct xf_key *xf_key);
int xf_map_num_masks(int map_fd);
int xf_map_next_key(int map_fd, struct xf_key *cxf_key, struct xf_key *bxf_key);
int xf_map_lookup(int map_fd, const struct xf_key *xf_key, struct xfa_buf *xfas);

int xf_map_count__by_name(char *map_name);
int xf_map_flush__by_name(char *map_name, int max_entries);

int xf_map_insert__by_name(char *map_name, struct xf_key *xf_key, struct xfa_buf *xfas);
int xf_map_remove__by_name(char *map_name, struct xf_key *xf_key);
int xf_map_num_masks__by_name(char *map_name);
int xf_map_next_key__by_name(char *map_name, struct xf_key *cxf_key, struct xf_key *bxf_key);
int xf_map_lookup__by_name(char *map_name, const struct xf_key *xf_key, struct xfa_buf *xfas);

#endif /* xf_map.h */                     