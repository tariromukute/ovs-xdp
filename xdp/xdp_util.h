#ifndef XDP_UTIL_H
#define XDP_UTIL_H 1

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <openvswitch/dynamic-string.h>
#include "flow.h"

void xdp_flow_format(struct *xdp_flow, struct ds *ds);

#endif /* XDP_UTIL_H */