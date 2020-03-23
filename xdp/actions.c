/*
 * Copyright (c) 2016, 2017, 2018 Nicira, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 */

/* OVS Datapath Execution
 * ======================
 *
 * When a lookup is successful the eBPF gets a list of actions to be
 * executed,  such as outputting the packet to a certain port, or
 * pushing a VLAN tag.  The list of actions is configured in ovs-vswitchd
 * and may be a variable length depending on the desired network processing
 * behaviour. For example, an L2 switch doing unknown broadcast sends
 * packet to all its current ports. The OVS datapath’s actions is derived
 * from the OpenFlow action specification and the OVSDB schema for
 * ovs-vswitchd.
 *
 */
#include <errno.h>
#include <stdint.h>
#include <linux/ip.h>
#include <linux/openvswitch.h>
#include <linux/bpf.h>
#include "bpf_helpers.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

SEC("xdp")
int  xdp_prog_simple(struct xdp_md *ctx)
{
    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";

#pragma GCC diagnostic pop