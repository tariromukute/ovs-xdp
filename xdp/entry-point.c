/**
 * The file contains the code/program that will listen in the kernel for
 * events. It programs are the entry point into the datapath. The calls
 * can be from the userspace (downcall) or some 'controller' or triggered
 * by an incoming packet at with point.
 *
 * The overal program for the following scenarios is a follows
 * 
 * 1) from an incoming packet
 *
 *    a) entry_point -> receives the packet, calls parse to get the flow 
 *
 *    b) flow -> parse the packet to get the flow, return to ep
 *
 *    c) entry_point -> send it to datapath
 *
 *    d) datapath -> check for flow key from flow_map/table
 *    
      e) flow_map -> lookup and return if any

      f) datapath -> return the attributes to 

      g) entry_point -> check if it's among the implement actions and tail else upcall

      h) ..entry_point -> if error anywhere drop packet

      .... if upcall was required ....

      . datapath -> format for upcall
      
      . flow_xdp -> change the xdp flow to the nattlr expected by userspace daemon

      . datapath -> return code and metadata to upcall with AF_XDP

      . entry_point -> upcall

   2) downcall

      a) entry_point -> get the packet and metadata needed

      b) datapath -> extract the ovs format and convert to flow

      c) xlate -> convert ovs and produce xdp flow + actions

      d) datapath -> if everything ok get the ufid

      e) flow -> return the ufid

      d) datapath -> if everything ok store flow and key and actions

      e) flow_map -> store the entry

      f) datapath -> send a result back

      h) entry-point -> acknowledge or respond to error appropriately

   3) Set up information from controller

      ....This haven't completely thought through but an option is to use the already
      existing netlink to set up and trigger the setup etc..... 
      
      ...using a single tap devices can be used, however the tap device or bridge will
      need to be created. Guess that's what netdev is for....
 * 
 */


/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include "bpf_helpers.h"
#include "flow.h"

struct bpf_map_def SEC("maps") flow_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = (sizeof(struct xdp_flow_id)),
	.value_size = (sizeof(struct xdp_flow)),
	.max_entries = 256,
};

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
SEC("process")
int xdp_process(struct xdp_md *ctx)
{
    /* TODO: implement method */

    /* Receives incoming packets and then sends to flow to compute
       the flow details e.g. flow_key. Then sends to datapath to process
       the packet. Datapath returns the flow and it's actions, with error
       0 or NFF for upcall miss or internal error for logging and dropping
       the packet.

       It then checks of the actions can be implemented on the fast path
       if so it tails the actions else if upcalls for userspace processing.

       If upcall miss is required it will upcall the to userspace. 

       If error it will drop the packet and log the operation. 
       
       If any error occurs from the tailed fuctions the packets will be dropped.*/
	return XDP_PASS; 
}

SEC("xdp")
int  xdp_downcall(struct xdp_md *ctx)
{
	return XDP_DROP;
}
#pragma GCC diagnostic pop

char _license[] SEC("license") = "GPL";