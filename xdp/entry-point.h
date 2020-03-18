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

      f) datapath -> if not found initiate an upcall (call flow_map so that we add
      the attributes as expected by the ovs switch else continue and get actions for
      the key and then tails actions.c)

      g) actions -> execute the actions

      h) ..entry_point -> if error anywhere drop packet

      .... if upcall was required ....

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

 