#include <linux/bpf.h>
#include <linux/in.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <net/if_arp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "nsh.h" /* nsh was getting redefinition error with <openvswitch/nsh.h> in dpif */
// #include <openvswitch/nsh.h>
#include "flow.h"
#include "tail_actions.h"

#include "parsing_helpers.h"
#include "rewrite_helpers.h"

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

#define bpf_printk(fmt, ...)                       \
    ({                                             \
        char ____fmt[] = fmt;                      \
        bpf_trace_printk(____fmt, sizeof(____fmt), \
                         ##__VA_ARGS__);           \
    })

SEC("process")
int xdp_process(struct xdp_md *ctx)
{
    int action = XDP_PASS;
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    /* These keep track of the next header type and iterator pointer */
    struct hdr_cursor nh;
    struct xdp_flow_key key;
    struct xdp_flow *flow;
    nh.pos = data;
    // int err;

    // initialise to avoid unbound error during load
    memset(&key, 0, sizeof(struct xdp_flow_key));

    /* Parse and extract the xdp_flow_key */
    /* NOTE: putting this in a separate method e.g., key_extract(struct hdr_cursor *nh, void *data_end, struct xdp_flow_key *key)
     * was working but the moment I added bpf_tail_call the program was failing to load. I commented out some parts of the method
     * and then it started working but then could not extract the whole key. Moving some methods for e.g., parse_iphdr and putting
     * them directly into key_extract allowed for more instruction to be loaded but again could not have all the key being extracted.
     * However moving the whole metho key_extract and putting it directly here allowed for the program to be loaded. Not sure what
     * the cause for the error is but might be the limit to the maximum number of subsequent branches. However could not find the 
     * number and the number didn't seem to be linear either. So it might be something else */
    int nh_type;
    struct xdp_key_ethernet *eth; // = &key.eth;
    nh_type = parse_xdp_key_ethhdr(&nh, data_end, &eth);
    if (nh_type < 0)
    {
        goto out;
    }
    __builtin_memcpy(&key.eth, eth, sizeof(key.eth));

    /* Network layer. */
    if (nh_type == ETH_P_IP)
    {
        struct xdp_key_ipv4 *iph = &key.iph;
        nh_type = parse_xdp_key_iphdr(&nh, data_end, &iph);
        if (nh_type < 0)
        {
            goto out;
        }

        __builtin_memcpy(&key.iph, iph, sizeof(struct xdp_key_ipv4));

        /* Transport layer. */
        if (nh_type == IPPROTO_TCP)
        {
            struct xdp_key_tcp *tcph = &key.tcph;
            nh_type = parse_xdp_key_tcphdr(&nh, data_end, &tcph);
            if (nh_type < 0)
            {
                goto out;
            }

            memcpy(&key.tcph, tcph, sizeof(struct xdp_key_tcp));
        }
        else if (nh_type == IPPROTO_UDP)
        {
            struct xdp_key_udp *udph = &key.udph;
            nh_type = parse_xdp_key_udphdr(&nh, data_end, &udph);
            if (nh_type < 0)
            {
                goto out;
            }

            memcpy(&key.udph, udph, sizeof(struct xdp_key_udp));
        }
        else if (nh_type == IPPROTO_SCTP)
        {
            /* TODO: implement code */
        }
        else if (nh_type == IPPROTO_ICMP)
        {
            struct xdp_key_icmp *icmph = &key.icmph;
            nh_type = parse_xdp_key_icmphdr(&nh, data_end, &icmph);
            if (nh_type < 0)
            {
                goto out;
            }

            memcpy(&key.icmph, icmph, sizeof(struct xdp_key_icmp));
        }
    }
    else if (nh_type == ETH_P_ARP || nh_type == ETH_P_RARP)
    {

        /* TODO: implement code */
    }
    else if (nh_type == ETH_P_MPLS_MC || nh_type == ETH_P_MPLS_UC)
    {

        /* TODO: implement code */
    }
    else if (nh_type == ETH_P_IPV6)
    {
        struct xdp_key_ipv6 *ip6h;
        nh_type = parse_xdp_key_ip6hdr(&nh, data_end, &ip6h);
        if (nh_type < 0)
        {
            goto out;
        }

        memcpy(&key.ipv6h, ip6h, sizeof(struct xdp_key_ipv6));

        /* Transport layer. */
        if (nh_type == IPPROTO_TCP)
        {
            struct xdp_key_tcp *tcph;
            nh_type = parse_xdp_key_tcphdr(&nh, data_end, &tcph);
            if (nh_type < 0)
            {
                goto out;
            }

            // memcpy(&key.tcph, tcph, sizeof(struct xdp_key_tcp)); // TODO: emiting this for now
        }
        else if (nh_type == IPPROTO_UDP)
        {
            struct xdp_key_udp *udph;
            nh_type = parse_xdp_key_udphdr(&nh, data_end, &udph);
            if (nh_type < 0)
            {
                goto out;
            }

            // memcpy(&key.udph, udph, sizeof(struct xdp_key_udp)); // TODO: emiting this for now
        }
        else if (nh_type == IPPROTO_SCTP)
        {
            /* TODO: implement code */
        }
        else if (nh_type == IPPROTO_ICMPV6)
        {
            struct xdp_key_icmpv6 *icmp6h;
            nh_type = parse_xdp_key_icmp6hdr(&nh, data_end, &icmp6h);
            if (nh_type < 0)
            {
                goto out;
            }

            memcpy(&key.icmp6h, icmp6h, sizeof(struct xdp_key_icmpv6));
        }
    }
    else if (nh_type == ETH_P_NSH)
    {
        struct xdp_key_nsh_base *nshh;
        nh_type = parse_xdp_key_nsh_base(&nh, data_end, &nshh);
        if (nh_type < 0)
        {
            goto out;
        }

        memcpy(&key.nsh_base, nshh, sizeof(struct xdp_key_nsh_base));

        if (nshh->mdtype == NSH_M_TYPE1) {
            struct xdp_key_nsh_md1 *md1h;
            nh_type = parse_xdp_key_nsh_md1(&nh, data_end, &md1h);
            if (nh_type < 0)
            {
                goto out;
            }

            memcpy(&key.nsh_md1, md1h, sizeof(struct xdp_key_nsh_md1));
        } else if (nh_type != NSH_BASE_HDR_LEN && nshh->mdtype == NSH_M_TYPE1) {
            struct xdp_key_nsh_md2 *md2h;
            nh_type = parse_xdp_key_nsh_md2(&nh, data_end, &md2h);
            if (nh_type < 0)
            {
                goto out;
            }

            memcpy(&key.nsh_md2, md2h, sizeof(struct xdp_key_nsh_md2));
        } 
    }

    key.valid = 1;

    flow = bpf_map_lookup_elem(&flow_table, &key);
    if (!flow)
    {
        bpf_printk("Upcall needed\n");
        free(flow);
        int index = ctx->rx_queue_index;

        struct xdp_upcall upcall;
        memset(&upcall, 0, sizeof(struct xdp_upcall));
        upcall.type = XDP_PACKET_CMD_MISS;
        upcall.subtype = 0;
        upcall.ifindex = ctx->ingress_ifindex;
        upcall.pkt_len = data_end - data;
        memcpy(&upcall.key, &key, sizeof(struct xdp_flow_key));

        if (bpf_xdp_adjust_head(ctx, 0 - (int)sizeof(struct xdp_upcall)))
            goto out;

        /* Need to re-evaluate data_end and data after head adjustment, and
        * bounds check, even though we know there is enough space (as we
        * increased it).
        */
        data_end = (void *)(long)ctx->data_end;
        struct xdp_upcall *up = (void *)(long)ctx->data;

        
        if (up + 1 > data_end)
        {
            action = XDP_DROP; // error should not occur, but if for some weird reason it does drop packet
            goto out;
        }

        memcpy(up, &upcall, sizeof(*up));

        bpf_printk("Added upcall info\n");
        /* NOTE: if you don't put bpf_redirect_map in the program that you load to on the interface
         * and rather put it in a tail program e.g., bpf_tail_call(ctx, &tail_table, OVS_ACTION_ATTR_UPCALL)
         * and you create a xsk_socket for the interface. The xsk_socket seems to be created without an error
         * but on trying to do xsk_socket__fd(xsk_socket->xsk) you get a segmentation fault. This is resolved
         * by putting bpf_redirect_map(&xsks_map, index, 0) directly into the program loaded. However, calling
         * bpf_tail_call(ctx, &tail_table, OVS_ACTION_ATTR_UPCALL) i.e, invoking a tail program that will send
         * to a xsk_socket, before bpf_redirect_map(&xsks_map, index, 0) will still result in the packets being
         * delivered, i.e, being sent by the tail program and not the bpf_redirect_map TODO: check the libbpf or 
         * helper function why this is, it maybe due to some 'enforced' logic that can be changed */
        if (bpf_map_lookup_elem(&xsks_map, &index))
            return bpf_redirect_map(&xsks_map, index, 0);

        goto out;
    }

    struct act_cursor cur;
    memcpy(&cur, &flow->actions.data[0], sizeof(struct act_cursor));
    int k = 0;
    if (bpf_map_update_elem(&percpu_actions, &k, &flow->actions, 0))
    {
        bpf_printk("Could not update percpu_actions map\n");
        goto out;
    }

    /* NOTE: Could not pass the array inside the struct flow.actions.data 
     * the program was failing at load time. Not sure what the cause was 
     * as the flow was initialised by memset hence should pass the bound 
     * check. Passing an independant array worked so designed it around that 
     * */
    struct flow_metadata fm_cpy;
    memset(&fm_cpy, 0, sizeof(struct flow_metadata));
    fm_cpy.pos = 0;
    fm_cpy.offset = 0;
    fm_cpy.key = key;
    memcpy(&fm_cpy.key, &key, sizeof(struct xdp_flow_key));
    fm_cpy.len = 4 + sizeof(struct xdp_flow_key);

    struct flow_metadata *fm = nh.pos;
    if (bpf_xdp_adjust_head(ctx, 0 - (int)fm_cpy.len))
        goto out;

    /* Need to re-evaluate data_end and data after head adjustment, and
     * bounds check, even though we know there is enough space (as we
     * increased it).
     */
    data_end = (void *)(long)ctx->data_end;
    fm = (void *)(long)ctx->data;

    
    if (fm + 1 > data_end)
    {
        action = XDP_DROP; // error should not occur, but if for some weird reason it does drop packet
        goto out;
    }

    memcpy(fm, &fm_cpy, sizeof(*fm));

    action = XDP_DROP; // if program fails after changing the ctx drop packet as it will be dropped
    
    tail_action(ctx);
out:
    bpf_printk("xdp_process - tail failed\n");
    return action;
}

char _license[] SEC("license") = "GPL";