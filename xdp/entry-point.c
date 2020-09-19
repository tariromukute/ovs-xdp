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

#include "parsing_xdp_key_helpers.h"
#include "parsing_helpers.h"
#include "rewrite_helpers.h"
#include "xdp_kern_helpers.h"

#ifndef MIN
#define MIN(X, Y) ((X) < (Y) ? (X) : (Y))
#endif

#ifndef MAX
#define MAX(X, Y) ((X) > (Y) ? (X) : (Y))
#endif

static inline int key_extract(struct hdr_cursor *nh, void *data_end, struct xdp_flow_key *key)
{

    int nh_type;
    struct xdp_key_ethernet *eth;
    nh_type = parse_xdp_key_ethhdr(nh, data_end, &eth);
    if (nh_type < 0)
    {
        goto out;
    }
    key->valid |= ETH_VALID;
    memcpy(&key->eth, eth, sizeof(key->eth));
    if (nh_type == ETH_P_IP)
    {
        struct xdp_key_ipv4 *iph;
        nh_type = parse_xdp_key_iphdr(nh, data_end, &iph);
        if (nh_type < 0)
        {
            goto out;
        }
        bpf_printk("---- ipv4_proto %d ---\n", iph->ipv4_proto);
        memcpy(&key->iph, iph, sizeof(struct xdp_key_ipv4));
        key->valid |= IPV4_VALID;

        /* Transport layer. */
        if (nh_type == IPPROTO_TCP)
        {
            struct xdp_key_tcp *tcph;
            nh_type = parse_xdp_key_tcphdr(nh, data_end, &tcph);
            if (nh_type < 0)
            {
                goto out;
            }

            memcpy(&key->tcph, tcph, sizeof(struct xdp_key_tcp));
            key->valid |= TCP_VALID;

        }
        else if (nh_type == IPPROTO_UDP)
        {
            struct xdp_key_udp *udph;
            nh_type = parse_xdp_key_udphdr(nh, data_end, &udph);
            if (nh_type < 0)
            {
                goto out;
            }

            memcpy(&key->udph, udph, sizeof(struct xdp_key_udp));
            key->valid |= UDP_VALID;
        }
        else if (nh_type == IPPROTO_SCTP)
        {
            /* TODO: implement code */
            // key->valid |= MPLS_VALID;
        }
        else if (nh_type == IPPROTO_ICMP)
        {
            struct xdp_key_icmp *icmph;
            nh_type = parse_xdp_key_icmphdr(nh, data_end, &icmph);
            if (nh_type < 0)
            {
                goto out;
            }

            memcpy(&key->icmph, icmph, sizeof(struct xdp_key_icmp));
            key->valid |= ICMP_VALID;
        }
    }
    else if (nh_type == ETH_P_ARP || nh_type == ETH_P_RARP)
    {
        struct arp_ethhdr *arph;
        nh_type = parse_arp_ethhdr(nh, data_end, &arph);
        if (nh_type < 0)
        {
            goto out;
        }
        
        // key->arph.ar_op = arph->ar_op;
        key->arph.arp_sip = arph->ar_sip;
        key->arph.arp_tip = arph->ar_tip;
        
        memcpy(key->arph.arp_sha, arph->ar_sha, sizeof(key->arph.arp_sha));
        memcpy(key->arph.arp_tha, arph->ar_tha, sizeof(key->arph.arp_tha));
        key->valid |= ARP_VALID;
    }
    else if (nh_type == ETH_P_MPLS_MC || nh_type == ETH_P_MPLS_UC)
    {

        /* TODO: implement code */
        // key->valid |= MPLS_VALID;
    }
    else if (nh_type == ETH_P_IPV6)
    {
        struct ipv6hdr *ip6h;
        nh_type = parse_ip6hdr(nh, data_end, &ip6h);
        if (nh_type < 0)
        {
            goto out;
        }

        key->ipv6h.ipv6_proto = ip6h->nexthdr;
        key->ipv6h.ipv6_tclass = ip6h->priority;
        key->ipv6h.ipv6_hlimit = ip6h->hop_limit;
        key->ipv6h.ipv6_frag = 0;

        memcpy(&key->ipv6h.ipv6_src, ip6h->saddr.s6_addr32, sizeof(key->ipv6h.ipv6_src));
        memcpy(&key->ipv6h.ipv6_dst, ip6h->daddr.s6_addr32, sizeof(key->ipv6h.ipv6_dst));
        key->valid |= IPV6_VALID;

        /* Transport layer. */
        if (nh_type == IPPROTO_TCP)
        {
            struct xdp_key_tcp *tcph;
            nh_type = parse_xdp_key_tcphdr(nh, data_end, &tcph);
            if (nh_type < 0)
            {
                goto out;
            }

            // memcpy(&key->tcph, tcph, sizeof(struct xdp_key_tcp)); // TODO: emiting this for now
            // key->valid |= TCP_VALID;
        }
        else if (nh_type == IPPROTO_UDP)
        {
            struct xdp_key_udp *udph;
            nh_type = parse_xdp_key_udphdr(nh, data_end, &udph);
            if (nh_type < 0)
            {
                goto out;
            }

            // memcpy(&key->udph, udph, sizeof(struct xdp_key_udp)); // TODO: emiting this for now
            // key->valid |= UDP_VALID;
        }
        else if (nh_type == IPPROTO_SCTP)
        {
            /* TODO: implement code */
        }
        else if (nh_type == IPPROTO_ICMPV6)
        {
            struct xdp_key_icmpv6 *icmp6h;
            nh_type = parse_xdp_key_icmp6hdr(nh, data_end, &icmp6h);
            if (nh_type < 0)
            {
                goto out;
            }

            memcpy(&key->icmp6h, icmp6h, sizeof(struct xdp_key_icmpv6));
            key->valid |= ICMPV6_VALID;
        }
    }
    else if (nh_type == ETH_P_NSH)
    {
        struct xdp_key_nsh_base *nshh;
        nh_type = parse_xdp_key_nsh_base(nh, data_end, &nshh);
        if (nh_type < 0)
        {
            goto out;
        }

        memcpy(&key->nsh_base, nshh, sizeof(struct xdp_key_nsh_base));
        key->valid |= NSH_BASE_VALID;

        if (nshh->mdtype == NSH_M_TYPE1)
        {
            struct xdp_key_nsh_md1 *md1h;
            nh_type = parse_xdp_key_nsh_md1(nh, data_end, &md1h);
            if (nh_type < 0)
            {
                goto out;
            }

            memcpy(&key->nsh_md1, md1h, sizeof(struct xdp_key_nsh_md1));
            key->valid |= NSH_MD1_VALID;
        }
        else if (nh_type != NSH_BASE_HDR_LEN && nshh->mdtype == NSH_M_TYPE1)
        {
            // struct xdp_key_nsh_md2 *md2h;
            // nh_type = parse_xdp_key_nsh_md2(nh, data_end, &md2h);
            // if (nh_type < 0)
            // {
            //     goto out;
            // }

            // memcpy(&key->nsh_md2, md2h, sizeof(struct xdp_key_nsh_md2));
            // key->valid |= NSH_MD2_VALID;
        }
    }
    return 0;
out:
    return -1;
}

SEC("process")
int xdp_process(struct xdp_md *ctx)
{
    int action = XDP_PASS;
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    /* These keep track of the next header type and iterator pointer */
    struct hdr_cursor nh;
    struct xdp_flow_actions *actions = NULL;
    nh.pos = data;
    int err;


    /* Metadata will be in the perf event before the packet data. */
    struct S {
        __u16 cookie;
        __u16 pkt_len;
        struct xdp_flow_key key;
    } __attribute__((packed)) metadata;

    __u8 keybuf[XDP_FLOW_KEY_LEN_u64];
    __u8 fmbuf[XDP_FLOW_METADATA_KEY_LEN_u64];
    memset(keybuf, 0, XDP_FLOW_KEY_LEN_u64);

    /* Check if you can read inner map */
    struct xdp_flow_actions *acts = bpf_map_lookup_elem(&port_flow, keybuf);
    bpf_printk("--- length printed is: %x ----\n", acts->len);
    free(acts);

    // Get port no. 1
    __u32 p = 1;
    void * inner_map = bpf_map_lookup_elem(&_ports, &p);
    struct xdp_flow_actions *acs = bpf_map_lookup_elem(inner_map, keybuf);
    bpf_printk("--- length 2 printed is: %x ----\n", acs->len);

    /* Extract the flow key from the packet and put it in the key buffer (keybuf) */
    struct xdp_flow_key *key = (struct xdp_flow_key *)keybuf;
    err = key_extract(&nh, data_end, key);
    if (err)
    {
        goto out;
    }

    

    // If ARP upcall
    // if (!(key->valid & ARP_VALID) // ||
    //     !((key->valid & ICMPV6_VALID) && key->icmp6h.icmpv6_code == 8) // Doesn't make if key->icmp6h.type is reading a none icmp6h valid will factor that in 
    // ) {

    //     /* Check if there are flow actions for the extracted key */
    // }

    actions = bpf_map_lookup_elem(&flow_table, keybuf);
    
    /* The XDP perf_event_output handler will use the upper 32 bits
        * of the flags argument as a number of bytes to include of the
        * packet payload in the event data. If the size is too big, the
        * call to bpf_perf_event_output will fail and return -EFAULT.
        *
        * See bpf_xdp_event_output in net/core/filter.c.
        *
        * The BPF_F_CURRENT_CPU flag means that the event output fd
        * will be indexed by the CPU number in the event map.
        */
    __u64 flags = BPF_F_CURRENT_CPU;
    __u16 sample_size;
    int ret;
    bpf_printk("size of key %d \n", sizeof(*key));
    metadata.cookie = actions ? 0xa1ee : 0xdead;
    metadata.pkt_len = (__u16)0; // (data_end - data);
    memcpy(&metadata.key, key, sizeof(struct xdp_flow_key));
    sample_size = MIN(metadata.pkt_len, SAMPLE_SIZE);
    flags |= (__u64)sample_size << 32;

    ret = bpf_perf_event_output(ctx, &_perf_map, flags,
                    &metadata, sizeof(metadata));
    if (ret) {
        bpf_printk("perf_event_output failed: %d\n", ret);
        action = XDP_DROP;
        goto out;
    }

    if (!actions) /* If there are no flow actions, make an upcall */
    {
        /* NOTE: for debug only. In production uncomment */
        bpf_printk("INFO: Upcall needed\n");
        log_flow_key(key);
        free(actions);
        /* Get the receive queue index and upcall via the XSK socket */
        int index = ctx->rx_queue_index;

        /* Add upcall information at the head of the packet */
        struct xdp_upcall upcall;
        memset(&upcall, 0, sizeof(struct xdp_upcall));
        upcall.type = XDP_PACKET_CMD_MISS;
        upcall.subtype = 0;
        upcall.ifindex = ctx->ingress_ifindex;
        upcall.pkt_len = data_end - data;
        memcpy(&upcall.key, keybuf, sizeof(struct xdp_flow_key));

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
        bpf_printk("- %d\n", XDP_FLOW_KEY_LEN_u64);
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

    bpf_printk("Tail ctx\n");
    /* Flow actions were found. Redirect the packet to a tail program that executes the action */

    /* And the actions found to the actions buffer (actbuf) */
    // __u8 actbuf[XDP_FLOW_ACTIONS_LEN_u64];
    // memcpy(actbuf, &flow->actions, XDP_FLOW_ACTIONS_LEN_u64);
    // int k = 0;
    // if (bpf_map_update_elem(&percpu_actions, &k, actbuf, 0))
    // {
    //     bpf_printk("Could not update percpu_actions map\n");
    //     goto out;
    // }

    /* NOTE: Could not pass the array inside the struct flow.actions.data 
     * the program was failing at load time. Not sure what the cause was 
     * as the flow was initialised by memset hence should pass the bound 
     * check. Passing an independant array worked so designed it around that 
     * */
     
    /* Add the flow metadata to the head of the packet. The metadata is used 
       for executing the actions */
    struct flow_metadata *fm_cpy = (struct flow_metadata *)fmbuf;
    memset(fmbuf, 0, XDP_FLOW_METADATA_KEY_LEN_u64);
    fm_cpy->pos = 0;
    fm_cpy->offset = 0;
    memcpy(&fm_cpy->key, keybuf, sizeof(struct xdp_flow_key));
    fm_cpy->len = 4 + sizeof(struct xdp_flow_key);

    // struct flow_metadata *fm = nh.pos;
    if (bpf_xdp_adjust_head(ctx, 0 - (int)XDP_FLOW_METADATA_KEY_LEN_u64))
        goto out;

    /* Need to re-evaluate data_end and data after head adjustment, and
     * bounds check, even though we know there is enough space (as we
     * increased it).
     */
    data_end = (void *)(long)ctx->data_end;
    nh.pos = (void *)(long)ctx->data;

    if (nh.pos + XDP_FLOW_METADATA_KEY_LEN_u64 > data_end)
    {
        action = XDP_DROP; // error should not occur, but if for some weird reason it does drop packet
        goto out;
    }

    memcpy(nh.pos, fmbuf, XDP_FLOW_METADATA_KEY_LEN_u64);

    action = XDP_DROP; // if program fails after changing the ctx drop packet as it will be dropped

    tail_action(ctx);
out:
    bpf_printk("xdp_process - tail failed\n");
    return action;
}

SEC("xdp")
int  xdp_prog_simple(struct xdp_md *ctx)
{
    bpf_printk("xdp passing packet\n");
    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";