/* SPDX-License-Identifier: GPL-2.0 */
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

#include "parsing_xdp_key_helpers.h"
#include "parsing_helpers.h"
#include "rewrite_helpers.h"
#include "xf_kern.h"
#include "xf.h"
#include "actions.h"

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

/* Solution to packet03/assignment-4 */
SEC("prog")
int xdp_ep_router_actions(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct bpf_fib_lookup fib_params = {};
	struct ethhdr *eth = data;
	struct ipv6hdr *ip6h;
	struct iphdr *iph;
	struct arp_ethhdr *arph;
	__u16 h_proto;
	__u64 nh_off;
	int rc;
	int action = XDP_PASS;

	nh_off = sizeof(*eth);
	if (data + nh_off > data_end) {
		action = XDP_DROP;
		goto out;
	}

	h_proto = eth->h_proto;
	if (h_proto == bpf_htons(ETH_P_IP)) {
		iph = data + nh_off;

		if (iph + 1 > data_end) {
			action = XDP_DROP;
			goto out;
		}

		if (iph->ttl <= 1)
			goto out;

		fib_params.family	= AF_INET;
		fib_params.tos		= iph->tos;
		fib_params.l4_protocol	= iph->protocol;
		fib_params.sport	= 0;
		fib_params.dport	= 0;
		fib_params.tot_len	= bpf_ntohs(iph->tot_len);
		fib_params.ipv4_src	= iph->saddr;
		fib_params.ipv4_dst	= iph->daddr;
	} else if (h_proto == bpf_htons(ETH_P_IPV6)) {
		struct in6_addr *src = (struct in6_addr *) fib_params.ipv6_src;
		struct in6_addr *dst = (struct in6_addr *) fib_params.ipv6_dst;

		ip6h = data + nh_off;
		if (ip6h + 1 > data_end) {
			action = XDP_DROP;
			goto out;
		}

		if (ip6h->hop_limit <= 1)
			goto out;

		fib_params.family	= AF_INET6;
		fib_params.flowinfo	= *(__be32 *) ip6h & IPV6_FLOWINFO_MASK;
		fib_params.l4_protocol	= ip6h->nexthdr;
		fib_params.sport	= 0;
		fib_params.dport	= 0;
		fib_params.tot_len	= bpf_ntohs(ip6h->payload_len);
		*src			= ip6h->saddr;
		*dst			= ip6h->daddr;
	} else if (h_proto == bpf_htons(ETH_P_ARP) || h_proto == bpf_htons(ETH_P_RARP)) {
		bpf_printk("ETH_P_ARP\n");
		arph = data + nh_off;
		if (arph + 1 > data_end) {
			action = XDP_DROP;
			goto out;
		}

		fib_params.family	= AF_INET;
		// fib_params.tos		= iph->tos;
		// fib_params.l4_protocol	= iph->protocol;
		fib_params.sport	= 0;
		fib_params.dport	= 0;
		// fib_params.tot_len	= bpf_ntohs(iph->tot_len);
		fib_params.ipv4_src	= arph->ar_sip;
		fib_params.ipv4_dst	= arph->ar_tip;
	} else {
		goto out;
	}

	fib_params.ifindex = ctx->ingress_ifindex;

	rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
	switch (rc) {
	case BPF_FIB_LKUP_RET_SUCCESS:         /* lookup successful */
		bpf_printk("BPF_FIB_LKUP_RET_SUCCESS\n");
		if (h_proto == bpf_htons(ETH_P_IP))
			ip_decrease_ttl(iph);
		else if (h_proto == bpf_htons(ETH_P_IPV6))
			ip6h->hop_limit--;
		
		__u8 h_dest[ETH_ALEN];
		__u8 h_source[ETH_ALEN];
		memcpy(h_dest, fib_params.dmac, ETH_ALEN);
		memcpy(h_source, fib_params.smac, ETH_ALEN);
		bpf_printk("eth->h_dest: %llx", u8_arr_to_u64(h_dest, ETH_ALEN));
        bpf_printk("eth->h_source: %llx", u8_arr_to_u64(h_source, ETH_ALEN));

		__u8 dmac[ETH_ALEN];
		__u8 smac[ETH_ALEN];
		memcpy(dmac, fib_params.dmac, ETH_ALEN);
		memcpy(smac, fib_params.smac, ETH_ALEN);
		bpf_printk("fib_params.dmac: %llx", u8_arr_to_u64(dmac, ETH_ALEN));
        bpf_printk("fib_params.smac: %llx", u8_arr_to_u64(smac, ETH_ALEN));

		memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
		memcpy(eth->h_source, fib_params.smac, ETH_ALEN);
		action = bpf_redirect_map(&tx_port, fib_params.ifindex, 0);
		break;
	case BPF_FIB_LKUP_RET_BLACKHOLE:    /* dest is blackholed; can be dropped */
	case BPF_FIB_LKUP_RET_UNREACHABLE:  /* dest is unreachable; can be dropped */
	case BPF_FIB_LKUP_RET_PROHIBIT:     /* dest not allowed; can be dropped */
		bpf_printk("BPF_FIB_LKUP_RET_PROHIBIT\n");
		action = XDP_DROP;
		break;
	case BPF_FIB_LKUP_RET_NOT_FWDED:    /* packet is not forwarded */
	case BPF_FIB_LKUP_RET_FWD_DISABLED: /* fwding is not enabled on ingress */
	case BPF_FIB_LKUP_RET_UNSUPP_LWT:   /* fwd requires encapsulation */
	case BPF_FIB_LKUP_RET_NO_NEIGH:     /* no neighbor entry for nh */
	case BPF_FIB_LKUP_RET_FRAG_NEEDED:  /* fragmentation required to fwd */
		bpf_printk("BPF_FIB_LKUP_RET_FRAG_NEEDED\n");
		/* PASS */
		break;
	}

out:
	bpf_printk("action: %d\n", action);
	return action;
}


char _license[] SEC("license") = "GPL";
