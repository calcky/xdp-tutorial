/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// The parsing helper functions from the packet01 lesson have moved here
#include "../common/parsing_helpers.h"

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif
#define IPV6_FLOWINFO_MASK bpf_htonl(0x0FFFFFFF)

/* Assignment 2 */
SEC("xdp_assign")
int xdp_redirect_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor nh;
	struct ethhdr *eth;
	int eth_type;
	int action = XDP_PASS;
	unsigned char dst[ETH_ALEN] = {0x4a,0xd7,0xf8,0xe9,0x97,0xd5}; 	/* Assignment 2: fill in with the MAC address of the left inner interface */
	unsigned ifindex = 29;   /*Assignment 2: fill in with the ifindex of the left interface */

	/* These keep track of the next header type and iterator pointer */
	nh.pos = data;

	/* Parse Ethernet and IP/IPv6 headers */
	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type == -1)
		goto out;

	/* Set a proper destination address */
	memcpy(eth->h_dest, dst, ETH_ALEN);
	action = bpf_redirect(ifindex, 0);

out:
	return action;
}

/* from include/net/ip.h */
static __always_inline int ip_decrease_ttl(struct iphdr *iph)
{
	/* Assignment 4: see samples/bpf/xdp_fwd_kern.c from the kernel */
	__u32 check = iph->check;
	check += bpf_htons(0x0100);
	iph->check = (__u16)(check + (check >= 0xFFFF));
	return --iph->ttl;
}

/* Assignment 4: Complete this router program */
SEC("xdp_rdt")
int xdp_router_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct bpf_fib_lookup fib_params = {};
	struct ethhdr *eth = data;
	struct ipv6hdr *ip6h;
	struct iphdr *iph;
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
	} else {
		goto out;
	}

	fib_params.ifindex = ctx->ingress_ifindex;

	rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
	switch (rc) {
	case BPF_FIB_LKUP_RET_SUCCESS:         /* lookup successful */
		if (h_proto == bpf_htons(ETH_P_IP))
			ip_decrease_ttl(iph);
		else if (h_proto == bpf_htons(ETH_P_IPV6))
			ip6h->hop_limit--;

		memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
		memcpy(eth->h_source, fib_params.smac, ETH_ALEN);
		action = bpf_redirect(fib_params.ifindex, 0);
		break;
	case BPF_FIB_LKUP_RET_BLACKHOLE:    /* dest is blackholed; can be dropped */
	case BPF_FIB_LKUP_RET_UNREACHABLE:  /* dest is unreachable; can be dropped */
	case BPF_FIB_LKUP_RET_PROHIBIT:     /* dest not allowed; can be dropped */
		action = XDP_DROP;
		break;
	case BPF_FIB_LKUP_RET_NOT_FWDED:    /* packet is not forwarded */
	case BPF_FIB_LKUP_RET_FWD_DISABLED: /* fwding is not enabled on ingress */
	case BPF_FIB_LKUP_RET_UNSUPP_LWT:   /* fwd requires encapsulation */
	case BPF_FIB_LKUP_RET_NO_NEIGH:     /* no neighbor entry for nh */
	case BPF_FIB_LKUP_RET_FRAG_NEEDED:  /* fragmentation required to fwd */
		/* PASS */
		break;
	}

out:
	//bpf_printk("action: %d", action);
	return action;
}

SEC("xdp_tun")
int xdp_router_tun_func(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
    struct bpf_fib_lookup fib_params = {};
    struct iphdr *iph;
    __u64 nh_off;
    int rc;
    int action = XDP_PASS;

	nh_off = sizeof(*iph);
	if (data + nh_off > data_end) {
		action = XDP_DROP;
		goto out;
	}

    if (bpf_xdp_adjust_head(ctx, 0 - (int)sizeof(struct ethhdr))) {
        action = XDP_DROP;
        goto out;
    }
	data_end = (void *)(long)ctx->data_end;
    data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

	nh_off = sizeof(*eth);
	if (data + nh_off > data_end) {
		action = XDP_DROP;
		goto out;
	}

	eth->h_proto = bpf_htons(ETH_P_IP);
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
	fib_params.ifindex = ctx->ingress_ifindex;
	//bpf_printk("input ifindex: %d", fib_params.ifindex);

	rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
	switch (rc) {
	case BPF_FIB_LKUP_RET_SUCCESS:         /* lookup successful */
		ip_decrease_ttl(iph);

		memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
		memcpy(eth->h_source, fib_params.smac, ETH_ALEN);
		action = bpf_redirect(fib_params.ifindex, 0);
		//bpf_printk("output ifindex: %d", fib_params.ifindex);
		//bpf_printk("redirect: %d", action);
		break;
	case BPF_FIB_LKUP_RET_BLACKHOLE:    /* dest is blackholed; can be dropped */
	case BPF_FIB_LKUP_RET_UNREACHABLE:  /* dest is unreachable; can be dropped */
	case BPF_FIB_LKUP_RET_PROHIBIT:     /* dest not allowed; can be dropped */
		action = XDP_DROP;
		//bpf_printk("drop: %d", action);
		break;
	case BPF_FIB_LKUP_RET_NOT_FWDED:    /* packet is not forwarded */
	case BPF_FIB_LKUP_RET_FWD_DISABLED: /* fwding is not enabled on ingress */
	case BPF_FIB_LKUP_RET_UNSUPP_LWT:   /* fwd requires encapsulation */
	case BPF_FIB_LKUP_RET_NO_NEIGH:     /* no neighbor entry for nh */
	case BPF_FIB_LKUP_RET_FRAG_NEEDED:  /* fragmentation required to fwd */
		//bpf_printk("pass: %d", action);
		/* PASS */
		break;
	}

out:
	//bpf_printk("action: %d, len: %d", action, data_end-data);
	return action; //xdp_stats_record_action(ctx, action);
}

SEC("xdp_pass")
int xdp_pass_func(struct xdp_md *ctx)
{
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
