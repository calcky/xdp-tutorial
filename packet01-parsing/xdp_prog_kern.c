/* SPDX-License-Identifier: GPL-2.0 */
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
/* Defines xdp_stats_map from packet04 */
#include "../common/xdp_stats_kern_user.h"
#include "../common/xdp_stats_kern.h"

/* Header cursor to keep track of current parsing position */
struct hdr_cursor {
	void *pos;
};

struct vlan_hdr {
	__be16	h_vlan_TCI;
	__be16	h_vlan_encapsulated_proto;
};

/* Packet parsing helpers.
 *
 * Each helper parses a packet header, including doing bounds checking, and
 * returns the type of its contents if successful, and -1 otherwise.
 *
 * For Ethernet and IP headers, the content type is the type of the payload
 * (h_proto for Ethernet, nexthdr for IPv6), for ICMP it is the ICMP type field.
 * All return values are in host byte order.
 */
static __always_inline int parse_ethhdr(struct hdr_cursor *nh,
					void *data_end,
					struct ethhdr **ethhdr)
{
	struct ethhdr *eth = nh->pos;
	int hdrsize = sizeof(*eth);

	/* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */
	if (eth + 1 > data_end)
		return -1;

	nh->pos += hdrsize;
	*ethhdr = eth;

	return eth->h_proto; /* network-byte-order */
}

static __always_inline int parse_vlanhdr(struct hdr_cursor *nh,
					void *data_end,
					struct vlan_hdr **vlanhdr)
{
	struct vlan_hdr *vlan = nh->pos;
	int hdrsize = sizeof(*vlan);

	/* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */
	if (vlan + 1 > data_end)
		return -1;

	nh->pos += hdrsize;
	*vlanhdr = vlan;

	return vlan->h_vlan_encapsulated_proto; /* network-byte-order */
}

/* Assignment 2: Implement and use this */
static __always_inline int parse_ip6hdr(struct hdr_cursor *nh,
					void *data_end,
					struct ipv6hdr **ip6hdr)
{
	struct ipv6hdr *ip6 = nh->pos;
	int hdrsize = sizeof(*ip6);
	if(ip6+1 > data_end){
		return -1;
	}
	nh->pos += hdrsize;
	*ip6hdr = ip6;
	return 0;
}

/* Assignment 3: Implement and use this */
static __always_inline int parse_icmp6hdr(struct hdr_cursor *nh,
					  void *data_end,
					  struct icmp6hdr **icmp6hdr)
{
	struct icmp6hdr *icmp6 = nh->pos;
	if(icmp6+1 > data_end) {
		return -1;
	}
	*icmp6hdr = icmp6;
	return 0;
}

static __always_inline int proto_is_vlan(__u16 h_proto)
{
        return !!(h_proto == bpf_htons(ETH_P_8021Q) ||
                  h_proto == bpf_htons(ETH_P_8021AD));
}

SEC("xdp")
int  xdp_parser_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth;
	struct vlan_hdr *vlan;
	struct ipv6hdr *ip6;
	struct icmp6hdr *icmp6;

	/* Default action XDP_PASS, imply everything we couldn't parse, or that
	 * we don't want to deal with, we just pass up the stack and let the
	 * kernel deal with it.
	 */
	__u32 action = XDP_PASS; /* Default action */

        /* These keep track of the next header type and iterator pointer */
	struct hdr_cursor nh;
	int nh_type;

	/* Start next header cursor position at data start */
	nh.pos = data;

	/* Packet parsing in steps: Get each header one at a time, aborting if
	 * parsing fails. Each helper function does sanity checking (is the
	 * header type in the packet correct?), and bounds checking.
	 */
	nh_type = parse_ethhdr(&nh, data_end, &eth);

	if (!proto_is_vlan(nh_type)) 
		goto out;

	nh_type = parse_vlanhdr(&nh, data_end, &vlan);
	if (nh_type != bpf_htons(ETH_P_IPV6))
		goto out;

	/* Assignment additions go below here */
	if (parse_ip6hdr(&nh, data_end, &ip6)!=0)
		goto out;

	if (parse_icmp6hdr(&nh, data_end, &icmp6)!=0)
		goto out;
	
	int seq = icmp6->icmp6_sequence;
	if(bpf_ntohs(seq) % 2 !=0 )
		goto out;

	action = XDP_DROP;
out:
	return xdp_stats_record_action(ctx, action); /* read via xdp_stats */
}

char _license[] SEC("license") = "GPL";
