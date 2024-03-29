/*
 *  Copyright (C) 2013  Gregory Detal <gregory.detal@uclouvain.be>
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version 2
 *  of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301, USA.
 */

#ifndef __PROBE_H__
#define __PROBE_H__

#include <string.h>
#include <sys/types.h>

#include "libtracebox/dnet_compat.h"

static inline size_t probe_ip_udp_pack(u_char *ptr, struct addr *ip_src,
				       struct addr *ip_dst, u_char ttl,
				       u_short sport, u_short dport,
				       u_char *data, size_t dlen)
{
	struct ip_hdr  *ip  = (struct ip_hdr *)ptr;
	struct udp_hdr *udp = (struct udp_hdr *)(ptr + IP_HDR_LEN);
	u_char *payload = (u_char *) (ptr + IP_HDR_LEN + UDP_HDR_LEN);

	ip_pack_hdr(ip, 0x0, IP_HDR_LEN + UDP_HDR_LEN + dlen, 0x0, 0x0, ttl,
		    IPPROTO_UDP, ip_src->addr_ip, ip_dst->addr_ip);
	udp_pack_hdr(udp, sport, dport, UDP_HDR_LEN + dlen);
	memcpy(payload, data, dlen);
	ip_checksum(ip, IP_HDR_LEN + UDP_HDR_LEN + dlen);
	return (IP_HDR_LEN + UDP_HDR_LEN + dlen);
}

static u_short __id;
static u_int __seq;
static u_int __ack;
static u_char __tcp_flags;

static inline void probe_tcp_setup(u_int seq, u_int ack, u_char flags)
{
	__seq = seq;
	__ack = ack;
	__tcp_flags = flags;
}

static inline size_t probe_ip_tcp_pack(u_char *ptr, struct addr *ip_src,
				       struct addr *ip_dst, u_char ttl,
				       u_short sport, u_short dport,
				       u_char *opt, size_t olen)
{
	struct ip_hdr  *ip  = (struct ip_hdr *) ptr;
	struct tcp_hdr *tcp = (struct tcp_hdr *)(ptr + IP_HDR_LEN);
	u_char *option = (u_char *)(ptr + IP_HDR_LEN + TCP_HDR_LEN);
	ip_pack_hdr(ip, 0x0, IP_HDR_LEN + TCP_HDR_LEN + olen, __id, 0x0, ttl,
		    IPPROTO_TCP, ip_src->addr_ip, ip_dst->addr_ip);
	tcp_pack_hdr(tcp, sport, dport, __seq,  __tcp_flags & TH_ACK ? __ack : 0, __tcp_flags, 65535, 0x0);
	tcp->th_off += olen / 4;
	memcpy(option, opt, olen);
	ip_checksum(ip, IP_HDR_LEN + TCP_HDR_LEN + olen);
	return (IP_HDR_LEN + TCP_HDR_LEN + olen);
}

static inline void probe_ip_setup(u_short id)
{
	__id = id;
}


static inline size_t probe_ip_pack(u_char *ptr, u_char proto,
				   struct addr *ip_src, struct addr *ip_dst,
				   u_char ttl, u_short sport, u_short dport,
				   u_char *data, size_t dlen)
{
	switch (proto) {
		case IPPROTO_UDP:
			return probe_ip_udp_pack(ptr, ip_src, ip_dst, ttl,
						 sport, dport, data, dlen);
		case IPPROTO_TCP:
			return probe_ip_tcp_pack(ptr, ip_src, ip_dst, ttl,
						 sport, dport, data, dlen);
	}
}

static inline size_t probe_pack(u_char *ptr, u_char proto, struct addr *ip_src,
				struct addr *ip_dst, u_char ttl, u_short sport,
				u_short dport, u_char *data, size_t dlen)
{
	return probe_ip_pack(ptr, proto, ip_src, ip_dst, ttl, sport, dport,
			     data, dlen);
}

#endif
