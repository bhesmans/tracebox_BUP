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

#include "dnet_compat.h"
#include "packet.h"

#define ip_hdrlen(ip)	((ip)->ip_hl << 2)
#define tcp_hdrlen(tcp)	((tcp)->th_off << 2)
#define min(a,b)	(a > b ? b : a)

uint8_t *tbox_trim_pkt(uint8_t *pkt, size_t *len, uint32_t *from)
{
	struct ip_hdr	*ip = (struct ip_hdr *)pkt;
	size_t		 off = ip->ip_hl << 2;

	if (from)
		*from = ip->ip_src;

	if (ip->ip_p == IPPROTO_ICMP) {
		struct icmp_hdr *icmp = (struct icmp_hdr *)(pkt + off);

		off += sizeof(*icmp) + 4;
		pkt += off;
		*len -= off;

		/* Check if ICMP Multipart is present: */
		ip = (struct ip_hdr *)(pkt);
		if (ntohs(ip->ip_len) < (uint16_t)*len)
			*len = ntohs(ip->ip_len);
	}
	return pkt;
}

uint32_t diff_udp(const struct udp_hdr *orig, size_t orig_len,
		  const struct udp_hdr *other, size_t other_len)
{
	uint32_t flags = 0;

	flags |= (orig->uh_sport != other->uh_sport ? L4_SPORT : 0);
	flags |= (orig->uh_sum != other->uh_sum ? UDP_CHKSUM : 0);
	flags |= (memcmp(orig + sizeof(*orig), other + sizeof(*other),
			 min(orig_len - sizeof(*orig),
			 other_len - sizeof(*other))) ? PAYLOAD : 0);
	return flags;
}

uint32_t diff_tcp(const struct tcp_hdr *orig, size_t orig_len,
		  const struct tcp_hdr *other, size_t other_len)
{
	uint32_t flags = 0;
	int reply = orig->th_dport == other->th_sport;

	if (!reply) {
		flags |= (orig->th_sport != other->th_sport ? L4_SPORT : 0);
		flags |= (orig->th_seq != other->th_seq ? TCP_SEQ : 0);
	} else {
		flags |= (orig->th_sport != other->th_dport ? L4_SPORT : 0);
		if (other->th_flags & TH_ACK)
			flags |= (ntohl(orig->th_seq) + 1 !=
				  ntohl(other->th_ack) ? TCP_SEQ : 0);
		flags |= SRV_REPLY;
	}

	if (other_len <= 8 || orig_len <= 8) /* Only received the first 64 bits of the header */
		return flags;

	flags |= (!reply && orig->th_flags != other->th_flags ? TCP_FLAGS : 0);
	flags |= (!reply && orig->th_off != other->th_off ? TCP_DOFF : 0);
	flags |= (!reply && orig->th_win != other->th_win ? TCP_WIN : 0);

	if (!reply && (flags & TCP_DOFF)) {/* Same data offset */
		/* Check if NOP */
		flags |= TCP_OPT;
	} else if (!reply) {
		flags |= (memcmp(((uint8_t *)orig) + sizeof(*orig),
				 ((uint8_t *)other) + sizeof(*other),
				 (orig->th_off << 2) - sizeof(*orig))
			? TCP_OPT : 0);
	} else if ((orig->th_off << 2) != sizeof(*orig) &&
		   !(other->th_flags & TH_RST)) {
		/* Has the destination replied with the option ? */
		size_t data_off = other->th_off << 2;
		size_t opt_off = sizeof(*other);

		if (opt_off > 0) {
			struct tcp_opt *opt, *orig_opt;
			int find = 0;

			orig_opt = (struct tcp_opt *)(((uint8_t *)orig)
						      + sizeof(*orig));
			while (opt_off < data_off) {
				opt = (struct tcp_opt *)(((uint8_t *)other)
							 + opt_off);

				if (opt->opt_type == orig_opt->opt_type)
					goto out;

				if (opt->opt_type == TCP_OPT_EOL ||
				    opt->opt_type == TCP_OPT_NOP)
					opt_off += 1;
				else
					opt_off += opt->opt_len;
			}
			flags |= TCP_OPT;
		}
	}

out:
	flags |= (!reply && memcmp(orig + tcp_hdrlen(orig),
				   other + tcp_hdrlen(other),
				   min(orig_len - tcp_hdrlen(orig),
				   other_len - tcp_hdrlen(other))) ? PAYLOAD : 0);
	return flags;
}

struct ip_tos {
#if DNET_BYTESEX == DNET_BIG_ENDIAN
	uint8_t	ip_dscp:6,
		ip_ecn:2;
#else
	uint8_t	ip_ecn:2,
		ip_dscp:6;
#endif
};

uint32_t diff_ip(const struct ip_hdr *orig, size_t orig_len,
		 const struct ip_hdr *other, size_t other_len)
{
	uint32_t flags = 0;
	int reply = orig->ip_dst == other->ip_src;
	struct ip_tos *orig_tos = (struct ip_tos *)orig;
	struct ip_tos *other_tos = (struct ip_tos *)other;

	flags |= (!reply && orig->ip_hl != other->ip_hl ? IP_HLEN : 0);
	flags |= (!reply && orig_tos->ip_dscp != other_tos->ip_dscp ? IP_DSCP : 0);
	flags |= (orig_tos->ip_ecn != other_tos->ip_ecn ? IP_ECN : 0);
	flags |= (!reply && orig->ip_len < other->ip_len ? IP_TLEN_INCR : 0);
	flags |= (!reply && orig->ip_len > other->ip_len ? IP_TLEN_DECR : 0);
	flags |= (!reply && orig->ip_id != other->ip_id ? IP_ID : 0);
	flags |= (!reply && orig->ip_off != other->ip_off ? IP_FRAG : 0);
	flags |= (!reply && orig->ip_src != other->ip_src ? IP_SADDR : 0);
	flags |= (reply && orig->ip_src != other->ip_dst ? IP_SADDR : 0);
	flags |= (reply ? SRV_REPLY : 0);

	return flags;
}

uint32_t tbox_diff_packet(const uint8_t *orig, size_t orig_len,
			  const uint8_t *other, size_t other_len)
{
	struct ip_hdr *orig_ip = (struct ip_hdr *)orig;
	struct ip_hdr *other_ip = (struct ip_hdr *)other;
	uint32_t flags = 0;

	if (orig_ip->ip_v != 4)
		return(0);

	flags = diff_ip(orig_ip, orig_len, other_ip, other_len);

	switch (orig_ip->ip_p) {
	case IP_PROTO_TCP:
		flags |= diff_tcp((struct tcp_hdr *)(orig + ip_hdrlen(orig_ip)),
				  orig_len - ip_hdrlen(orig_ip),
				  (struct tcp_hdr *)(other + ip_hdrlen(other_ip)),
				  other_len - ip_hdrlen(other_ip));
		break;
	case IP_PROTO_UDP:
		flags |= diff_udp((struct udp_hdr *)(orig + ip_hdrlen(orig_ip)),
				  orig_len - ip_hdrlen(orig_ip),
				  (struct udp_hdr *)(other + ip_hdrlen(other_ip)),
				  other_len - ip_hdrlen(other_ip));
		break;
	}

	return(flags);
}

