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

#include "probe.h"
#include "probing.h"
#include "resolve.h"
#include "options.h"

#include <dnet.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <unistd.h>

#define error(format, args...)  \
	fprintf(stderr, format "\n", ## args)

static u_char hops_max = 30;
static struct addr ip_src;
static struct addr ip_dst;
static struct addr last_from;
static struct timeval sent_tv;
static int last_ttl = -1;
static int resolve = 1;
static u_int changes = 0;
static u_int last_changes = 0;
static int timeout = 0;
static int option_type = -1;

static struct {
	u_char option_type;
	char name[8];
} tcp_options[] = {
	{ TCP_OPT_MPTCP,	"mptcp" },
	{ TCP_OPT_MSS,		"mss" },
	{ TCP_OPT_WSCALE,	"wscale" },
	{ TCP_OPT_TIMESTAMP,	"ts" },
	{ TCP_OPT_SACKOK,	"sack" },
};

static void sub_tv(struct timeval *out, struct timeval *in)
{
	if ((out->tv_usec -= in->tv_usec) < 0) {
		--out->tv_sec;
		out->tv_usec += 1000000;
	}
	out->tv_sec -= in->tv_sec;
}

static void print_addr(struct addr *addr)
{
	char name[255], addr_str[INET6_ADDRSTRLEN];

	addr_ntop(addr, addr_str, sizeof(addr_str));

	if (resolve && resolve_addr(AF_INET, &addr->addr_ip,
				    sizeof(addr->addr_ip), name) < 0)
		addr_ntop(addr, name, sizeof(addr_str));

	if (resolve)
		printf("%s (%s)", name, addr_str);
	else
		printf("%s ", addr_str);
}

enum header_change_t {
	IP_HLEN		= 1,
	IP_DSCP		= 1 << 1,
	IP_TLEN		= 1 << 2,
	IP_ID		= 1 << 3,
	IP_FRAG		= 1 << 4,
	IP_SADDR	= 1 << 5,
	TCP_SPORT	= 1 << 6,
	TCP_SEQ		= 1 << 7,
	TCP_DOFF	= 1 << 8,
	TCP_WIN		= 1 << 9,
	TCP_OPT		= 1 << 10,

	FULL_REPLY	= 1 << 30,
	TCP_REPLY	= 1 << 31,
};

static int compare_packet(const u_char *orig, size_t orig_len,
			  const u_char *packet, size_t len)
{
	struct ip_hdr	*orig_ip = (struct ip_hdr *)orig;
	struct ip_hdr	*ip = (struct ip_hdr *)packet;
	struct tcp_hdr	*orig_tcp = (struct tcp_hdr *)(orig + (orig_ip->ip_hl << 2));
	struct tcp_hdr	*tcp = (struct tcp_hdr *)(packet + (ip->ip_hl << 2));
	int ret = 0;

	ret |= (orig_ip->ip_hl != ip->ip_hl ? IP_HLEN : 0);
	ret |= (orig_ip->ip_tos != ip->ip_tos ? IP_DSCP : 0);
	ret |= (orig_ip->ip_len != ip->ip_len ? IP_TLEN : 0);
	ret |= (orig_ip->ip_id != ip->ip_id ? IP_ID : 0);
	ret |= (orig_ip->ip_off != ip->ip_off ? IP_FRAG : 0);
	ret |= (orig_ip->ip_src != ip->ip_src ? IP_SADDR : 0);

	ret |= (orig_tcp->th_sport != tcp->th_sport ? TCP_SPORT : 0);
	ret |= (orig_tcp->th_seq != tcp->th_seq ? TCP_SEQ : 0);

	if (len < ntohs(ip->ip_len))
		goto out;

	ret |= (orig_tcp->th_off != tcp->th_off ? TCP_DOFF : 0);
	ret |= (orig_tcp->th_win != tcp->th_win ? TCP_WIN : 0);

	ret |= (orig_ip->ip_len == ip->ip_len ? FULL_REPLY : 0);

	/* Check if NOP */
	if (orig_ip->ip_len == ip->ip_len)
		ret |= (memcmp(orig + (orig_ip->ip_hl << 2) + sizeof(*orig_tcp),
			       packet + (ip->ip_hl << 2) + sizeof(*tcp),
			       ntohs(ip->ip_len) - (ip->ip_hl << 2) - sizeof(*tcp))
			? TCP_OPT : 0);

out:
	return ret;
}

static int compare_reply(const u_char *orig, size_t orig_len,
			 const u_char *packet, size_t len)
{
	struct ip_hdr	*orig_ip = (struct ip_hdr *)orig;
	struct ip_hdr	*ip = (struct ip_hdr *)packet;
	struct tcp_hdr	*orig_tcp = (struct tcp_hdr *)(orig + (orig_ip->ip_hl << 2));
	struct tcp_hdr	*tcp = (struct tcp_hdr *)(packet + (ip->ip_hl << 2));
	int ret = 0;
	size_t opt_off, tot_len;

	ret |= (orig_tcp->th_sport != tcp->th_dport ? TCP_SPORT : 0);
	ret |= (orig_tcp->th_seq != tcp->th_ack ? TCP_SEQ : 0);
	ret |= (tcp->th_flags & (TH_SYN | TH_ACK) ? TCP_REPLY : 0);

	/* Has the destination replied with the option ? */
	tot_len = ntohs(ip->ip_len);
	opt_off = (ip->ip_hl << 2) + sizeof(*tcp);
	if (opt_off > 0) {
		struct tcp_opt *opt, *orig_opt;
		int find = 0;

		orig_opt = (struct tcp_opt *)(orig + (orig_ip->ip_hl << 2) +
					      sizeof(*tcp));

		while (opt_off < tot_len) {
			opt = (struct tcp_opt *)(packet + opt_off);

			if (opt->opt_type == orig_opt->opt_type)
				goto out;
			opt_off += opt->opt_len;
		}
		ret |= TCP_OPT;
	}
out:
	return ret;
}

static int send_probe_callback(u_char ttl, u_char *packet, size_t *len)
{
	u_short sport = (getpid() & 0xffff) | 0x8000;
	u_short dport = 80;
	u_char opt[TCP_OPT_LEN_MAX];
	size_t opt_len = TCP_OPT_LEN_MAX;
	int ret;

	if (ttl != last_ttl) {
		printf("%2d ", ttl);
		fflush(stdout);
	}

	ret = gettimeofday(&sent_tv, NULL);
	assert(ret != -1);

	if (option_type >= 0)
		tcp_opt_pack(option_type, opt, &opt_len);
	else
		opt_len = 0;
	*len = probe_pack(packet, IPPROTO_TCP, &ip_src, &ip_dst, ttl, sport,
			  dport, opt, opt_len);
	last_ttl = ttl;
	return 0;
}

static int recv_probe_callback(struct timeval ts, const u_char *sent_packet,
			       size_t sent_len, const u_char *rcv_packet,
			       size_t rcv_len)
{
	struct ip_hdr	*ip;
	struct ip_hdr	*base_ip;
	struct ip_hdr	*last_ip;
	struct tcp_hdr	*tcp;
	struct tcp_hdr	*last_tcp;
	size_t		 len;
	u_int		 chg = 0;

	base_ip = ip = (struct ip_hdr *)rcv_packet;

	last_ip = (struct ip_hdr *)sent_packet;
	last_tcp = (struct tcp_hdr *)(sent_packet + (last_ip->ip_hl << 2));

	len = ip->ip_hl << 2;
	if (ip->ip_p == IPPROTO_TCP) {
		/* We received either a RST or a SYN/ACK */
		tcp = (struct tcp_hdr *)(rcv_packet + len);

		if (last_tcp->th_sport != tcp->th_dport)
			return -1;
		len -= ip->ip_hl << 2;
		chg = compare_reply(sent_packet, sent_len, rcv_packet + len,
				    rcv_len - len);
		goto probe_recv;
	} else if (ip->ip_p == IPPROTO_ICMP) {
		struct icmp_hdr *icmp;

		icmp = (struct icmp_hdr *)(rcv_packet + len);
		len += sizeof(*icmp) + 4;

		if (icmp->icmp_type == ICMP_UNREACH ||
		    icmp->icmp_type == ICMP_TIMEXCEED) {
			ip = (struct ip_hdr *)(rcv_packet + len);
			len += ip->ip_hl << 2;
			tcp = (struct tcp_hdr *)(rcv_packet + len);

			if (ip->ip_dst == last_ip->ip_dst &&
			    last_tcp->th_sport == tcp->th_sport) {
				len -= ip->ip_hl << 2;
				chg = compare_packet(sent_packet, sent_len,
						     rcv_packet + len,
						     rcv_len - len);
				goto probe_recv;
			} else
				return -1;
		}
	}
	return -1;

probe_recv:
	addr_pack(&last_from, ADDR_TYPE_IP, IP_ADDR_BITS, &base_ip->ip_src,
		  IP_ADDR_LEN);
	last_changes |= chg;
	return !!!memcmp(&last_from, &ip_dst, sizeof(ip_dst));
}

static void step_probe_callback(void)
{
	u_int chg = last_changes & ~changes;

	if (timeout == probe_nprobes) {
		printf("*\n");
		timeout = 0;
		return;
	}

	print_addr(&last_from);

	if (chg & IP_DSCP)
		printf("[DSCP changed] ");
	if (chg & IP_ID)
		printf("[IP ID] ");
	if (chg & IP_FRAG)
		printf("[Fragmented] ");
	if ((chg & TCP_SPORT) || (chg & IP_SADDR))
		printf("[NAT] ");
	if (chg & TCP_SEQ)
		printf("[TCP seq changed] ");
	if ((chg & IP_TLEN) || ((chg & TCP_OPT) && !(chg & TCP_REPLY)))
		printf("[TCP opt removed/changed] ");
	if ((chg & TCP_OPT) && (chg & TCP_REPLY))
		printf("[Did not reply with opt] ");
	if (chg & TCP_WIN)
		printf("[TCP win changed] ");

	if (chg & FULL_REPLY)
		printf("[Reply ICMP full pkt] ");

	changes |= last_changes;
	printf("\n");
}

static void timeout_probe_callback(void)
{
	timeout += 1;
}

static prober_t prober = {
	.send	 = send_probe_callback,
	.recv	 = recv_probe_callback,
	.step	 = step_probe_callback,
	.timeout = timeout_probe_callback,
};

int main(int argc, char *argv[])
{
	char		 iface[INTF_NAME_LEN];
	int		 iface_set = 0;
	char		 addr_name[255];
	struct addr	 tmp;
	size_t		 i, j;
	char		 c;

	if (geteuid() != 0) {
		error("tracebox can only be used as root");
		exit(EXIT_FAILURE);
	}

	srand(time(NULL) ^ getpid());

	while ((c = getopt (argc, argv, ":i:m:o:hn")) != -1) {
		switch (c) {
			case 'i':
				strncpy(iface, optarg, INTF_NAME_LEN);
				iface_set = 1;
				break;
			case 'm':
				hops_max = strtol(optarg, NULL, 10);
				break;
			case 'n':
				resolve = 0;
				break;
			case 'o':
				if (!strcmp(optarg, "list")) {
					int i;
					for (i = 0; i < sizeof(tcp_options) / sizeof(tcp_options[0]); ++i)
						printf("%s ", tcp_options[i].name);
					printf("\n");
					exit(EXIT_SUCCESS);
				} else {
					int i;
					for (i = 0; i < sizeof(tcp_options) / sizeof(tcp_options[0]); ++i)
						if (!strcmp(tcp_options[i].name, optarg))
							option_type = tcp_options[i].option_type;
				}
				break;
			case 'h':
				goto usage;
			case ':':
				error("missing option argument");
			default:
				goto usage;
		}
	}

	if (optind == argc)
		goto usage;

	if (resolve_host(AF_INET, argv[argc-1], &ip_dst, addr_name, sizeof(addr_name)) < 0) {
		error("error resolving %s", argv[argc-1]);
		exit(EXIT_FAILURE);
	}

	if (!iface_set) {
		if (resolve_iface_addr(&ip_dst, iface) == NULL) {
			error("unable to find a suitable interface");
			exit(EXIT_FAILURE);
		}
	}

	if (resolve_iface(iface, &tmp, &ip_src) < 0) {
		error("unable to retrieve ip address of interface %s", iface);
		exit(EXIT_FAILURE);
	}

	char buf[INET_ADDRSTRLEN];
	addr_ntop(&ip_dst, buf, sizeof(buf));
	printf("tracebox to %s (%s): %d hops max\n", addr_name, buf, hops_max);

	probing_loop(iface, &ip_dst, hops_max, &prober);

	return EXIT_SUCCESS;
	
usage:
	fprintf(stderr, "Usage:\n"
"  %s [ -hn ] [ -i device ] [ -m hops_max ] [ -o option ] host\n"
"Options:\n"
"  -h                          Display this help and exit\n"
"  -n                          Do not resolve IP adresses\n"
"  -i device                   Specify a network interface to operate with\n"
"  -m hops_max                 Set the max number of hops (max TTL to be\n"
"                              reached). Default is 30\n"
"  -o option                   Define the TCP option to put in the SYN segment.\n"
"                              Default is none. -o list for a list of available\n"
"                              options.\n"
"\n", argv[0]);
	exit(EXIT_FAILURE);	
}
