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

#include <dnet.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <string.h>

#define error(format, args...)  \
	fprintf(stderr, format "\n", ## args)

static u_char hops_max = 30;
static struct addr ip_src;
static struct addr ip_dst;

static int send_probe_callback(u_char ttl, u_char *packet, size_t *len)
{
	u_short sport = (rand() & 0xffff) | 0x8000;
	u_short dport = 80;

	*len = probe_pack(packet, IPPROTO_TCP, &ip_src, &ip_dst, ttl, sport,
			  dport, NULL, 0);
	return 0;
}

static int recv_probe_callback(const u_char *sent_packet, size_t sent_len,
			       const u_char *rcv_packet, size_t rcv_len)
{
	struct ip_hdr	*ip;
	struct ip_hdr	*icmp_ip;
	struct ip_hdr	*last_ip;
	size_t		 len;

	ip  = (struct ip_hdr *)rcv_packet;
	len = ip->ip_hl << 2;

	if (ip->ip_p == IPPROTO_TCP) {
		/* We received either a RST or a SYN/ACK */
		return 0;
	} else if (ip->ip_p == IPPROTO_ICMP) {
		struct icmp_hdr *icmp;

		icmp = (struct icmp_hdr *) (rcv_packet + len);
		len += sizeof(*icmp) + 4;

		if (icmp->icmp_type == ICMP_UNREACH ||
		    icmp->icmp_type == ICMP_TIMEXCEED) {
			icmp_ip = (struct ip_hdr *)(rcv_packet + len);
			last_ip = (struct ip_hdr *)sent_packet;

			if (icmp_ip->ip_dst == last_ip->ip_dst)
				return 0;
			else
				return -1;
		}
	}
	return -1;
}

int main(int argc, char *argv[])
{
	char		 iface[INTF_NAME_LEN];
	int		 iface_set = 0;
	char		 addr_name[255];
	struct addr	 tmp;
	int		 resolve = 1;
	size_t		 i, j;
	char		 c;

	if (geteuid() != 0) {
		error("tracebox can only be used as root");
		exit(EXIT_FAILURE);
	}

	srand(time(NULL) ^ getpid());

	while ((c = getopt (argc, argv, ":i:p:m:r:c:k:thnb6")) != -1) {
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
			case 'h':
				goto usage;
			case ':':
				error("missing option argument");
			default:
				goto usage;
		}
	}

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
	printf("traceroute to %s (%s): %d hops max\n", addr_name, buf, hops_max);

	probing_loop(iface, &ip_dst, hops_max, resolve, send_probe_callback,
		     recv_probe_callback);

	return EXIT_SUCCESS;
	
usage:
	fprintf(stderr, "Usage:\n"
"  %s [ -6thnb ] [ -i device ] host\n"
"Options:\n"
"  -6                          Use IPv6\n"
"  -t                          Use TCP\n"
"  -h                          Display this help and exit\n"
"  -n                          Do not resolve IP adresses\n"
"  -i device                   Specify a network interface to operate with\n"
"  -m hops_max                 Set the max number of hops (max TTL to be\n"
"                              reached). Default is 30\n"
"\n", argv[0]);
	exit(EXIT_FAILURE);	
}
