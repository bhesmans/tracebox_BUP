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

static int send_probe_callback(u_char ttl, u_char *packet, size_t *len)
{
	u_short sport = (rand() & 0xffff) | 0x8000;
	u_short dport = 80;
	int ret;

	if (ttl != last_ttl) {
		printf("\n%2d ", ttl);
		fflush(stdout);
	}

	ret = gettimeofday(&sent_tv, NULL);
	assert(ret != -1);

	*len = probe_pack(packet, IPPROTO_TCP, &ip_src, &ip_dst, ttl, sport,
			  dport, NULL, 0);
	last_ttl = ttl;
	return 0;
}

static int recv_probe_callback(struct timeval ts, const u_char *sent_packet,
			       size_t sent_len, const u_char *rcv_packet,
			       size_t rcv_len)
{
	struct ip_hdr	*ip;
	struct ip_hdr	*icmp_ip;
	struct ip_hdr	*last_ip;
	struct addr	from;
	size_t		 len;

	ip  = (struct ip_hdr *)rcv_packet;
	len = ip->ip_hl << 2;

	if (ip->ip_p == IPPROTO_TCP) {
		/* We received either a RST or a SYN/ACK */
		goto probe_recv;
	} else if (ip->ip_p == IPPROTO_ICMP) {
		struct icmp_hdr *icmp;

		icmp = (struct icmp_hdr *) (rcv_packet + len);
		len += sizeof(*icmp) + 4;

		if (icmp->icmp_type == ICMP_UNREACH ||
		    icmp->icmp_type == ICMP_TIMEXCEED) {
			icmp_ip = (struct ip_hdr *)(rcv_packet + len);
			last_ip = (struct ip_hdr *)sent_packet;

			if (icmp_ip->ip_dst == last_ip->ip_dst)
				goto probe_recv;
			else
				return -1;
		}
	}
	return -1;

probe_recv:
	addr_pack(&from, ADDR_TYPE_IP, IP_ADDR_BITS, &ip->ip_src, IP_ADDR_LEN);

	if (memcmp(&from, &last_from, sizeof(last_from)) != 0) {
		memcpy(&last_from, &from, sizeof(last_from));
		print_addr(&from);
	}

	sub_tv(&ts, &sent_tv);
	printf("%.3f ms ", ts.tv_sec * 1000.0 +
			   ts.tv_usec / 1000.0);

	return !!!memcmp(&last_from, &ip_dst, sizeof(ip_dst));
}

static void timeout_probe_callback(void)
{
	printf("* ");
}

static prober_t prober = {
	.send = send_probe_callback,
	.recv = recv_probe_callback,
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
	printf("traceroute to %s (%s): %d hops max", addr_name, buf, hops_max);

	probing_loop(iface, &ip_dst, hops_max, &prober);

	printf("\n");
	return EXIT_SUCCESS;
	
usage:
	fprintf(stderr, "Usage:\n"
"  %s [ -6thnb ] [ -i device ] host\n"
"Options:\n"
"  -h                          Display this help and exit\n"
"  -n                          Do not resolve IP adresses\n"
"  -i device                   Specify a network interface to operate with\n"
"  -m hops_max                 Set the max number of hops (max TTL to be\n"
"                              reached). Default is 30\n"
"\n", argv[0]);
	exit(EXIT_FAILURE);	
}
