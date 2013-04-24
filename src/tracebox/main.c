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

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "libtracebox/packet.h"
#include "libtracebox/tracebox.h"
#include "libtracebox/dnet_compat.h"

#ifdef HAVE_LUA
#include "tracebox_lua.h"
#endif

#include "options.h"
#include "probe.h"

#define error(format, args...)  \
	fprintf(stderr, format "\n", ## args)

static uint8_t		 hops_max = TBOX_HARD_TTL;
static uint16_t		 dport = 80;
static int		 option_type = -1;
static struct addr	 ip_dst;
static pcap_t		*pcap = NULL;
static pcap_dumper_t	*dumper = NULL;
static int		 resolve = 1;
static int		 output_format = 0;

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

static struct {
	u_char flag;
	char name[8];
} tcp_flags[] = {
	{ TH_FIN,	"fin" },
	{ TH_SYN,	"syn" },
	{ TH_RST,	"rst" },
	{ TH_PUSH,	"push" },
	{ TH_ACK,	"ack" },
	{ TH_URG,	"urg" },
	{ TH_ECE,	"ece" },
	{ TH_CWR,	"cwr" },
};

static uint8_t parse_flags(char *args)
{
	char *flag;
	uint8_t flags = 0;

	for (flag = strtok(args, ","); flag; flag = strtok(NULL, ",")) {
		int i;
		for (i = 0; i < sizeof(tcp_flags) / sizeof(tcp_flags[0]); ++i)
			if (!strcmp(tcp_flags[i].name, flag))
				flags |= tcp_flags[i].flag;
	}
	return flags;
}

static int resolve_host(int af, const char *host, struct addr *addr, char *name,
		 size_t len)
{
	int		 n;
	struct addrinfo	 hints;
	struct addrinfo	*res = NULL;

	bzero(&hints, sizeof(struct addrinfo));
	hints.ai_flags = AI_CANONNAME;
	hints.ai_family = af;
	hints.ai_socktype = 0;

	n = getaddrinfo(host, NULL, &hints, &res);
	if (n != 0) return -1;

	switch (af) {
		case AF_INET:
			addr_pack(addr, ADDR_TYPE_IP, IP_ADDR_BITS,
				  &((struct sockaddr_in *)res->ai_addr)->sin_addr,
				  IP_ADDR_LEN);
			break;
		case AF_INET6:
			addr_pack(addr, ADDR_TYPE_IP6, IP6_ADDR_BITS,
				  &((struct sockaddr_in6 *)res->ai_addr)->sin6_addr,
				  IP6_ADDR_LEN);
			break;
	}

	if (res->ai_canonname)
		strncpy(name, res->ai_canonname, len);
	else
		addr_ntop(addr, name, len);

	freeaddrinfo(res);

	return 0;
}

static int resolve_addr(int af, struct addr *addr, char *name, size_t len)
{
	struct sockaddr_in sin;

	addr_ntos(addr, (struct sockaddr *)&sin);
	return getnameinfo((struct sockaddr*)&sin, sizeof(sin), name, len,
			   NULL, 0, 0);
}

static int generate_probe(u_char *packet, size_t *len)
{
	u_short sport = (getpid() & 0xffff) | 0x8000;
	u_char opt[TCP_OPT_LEN_MAX];
	size_t opt_len = TCP_OPT_LEN_MAX;
	int ret;

	if (option_type >= 0)
		tcp_opt_pack(option_type, opt, &opt_len);
	else
		opt_len = 0;
	*len = probe_pack(packet, IPPROTO_TCP, &ip_dst, &ip_dst, 0, sport,
			  dport, opt, opt_len);
	return 0;
}

static const char *change_str(tbox_res_t *res)
{
	if (res->chg_prev & IP_DSCP)
		printf("[DSCP changed] ");
	if (res->chg_prev & IP_ID)
		printf("[IP ID] ");
	if (res->chg_prev & IP_TLEN_INCR)
		printf("[TCP/IP option added] ");
	if (res->chg_prev & IP_FRAG)
		printf("[Fragmented] ");
	if ((res->chg_prev & L4_SPORT) || (res->chg_prev & IP_SADDR))
		printf("[NAT] ");
	if (res->chg_prev & TCP_SEQ)
		printf("[TCP seq changed] ");
	if ((res->chg_prev & IP_TLEN_DECR) || ((res->chg_start & TCP_OPT) && !(res->chg_start & SRV_REPLY)))
		printf("[TCP opt removed/changed] ");
	if ((res->chg_start & TCP_OPT) && (res->chg_start & SRV_REPLY))
		printf("[Did not reply with opt] ");
	if (res->chg_start & TCP_WIN)
		printf("[TCP win changed] ");
	if (res->chg_start & FULL_REPLY)
		printf("[Reply ICMP full pkt] ");
}

static const char *flags_str(tbox_res_t *res)
{
#define test_flag(flags, flag) if (flags & flag) printf(#flag " ");
	test_flag(res->chg_prev, IP_HLEN);
	test_flag(res->chg_prev, IP_DSCP);
	test_flag(res->chg_prev, IP_ECN);
	test_flag(res->chg_prev, IP_TLEN_INCR);
	test_flag(res->chg_prev, IP_TLEN_DECR);
	test_flag(res->chg_prev, IP_ID);
	test_flag(res->chg_prev, IP_FRAG);
	test_flag(res->chg_prev, IP_SADDR);
	test_flag(res->chg_prev, L4_SPORT);
	test_flag(res->chg_prev, TCP_SEQ);
	test_flag(res->chg_start, TCP_DOFF);
	test_flag(res->chg_start, TCP_WIN);
	test_flag(res->chg_start, TCP_OPT);
	test_flag(res->chg_start, TCP_FLAGS);
	test_flag(res->chg_start, UDP_LEN);
	test_flag(res->chg_start, UDP_CHKSUM);
	test_flag(res->chg_start, PAYLOAD);
	test_flag(res->chg_start, FULL_REPLY);
	test_flag(res->chg_start, SRV_REPLY);
}

static int open_dump(const char *file)
{
	pcap = pcap_open_dead(DLT_RAW, 65535);
	if (!pcap)
		return -1;

	dumper = pcap_dump_open(pcap, file);
	if (!dumper) {
		pcap_close(pcap);
		return -1;
	}
	return 0;
}

static void dump_pkt(const uint8_t const *pkt, size_t len)
{
	struct pcap_pkthdr ph = {
		.caplen	= len,
		.len	= len,
	};

	if (!dumper)
		return;

	if (gettimeofday(&ph.ts, NULL) < 0)
		return;

	pcap_dump((u_char *)dumper, &ph, pkt);
}

static void tbox_print_classic(int ttl, tbox_res_t *res)
{
	if (!res->recv_probes)
		printf("%2d: *\n", ttl);
	else {
		struct addr addr;
		addr_pack(&addr, ADDR_TYPE_IP, IP_ADDR_BITS, &res->from,
			  IP_ADDR_LEN);
		if (resolve) {
			char name[255];
			resolve_addr(AF_INET, &addr, name, sizeof(name));
			printf("%2d: %s (%s) ", ttl, name, addr_ntoa(&addr));
		} else
			printf("%2d: %s ", ttl, addr_ntoa(&addr));
		change_str(res);
		printf("\n");
		fflush(stdout);
	}
}

static void tbox_print_changes(int ttl, tbox_res_t *res)
{
	if (!res->recv_probes)
		printf("%2d *:\n", ttl);
	else {
		struct addr addr;
		addr_pack(&addr, ADDR_TYPE_IP, IP_ADDR_BITS, &res->from,
			  IP_ADDR_LEN);
		printf("%2d %s: ", ttl, addr_ntoa(&addr));
		flags_str(res);
		printf("\n");
		fflush(stdout);
	}
}

static void tbox_print(int ttl, tbox_res_t *res)
{
	switch (output_format) {
	case 0:
		tbox_print_classic(ttl, res);
		break;
	case 1:
		tbox_print_changes(ttl, res);
		break;
	}
}

static int tbox_callback(int ttl, tbox_res_t *res)
{
	if (res->sent_probes == 0)
		return 0;

	tbox_print(ttl, res);

	return 0;
}

static int close_dump(void)
{
	if (dumper) {
		pcap_close(pcap);
		pcap_dump_close(dumper);
	}
}

int main(int argc, char *argv[])
{
	char		 iface[INTF_NAME_LEN];
	char		 c;
	int		 ret = 0;
	int		 iface_set = 0;
	char		 addr_name[255];
	int		 i;
	uint32_t	 chg = 0;
	tbox_res_t	 res[TBOX_HARD_TTL];
	uint8_t		 pkt[1024];
	size_t		 pkt_len = sizeof(pkt);
	uint8_t		 tcp_flags = TH_SYN;
	char		*output_file = NULL;
	const char	*script_file = NULL;
	const char	*command = NULL;

	if (geteuid() != 0) {
		error("%s can only be used as root", argv[0]);
		exit(EXIT_FAILURE);
	}

	srand(time(NULL) ^ getpid());

	while ((c = getopt (argc, argv, ":i:m:o:O:p:f:M:S:c:hny")) != -1) {
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
			case 'p':
				dport = strtol(optarg, NULL, 10);
				break;
			case 'f':
				tcp_flags = parse_flags(optarg);
				break;
			case 'M':
				__mss = strtol(optarg, NULL, 10);
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
#if HAVE_LUA
			case 'S':
				script_file = optarg;
				break;
			case 'c':
				command = optarg;
				break;
#endif
			case 'O':
				output_file = optarg;
				break;
			case 'y':
				output_format = 1;
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

	if (resolve_host(AF_INET, argv[argc-1], &ip_dst, addr_name,
			 sizeof(addr_name)) < 0) {
		error("error resolving %s", argv[argc-1]);
		exit(EXIT_FAILURE);
	}

	if (command && script_file) {
		error("You can only specify a script or a command, not both.");
		exit(EXIT_FAILURE);
	} else if (command) {
		tracebox_lua_run(command);
	} else if (script_file) {
		tracebox_lua_load(script_file);
	} else {
		if (output_file)
			open_dump(output_file);

		printf("tracebox to %s (%s): %d hops max\n", addr_name,
		       addr_ntoa(&ip_dst), hops_max);

		probe_ip_setup(rand());
		probe_tcp_setup(rand(), rand(), tcp_flags);
		generate_probe(pkt, &pkt_len);

		memset(res, 0, sizeof(res));
		ret = tracebox(pkt, pkt_len, res, 5,
			       TBOX_IFACE, iface_set ? iface : NULL,
			       TBOX_MAX_TTL, hops_max, TBOX_SENT_CB, dump_pkt,
			       TBOX_RECV_CB, dump_pkt, TBOX_CB, tbox_callback);
		close_dump();
	}

	return(ret);
usage:
	fprintf(stderr, "Usage:\n"
"  %s [ -hn ] [ OPTIONS ] host\n"
"Options are:\n"
"  -h                          Display this help and exit\n"
"  -n                          Do not resolve IP adresses\n"
"  -i device                   Specify a network interface to operate with\n"
"  -m hops_max                 Set the max number of hops (max TTL to be\n"
"                              reached). Default is 30\n"
"  -o option                   Define the TCP option to put in the SYN segment.\n"
"                              Default is none. -o list for a list of available\n"
"                              options.\n"
"  -O file                     Use file to dump the sent and received packets\n"
"  -p port                     Specify the destination port to use when\n"
"                              generating probes. Default is 80.\n"
"  -f flag1[,flag2[,flag3...]] Specify the TCP flags to use. Values are: syn,\n"
"                              ack, fin, rst, push, urg, ece, cwr. Default is:\n"
"                              syn.\n"
"  -M mss                      Specify the MSS to use when generating the TCP\n"
"                              MSS option. Default is 9140.\n"
#ifdef HAVE_LUA
"  -S script                   Run a script.\n"
"  -C cmd                      Execute a command.\n"
#endif
"", argv[0]);
	exit(EXIT_FAILURE);
}
