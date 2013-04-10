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

#ifdef HAVE_NET_BPF_H
#include <net/bpf.h>
#endif
#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>

#include "probing.h"

#define pcap_filter	("%s and (((tcp[13] & 4 == 4 or tcp[13] = 18) and " \
			 "ip src %s and port %hu) or (icmp and " \
			 "(icmp[0] = 11 or icmp[0] = 3)) or " \
			 "(udp and ip src %s and port %hu))")

struct probing {
	pcap_t			*pcap;
	const struct intf_entry	*iface;
	int			 pcapfd;
	int			 timeout;
	ip_t			*sendfd;
	struct addr		 dst_addr;
	uint16_t		 port;
};

static int probing_pcap_init(probing_t *probing, const char *iface)
{
	char			pcap_errbuf[PCAP_ERRBUF_SIZE];
	char			filter_exp[255];
	char			addr_buf[INET6_ADDRSTRLEN];
	int			ret;
	bpf_u_int32		net = 0;
	bpf_u_int32		mask = 0;
	struct bpf_program	fp;

	ret = pcap_lookupnet(iface, &net, &mask, pcap_errbuf);

	probing->pcap = pcap_open_live(iface, 65535, 0, 5000, pcap_errbuf);
	if (!probing->pcap)
		return(-1);

	addr_ntop(&probing->dst_addr, addr_buf, sizeof(addr_buf));
	sprintf(filter_exp, pcap_filter, "ip", addr_buf, probing->port,
		addr_buf, probing->port);

	ret = pcap_compile(probing->pcap, &fp, filter_exp, 0, net);
	if (ret < 0)
		goto error;

	ret = pcap_setfilter(probing->pcap, &fp);
	if (ret < 0)
		goto error;

	ret = pcap_setnonblock(probing->pcap, 1, pcap_errbuf);
	if (ret < 0)
		goto error;

	probing->pcapfd = pcap_get_selectable_fd(probing->pcap);
	if (probing->pcapfd < 0)
		goto error;

	#ifdef HAVE_NET_BPF_H
	{
		int on = 1;
		ret = ioctl(probing->pcapfd, BIOCIMMEDIATE, &on);
		if (ret < 0) {
			close(probing->pcapfd);
			goto error;
		}
	}
	#endif

	return(0);

error:
	pcap_close(probing->pcap);
	return(-1);
}

probing_t *probing_init(const struct intf_entry *iface,
			const struct addr *dst_addr, uint16_t port, int timeout)
{
	probing_t *probing;

	probing = malloc(sizeof(*probing));
	if (!probing)
		return(NULL);

	probing->iface = iface;
	probing->timeout = timeout;
	memcpy(&probing->dst_addr, dst_addr, sizeof(*dst_addr));
	probing->port = port;
	probing->sendfd = ip_open();
	if (!probing->sendfd)
		goto error;

	#ifdef HAVE_PLANETLAB
	{
		struct sockaddr_in sin;
		memset(& sin, 0, sizeof(sin));
		sin.sin_port = htons(port);
		bind(*(int *)probing->sendfd, (struct sockaddr *)&sin,
		     sizeof(sin));
	}
	#endif

	#ifdef HAVE_IP_NODEFRAG
	/* avoid reassembly when seding packets */
	{
		int n = 1;
		if (setsockopt(*(int *)probing->sendfd, IPPROTO_IP, 22, &n, sizeof(n)) < 0)
			goto error_pcap;
	}
	#endif

	if (probing_pcap_init(probing, iface->intf_name) < 0)
		goto error_pcap;
	return probing;

error_pcap:
	ip_close(probing->sendfd);
error:
	free(probing);
	return(NULL);
}
int probing_send(probing_t *probing, const uint8_t *probe, size_t len)
{
	return ip_send(probing->sendfd, probe, len);
}

static int probing_offset(probing_t *probing)
{
	switch (pcap_datalink(probing->pcap)) {
	case DLT_EN10MB:
		return(14);
	case DLT_NULL:
	case DLT_PPP:
		return(4);
	case DLT_SLIP:
		return(16);
	case DLT_RAW:
		return(0);
	case DLT_SLIP_BSDOS:
	case DLT_PPP_BSDOS:
		return(24);
	case DLT_ATM_RFC1483:
		return(8);
	case DLT_IEEE802:
		return(22);
	default:
		return(-1);
	}
}

static int probing_is_valid(probing_t *probing, const uint8_t *reply, size_t len)
{
	struct ip_hdr	*ip = (struct ip_hdr *)reply;
	struct ip_hdr	*in_ip;
	struct tcp_hdr	*l4;
	size_t		 offset = ip->ip_hl << 2;
	struct addr	 dst_addr;
	uint16_t	 port;

	switch (ip->ip_p) {
	case IP_PROTO_TCP:
	case IP_PROTO_UDP:
		/* Handle replies from the destination */
		l4 = (struct tcp_hdr *)(reply + offset);
		port = ntohs(l4->th_dport);
		addr_pack(&dst_addr, ADDR_TYPE_IP, IP_ADDR_BITS, &ip->ip_src,
			  sizeof(in_ip->ip_src));
		break;
	case IP_PROTO_ICMP:
		offset += sizeof(struct icmp_hdr) + 4;
		in_ip = (struct ip_hdr *)(reply + offset);

		offset += in_ip->ip_hl << 2;
		l4 = (struct tcp_hdr *)(reply + offset);

		addr_pack(&dst_addr, ADDR_TYPE_IP, IP_ADDR_BITS, &in_ip->ip_dst,
			  sizeof(in_ip->ip_dst));
		port = ntohs(l4->th_sport);
		break;
	default:
		return 0;
	}

	return !addr_cmp(&dst_addr, &probing->dst_addr) &&
	       port == probing->port;
}

int probing_recv(probing_t *probing, uint8_t **reply, size_t *len)
{
	int			 ret;
	uint8_t			*packet;
	struct pcap_pkthdr	 pcap_hdr;
	struct timeval		 ts = {probing->timeout, 0};
	struct timeval		 ts_start, ts_now;
	fd_set			 read_fd;
	int			 offset;

	FD_ZERO(&read_fd);
	FD_SET(probing->pcapfd, &read_fd);

	if (gettimeofday(&ts_start, NULL) < 0)
		return(-1);

	for ( ; ; ) {
		if (gettimeofday(&ts_now, NULL) < 0)
			return(-1);

		ts.tv_sec = probing->timeout - (ts_now.tv_sec - ts_start.tv_sec);
		if (ts.tv_sec <= 0)
			return(-1);

		ret = select(probing->pcapfd+1, &read_fd, NULL, NULL, &ts);
		if (ret <= 0)
			return(-1);

		packet = (uint8_t *)pcap_next(probing->pcap, &pcap_hdr);
		if (!packet)
			return(-1);

		/* Skip link-layer header */
		offset = probing_offset(probing);
		if (offset < 0)
			return(-1);

		if (!probing_is_valid(probing, packet + offset,
				      pcap_hdr.len - offset))
			continue;

		*reply = packet + offset;
		*len = pcap_hdr.len - offset;

		return(0);
	}
	return(-1);
}

void probing_free(probing_t * probing)
{
	close(probing->pcapfd);
	pcap_close(probing->pcap);
	ip_close(probing->sendfd);
	free(probing);
}
