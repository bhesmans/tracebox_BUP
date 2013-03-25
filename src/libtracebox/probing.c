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

#define pcap_filter	("%s and (((tcp[13] & 4 == 4 or tcp[13] = 18) " \
			 "and ip src %s) or (icmp and (icmp[0] = 11 or " \
			 "icmp[0] = 3)) or (udp and ip src %s))")

struct probing {
	pcap_t			*pcap;
	const struct intf_entry	*iface;
	int			 pcapfd;
	int			 timeout;
	eth_t			*sendfd;
};

static int probing_pcap_init(probing_t *probing, const char *iface,
			     const struct addr *ip)
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

	addr_ntop(ip, addr_buf, sizeof(addr_buf));
	sprintf(filter_exp, pcap_filter, "ip", addr_buf, addr_buf);

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
			const struct addr *dst_addr, int timeout)
{
	probing_t *probing;

	probing = malloc(sizeof(*probing));
	if (!probing)
		return(NULL);

	probing->iface = iface;
	probing->timeout = timeout;
	probing->sendfd = eth_open(iface->intf_name);
	if (probing->sendfd < 0)
		goto error;
	if (probing_pcap_init(probing, iface->intf_name, dst_addr) < 0)
		goto error_pcap;

	return probing;

error_pcap:
	eth_close(probing->sendfd);
error:
	free(probing);
	return(NULL);
}

static int probing_lookup_ether(struct addr *addr, struct addr *ether_dst)
{
	struct route_entry	rentry;
	struct arp_entry	aentry;
	route_t			*route;
	arp_t			*arp;

	if ((route = route_open()) == NULL)
		return(-1);

	memset(&rentry, 0, sizeof(rentry));
	memset(&aentry, 0, sizeof(aentry));

	rentry.route_dst = *addr;
	if (route_get(route, &rentry) < 0)
		goto error_route;

	route_close(route);

	if ((arp = arp_open()) == NULL)
		return (-1);

	aentry.arp_pa = rentry.route_gw;
	if (arp_get(arp, &aentry) < 0)
		goto error_arp;

	*ether_dst = aentry.arp_ha;
	arp_close(arp);

	return(0);

error_arp:
	arp_close(arp);
	return(-1);
error_route:
	route_close(route);
	return(-1);
}

int probing_send(probing_t *probing, const uint8_t *probe, size_t len)
{
	u_char		 buffer[ETH_HDR_LEN + len];
	struct ip_hdr	*ip;
	struct eth_hdr	*eth;
	struct addr	 ether_src = probing->iface->intf_link_addr;
	struct addr	 ether_dst;
	struct addr	 ip_dst;

	ip = (struct ip_hdr *)probe;
	addr_pack(&ip_dst, ADDR_TYPE_IP, IP_ADDR_BITS, &ip->ip_dst, IP_ADDR_LEN);
	if (probing_lookup_ether(&ip_dst, &ether_dst) < 0)
		return(-1);

	eth_pack_hdr(buffer, ether_dst.addr_eth, ether_src.addr_eth, ETH_TYPE_IP);
	memcpy(buffer+ETH_HDR_LEN, probe, len);

	return eth_send(probing->sendfd, buffer, sizeof(buffer));
}

int probing_recv(probing_t *probing, uint8_t **reply, size_t *len)
{
	int			 ret;
	uint8_t			*packet;
	struct pcap_pkthdr	 pcap_hdr;
	struct timeval		 ts = {probing->timeout, 0};
	fd_set			 read_fd;

	FD_ZERO(&read_fd);
	FD_SET(probing->pcapfd, &read_fd);

	for ( ; ; ) {
		ret = select(probing->pcapfd+1, &read_fd, NULL, NULL, &ts);
		if (ret <= 0)
			return -1;

		packet = (uint8_t *)pcap_next(probing->pcap, &pcap_hdr);
		if (packet == NULL)
			continue;

		*reply = packet + ETH_HDR_LEN;
		*len = pcap_hdr.len - ETH_HDR_LEN;
		return 0;
	}
	return -1;
}

void probing_free(probing_t * probing)
{
	close(probing->pcapfd);
	pcap_close(probing->pcap);
	eth_close(probing->sendfd);
	free(probing);
}
