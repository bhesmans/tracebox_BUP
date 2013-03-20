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

#include "probing.h"
#include "resolve.h"

#include <dnet.h>
#ifdef HAVE_NET_BPF_H
#include <net/bpf.h>
#endif
#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/ioctl.h>

#define error(format, args...)  \
	fprintf(stderr, format "\n", ## args)
#define probe_timeout	(3)
#define probe_nprobes	(3)
#define pcap_filter	("%s and (((tcp[13] & 4 == 4 or tcp[13] = 18)" \
			 "and ip src %s) or icmp)")
#define buffer_size	(1024)

typedef struct {
	struct addr	*ip_dst;
	const char	*iface;
	pcap_t		*pcap;
	int		 pcapfd;
	eth_t		*sendfd;
	prober_t	*prober;
	u_char		 last_packet[buffer_size];
	size_t		 last_packet_len;
} probing_t;

static void probing_pcap_init(probing_t *probing, const char *iface,
			      struct addr *ip) 
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
	assert(probing->pcap != NULL);

	addr_ntop(ip, addr_buf, sizeof(addr_buf));
	sprintf(filter_exp, pcap_filter, "ip", addr_buf);

	ret = pcap_compile(probing->pcap, &fp, filter_exp, 0, net);
	assert(ret != -1);

	ret = pcap_setfilter(probing->pcap, &fp);
	assert(ret != -1);

	ret = pcap_setnonblock(probing->pcap, 1, pcap_errbuf);
	assert(ret != -1);

	probing->pcapfd = pcap_get_selectable_fd(probing->pcap);
	assert(probing->pcapfd != -1);

	#ifdef HAVE_NET_BPF_H
	{
		int on = 1;
		ret = ioctl(probing->pcapfd, BIOCIMMEDIATE, &on);
		assert(ret >= 0);
	}
	#endif
}

static probing_t *probing_init(const char *iface, struct addr *ip_dst,
			       prober_t *prober)
{
	probing_t *probing;

	probing = malloc(sizeof(*probing));
	assert(probing != NULL);

	probing->sendfd = eth_open(iface);
	assert(probing->sendfd != NULL);

	probing_pcap_init(probing, iface,  ip_dst);

	probing->iface	= iface;
	probing->ip_dst	= ip_dst;
	probing->prober = prober;

	return probing;
}

static void probing_free(probing_t * probing) 
{
	close(probing->pcapfd);
	pcap_close(probing->pcap);
	eth_close(probing->sendfd);
	free(probing);
}

static int probing_recv_packet(probing_t *probing, const u_char *packet,
			       size_t packet_len, struct addr *from,
			       struct timeval ts)
{
	struct ip_hdr	*ip;
	struct ip_hdr	*icmp_ip;
	struct ip_hdr	*last_ip;
	size_t		 ip_len, len;

	len	= ETH_HDR_LEN;
	ip	= (struct ip_hdr *) (packet + ETH_HDR_LEN);
	addr_pack(from, ADDR_TYPE_IP, IP_ADDR_BITS, &ip->ip_src, IP_ADDR_LEN);

	return probing->prober->recv(ts, probing->last_packet,
				     probing->last_packet_len,
				     packet + ETH_HDR_LEN,
				     packet_len - ETH_HDR_LEN);
}

static int probing_recv(probing_t *probing, struct addr *from)
{
	int			 ret;
	const u_char		*packet;
	struct pcap_pkthdr	 pcap_hdr;
	struct timeval		 ts = {probe_timeout, 0};
	fd_set			 read_fd;

	FD_ZERO(&read_fd);

	FD_SET(probing->pcapfd, &read_fd);

	for ( ; ; ) {
		ret = select(probing->pcapfd+1, &read_fd, NULL, NULL, &ts);
		assert(ret != -1);

		if (ret == 0) 
			return -1;

		packet = pcap_next(probing->pcap, &pcap_hdr);
		if (packet == NULL)
			continue;
		return probing_recv_packet(probing, packet, pcap_hdr.len, from,
					  pcap_hdr.ts);
	}
	return -1;
}

static int probing_send(probing_t *probing, u_char *packet, size_t len)
{
	u_char		 buffer[buffer_size+ETH_HDR_LEN];
	struct ip_hdr	*ip;
	struct eth_hdr	*eth;
	struct addr	 ether_src;
	struct addr	 ether_dst;
	struct addr	 tmp;
	struct addr	 ip_dst;

	if (resolve_iface(probing->iface, &ether_src, &tmp) < 0) {
		error("unable to retrieve mac address of interface %s",
		      probing->iface);
		return -1;
	}

	ip = (struct ip_hdr *) packet;
	addr_pack(&ip_dst, ADDR_TYPE_IP, IP_ADDR_BITS, &ip->ip_dst, IP_ADDR_LEN);

	if (resolve_ip(probing->iface, &ip_dst, &ether_dst) < 0) {
		char addr_buf[INET6_ADDRSTRLEN];
		addr_ntop(&ip_dst, addr_buf, sizeof(addr_buf));
		return -1;
	}

	eth_pack_hdr(buffer, ether_dst.addr_eth, ether_src.addr_eth, ETH_TYPE_IP);
	memcpy((buffer+ETH_HDR_LEN), packet, len);

	return eth_send(probing->sendfd, buffer, len+ETH_HDR_LEN);	
}

void probing_loop(const char *iface, struct addr *ip_dst, int max_ttl,
		  prober_t *prober)
{
	u_char		 ttl;
	int		 p;
	int		 ret = 0;
	probing_t	*probing;
	struct addr	 from;
	struct addr	 last_from;

	probing = probing_init(iface, ip_dst, prober);
	assert(probing != NULL);

	for (ttl = 1; ttl <= max_ttl; ttl++) {
		for (p = 0; p < probe_nprobes; p++) {
			probing->last_packet_len = buffer_size;
			if (prober->send(ttl, probing->last_packet,
					 &probing->last_packet_len)) {
				error("no more packet to send");
				goto done;
			}

			if (probing_send(probing, probing->last_packet,
					 probing->last_packet_len) < 0) {
				error("unable to send probe");
				goto done;
			}

			if ((ret = probing_recv(probing, &from)) < 0)
				prober->timeout();
			fflush(stdout);
		}
		prober->step();
		if (ret > 0)
			goto done;
	}
done:
	probing_free(probing);
}
