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

#include <dnet.h>
#ifdef HAVE_NET_BPF_H
#include <net/bpf.h>
#endif
#include <pcap.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#define arp_timeout (3)
#define arp_nprobes (3)
#define pcap_filter ("arp and dst host %s and src host %s")

typedef struct {
	pcap_t	*pcap;
	int	 pcapfd;
	eth_t	*ethfd;
} arp_ctx_t;

static arp_ctx_t * arp_ctx_init(const char *iface, const struct addr *ip_src,
				const struct addr *ip_dst) 
{
	char			 filter_exp[255];
	char			 pcap_errbuf[PCAP_ERRBUF_SIZE];
	char			 src_buf[255];
	char			 dst_buf[255];
	bpf_u_int32		 net = 0;
	bpf_u_int32		 mask = 0;
	arp_ctx_t		*arp_ctx;
	struct bpf_program	 fp;
	int			 ret;

	arp_ctx = malloc(sizeof(*arp_ctx));
	assert(arp_ctx != NULL);
	
	pcap_lookupnet(iface, &net, &mask, pcap_errbuf);
	arp_ctx->pcap = pcap_open_live(iface, 65535, 0, 5000, pcap_errbuf);
	assert(arp_ctx->pcap != NULL);

	ip_ntop(&ip_src->addr_ip, src_buf, sizeof(src_buf));
	ip_ntop(&ip_dst->addr_ip, dst_buf, sizeof(dst_buf));
	sprintf(filter_exp, pcap_filter, src_buf, dst_buf);

	ret = pcap_compile(arp_ctx->pcap, &fp, filter_exp, 0, net);
	assert(ret != -1);

	ret = pcap_setfilter(arp_ctx->pcap, &fp);
	assert(ret != -1);

	ret = pcap_setnonblock(arp_ctx->pcap, 1, pcap_errbuf);
	assert(ret != -1);

	arp_ctx->pcapfd = pcap_get_selectable_fd(arp_ctx->pcap);
	assert(arp_ctx->pcapfd != -1);

	#ifdef HAVE_NET_BPF_H
	{
		int on = 1;
		ret = ioctl(arp_ctx->pcapfd, BIOCIMMEDIATE, &on);
		assert(ret >= 0);
	}
	#endif

	arp_ctx->ethfd = eth_open(iface);
	assert(arp_ctx->ethfd != NULL);

	return arp_ctx;
}

static void arp_ctx_free(arp_ctx_t * arp_ctx) 
{
	close(arp_ctx->pcapfd);
	pcap_close(arp_ctx->pcap);
	free(arp_ctx);
}

static int send_arp(arp_ctx_t *arp_ctx, struct addr *ether_src,
		    struct addr *ip_src, struct addr *ip_dst)
{
	u_char		 packet[ETH_HDR_LEN + ARP_HDR_LEN + ARP_ETHIP_LEN];
	struct eth_hdr	*eth;
	struct arp_hdr	*arp;
	struct addr	 ether_dst;
	int		 n;

	addr_pton("ff:ff:ff:ff:ff:ff", &ether_dst);
	eth = (struct eth_hdr *) packet;
	eth_pack_hdr(eth, ether_dst.addr_eth, ether_src->addr_eth, ETH_TYPE_ARP);

	addr_pton("00:00:00:00:00:00", &ether_dst);	
	arp = (struct arp_hdr *) (packet + ETH_HDR_LEN);
	arp_pack_hdr_ethip(arp, ARP_OP_REQUEST, ether_src->addr_eth,
			   ip_src->addr_ip, ether_dst.addr_eth, ip_dst->addr_ip);

	n = eth_send(arp_ctx->ethfd, packet, ETH_HDR_LEN + ARP_HDR_LEN +
		     ARP_ETHIP_LEN);
	assert(n == ETH_HDR_LEN + ARP_HDR_LEN + ARP_ETHIP_LEN);
}

static int recv_arp(arp_ctx_t *arp_ctx, struct addr *ether_dst,
		    struct addr *ip_dst)
{
	const u_char		*packet;
	struct pcap_pkthdr	 pcap_hdr;
	struct arp_hdr		*arp;
	struct arp_ethip	*ethip;
	fd_set			 read_fd;
	struct timeval		 ts = {arp_timeout, 0};
	int			 ret, n;

	FD_ZERO(&read_fd);
	FD_SET(arp_ctx->pcapfd, &read_fd);

	for ( ; ; ) {
		ret = select(arp_ctx->pcapfd+1, &read_fd, 0, 0, &ts);
		assert(ret != -1);

		if (ret == 0)
			return -1;

		packet = pcap_next(arp_ctx->pcap, &pcap_hdr);

		if (packet == NULL) continue;

		arp	= (struct arp_hdr *) (packet + ETH_HDR_LEN);
		ethip	= (struct arp_ethip *) (packet + ETH_HDR_LEN +
						ARP_HDR_LEN);

		if (ntohs(arp->ar_op) != ARP_OP_REPLY)
			continue;
		addr_pack(ether_dst, ADDR_TYPE_ETH, ETH_ADDR_BITS,
			  ethip->ar_sha, ETH_ADDR_LEN);
		return 0;
	}
}

static int resolve_arp(const char *iface, struct addr *ip_dst,
		       struct addr *ether_dst)
{
	arp_ctx_t		*ctx;
	int			 i;
	int			 ret;
	struct addr		 ether_src;
	struct addr		 ip_src;
	intf_t			*intf;
	struct intf_entry	 ientry;

	ret = -1;

	if (resolve_iface(iface, &ether_src, &ip_src) < 0)
		return -1;

	ctx = arp_ctx_init(iface, &ip_src, ip_dst);
	assert(ctx != NULL);

	for (i = 0; i < 3; i += 1) {
		send_arp(ctx, &ether_src, &ip_src, ip_dst);

		if (recv_arp(ctx, ether_dst, ip_dst) < 0)
			continue;
		ret = 0;
		break;
	}
	arp_ctx_free(ctx);
	return ret;
}

int resolve_ip_arp(const char *iface, struct addr *ip_dst,
		   struct addr *ether_dst)
{
	struct arp_entry	 aentry;
	arp_t			*arp;

	arp = arp_open();
	assert(arp != NULL);

	memcpy(&aentry.arp_pa, ip_dst, sizeof(aentry.arp_pa));
	if (arp_get(arp, &aentry) < 0) {
		if (resolve_arp(iface, ip_dst, ether_dst) < 0)
			goto arp_failed;
	} else
		memcpy(ether_dst, &aentry.arp_ha, sizeof(aentry.arp_ha));

	arp_close(arp);
	return 0;

arp_failed:
	arp_close(arp);
	return -1;
}

int resolve_iface(const char *iface, struct addr *ether, struct addr *ip)
{
	intf_t			*intf;
	struct intf_entry	 ientry;
	int			 ret;

	intf = intf_open();
	assert(intf != NULL);

	strncpy(ientry.intf_name, iface, INTF_NAME_LEN);
	ientry.intf_len = sizeof(ientry);

	ret = intf_get(intf, &ientry);
	if (ret < 0) {
		intf_close(intf);
		return -1;
	}

	*ether	= ientry.intf_link_addr;
	*ip	= ientry.intf_addr;

	intf_close(intf);

	return 0;
}

int resolve_ip(const char *iface, struct addr *addr, struct addr *eth)
{
	struct route_entry	 rentry;
	route_t			*route;

	route = route_open();
	assert(route != NULL);

	memcpy(&rentry.route_dst, addr, sizeof(rentry.route_dst));
	if (route_get(route, &rentry) < 0) {
		if (resolve_ip_arp(iface, addr, eth) < 0)
			goto ip_arp_failed;
	} else {
		if (resolve_ip_arp(iface, &rentry.route_gw, eth) < 0)
			goto ip_arp_failed;
	}

	route_close(route);
	return 0;
	
ip_arp_failed:
	route_close(route);
	return -1;
}

const char * resolve_iface_addr (struct addr *addr, char *iface) 
{
	intf_t			*intf;
	struct intf_entry	 ientry;
	int			 ret;

	intf = intf_open();
	assert(intf != NULL);

	ientry.intf_len = sizeof(ientry);

	ret = intf_get_dst(intf, &ientry, addr);
	if (ret < 0) {
		intf_close(intf);
		return NULL;
	}

	strncpy(iface, ientry.intf_name, INTF_NAME_LEN);

	intf_close(intf);

	return iface;
}

int resolve_host(int af, const char *host, struct addr *addr, char *name, 
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

int resolve_addr(int af, void *addr, socklen_t addr_len, char *name) 
{
	struct hostent	* hptr;

	hptr = gethostbyaddr(addr, addr_len, af);

	if (hptr != NULL && hptr->h_name != NULL)
		strcpy(name, hptr->h_name);
	else
		return -1;
}
