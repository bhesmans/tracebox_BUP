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
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "dnet_compat.h"
#include "packet.h"
#include "probing.h"
#include "tracebox.h"

#define error(format, args...)  \
	fprintf(stderr, "tracebox: " format "\n", ## args)
#define min(a,b)	(a > b ? b : a)
#define TBOX_PARSE_OPT(o,f) { \
	typeof(tbox.f) __val; \
	if (((tbox_opt_t)opt) == ((tbox_opt_t)o)) { \
		tbox.f = va_arg(argp, typeof(tbox.f)); \
		continue; \
	} \
}

static int tbox_intf(tbox_conf_t *tbox, struct intf_entry *iface,
		     struct addr *addr)
{
	intf_t	*intf;

	if ((intf = intf_open()) == NULL)
		return(-1);

	memset(iface, 0, sizeof(*iface));
	iface->intf_len = sizeof(*iface);

	if (tbox->iface) {
		strlcpy(iface->intf_name, tbox->iface,
			sizeof(iface->intf_name));
		if (intf_get(intf, iface) < 0)
			goto error;
	} else {
		if (intf_get_dst(intf, iface, addr) < 0)
			goto error;
	}

	intf_close(intf);
	return(0);

error:
	intf_close(intf);
	return(-1);
}

static uint8_t *tbox_parse_pkt(uint8_t *pkt, size_t *len, struct addr *from)
{
	struct ip_hdr	*ip = (struct ip_hdr *)pkt;
	size_t		 off = ip->ip_hl << 2;

	addr_pack(from, ADDR_TYPE_IP, IP_ADDR_BITS, &ip->ip_src, sizeof(ip->ip_src));

	if (ip->ip_p == IPPROTO_ICMP) {
		struct icmp_hdr *icmp = (struct icmp_hdr *)(pkt + off);

		off += sizeof(*icmp) + 4;
		pkt += off;
		*len -= off;

		/* Check if ICMP Multipart is present: */
		ip = (struct ip_hdr *)(pkt );
		if (ntohs(ip->ip_len) < *len)
			*len = ntohs(ip->ip_len);
	}
	return pkt;
}

static int cont;

static int tbox_loop(tbox_conf_t *tbox, uint8_t *probe, size_t len,
		     tbox_res_t *res)
{
	uint8_t			 ttl;
	uint8_t			*ppkt = NULL;
	size_t			 plen;
	struct intf_entry	 iface;
	struct ip_hdr		*ip = (struct ip_hdr *)probe;
	uint16_t		 port;
	struct addr		 dst_addr;
	probing_t		*probing;
	int			 noreply = 0;
	struct addr		 from;

	if (len > TBOX_PKT_SIZE) {
		error("Probe too big");
		return(-1);
	}

	switch (ip->ip_v) {
	case 4:
		addr_pack(&dst_addr, ADDR_TYPE_IP, IP_ADDR_BITS, &ip->ip_dst,
			  sizeof(ip->ip_dst));
		break;
	default:
		error("Unsupported IP version %d", ip->ip_v);
		return(-1);
	}

	if (tbox_intf(tbox, &iface, &dst_addr) < 0) {
		error("Unable to find a suitable interface");
		return(-1);
	}

	/* Ensure the packet uses the right source address */
	ip->ip_src = iface.intf_addr.addr_ip;
	ip_checksum(probe, ntohs(ip->ip_len));
	port = ntohs(((struct udp_hdr *)(probe + (ip->ip_hl << 2)))->uh_sport);

	/* Do the probing */
	probing = probing_init(&iface, &dst_addr, port, 3);
	if (!probing) {
		error("Unable to start probing");
		return(-1);
	}

	cont = 1;
	for (ttl = ip->ip_ttl = tbox->min_ttl;
	     ttl <= tbox->max_ttl && cont && noreply < tbox->noreply; ++ttl) {
		int p;

		ip->ip_ttl = ttl;
		ip_checksum(probe, ntohs(ip->ip_len));

		for (p = 0; p < tbox->nprobes && cont; ++p) {
			uint8_t	*pkt;
			size_t	 pkt_len;

			if (tbox->pkt_sent_cb)
				tbox->pkt_sent_cb(probe, len);

			if (probing_send(probing, probe, len) < 0) {
				error("Unable to send probe");
				goto error;
			}
			res[ttl].sent_probes++;
			res[ttl].probe_len = min(len, TBOX_PKT_SIZE);
			memcpy(res[ttl].probe, probe, res[ttl].probe_len);

			if (probing_recv(probing, &pkt, &pkt_len) < 0)
				continue;

			res[ttl].recv_probes++;
			if (tbox->pkt_recv_cb)
				tbox->pkt_recv_cb(pkt, pkt_len);

			pkt = tbox_parse_pkt(pkt, &pkt_len, &from);
			res[ttl].chg_start |= diff_packet(probe, len, pkt,
							  pkt_len);
			if (ppkt)
				res[ttl].chg_prev |= diff_packet(ppkt, plen,
								 pkt, pkt_len);
			else
				res[ttl].chg_prev |= res[ttl].chg_start;
			res[ttl].chg_start |= (len <= pkt_len ? FULL_REPLY : 0);

			res[ttl].reply_len = min(pkt_len, TBOX_PKT_SIZE);
			memcpy(res[ttl].reply, pkt, pkt_len);
			ppkt = pkt;
			plen = pkt_len;
			break;
		}

		if (res[ttl].recv_probes > 0)
			noreply = 0;
		else
			noreply++;

		res[ttl].from = from.addr_ip;
		if (!addr_cmp(&dst_addr, &from))
			break;
	}

	probing_free(probing);
	return(0);

error:
	probing_free(probing);
	return(-1);
}

static void handle_term(int sig)
{
	cont = 0;
}

int tracebox(uint8_t *probe, size_t len, tbox_res_t *res, int nopts, ...)
{
	tbox_conf_t	tbox = TBOX_DEFAULT;
	va_list		argp;

	va_start(argp, nopts);
	while (nopts--) {
		tbox_opt_t	opt;

		opt = va_arg(argp, tbox_opt_t);

		TBOX_PARSE_OPT(TBOX_IFACE,	iface);
		TBOX_PARSE_OPT(TBOX_MIN_TTL,	min_ttl);
		TBOX_PARSE_OPT(TBOX_MAX_TTL,	max_ttl);
		TBOX_PARSE_OPT(TBOX_NPROBES,	nprobes);
		TBOX_PARSE_OPT(TBOX_PROBE_TIMEO,probe_timeo);
		TBOX_PARSE_OPT(TBOX_NOREPLY,	noreply);
		TBOX_PARSE_OPT(TBOX_SENT_CB,	pkt_sent_cb);
		TBOX_PARSE_OPT(TBOX_RECV_CB,	pkt_recv_cb);

		error("Unknown option %d.", opt);
		return(-1);
	}
	va_end(argp);

	/* Check options values */
	if (tbox.min_ttl > tbox.max_ttl) {
		error("Min TTL should be <= Max TTL");
		return(-1);
	}

	if (tbox.max_ttl > TBOX_HARD_TTL) {
		error("Max TTL should be <= %d", TBOX_HARD_TTL);
		return(-1);
	}

	signal(SIGTERM, handle_term);
	signal(SIGKILL, handle_term);
	signal(SIGINT, handle_term);

	return tbox_loop(&tbox, probe, len, res);
}
