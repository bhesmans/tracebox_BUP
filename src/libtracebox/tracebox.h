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

#ifndef __TRACEBOX_H__
#define __TRACEBOX_H__

#include <stddef.h>
#include <stdint.h>

#define TBOX_HARD_TTL	(15)

typedef enum {
	TBOX_IFACE,
	TBOX_MIN_TTL,
	TBOX_MAX_TTL,
	TBOX_NPROBES,
	TBOX_PROBE_TIMEO,
	TBOX_NOREPLY,
	TBOX_SENT_CB,
	TBOX_RECV_CB,
} tbox_opt_t;

typedef void (*tbox_cb_t)(const uint8_t const *pkt, size_t len);

typedef struct {
	const char	*iface;
	int		 min_ttl;
	int		 max_ttl;
	int		 nprobes;
	int		 probe_timeo;
	int		 noreply;
	tbox_cb_t	 pkt_sent_cb;
	tbox_cb_t	 pkt_recv_cb;
} tbox_conf_t;

#define TBOX_DEFAULT (tbox_conf_t) { \
	.iface		= NULL, \
	.min_ttl	= 1, \
	.max_ttl	= TBOX_HARD_TTL, \
	.nprobes	= 3, \
	.probe_timeo	= 3, \
	.noreply	= 3, \
	.pkt_sent_cb	= NULL, \
	.pkt_recv_cb	= NULL, \
}

typedef struct {
	uint32_t	from;
	uint8_t		sent_probes;
	uint8_t		recv_probes;
	uint32_t	chg_start;
	uint32_t	chg_prev;
} tbox_res_t;

int tracebox(uint8_t *probe, size_t len, tbox_res_t *res, int nopts, ...);

#endif
