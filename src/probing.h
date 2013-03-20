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

#ifndef __PROBING_H__
#define __PROBING_H__

#include <dnet.h>
#include <sys/time.h>

#define probe_nprobes	(3)

typedef struct {
	int (*send)(u_char ttl, u_char *packet, size_t *len);
	int (*recv)(struct timeval ts, const u_char *sent_packet,
		    size_t sent_len, const u_char *recv_packet,
		    size_t recv_len);
	void (*step)(void);
	void (*timeout)(void);
} prober_t;

void probing_loop(const char *iface, struct addr *ip_dst, int max_ttl,
		  prober_t *prober, const char *dump_file);

#endif
