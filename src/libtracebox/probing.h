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

#include "dnet_compat.h"

typedef struct probing probing_t;

probing_t *probing_init(const struct intf_entry *iface,
			const struct addr *dst_addr, uint16_t port, int timeout);

int probing_send(probing_t *probing, const uint8_t *probe, size_t len);
int probing_recv(probing_t *probing, uint8_t **reply, size_t *len);

void probing_free(probing_t * probing);

#endif
