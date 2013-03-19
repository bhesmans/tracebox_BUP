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

#ifndef __RESOLVE_H__
#define __RESOLVE_H__

#include <dnet.h>

int resolve_iface (const char *iface, struct addr *ether, struct addr *ip);
int resolve_ip(const char *iface, struct addr *ip, struct addr *ether);
int resolve_ip_arp(const char *iface, struct addr *ip, struct addr *ether);
const char *resolve_iface_addr(struct addr *addr, char *iface);
int resolve_host(int af, const char *host, struct addr *addr, char *name,
		 size_t len);
int resolve_addr(int af, void *addr, socklen_t addr_len, char *name);

#endif
