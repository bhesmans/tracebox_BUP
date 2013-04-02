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

#ifndef __PACKET_H__
#define __PACKET_H__

#include <stddef.h>
#include <stdint.h>

enum packet_change_t {
	IP_HLEN		= 1,

	IP_DSCP		= 1 << 1,
	IP_ECT		= 1 << 2,
	IP_CE		= 1 << 3,

	IP_TLEN_INCR	= 1 << 4,
	IP_TLEN_DECR	= 1 << 5,
	IP_ID		= 1 << 6,
	IP_FRAG		= 1 << 7,
	IP_SADDR	= 1 << 8,

	L4_SPORT	= 1 << 9,

	TCP_SEQ		= 1 << 10,
	TCP_DOFF	= 1 << 11,
	TCP_WIN		= 1 << 12,
	TCP_OPT		= 1 << 13,
	TCP_FLAGS	= 1 << 14,

	UDP_LEN		= 1 << 15,
	UDP_CHKSUM	= 1 << 16,

	PAYLOAD		= 1 << 17,

	FULL_REPLY	= 1 << 30,
	SRV_REPLY	= 1 << 31,
};

uint32_t diff_packet(const uint8_t *orig, size_t orig_len,
		     const uint8_t *other, size_t other_len);

#endif
