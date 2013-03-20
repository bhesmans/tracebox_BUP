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

#ifndef __OPTIONS_H__
#define __OPTIONS_H__

#ifndef TCP_OPT_MPTCP
#define TCP_OPT_MPTCP 30
#endif


struct mp_capable {
#if __LITTLE_ENDIAN__
	uint8_t	ver : 4,
		sub : 4;
	uint8_t	s : 1,
		rsv : 6,
		c : 1;
#else
	uint8_t	sub : 4,
		ver : 4;
	uint8_t	c : 1,
		rsv : 6,
		s : 1;
#endif
	uint64_t key;
} __attribute__((__packed__));

static inline size_t mptcp_pack(struct tcp_opt *opt)
{
	struct mp_capable *mpc = (struct mp_capable *)&opt->opt_data.data8;

	mpc->ver = 0;
	mpc->sub = 0;
	mpc->rsv = 0;
	mpc->s = 1;
	mpc->c = rand() % 2;
	mpc->key = ((uint64_t)rand()) << 32 | rand();

	return sizeof(*mpc) + 2;
}

static inline size_t mss_pack(struct tcp_opt *opt)
{
	opt->opt_data.mss = htons(1460);
	return 4;
}

static inline size_t wscale_pack(struct tcp_opt *opt)
{
	opt->opt_data.wscale = (rand() % 13) + 1;
	return 3;
}

static inline size_t ts_pack(struct tcp_opt *opt)
{
	opt->opt_data.timestamp[0] = htonl(rand());
	opt->opt_data.timestamp[1] = 0;
	return 10;
}

static inline size_t sack_pack(struct tcp_opt *opt)
{
	return 2;
}

static inline void tcp_opt_pack(u_char type, u_char *u, size_t *len)
{
	struct tcp_opt *opt = (struct tcp_opt *)u;

	switch ((opt->opt_type = type)) {
	case TCP_OPT_MPTCP:
		*len = mptcp_pack(opt);
		break;
	case TCP_OPT_MSS:
		*len = mss_pack(opt);
		break;
	case TCP_OPT_WSCALE:
		*len = wscale_pack(opt);
		break;
	case TCP_OPT_TIMESTAMP:
		*len = ts_pack(opt);
		break;
	case TCP_OPT_SACK:
		*len = sack_pack(opt);
		break;
	default:
		*len = 0;
	}

	opt->opt_len = *len;
	*len = (*len + 3) & ~3;

	/* Fill with NOP */
	memset(u + opt->opt_len, TCP_OPT_NOP, *len - opt->opt_len);
}

#endif /* __OPTIONS_H__ */
