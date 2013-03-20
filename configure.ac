AC_INIT([tracebox], [0.0], [gregory.detal@uclouvain.be])

AC_PREREQ([2.59])
AM_INIT_AUTOMAKE([1.10 -Werror -Wall no-define foreign])

LT_INIT

AC_CONFIG_MACRO_DIR([m4])

AC_PROG_CC
AC_PROG_LIBTOOL
AC_C_BIGENDIAN([AC_DEFINE(__BIG_ENDIAN__)], [AC_DEFINE(__LITTLE_ENDIAN__)], [])

AC_HEADER_STDC
AC_HEADER_ASSERT
AC_CHECK_HEADER([net/ethernet.h])
AC_CHECK_HEADER([netinet/ip.h])
AC_CHECK_HEADER([net/bpf.h], [AC_DEFINE(HAVE_NET_BPF_H)], [])
AC_CHECK_HEADER([pcap.h], [], [AC_MSG_ERROR([need libcap])])
AC_CHECK_HEADER([dnet.h], [], [AC_MSG_ERROR([need libdnet])])

AC_CONFIG_FILES([
	Makefile
	src/Makefile
])
AC_OUTPUT
