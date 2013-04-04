AC_INIT([tracebox], [0.0], [gregory.detal@uclouvain.be])

AC_PREREQ([2.59])
AM_INIT_AUTOMAKE([1.10 -Werror -Wall no-define foreign])
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])

LT_INIT

AC_CONFIG_MACRO_DIR([m4])

AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_LIBTOOL
AC_C_BIGENDIAN([AC_DEFINE(__BIG_ENDIAN__)], [AC_DEFINE(__LITTLE_ENDIAN__)], [])

AC_HEADER_STDC
AC_HEADER_ASSERT
AC_CHECK_HEADER([net/ethernet.h])
AC_CHECK_HEADER([netinet/ip.h])
AC_CHECK_HEADER([net/bpf.h], [AC_DEFINE(HAVE_NET_BPF_H)], [])
AC_CHECK_HEADER([pcap.h], [], [AC_MSG_ERROR([need libcap])])
AC_CHECK_HEADER([dnet.h], [AC_DEFINE(HAVE_DNET)], [DNET="no"])
AC_CHECK_HEADER([dumbnet.h], [AC_DEFINE(HAVE_DUMBNET)], [DUMBNET="no"])

AS_IF([test "x$DNET" = "xno" || test "x$DUMBNET" = "xno"], [],
      [AC_MSG_ERROR([need libdnet])])

AC_RUN_IFELSE([AC_LANG_PROGRAM([[#include <linux/in.h>]], [[IP_NODEFRAG;]])],
	[AC_DEFINE(HAVE_IP_NODEFRAG)],[])

AC_ARG_ENABLE(wrappers,
	      AS_HELP_STRING([--disable-wrappers], [Disable wrappers]))

AS_IF([test "x$enable_wrappers" != "xno"], [
	AM_PATH_PYTHON(2.6.0)
	PY_PREFIX=`$PYTHON -c 'import sys ; print sys.prefix'`
	PYTHON_LIBS="-lpython$PYTHON_VERSION"
	PYTHON_CFLAGS="-I$PY_PREFIX/include/python$PYTHON_VERSION"
	AC_SUBST([PYTHON_LIBS])
	AC_SUBST([PYTHON_CFLAGS])
])

AC_ARG_ENABLE([planetlab],
	      AS_HELP_STRING([--enable-planetlab], [Enable planetlab support]))

AS_IF([test "x$enable_planetlab" = "xyes"], [AC_DEFINE(HAVE_PLANETLAB)])

AM_CONDITIONAL(LINUX, test "$OSTYPE" = "linux-gnu")
AM_CONDITIONAL(WRAPPERS, test "x$enable_wrappers" != "xno")

AC_CONFIG_FILES([
	Makefile
	src/Makefile
	src/libtracebox/Makefile
	src/tracebox/Makefile
	src/wrappers/Makefile
	src/wrappers/py/Makefile
])
AC_OUTPUT
