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
AC_PATH_PROG([DEBUILD], [dpkg-buildpackage], [notfound])

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

AC_ARG_ENABLE([deb],
	[AS_HELP_STRING([--enable-deb=@<:@yes/no@:>@],
		[Configure for building Debian package @<:@default=no@:>@ (requires dpkg-buildpackage)])],
	[AS_IF([test "x$enable_deb" = "xyes"],
		[AS_IF([test "x$DEBUILD" = "xnotfound"],
			[AC_MSG_ERROR([dpkg-buildpackage is required for --enable-deb])],
		[test "x$enable_rpm" = "xyes"],
			[AC_MSG_ERROR([--enable-rpm and --enable-deb are mutually exclusive])])])],
	[enable_deb=no])
AM_CONDITIONAL([BUILDING_DEB], [test "x$enable_deb" = "xyes"])

AM_CONDITIONAL(DUMBNET, test "x$DUMBNET" != "xno")
AM_CONDITIONAL(WRAPPERS, test "x$enable_wrappers" != "xno")

AC_CONFIG_FILES([
	Makefile
	src/Makefile
	src/libtracebox/Makefile
	src/tracebox/Makefile
	src/wrappers/Makefile
	src/wrappers/py/Makefile
	src/wrappers/py/examples/Makefile
])
AC_OUTPUT
