
EXTRA_DIST = \
	options.h \
	probe.h \
	tracebox_lua.h

bin_PROGRAMS = tracebox
tracebox_SOURCES = main.c

if ENABLE_LUA
tracebox_SOURCES += \
	tracebox_lua.c \
	$(top_srcdir)/src/libnet/lua/libnet_decode.c \
	$(top_srcdir)/src/libnet/lua/net.c
endif

tracebox_CPPFLAGS = -I$(top_srcdir)/src
if ENABLE_LUA
tracebox_CPPFLAGS += -I$(top_srcdir)/src/libnet/lua/
endif

tracebox_LDADD = ../libtracebox/libtracebox.la
if ENABLE_LUA
tracebox_LDADD += -llua -lnet
endif

if DUMBNET
tracebox_LDADD += -ldumbnet
else
tracebox_LDADD += -ldnet
endif
