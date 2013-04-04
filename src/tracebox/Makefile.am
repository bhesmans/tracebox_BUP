
EXTRA_DIST = \
	options.h \
	probe.h

bin_PROGRAMS = tracebox
tracebox_SOURCES = main.c
tracebox_CPPFLAGS = -I$(top_srcdir)/src
tracebox_LDADD = ../libtracebox/libtracebox.la

if DUMBNET
tracebox_LDADD += -ldumbnet
else
tracebox_LDADD += -ldnet
endif
