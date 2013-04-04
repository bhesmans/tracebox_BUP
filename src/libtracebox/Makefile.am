
lib_LTLIBRARIES = libtracebox.la

libtracebox_la_SOURCES = \
	packet.c \
	probing.c \
	tracebox.c

libtracebox_includedir = $(includedir)/libtracebox/

libtracebox_include_HEADERS = \
	packet.h \
	probing.h \
	tracebox.h

if DUMBNET
libtracebox_la_LIBADD = -lpcap -ldumbnet
else
libtracebox_la_LIBADD = -lpcap -ldnet
endif
