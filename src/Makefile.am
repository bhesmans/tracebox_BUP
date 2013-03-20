bin_PROGRAMS = tracebox

tracebox_SOURCES = \
	probing.h \
	resolve.h \
	probe.h \
	main.c \
	probing.c \
	resolve.c
if LINUX
tracebox_LDADD = -lpcap -ldumbnet
else
tracebox_LDADD = -lpcap -ldnet
endif
