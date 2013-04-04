
bin_PROGRAMS = tracebox
tracebox_SOURCES = main.c
tracebox_CPPFLAGS = -I../
tracebox_LDADD = ../libtracebox/libtracebox.la

if DUMBNET
tracebox_LDADD += -ldumbnet
else
tracebox_LDADD += -ldnet
endif
