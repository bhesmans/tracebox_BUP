
bin_SCRIPTS = pytracebox
EXTRA_DIST = pytracebox.in

traceboxdir = $(pythondir)
tracebox_LTLIBRARIES = tracebox.la

tracebox_la_SOURCES = \
	pytracebox.c

tracebox_la_CFLAGS = \
	-I ../../ \
	$(PYTHON_CFLAGS)

tracebox_la_LDFLAGS = \
	-module \
	-avoid-version \
	-export-symbols-regex inittracebox

tracebox_la_LIBADD = $(top_builddir)/src/libtracebox/libtracebox.la

do_substitution = sed -e 's,[@]pythondir[@],$(pythondir),g'

pytracebox: pytracebox.in Makefile
	$(do_substitution) < $(srcdir)/pytracebox.in > pytracebox
	chmod +x pytracebox
