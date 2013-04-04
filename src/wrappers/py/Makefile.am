
SUBDIRS = examples

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

