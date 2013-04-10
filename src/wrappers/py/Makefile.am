
SUBDIRS = examples

pyexecdir = $(pythondir)/$(PACKAGE)
pyexec_LTLIBRARIES = _tracebox.la

py_traceboxdir = $(pythondir)/$(PACKAGE)
py_tracebox_PYTHON = \
	__init__.py

_tracebox_la_SOURCES = \
	pytracebox.c

_tracebox_la_CFLAGS = \
	-I ../../ \
	$(PYTHON_CFLAGS)

_tracebox_la_LDFLAGS = \
	-module \
	-avoid-version \
	-export-symbols-regex init_tracebox

_tracebox_la_LIBADD = $(top_builddir)/src/libtracebox/libtracebox.la
