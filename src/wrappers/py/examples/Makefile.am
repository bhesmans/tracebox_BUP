
doc_in = \
	args.in \
	reporting_server.in
doc_py = \
	detect_ipid.py \
	detect_full_icmp.py \
	detect_tcp_seq_changes.py \
	detect_tcp_opts.py \
	detect_tcp_win_changes.py \
	detect_ecn.py \
	detect_frags.py \
	detect_statefull.py \
	detect_proxy.py \
	detect_all.sh

doc_examplesdir = $(docdir)/examples
doc_examples_DATA = \
	$(doc_in:.in=.py) \
	$(doc_py)

EXTRA_DIST = \
	$(doc_in) \
	$(doc_py)

CLEANFILES = $(doc_in:.in=.py)

SUFFIXES = .in .py

if ENABLE_REPORTING
REPORTING = True
else
REPORTING = False
endif

.in.py:
	sed -e 's,[@]pythondir[@],$(pythondir),g' \
	    -e 's,[@]reporting_enabled[@],$(REPORTING),g' \
	    -e 's,[@]reporting_server[@],$(REPORTING_SERVER),g' < $(srcdir)/$< > $@
	chmod +x $@

install-data-hook:
	for i in $(doc_examples_DATA); do \
		chmod +x $(DESTDIR)$(doc_examplesdir)/$$i; \
	done
