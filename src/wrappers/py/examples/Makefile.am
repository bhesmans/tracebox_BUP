
doc_in = \
	args.in
doc_py = \
	detect_ipid.py \
	detect_full_icmp.py \
	detect_tcp_seq_changes.py \
	detect_tcp_opts.py \
	detect_tcp_win_changes.py \
	detect_ecn.py \
	detect_frags.py \
	detect_statefull.py \
	detect_proxy.py

doc_examplesdir = $(docdir)/examples
doc_examples_DATA = \
	$(doc_in:.in=.py) \
	$(doc_py)

EXTRA_DIST = \
	$(doc_in) \
	$(doc_py)

CLEANFILES = $(doc_in:.in=.py)

SUFFIXES = .in .py

.in.py:
	sed -e 's,[@]pythondir[@],$(pythondir),g' < $(srcdir)/$< > $@
	chmod +x $@
