
TESTS = \
	build.sh 

SUFFIXES = .sh .sh.in

.sh.in.sh:
	sed -e 's,[@]src_dir[@],$(abs_top_srcdir),g' < $(srcdir)/$< > $@
	chmod +x $@

$(TESTS): install_script

.PHONY: dist
dist:
	make -C $(top_srcdir) dist

install_script: install_script.in dist test-fs
	sed -e 's,[@]src_dir[@],$(abs_top_srcdir),g' \
	    -e 's,[@]dist_name[@],$(PACKAGE)-$(VERSION),g' \
	    -e 's,[@]home[@],$(HOME),g' < $(srcdir)/$< > $@

test-fs:
	@echo "Please retrieve and install the filesystem"
	@exit 1

CLEANFILES = $(TESTS)

