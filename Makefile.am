ACLOCAL_AMFLAGS = -I .

SUBDIRS = src/util src

dist_man_MANS = hitch.8 hitch.conf.5

if ENABLE_DOCUMENTATION
hitch.8: hitch.man.rst
	${RST2MAN} --halt=2 $(srcdir)/hitch.man.rst $@

hitch.conf.5: hitch.conf.man.rst
	${RST2MAN} --halt=2 $(srcdir)/hitch.conf.man.rst $@

endif

check-recursive: hitch.conf.example

hitch.conf.example: hitch.conf.man.rst
	echo "# Run 'man hitch.conf' for a description of all options." > $@.tmp
	sed -e '1,/^.. example-start/d' \
		-e '/.. example-end/,$$d' \
		-e '/^[^ ]/d' \
		-e 's/^    //' $(srcdir)/hitch.conf.man.rst >> $@.tmp
	mv $@.tmp $@

dist_doc_DATA = hitch.conf.example CHANGES.rst README.md

EXTRA_DIST = LICENSE hitch.man.rst hitch.conf.man.rst docs
CLEANFILES = hitch.conf.example
