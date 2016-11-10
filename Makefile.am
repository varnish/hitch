
SUBDIRS = src src/util

if FOUND_RST2MAN

hitch.8: hitch.man.rst
	${RST2MAN} --halt=2 $(srcdir)/hitch.man.rst $@
hitch.conf.5: hitch.conf.man.rst
	${RST2MAN} --halt=2 $(srcdir)/hitch.conf.man.rst $@

dist_man_MANS = hitch.8 hitch.conf.5

endif

hitch.conf.example: hitch.conf.man.rst
	echo "# Run 'man hitch.conf' for a description of all options." > $@.tmp
	sed -e '1,/^.. example-start/d' \
		-e '/.. example-end/,$$d' \
		-e '/^[^ ]/d' \
		-e 's/^    //' hitch.conf.man.rst >> $@.tmp
	mv $@.tmp $@

doc_DATA = hitch.conf.example CHANGES.rst README.md

EXTRA_DIST = LICENSE README.md hitch.man.rst hitch.conf.man.rst hitch.conf.example CHANGES.rst docs

CLEANFILES = hitch.conf.example
