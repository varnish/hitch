
SUBDIRS = src

hitch.8: hitch.man.rst
	rst2man --halt=2 $< $@

doc_DATA = hitch.conf.ex CHANGES.rst README.md

dist_man_MANS = hitch.8

EXTRA_DIST = LICENSE README.md hitch.man.rst hitch.conf.ex CHANGES.rst
