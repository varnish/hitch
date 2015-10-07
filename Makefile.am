
SUBDIRS = src

hitch.8: hitch.man.rst
	rst2man --halt=2 $< $@

dist_man_MANS = hitch.8

EXTRA_DIST = LICENSE README.md hitch.man.rst
