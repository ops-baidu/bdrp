## Run `./bootstrap` to generate the "Makefile.in" files in this directory and
## the "$SUBDIRS" subdirectories.

ACLOCAL_AMFLAGS = -I m4

SUBDIRS = src . tests

EXTRA_DIST = README LICENSE doc/doxygen.cfg include/yaml.h

#pkgconfigdir = $(libdir)/pkgconfig
#pkgconfig_DATA = yaml-0.1.pc

maintainer-clean-local:
	-rm -f aclocal.m4 config.h.in configure config/*
	-find ${builddir} -name Makefile.in -exec rm -f '{}' ';'

.PHONY: bootstrap
bootstrap: maintainer-clean
	./bootstrap

