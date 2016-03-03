SUBDIRS = src include
ACLOCAL_AMFLAGS = -I m4

if BUILD_TEST
  SUBDIRS += test
endif

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libcnavi.pc libcnavidriver.pc

