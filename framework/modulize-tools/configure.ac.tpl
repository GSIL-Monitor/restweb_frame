#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT([lib%{MODULE_NAME}], [%{MODULE_VERSION}], [yourname@youku.com])
AM_INIT_AUTOMAKE([foreign -Wall -Werror])
AC_CONFIG_SRCDIR([navi_%{MODULE_NAME}_module.c])
AC_CONFIG_HEADER([config.h])

AC_SUBST([LIB%{MODULE_CASE_NAME}_VERSION],[%{MODULE_LIB_VERSION}])

WITH_TEST=""
AC_ARG_WITH([test],
AC_HELP_STRING([--with-test],[whether build test]),
	[WITH_TEST="yes"]
)   

AC_ARG_ENABLE([debug],
	[AS_HELP_STRING([--enable-debug],[debug program(default is no)])],
	[CFLAGS="${CFLAGS} -DDEBUG -g -O0"],
	[CFLAGS="-g -O2"])

# Checks for programs.
AC_PROG_CC
AC_PROG_LIBTOOL

# Checks for libraries.
PKG_CHECK_MODULES([CNAVI],[libcnavi >= 6.0.0])

# Checks for header files.

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.

AC_CONFIG_FILES([Makefile])
AC_OUTPUT

