#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT([libcnavi], [6.0], [zhangyufeng@youku.com,pengjinzhen@youku.com,lilei@youku.com])
AM_INIT_AUTOMAKE([foreign -Wall -Werror])
AC_CONFIG_SRCDIR([include/cnavi/navi_module.h])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_MACRO_DIR([m4])

AC_SUBST([LIBCNAVI_VERSION],[6:0:0])

WITH_TEST=""
AC_ARG_WITH([test],
	AC_HELP_STRING([--with-test],[whether build test]),
	[WITH_TEST="yes"]
)

WITH_TCMALLOC=""
AC_ARG_WITH([tcmalloc],
	AC_HELP_STRING([--with-tcmalloc],[whether build with tcmalloc]),
	[LDFLAGS="-ltcmalloc"]
)

AC_ARG_ENABLE([debug],
	[AS_HELP_STRING([--enable-debug],[debug program(default is no)])],
	[CFLAGS="${CFLAGS} -DDEBUG -g -O0"],
	[CFLAGS="-g -O2"])

AM_CONDITIONAL([BUILD_TEST],[test "$WITH_TEST" = "yes"])
AM_CONDITIONAL([BUILD_TCMALLOC],[test "$WITH_TCMALLOC" = "yes"])

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_LIBTOOL

# Checks for libraries.
PKG_CHECK_MODULES([jansson],[jansson >= 2.6])
PKG_CHECK_MODULES([libcurl],[libcurl >= 7.27.0])

# Checks for header files.
AC_HEADER_DIRENT
AC_HEADER_STDC
AC_CHECK_HEADERS([fcntl.h stdint.h stdlib.h string.h sys/time.h syslog.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_CONST
AC_C_INLINE
AC_TYPE_SIZE_T
AC_HEADER_TIME

# Checks for library functions.
AC_FUNC_CLOSEDIR_VOID
AC_FUNC_MALLOC
AC_FUNC_STAT
AC_CHECK_FUNCS([getcwd gettimeofday memset strcasecmp strchr strdup strerror])

AC_CONFIG_FILES([Makefile
				 libcnavi.pc
				 libcnavidriver.pc
                 src/Makefile
                 include/Makefile
                 test/Makefile])
AC_OUTPUT
