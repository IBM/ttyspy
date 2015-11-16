#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([ttyspy], [0.0.0], [dlundquist@us.ibm.com])
AM_INIT_AUTOMAKE([foreign -Wall -Werror])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([src/ttyspy.c])
# AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC_C99
AM_PROG_CC_C_O

AC_USE_SYSTEM_EXTENSIONS

# Checks for libraries.
LIBCURL_CHECK_CONFIG()

# Checks for header files.
AC_CHECK_HEADERS([stdlib.h string.h pty.h unistd.h curl/curl.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_PID_T
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_CHECK_FUNCS([dup2 gethostname select strdup asprintf])
AC_CHECK_LIB([util], [openpty], [
  LIBUTIL="-lutil"
  AC_SUBST([LIBUTIL])
])

AC_CONFIG_FILES([Makefile src/Makefile])

AC_OUTPUT()
