#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([c-inside], [1.3], [jtodd1@earthlink.net])
AM_INIT_AUTOMAKE([-Wall -Werror])
AC_CONFIG_MACRO_DIRS([m4])
AM_PROG_AR
LT_INIT
AM_PROG_AS

AC_CONFIG_SRCDIR([utilities/c-inside.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_MAKE_SET
AC_PROG_LIBTOOL

# Checks for libraries.
AC_CHECK_LIB([dl], [dlopen])
AC_CHECK_LIB([readline], [readline])

# Checks for header files.
AC_CHECK_HEADERS([inttypes.h stddef.h stdlib.h string.h sys/time.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_CHECK_FUNCS([gettimeofday memset strchr strdup strerror strtoul])
AC_CHECK_FUNCS([dlopen dlsym dlclose])
AC_CHECK_FUNCS([add_history rl_readline_name rl_attempted_completion_function \
                rl_completion_query_items rl_basic_word_break_characters \
                rl_special_prefixes rl_instream rl_attempted_completion_over \
                rl_completion_matches completion_matches \
                rl_completion_append_character])

case $host_cpu in
    i?86)
        AH_TEMPLATE([CINSIDE_BUILD_IA32], \
                    [Define to 1 if building for an x86 system])
        AC_DEFINE([CINSIDE_BUILD_IA32], [1])
        ;;
    *)
        AC_MSG_ERROR([architecture $host_cpu not supported: currently only x86])
        ;;
esac

case $host_os in
    *linux*)
        AH_TEMPLATE([CINSIDE_BUILD_LINUX],
                    [Define to 1 if building for Linux])
        AC_DEFINE([CINSIDE_BUILD_LINUX], [1])
        ;;
    *)
        AC_MSG_ERROR([OS $host_os not supported: currently only Linux])
        ;;
esac

AC_CONFIG_FILES([Makefile libc-inside/Makefile utilities/Makefile])

AC_OUTPUT
