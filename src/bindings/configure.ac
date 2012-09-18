#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.64])
AC_INIT(pyPACE, 0.3, oepen@informatik.hu-berlin.de)
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_SED
AM_PATH_PYTHON
AC_PROG_CC
AC_PROG_LIBTOOL
AX_PKG_SWIG([],[], [AC_MSG_ERROR([SWIG is required to build]) ])
PKG_PROG_PKG_CONFIG

# Checks for libraries, header files and library functions
PKG_CHECK_EXISTS([libeac],
                 [PKG_CHECK_MODULES([OPENPACE], [libeac])],
                 [AC_MSG_WARN([libeac not found by pkg-config])])
saved_CPPFLAGS="$CPPFLAGS"
saved_LDFLAGS="$LDFLAGS"
CPPFLAGS="$CPPFLAGS $OPENPACE_CFLAGS"
LDFLAGS="$LDFLAGS $OPENPACE_LIBS"

AC_MSG_CHECKING([for EAC_CTX_init_ef_cardaccess])
AC_TRY_LINK_FUNC(EAC_CTX_init_ef_cardaccess, [ AC_MSG_RESULT([yes]) ], [
                   AC_MSG_ERROR([OpenPACE not found, use ./configure OPENPACE_LIBS=...]) ])
AC_CHECK_HEADERS(eac/pace.h, [], [ AC_MSG_ERROR([eac/pace.h not found, install
                    OpenPACE or use ./configure OPENPACE_CFLAGS=...]) ])

CPPFLAGS="$saved_CPPFLAGS"
LDFLAGS="$saved_LDFLAGS"
AC_SUBST(OPENPACE_CFLAGS)
AC_SUBST(OPENPACE_LIBS)

PKG_CHECK_EXISTS([libcrypto],
                 [PKG_CHECK_MODULES([OPENSSL], [libcrypto])],
                 [AC_MSG_WARN([libcrypto not found by pkg-config])])
CPPFLAGS="$CPPFLAGS $OPENSSL_CFLAGS"
LDFLAGS="$LDFLAGS $OPENSSL_LIBS"

AC_CHECK_HEADERS(openssl/obj_mac.h, [], [ AC_MSG_ERROR([openssl/objects.h not
                    found, install OpenSSL or use ./configure OPENSSL_CFLAGS=...]) ])
AC_CHECK_DECL(NID_id_PACE_DH_GM, [], [ AC_MSG_ERROR([PACE OIDs could not be
                found in openssl/obj_mac.h. Please use a patched version of OpenSSL
                including the EAC OIDs ])], [[#include <openssl/obj_mac.h>]])

CPPFLAGS="$saved_CPPFLAGS"
LDFLAGS="$saved_LDFLAGS"
AC_SUBST(OPENSSL_CFLAGS)
AC_SUBST(OPENSSL_LIBS)
AC_CHECK_HEADERS([stdlib.h string.h])
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memcpy])

AC_ARG_VAR([PYTHON_INCLUDE], [Include flags for python, bypassing python-config])
AC_ARG_VAR([PYTHON_CONFIG], [Path to python-config])
AS_IF([test -z "$PYTHON_INCLUDE"], [
    AS_IF([test -z "$PYTHON_CONFIG"], [
        AC_PATH_PROGS([PYTHON_CONFIG],
            [python$PYTHON_VERSION-config python-config],
            [no],
            [`dirname $PYTHON`])
        AS_IF([test "$PYTHON_CONFIG" = no], [AC_MSG_ERROR([cannot find python-config for $PYTHON.])])
    ])
    AC_MSG_CHECKING([python include flags])
    PYTHON_INCLUDE=`$PYTHON_CONFIG --includes`
    AC_MSG_RESULT([$PYTHON_INCLUDE])
])
saved_CPPFLAGS="$CPPFLAGS"
CPPFLAGS="$CPPFLAGS $PYTHON_INCLUDE"

AC_CHECK_HEADERS(Python.h, [], [AC_MSG_ERROR([Python.h not found, please install the python header files]) ])

CPPFLAGS="$saved_CPPFLAGS"
AC_SUBST(PYTHON_INCLUDE)

# Java support (defaul: no)
AC_ARG_ENABLE([java],AS_HELP_STRING([--enable-java],[Enable java interface generation.]),[enable_java=$enableval],[enable_java="no"])
if test x"$enable_java" = "xyes"
then
    AC_PROG_JAVA
    AC_PROG_JAVAC
    AC_JNI_INCLUDE_DIR
    for JNI_INCLUDE_DIR in $JNI_INCLUDE_DIRS
    do
        JAVA_INCLUDES="$JAVA_INCLUDES -I$JNI_INCLUDE_DIR"
    done
    saved_CPPFLAGS="$CPPFLAGS"
    CPPFLAGS="$CPPFLAGS $JAVA_INCLUDES"
    AC_CHECK_HEADERS(jni.h, [], [AC_MSG_ERROR([jni.h not found, please install the java header files]) ])
    CPPFLAGS="$saved_CPPFLAGS"
    AC_SUBST(JAVA_INCLUDES)
    #The JNI code must be compiled as position independent code
    CFLAGS="$CFLAGS -fpic -shared"
fi
AM_CONDITIONAL(JAVA_ENABLED, [test x"$enable_java" = "xyes"])

cat << EOF

pyPace has been configured with following options:

Version:              ${PACKAGE_VERSION}
User binaries:        $(eval eval eval echo "${bindir}")
Configuration files:  $(eval eval eval echo "${sysconfdir}")
Python site-packages: $(eval eval eval echo "${pythondir}")

Host:                 ${host}
Compiler:             ${CC}
Preprocessor flags:   ${CPPFLAGS}
Compiler flags:       ${CFLAGS}
Preprocessor flags:   ${CPPFLAGS}
Linker flags:         ${LDFLAGS}
Libraries:            ${LIBS}
OPENSSL_CFLAGS:       ${OPENSSL_CFLAGS}
OPENSSL_LIBS:         ${OPENSSL_LIBS}
OPENPACE_CFLAGS:      ${OPENPACE_CFLAGS}
OPENPACE_LIBS:        ${OPENPACE_LIBS}
BUNDLE_HOST:          ${BUNDLE_HOST}
DYN_LIB_EXT:          ${DYN_LIB_EXT}

PYTHON_VERSION:       ${PYTHON_VERSION}
PYTHON_INCLUDE:       ${PYTHON_INCLUDE}

Java bindings:        ${enable_java}
JNI_INCLUDE_DIRS:     ${JAVA_INCLUDES}

EOF

AC_CONFIG_FILES([Makefile
                 src/Makefile
                 src/python/Makefile
                 src/java/Makefile])

AC_OUTPUT
