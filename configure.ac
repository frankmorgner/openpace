#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.67])
AC_INIT([OpenPACE], [0.9], [http://sourceforge.net/projects/openpace/support], [openpace], [http://openpace.sourceforge.net])
AC_CONFIG_SRCDIR([src/eactest.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE

# If you need to see the details, just run make V=1.
m4_ifdef([AM_SILENT_RULES],[AM_SILENT_RULES([yes])])

# Checks for programs.
AC_PROG_CC
AC_PROG_SED
AM_PROG_CC_C_O
PKG_PROG_PKG_CONFIG
ifdef(
	[LT_INIT],
	[
		LT_INIT([win32-dll])
	],
	[
		AC_LIBTOOL_WIN32_DLL
		AC_PROG_LIBTOOL
	]
)

dnl Check for windows build
case "${host}" in
    *-mingw*|*-winnt*)
        WIN32="yes"
        ;;
    *-cygwin*)
        WIN32="yes"
        ;;
esac

# Checks for libcrypto.
AC_ARG_ENABLE([openssl-install],
              [AS_HELP_STRING([--enable-openssl-install],[enable installation of a patched version of OpenSSL @<:@default=no@:>@])],
              ,
              [enable_openssl_install="no"])

if test "${enable_openssl_install}" = "yes"
then
    INSTALL_OPENSSL=yes

    AC_ARG_VAR([GIT],
               [absolute path to git used for checking out OpenSSL])
    AC_PATH_PROG([GIT],
                 [git],
                 [not found])
    if test "${GIT}" = "not found"
    then
        AC_MSG_ERROR([Need git to build OpenSSL])
    fi

    AC_ARG_VAR([OPENSSL_CONFIGURE_FLAGS],
               [options for configuring OpenSSL])
    if test -z "$OPENSSL_CONFIGURE_FLAGS"
    then
        my_prefix=`test "$prefix" = NONE && echo \"$ac_default_prefix\" || echo \"${prefix}\"`
        OPENSSL_CONFIGURE_FLAGS="enable-ssl-trace no-asm shared --prefix=${my_prefix} `${srcdir}/cross/gentoo.config-1.0.0 ${host}` ${CFLAGS} ${CPPFLAGS} ${LDFLAGS}"
    fi

    builddir=`pwd`
    CRYPTO_CFLAGS="-I${builddir}/src/openssl/include"
    CRYPTO_LIBS="-L${builddir}/src/openssl -lcrypto"

else
    INSTALL_OPENSSL=no

    PKG_CHECK_EXISTS([libcrypto],
                     [PKG_CHECK_MODULES([CRYPTO], [libcrypto >= 1.0.2])],
                     [AC_MSG_WARN([libcrypto >= 1.0.2 not found by pkg-config])])

    if test -z "$CRYPTO_LIBS"
    then
        CRYPTO_LIBS="-lcrypto"
    fi

    saved_CPPFLAGS="$CPPFLAGS"
    CPPFLAGS="$CRYPTO_CFLAGS $CPPFLAGS"
    AC_CHECK_HEADERS([openssl/obj_mac.h openssl/buffer.h openssl/bio.h \
                      openssl/ecdh.h openssl/dh.h openssl/evp.h openssl/cmac.h \
                      openssl/sha.h openssl/aes.h openssl/des.h], [],
                     [AC_MSG_ERROR([Required OpenSSL headers not found])])
    AC_CHECK_DECL(NID_brainpoolP512r1,
                  ,
                  [AC_MSG_ERROR([OpenSSL 1.0.2 not found])],
                  [#include <openssl/obj_mac.h>])
    CPPFLAGS="$saved_CPPFLAGS"

    saved_LIBS="$LIBS"
    LIBS="$CRYPTO_LIBS $LIBS"
    AC_MSG_CHECKING([for OPENSSL_cleanse])
    AC_TRY_LINK_FUNC(OPENSSL_cleanse,
                     [AC_MSG_RESULT([yes])],
                     [AC_MSG_ERROR([Cannot link against libcrypto])])
    AC_MSG_CHECKING([for EVP_sha256])
    AC_TRY_LINK_FUNC(EVP_sha256,
                     [AC_MSG_RESULT([yes])],
                     [AC_MSG_ERROR([Need OpenSSL with SHA-256 support])])
    LIBS="$saved_LIBS"
fi
AM_CONDITIONAL([INSTALL_OPENSSL], [test "${INSTALL_OPENSSL}" = "yes"])


AC_ARG_ENABLE([python],AS_HELP_STRING([--enable-python],[Enable python interface generation.]),[enable_python=$enableval],[enable_python="no"])
AC_ARG_ENABLE([java],AS_HELP_STRING([--enable-java],[Enable java interface generation.]),[enable_java=$enableval],[enable_java="no"])
AC_ARG_ENABLE([ruby],AS_HELP_STRING([--enable-ruby],[Enable Ruby interface generation.]),[enable_ruby=$enableval],[enable_ruby="no"])
AC_ARG_ENABLE([go],AS_HELP_STRING([--enable-go],[Enable Go interface generation.]),[enable_go=$enableval],[enable_go="no"])
if test x"$enable_python" = "xyes" -o x"$enable_java" = "xyes" -o x"$enable_ruby" = "xyes" -o x"$enable_go" = "xyes"
then
    AX_PKG_SWIG([],[], [AC_MSG_ERROR([SWIG is required to build the bindings]) ])
fi

# Python support (default: no)
if test x"$enable_python" = "xyes"
then
    AM_PATH_PYTHON(,,AC_MSG_ERROR([Python is required to build the Python bindings]))
    AC_ARG_VAR([PYTHON_INCLUDE], [Include flags for python, bypassing python-config])
    AC_ARG_VAR([PYTHON_CONFIG], [Path to python-config])
    AS_IF([test -z "$PYTHON_INCLUDE"], [
        AS_IF([test -z "$PYTHON_CONFIG"], [
            AC_PATH_PROGS([PYTHON_CONFIG],
                [python$PYTHON_VERSION-config python-config],
                [no],
                [`dirname $PYTHON`])
            AS_IF([test "$PYTHON_CONFIG" = no], [AC_MSG_WARN([cannot find python-config for $PYTHON.])])
        ])
        AC_MSG_CHECKING([python include flags])
        PYTHON_INCLUDE=`$PYTHON_CONFIG --includes`
        AC_MSG_RESULT([$PYTHON_INCLUDE])
    ])
    saved_CPPFLAGS="$CPPFLAGS"
    CPPFLAGS="$CPPFLAGS $PYTHON_INCLUDE"
    AC_CHECK_HEADERS(Python.h, [], [AC_MSG_WARN([Python.h not found]) ])
    CPPFLAGS="$saved_CPPFLAGS"
fi
AM_CONDITIONAL(PYTHON_ENABLED, [test x"$enable_python" = "xyes"])

# Java support (default: no)
if test x"$enable_java" = "xyes"
then
    AC_ARG_VAR([JAVA_CFLAGS], [Java C compiler flags])
    AC_ARG_VAR([JAVACFLAGS], [Java byte compiler flags])
    AC_PROG_JAVAC
    if test -z "${JAVA_CFLAGS}"
    then
        AC_JNI_INCLUDE_DIR
        #The JNI code must be compiled as position independent code
        JAVA_CFLAGS="-fpic -shared"
        for JNI_INCLUDE_DIR in $JNI_INCLUDE_DIRS
        do
            JAVA_CFLAGS="$JAVA_CFLAGS -I$JNI_INCLUDE_DIR"
        done
    fi
    saved_CPPFLAGS="$CPPFLAGS"
    CPPFLAGS="$CPPFLAGS $JAVA_CFLAGS"
    AC_CHECK_HEADERS(jni.h, [], [AC_MSG_ERROR([jni.h not found]) ])
    CPPFLAGS="$saved_CPPFLAGS"
fi
AM_CONDITIONAL(JAVA_ENABLED, [test x"$enable_java" = "xyes"])

if test x"$enable_ruby" = "xyes"
then
    AC_ARG_VAR([RUBY],
               [absolute path to ruby used for building ruby bindings])
    AC_PATH_PROG([RUBY],
                  [ruby],
                  [not found])
    if test "${RUBY}" = "not found"
    then
        AC_MSG_ERROR([ruby required to build bindings.])
    fi
fi
AM_CONDITIONAL(RUBY_ENABLED, [test x"$enable_ruby" = "xyes"])

if test x"$enable_go" = "xyes"
then
    AC_PATH_PROG([GCCGO],
                  [gccgo],
                  [not found])
    if test "${GCCGO}" = "not found"
    then
        AC_MSG_ERROR([go tools required to build bindings.])
    fi
fi
AM_CONDITIONAL(GO_ENABLED, [test x"$enable_go" = "xyes"])


AC_ARG_ENABLE(cvcdir,
AC_HELP_STRING([--enable-cvcdir=DIR],
    [directory containing CV certificates (default /etc/eac/cvc)]),
    [cvcdir="${enableval}"],
    [cvcdir="${sysconfdir}/eac/cvc"])
AS_AC_EXPAND(cvcdir,$cvcdir)
CVCDIR="${cvcdir}"
AC_SUBST(CVCDIR)
AC_ARG_ENABLE(x509dir,
AC_HELP_STRING([--enable-x509dir=DIR],
    [directory containing X.509 certificates (default /etc/eac/x509)]),
    [x509dir="${enableval}"],
    [x509dir="${sysconfdir}/eac/x509"])
AS_AC_EXPAND(x509dir,$x509dir)
X509DIR="${x509dir}"
AC_SUBST(X509DIR)


PACKAGE_SUMMARY="Cryptographic library for EAC version 2"
AC_SUBST(PACKAGE_SUMMARY)


# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h limits.h stdint.h string.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_UINT32_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_MKTIME
AC_CHECK_FUNCS([memset memcpy])

AM_CONDITIONAL([WIN32], [test "${WIN32}" = "yes"])

AC_CONFIG_FILES([
                 Makefile
                 src/Makefile
                 bindings/Makefile
                 bindings/java/Makefile
                 bindings/python/Makefile
                 bindings/ruby/Makefile
                 bindings/go/Makefile
                 cross/Makefile
                 doc/Makefile
                 doc/_static/Makefile
                 ])
AC_OUTPUT

cat << EOF

${PACKAGE} ${PACKAGE_VERSION} has been configured with following options:

Libraries:               $(eval eval eval echo "${libdir}")
CVC directory:           ${CVCDIR}
X.509 directory:         ${X509DIR}

Host:                    ${host}
Compiler:                ${CC}
Preprocessor flags:      ${CPPFLAGS}
Compiler flags:          ${CFLAGS}
Linker flags:            ${LDFLAGS}
Libraries:               ${LIBS}
CRYPTO_CFLAGS:           ${CRYPTO_CFLAGS}
CRYPTO_LIBS:             ${CRYPTO_LIBS}

Install patched OpenSSL: ${INSTALL_OPENSSL}
GIT:                     ${GIT}
OPENSSL_CONFIGURE_FLAGS: ${OPENSSL_CONFIGURE_FLAGS}

SWIG:                    ${SWIG}
Python Bindings:         ${enable_python}
PYTHON:                  ${PYTHON}
Java Bindings:           ${enable_java}
JAVA_CFLAGS:             ${JAVA_CFLAGS}
JAVACFLAGS:              ${JAVACFLAGS}
Ruby Bindings:           ${enable_ruby}
RUBY:                    ${RUBY}
Go Bindings:             ${enable_go}
gccgo:                   ${GCCGO}
EOF
