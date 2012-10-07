#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])
AC_INIT([OpenPACE], [0.8], [http://sourceforge.net/projects/openpace/support], [openpace], [http://openpace.sourceforge.net])
AC_CONFIG_SRCDIR([src/eactest.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE

# If you need to see the details, just run make V=1.
m4_ifdef([AM_SILENT_RULES],[AM_SILENT_RULES([yes])])

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX
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
AC_ARG_ENABLE([openssl-build],
              [AS_HELP_STRING([--enable-openssl-build],[enable build of a patched version of OpenSSL @<:@default=detect@:>@])],
              ,
              [enable_openssl_build="detect"])
AC_ARG_ENABLE([openssl-install],
              [AS_HELP_STRING([--enable-openssl-install],[enable installation of a patched version of OpenSSL @<:@default=no@:>@])],
              ,
              [enable_openssl_install="no"])

if test "${enable_openssl_install}" = "yes"
then
    INSTALL_OPENSSL=yes
    AC_SUBST([PKG_REQUIRES], [libcrypto])
    if test ! "${enable_openssl_build}" = "yes"
    then
        enable_openssl_build=yes
        AC_MSG_NOTICE([A patched version of OpenSSL will be built in order to be installed])
    fi
else
    INSTALL_OPENSSL=no
fi

if test "${enable_openssl_build}" = "yes"
then
    BUILD_OPENSSL=yes
else
    BUILD_OPENSSL=no

    PKG_CHECK_EXISTS([libcrypto],
                     [PKG_CHECK_MODULES([CRYPTO], [libcrypto])],
                     [AC_MSG_WARN([libcrypto not found by pkg-config])])

    if test -z "$CRYPTO_LIBS"
    then
        CRYPTO_LIBS="-lcrypto"
    fi

    saved_CPPFLAGS="$CPPFLAGS"
    CPPFLAGS="$CRYPTO_CFLAGS $CPPFLAGS"
    AC_CHECK_HEADERS([openssl/obj_mac.h openssl/buffer.h openssl/bio.h \
                      openssl/ecdh.h openssl/dh.h openssl/evp.h openssl/cmac.h \
                      openssl/sha.h openssl/aes.h openssl/des.h], [],
                     [AC_MSG_WARN([Required OpenSSL headers not found])
                      BUILD_OPENSSL=yes])
    AC_CHECK_DECL(NID_id_PACE_ECDH_GM_AES_CBC_CMAC_256,
                  ,
                  [AC_MSG_WARN([OpenSSL patched with OpenPACE object identifiers not found])
                   BUILD_OPENSSL=yes],
                  [#include <openssl/obj_mac.h>])
    CPPFLAGS="$saved_CPPFLAGS"

    saved_LIBS="$LIBS"
    LIBS="$CRYPTO_LIBS $LIBS"
    AC_MSG_CHECKING([for OPENSSL_cleanse])
    AC_TRY_LINK_FUNC(OPENSSL_cleanse,
                     [AC_MSG_RESULT([yes])],
                     [AC_MSG_WARN([Cannot link against libcrypto])
                      BUILD_OPENSSL=yes])
    AC_MSG_CHECKING([for EVP_sha256])
    AC_TRY_LINK_FUNC(EVP_sha256,
                     [AC_MSG_RESULT([yes])],
                     [AC_MSG_WARN([Need OpenSSL with SHA-256 support])
                      BUILD_OPENSSL=yes])
    LIBS="$saved_LIBS"
fi
if test "${BUILD_OPENSSL}" = "yes"
then
    AC_ARG_VAR([CVS],
               [absolute path to cvs used for checking out OpenSSL])
    AC_PATH_PROG([CVS],
                 [cvs],
                 [not found])
    AC_ARG_VAR([PATCH],
               [absolute path to patch used for patching OpenSSL])
    AC_PATH_PROG([PATCH],
                 [patch],
                 [not found])
    if test "${enable_openssl_build}" = "no"
    then
        AC_MSG_ERROR([No suitable OpenSSL installation was found])
    else
        AC_MSG_NOTICE([No suitable OpenSSL installation was found, will create one])
        if test "${PATCH}" = "not found"
        then
            AC_MSG_ERROR([Need patch to build OpenSSL])
        fi
        if test "${CVS}" = "not found"
        then
            AC_MSG_ERROR([Need cvs to build OpenSSL])
        fi
    fi

    AC_ARG_VAR([OPENSSL_CONFIG_EXTRA],
               [options for configuring OpenSSL])
    if test -z "$OPENSSL_CONFIG_EXTRA"
    then
        if test "${INSTALL_OPENSSL}" = "yes"
        then
            OPENSSL_CONFIG_EXTRA=shared
        else
            OPENSSL_CONFIG_EXTRA=-fPIC
        fi
    fi

    builddir=`pwd`
    CRYPTO_CFLAGS="-I${builddir}/src/openssl/include"
    if test "${INSTALL_OPENSSL}" = "yes"
    then
        CRYPTO_LIBS="${builddir}/src/openssl/libcrypto.so"
    else
        CRYPTO_LIBS="${builddir}/src/openssl/libcrypto.a \`grep Libs.private ${builddir}/src/openssl/libcrypto.pc | ${SED} "-e" 's,Libs.private:\s*,,'\`"
    fi
else
    AC_SUBST([PKG_REQUIRES], [libcrypto])
fi
AM_CONDITIONAL([BUILD_OPENSSL], [test "${BUILD_OPENSSL}" = "yes"])
AM_CONDITIONAL([INSTALL_OPENSSL], [test "${INSTALL_OPENSSL}" = "yes"])


AC_ARG_ENABLE([python],AS_HELP_STRING([--enable-python],[Enable python interface generation.]),[enable_python=$enableval],[enable_python="no"])
AC_ARG_ENABLE([java],AS_HELP_STRING([--enable-java],[Enable java interface generation.]),[enable_java=$enableval],[enable_java="no"])
if test x"$enable_python" = "xyes" -o x"$enable_java" = "xyes"
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
                 src/bindings/Makefile
                 src/bindings/java/Makefile
                 src/bindings/python/Makefile
                 win32/Makefile
                 ])
AC_OUTPUT

cat << EOF

${PACKAGE} ${PACKAGE_VERSION} has been configured with following options:

User binaries:         $(eval eval eval echo "${bindir}")
Libraries:             $(eval eval eval echo "${libdir}")
Configuration files:   $(eval eval eval echo "${sysconfdir}")

Build patched OpenSSL:   ${BUILD_OPENSSL}
Install patched OpenSSL: ${INSTALL_OPENSSL}
Python Bindings:         ${enable_python}
Java Bindings:           ${enable_java}

Host:                    ${host}
Compiler:                ${CXX}
Preprocessor flags:      ${CPPFLAGS}
Compiler flags:          ${CFLAGS}
Linker flags:            ${LDFLAGS}
Libraries:               ${LIBS}

CRYPTO_CFLAGS:           ${CRYPTO_CFLAGS}
CRYPTO_LIBS:             ${CRYPTO_LIBS}

PATCH:                   ${PATCH}
CVS:                     ${CVS}
OPENSSL_CONFIG_EXTRA:    ${OPENSSL_CONFIG_EXTRA}

SWIG:                    ${SWIG}
JAVA_CFLAGS:             ${JAVA_CFLAGS}
JAVACFLAGS:              ${JAVACFLAGS}
EOF
