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
AM_PROG_CC_C_O
AC_PROG_CXX
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
              [AS_HELP_STRING([--enable-openssl-build],[enable build of a patched version of OpenSSL @<:@detect@:>@])],
              ,
              [enable_openssl_build="detect"])

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
        AC_ARG_VAR([OPENSSL_CONFIG_EXTRA],
                   [options for configuring OpenSSL])
        if test "${enable_openssl_build}" = "no"
        then
            AC_MSG_ERROR([No suitable OpenSSL installation was found])
        else
            CRYPTO_LIBS=""
            CRYPTO_CFLAGS=""
            CRYPTO_DEPEND=""
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
    else
        AC_DEFINE([CRYPTO_DEPEND],
                  [libcrypto],
                  [OpenSSL dependancy used for pkg-config])
    fi
fi
AM_CONDITIONAL([BUILD_OPENSSL], [test "${BUILD_OPENSSL}" = "yes"])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h limits.h stdint.h string.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_UINT32_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_MKTIME
AC_CHECK_FUNCS([memset])

AM_CONDITIONAL([WIN32], [test "${WIN32}" = "yes"])

AC_CONFIG_FILES([Makefile
                 win32/Makefile
                 src/Makefile])
AC_OUTPUT

cat << EOF

${PACKAGE} ${PACKAGE_VERSION} has been configured with following options:

User binaries:         $(eval eval eval echo "${bindir}")
Libraries:             $(eval eval eval echo "${libdir}")
Configuration files:   $(eval eval eval echo "${sysconfdir}")

Host:                  ${host}
Compiler:              ${CXX}
Preprocessor flags:    ${CPPFLAGS}
Compiler flags:        ${CFLAGS}
Linker flags:          ${LDFLAGS}
Libraries:             ${LIBS}

CRYPTO_CFLAGS:         ${CRYPTO_CFLAGS}
CRYPTO_LIBS:           ${CRYPTO_LIBS}

Build patched OpenSSL: ${BUILD_OPENSSL}
PATCH:                 ${PATCH}
CVS:                   ${CVS}
OPENSSL_CONFIG_EXTRA:  ${OPENSSL_CONFIG_EXTRA}
EOF
