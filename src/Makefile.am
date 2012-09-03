nobase_include_HEADERS = eac/ca.h \
						 eac/cv_cert.h \
						 eac/eac.h \
						 eac/pace.h \
						 eac/ri.h \
						 eac/ta.h
noinst_HEADERS = ca_lib.h \
				 eac_asn1.h \
				 eac_dh.h \
				 eac_ecdh.h \
				 eac_err.h \
				 eac_kdf.h \
				 eac_lib.h \
				 eac_util.h \
				 misc.h \
				 pace_lib.h \
				 pace_mappings.h \
				 ta_lib.h


lib_LTLIBRARIES = libeac.la

libeac_la_SOURCES  = ca_lib.c cv_cert.c eac_asn1.c eac.c eac_ca.c eac_dh.c eac_ecdh.c eac_kdf.c eac_lib.c eac_print.c eac_util.c misc.c pace.c pace_lib.c pace_mappings.c ri.c ri_lib.c ta.c ta_lib.c
libeac_la_CPPFLAGS = $(CRYPTO_CFLAGS)
libeac_la_LDFLAGS  = -no-undefined
libeac_la_LIBADD   = $(CRYPTO_LIBS)
if WIN32
AM_CPPFLAGS        = -DWIN32_LEAN_AND_MEAN
libeac_la_LIBADD  += -lws2_32
endif


noinst_PROGRAMS      = eactest cv_cert_test

EAC_LIBS             = libeac.la $(CRYPTO_LIBS)
EAC_CFLAGS           = $(CRYPTO_CFLAGS)

eactest_SOURCES      = eactest.c
eactest_LDADD        = $(EAC_LIBS)
eactest_CFLAGS       = $(EAC_CFLAGS)

cv_cert_test_SOURCES = cv_cert_test.c
cv_cert_test_LDADD   = $(EAC_LIBS)
cv_cert_test_CFLAGS  = $(EAC_CFLAGS)


if BUILD_OPENSSL
OPENSSL_DIR       = $(abs_builddir)/openssl
OPENSSL_CONFIG    = $(OPENSSL_DIR)/config
OPENSSL_INCLUDES  = $(OPENSSL_DIR)/include
OPENSSL_LIBCRYPTO = $(OPENSSL_DIR)/libcrypto.a
OPENSSL_MAKEFILE  = $(OPENSSL_DIR)/Makefile
OPENSSL_OBJ_MAC   = $(OPENSSL_INCLUDES)/openssl/obj_mac.h


# Fetch OpenSSL
$(OPENSSL_CONFIG):
	CVS_RSH=ssh $(CVS) -d anonymous@cvs.openssl.org:/openssl-cvs co -rOpenSSL_1_0_2-stable `basename $(OPENSSL_DIR)`

# Configure OpenSSL (and create $(OPENSSL_OBJ_MAC))
$(OPENSSL_MAKEFILE): $(OPENSSL_CONFIG)
	cd $(OPENSSL_DIR) \
		&& $(OPENSSL_CONFIG) $(OPENSSL_CONFIG_EXTRA)

# Patch OpenSSL with OpenPACE object identifiers
.PHONY: patch_openssl
patch_openssl: $(OPENSSL_MAKEFILE)
	grep NID_id_PACE_ECDH_GM_AES_CBC_CMAC_256 $(OPENSSL_OBJ_MAC) > /dev/null \
		|| $(PATCH) --directory=$(OPENSSL_DIR) -p1 < $(abs_top_srcdir)/oids.patch

# Build OpenSSL
$(OPENSSL_LIBCRYPTO): patch_openssl
	$(MAKE) -C $(OPENSSL_DIR)

# We require the patched headers of OpenSSL
$(libeac_la_SOURCES) $(nobase_include_HEADERS): patch_openssl


libeac_la_DEPENDENCIES = $(OPENSSL_LIBCRYPTO)
libeac_la_LIBADD      += $(OPENSSL_LIBCRYPTO)
libeac_la_CPPFLAGS    += -I$(OPENSSL_INCLUDES)
EAC_CFLAGS            += -I$(OPENSSL_INCLUDES)
EAC_LIBS              += $(OPENSSL_LIBCRYPTO) -ldl -lz


clean-local:
	test ! -r $(OPENSSL_MAKEFILE) \
		|| $(MAKE) -C $(OPENSSL_DIR) clean

distclean-local:
	rm -rf $(OPENSSL_DIR)
endif
