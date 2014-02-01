nobase_include_HEADERS = eac/ca.h \
						 eac/cv_cert.h \
						 eac/eac.h \
						 eac/pace.h \
						 eac/ri.h \
						 eac/objects.h \
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

libeac_la_SOURCES  = ca_lib.c cv_cert.c cvc_lookup.c x509_lookup.c eac_asn1.c eac.c eac_ca.c eac_dh.c eac_ecdh.c eac_kdf.c eac_lib.c eac_print.c eac_util.c misc.c pace.c pace_lib.c pace_mappings.c ri.c ri_lib.c ta.c ta_lib.c objects.c
libeac_la_CPPFLAGS = $(CRYPTO_CFLAGS) -DCVCDIR=\"@CVCDIR@\" -DX509DIR=\"@X509DIR@\"
libeac_la_LDFLAGS  = -no-undefined
libeac_la_LIBADD   = $(CRYPTO_LIBS)
if WIN32
AM_CPPFLAGS        = -DWIN32_LEAN_AND_MEAN
libeac_la_LIBADD  += -lws2_32
endif


bin_PROGRAMS         = eactest cvcprint example

EAC_LIBS             = libeac.la $(CRYPTO_LIBS)
EAC_CFLAGS           = $(CRYPTO_CFLAGS)

eactest_SOURCES      = eactest.c
eactest_LDADD        = $(EAC_LIBS)
eactest_CFLAGS       = $(EAC_CFLAGS)

cvcprint_SOURCES     = cvcprint.c
cvcprint_LDADD       = $(EAC_LIBS)
cvcprint_CFLAGS      = $(EAC_CFLAGS)

example_SOURCES      = example.c
example_LDADD        = $(EAC_LIBS)
example_CFLAGS       = $(EAC_CFLAGS)


if INSTALL_OPENSSL
OPENSSL_DIR           = $(abs_builddir)/openssl
OPENSSL_CONFIGURE     = $(OPENSSL_DIR)/Configure
OPENSSL_INCLUDES      = $(OPENSSL_DIR)/include
OPENSSL_LIBCRYPTO_A   = $(OPENSSL_DIR)/libcrypto.a
OPENSSL_MAKEFILE      = $(OPENSSL_DIR)/Makefile
OPENSSL_OBJ_MAC       = $(OPENSSL_INCLUDES)/openssl/obj_mac.h
OPENSSL_LIBS_PRIVATE  = `grep Libs.private $(OPENSSL_DIR)/libcrypto.pc | $(SED) "-e" 's,Libs.private:\s*,,'`


# Fetch OpenSSL
$(OPENSSL_CONFIGURE):
	$(GIT) clone --depth=10 git://openssl.net/openssl -b OpenSSL_1_0_2-stable $(OPENSSL_DIR)

# Configure OpenSSL (and create $(OPENSSL_OBJ_MAC))
$(OPENSSL_MAKEFILE): $(OPENSSL_CONFIGURE)
	cd $(OPENSSL_DIR) \
		&& CROSS_COMPILE="" MAKE=$(MAKE) CC=$(CC) AR=$(AR) RANLIB=$(RANLIB) $(OPENSSL_CONFIGURE) $(OPENSSL_CONFIGURE_FLAGS)

# Patch OpenSSL with OpenPACE object identifiers
.PHONY: patch_openssl
patch_openssl: $(OPENSSL_MAKEFILE)
	grep NID_id_PACE_ECDH_GM_AES_CBC_CMAC_256 $(OPENSSL_OBJ_MAC) > /dev/null \
		|| (cd $(OPENSSL_DIR) \
			&& $(GIT) apply $(abs_top_srcdir)/oids.patch \
			&& $(MAKE) update depend -C $(OPENSSL_DIR))

# Build OpenSSL
$(OPENSSL_LIBCRYPTO_A):
	$(MAKE) patch_openssl
	$(MAKE) -C $(OPENSSL_DIR)

# Install OpenSSL
install-openssl: $(OPENSSL_LIBCRYPTO_A)
	$(MAKE) -C $(OPENSSL_DIR) INSTALL_PREFIX=$(DESTDIR) install_sw


# We require the patched headers of OpenSSL
$(libeac_la_SOURCES) $(nobase_include_HEADERS): patch_openssl


libeac_la_DEPENDENCIES = $(OPENSSL_LIBCRYPTO_A)


distclean-local:
	test ! -r $(OPENSSL_MAKEFILE) \
		|| $(MAKE) -C $(OPENSSL_DIR) clean
	rm -f $(OPENSSL_MAKEFILE)

maintainerclean-local:
	rm -rf $(OPENSSL_DIR)

install-exec-local: install-openssl

else
install-openssl:
	@echo Nothing to install. OpenSSL was not built together with OpenPACE. Use \`./configure --enable-openssl-build\` if this is what you want.
endif
