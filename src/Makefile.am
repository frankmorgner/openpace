SUBDIRS = docs certs

BUILT_SOURCES = cvc-create-cmdline.c cvc-create-cmdline.h cvc-print-cmdline.c cvc-print-cmdline.h

EXTRA_DIST = bsi_objects.txt cvc-print.ggo.in cvc-create.ggo.in cvc-create.ggo cvc-print.ggo $(BUILT_SOURCES)

do_subst = $(SED) \
	   -e 's,[@]PACKAGE_BUGREPORT[@],$(PACKAGE_BUGREPORT),g'

dist_man1_MANS		= $(builddir)/cvc-create.1 $(builddir)/cvc-print.1

MAINTAINERCLEANFILES = $(BUILT_SOURCES) cvc-create.ggo cvc-print.ggo $(dist_man1_MANS)

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
				 read_file.h \
				 ssl_compat.h \
				 ta_lib.h


lib_LTLIBRARIES = libeac.la
noinst_LTLIBRARIES = libvc.la

libeac_la_SOURCES  = ca_lib.c cv_cert.c cvc_lookup.c x509_lookup.c eac_asn1.c eac.c eac_ca.c eac_dh.c eac_ecdh.c eac_kdf.c eac_lib.c eac_print.c eac_util.c misc.c pace.c pace_lib.c pace_mappings.c ri.c ri_lib.c ta.c ta_lib.c objects.c ssl_compat.c
libeac_la_CPPFLAGS = $(CRYPTO_CFLAGS) -DCVCDIR=\"@CVCDIR@\" -DX509DIR=\"@X509DIR@\"
libeac_la_LDFLAGS  = -no-undefined -version-info 2:1:0
libeac_la_LIBADD   = $(CRYPTO_LIBS)
if WIN32
AM_CPPFLAGS        = -DWIN32_LEAN_AND_MEAN
libeac_la_LIBADD  += -lws2_32
endif

libvc_la_SOURCES  = vc.c


bin_PROGRAMS         = eactest cvc-print cvc-create example

EAC_LIBS             = libeac.la libvc.la $(CRYPTO_LIBS)
EAC_CFLAGS           = $(CRYPTO_CFLAGS)

eactest_SOURCES      = eactest.c ssl_compat.c
eactest_LDADD        = $(EAC_LIBS)
eactest_CFLAGS       = $(EAC_CFLAGS)

cvc_print_SOURCES     = cvc-print.c read_file.c cvc-print-cmdline.c
cvc_print_LDADD       = $(EAC_LIBS)
cvc_print_CFLAGS      = $(EAC_CFLAGS)

cvc_create_SOURCES     = cvc-create.c read_file.c cvc-create-cmdline.c
cvc_create_LDADD       = $(EAC_LIBS)
cvc_create_CFLAGS      = $(EAC_CFLAGS)

example_SOURCES      = example.c
example_LDADD        = $(EAC_LIBS)
example_CFLAGS       = $(EAC_CFLAGS)


cvc-create-cmdline.c cvc-create-cmdline.h: cvc-create.ggo
	$(GENGETOPT) --file-name=cvc-create-cmdline --output-dir=$(builddir) < $<

cvc-print-cmdline.c cvc-print-cmdline.h: cvc-print.ggo
	$(GENGETOPT) --file-name=cvc-print-cmdline --output-dir=$(builddir) < $<

cvc-create.ggo: cvc-create.ggo.in
	@$(do_subst) < $< > $(builddir)/$@

cvc-print.ggo: cvc-print.ggo.in
	@$(do_subst) < $< > $(builddir)/$@



if INSTALL_OPENSSL

ENV = env \
	  LD_LIBRARY_PATH=$${LD_LIBRARY_PATH}:$(abs_top_builddir)/bindings/ruby/ext:$(abs_top_builddir)/bindings/java/.libs:$(abs_top_builddir)/bindings/python:$(abs_top_builddir)/src/.libs:$(abs_top_builddir)/src/openssl \
	  DYLD_LIBRARY_PATH=$${DYLD_LIBRARY_PATH}:$(abs_top_builddir)/bindings/ruby/ext:$(abs_top_builddir)/bindings/java/.libs:$(abs_top_builddir)/bindings/python:$(abs_top_builddir)/src/.libs:$(abs_top_builddir)/src/openssl \
	  SHLIB_PATH=$${SHLIB_PATH}:$(abs_top_builddir)/bindings/ruby/ext:$(abs_top_builddir)/bindings/java/.libs:$(abs_top_builddir)/bindings/python:$(abs_top_builddir)/src/.libs:$(abs_top_builddir)/src/openssl \
	  LIBPATH=$${LIBPATH}:$(abs_top_builddir)/bindings/ruby/ext:$(abs_top_builddir)/bindings/java/.libs:$(abs_top_builddir)/bindings/python:$(abs_top_builddir)/src/.libs:$(abs_top_builddir)/src/openssl \
	  PYTHONPATH=$(abs_top_builddir)/bindings/python \
	  RUBYLIB=$(abs_top_builddir)/bindings/ruby/ext

endif

cvc-create.1: cvc-create.ggo.in
	make -C $(builddir) cvc-create$(EXEEXT)
	$(ENV) $(HELP2MAN) \
		--output=$@ \
		--no-info \
		--source='$(PACKAGE_STRING)' \
		$(builddir)/cvc-create$(EXEEXT)

cvc-print.1: cvc-print.ggo.in
	make -C $(builddir) cvc-print$(EXEEXT)
	$(ENV) $(HELP2MAN) \
		--output=$@ \
		--no-info \
		--source='$(PACKAGE_STRING)' \
		$(builddir)/cvc-print$(EXEEXT)


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
	$(GIT) clone --depth=100 https://github.com/openssl/openssl.git -b OpenSSL_1_0_2-stable $(OPENSSL_DIR)
#	$(GIT) -C $(OPENSSL_DIR) checkout f243def213b24256db997bb30f729bc23d2c9d0a

# Configure OpenSSL (and create $(OPENSSL_OBJ_MAC))
$(OPENSSL_MAKEFILE): $(OPENSSL_CONFIGURE)
	cd $(OPENSSL_DIR) \
		&& CROSS_COMPILE="" MAKE=$(MAKE) CC=$(CC) AR=$(AR) RANLIB=$(RANLIB) $(OPENSSL_CONFIGURE) $(OPENSSL_CONFIGURE_FLAGS) >> /tmp/sslout 2>&1 \
		|| cat /tmp/sslout

# Patch OpenSSL with OpenPACE object identifiers
.PHONY: patch_openssl
patch_openssl: $(OPENSSL_MAKEFILE)
	grep NID_id_PACE_ECDH_GM_AES_CBC_CMAC_256 $(OPENSSL_OBJ_MAC) > /dev/null \
		|| (cd $(OPENSSL_DIR) \
			&& cat $(abs_srcdir)/bsi_objects.txt >> crypto/objects/objects.txt \
			&& $(MAKE) update -C $(OPENSSL_DIR) >> /tmp/sslout 2>&1 \
			|| cat /tmp/sslout)

# Build OpenSSL
$(OPENSSL_LIBCRYPTO_A):
	$(MAKE) patch_openssl
	$(MAKE) -C $(OPENSSL_DIR) >> /tmp/sslout 2>&1 || cat /tmp/sslout

# Install OpenSSL
install-openssl: $(OPENSSL_LIBCRYPTO_A)
	$(MAKE) -C $(OPENSSL_DIR) INSTALL_PREFIX=$(DESTDIR) install_sw >> /tmp/sslout 2>&1 || cat /tmp/sslout


# We require the patched headers of OpenSSL
$(libeac_la_SOURCES) $(nobase_include_HEADERS): patch_openssl


libeac_la_DEPENDENCIES = $(OPENSSL_LIBCRYPTO_A)


distclean-local:
	test ! -r $(OPENSSL_MAKEFILE) \
		|| $(MAKE) -C $(OPENSSL_DIR) clean >> /tmp/sslout 2>&1
	rm -f $(OPENSSL_MAKEFILE)

maintainerclean-local:
	rm -rf $(OPENSSL_DIR)

install-exec-local: install-openssl

else
install-openssl:
	@echo Nothing to install. OpenSSL was not built together with OpenPACE. Use \`./configure --enable-openssl-install\` if this is what you want.
endif
