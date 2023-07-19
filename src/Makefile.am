SUBDIRS = docs certs

BUILT_SOURCES = cvc-create-cmdline.c cvc-create-cmdline.h cvc-print-cmdline.c cvc-print-cmdline.h

EXTRA_DIST = bsi_objects.txt cvc-print.ggo.in cvc-create.ggo.in cvc-create.ggo cvc-print.ggo $(BUILT_SOURCES)

do_subst = $(SED) \
	   -e 's,[@]PACKAGE_BUGREPORT[@],$(PACKAGE_BUGREPORT),g'

dist_man1_MANS		= cvc-create.1 cvc-print.1

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
libeac_la_LDFLAGS  = -no-undefined -version-info 4:0:1
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


cvc-create.1: cvc-create.ggo.in
	$(ENV) $(HELP2MAN) \
		--output=$(builddir)/$@ \
		--no-info \
		--source='$(PACKAGE_STRING)' \
		$(builddir)/cvc-create$(EXEEXT)

cvc-print.1: cvc-print.ggo.in
	$(ENV) $(HELP2MAN) \
		--output=$(builddir)/$@ \
		--no-info \
		--source='$(PACKAGE_STRING)' \
		$(builddir)/cvc-print$(EXEEXT)
