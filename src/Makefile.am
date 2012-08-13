lib_LTLIBRARIES = libeac.la

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

libeac_la_SOURCES = ca_lib.c cv_cert.c eac_asn1.c eac.c eac_ca.c eac_dh.c eac_ecdh.c eac_kdf.c eac_lib.c eac_print.c eac_util.c misc.c pace.c pace_lib.c pace_mappings.c ri.c ri_lib.c ta.c ta_lib.c
libeac_la_LIBADD = $(CRYPTO_LIBS)
libeac_la_CPPFLAGS = $(CRYPTO_CFLAGS)


noinst_PROGRAMS = eactest cv_cert_test
EAC_LIBS = $(CRYPTO_LIBS) libeac.la
EAC_CFLAGS = $(CRYPTO_CFLAGS)

eactest_SOURCES = eactest.c
eactest_LDADD = $(EAC_LIBS)
eactest_CFLAGS = $(EAC_CFLAGS)

cv_cert_test_SOURCES = cv_cert_test.c
cv_cert_test_LDADD = $(EAC_LIBS)
cv_cert_test_CFLAGS = $(EAC_CFLAGS)


check-local:
	$(builddir)/eactest
