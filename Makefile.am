ACLOCAL_AMFLAGS = -I m4
SUBDIRS = src bindings

EXTRA_DIST = libeac.pc.in bootstrap generate-eac-pki.sh docs appveyor.yml NEWS.md
DISTCHECK_CONFIGURE_FLAGS = --enable-java --enable-python --disable-openssl-install

if WIN32
WS2_32 = -lws2_32
endif

do_subst = $(SED) \
	   -e 's,[@]PACKAGE_NAME[@],$(PACKAGE_NAME),g' \
	   -e 's,[@]PACKAGE_SUMMARY[@],$(PACKAGE_SUMMARY),g' \
	   -e 's,[@]CVCDIR[@],$(CVCDIR),g' \
	   -e 's,[@]X509DIR[@],$(X509DIR),g' \
	   -e 's,[@]VERSION[@],$(VERSION),g' \
	   -e 's,[@]WS2_32[@],$(WS2_32),g' \
	   -e 's,[@]exec_prefix[@],$(exec_prefix),g' \
	   -e 's,[@]includedir[@],$(includedir),g' \
	   -e 's,[@]libdir[@],$(libdir),g' \
	   -e 's,[@]prefix[@],$(prefix),g'

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libeac.pc

libeac.pc: libeac.pc.in
	@$(do_subst) < $(srcdir)/libeac.pc.in > libeac.pc

.PHONY: docs libeac.pc
docs:
	$(MAKE) -C src/docs $@

clean-local:
	rm -f libeac.pc

LOCAL_TESTS = test-eactest test-cvcutils
if PYTHON_ENABLED
LOCAL_TESTS += test-python
endif
if GO_ENABLED
LOCAL_TESTS += test-go
endif
if JAVA_ENABLED
LOCAL_TESTS += test-java
endif
if RUBY_ENABLED
LOCAL_TESTS += test-ruby
endif
check-local: $(LOCAL_TESTS)

ENV = env \
	  LD_LIBRARY_PATH=$${LD_LIBRARY_PATH}:$(abs_top_builddir)/bindings/ruby/ext:$(abs_top_builddir)/bindings/java/.libs:$(abs_top_builddir)/bindings/python:$(abs_top_builddir)/src/.libs:$(abs_top_builddir)/src/openssl \
	  DYLD_LIBRARY_PATH=$${DYLD_LIBRARY_PATH}:$(abs_top_builddir)/bindings/ruby/ext:$(abs_top_builddir)/bindings/java/.libs:$(abs_top_builddir)/bindings/python:$(abs_top_builddir)/src/.libs:$(abs_top_builddir)/src/openssl \
	  SHLIB_PATH=$${SHLIB_PATH}:$(abs_top_builddir)/bindings/ruby/ext:$(abs_top_builddir)/bindings/java/.libs:$(abs_top_builddir)/bindings/python:$(abs_top_builddir)/src/.libs:$(abs_top_builddir)/src/openssl \
	  LIBPATH=$${LIBPATH}:$(abs_top_builddir)/bindings/ruby/ext:$(abs_top_builddir)/bindings/java/.libs:$(abs_top_builddir)/bindings/python:$(abs_top_builddir)/src/.libs:$(abs_top_builddir)/src/openssl \
	  PYTHONPATH=$(abs_top_builddir)/bindings/python \
	  PYTHONDONTWRITEBYTECODE=1 \
	  RUBYLIB=$(abs_top_builddir)/bindings/ruby/ext

test-eactest:
	$(ENV) $(builddir)/src/eactest

test-cvcutils:
	echo "whatever" > ZZATTERM00001.txt
	openssl ecparam -out ZZATCVCA00001.pem -name prime192v1 -genkey \
		&& openssl pkcs8 -topk8 -nocrypt -in ZZATCVCA00001.pem -outform DER -out ZZATCVCA00001.pkcs8 \
		&& $(ENV) $(builddir)/src/cvc-create --role=cvca --type=at --chr=ZZATCVCA00001 --issued=170101 --expires=`date --date="next year" "+%^y%^m%^d"` --sign-with=ZZATCVCA00001.pkcs8 --scheme=ECDSA_SHA_512 --write-dg17 --write-dg18 --write-dg19 --write-dg20 --write-dg21 --at-rfu32 --at-rfu31 --at-rfu30 --at-rfu29 --read-dg1 --read-dg2 --read-dg3 --read-dg4 --read-dg5 --read-dg6 --read-dg7 --read-dg8 --read-dg9 --read-dg10 --read-dg11 --read-dg12 --read-dg13 --read-dg14 --read-dg15 --read-dg16 --read-dg17 --read-dg18 --read-dg19 --read-dg20 --read-dg21 --install-qual-cert --install-cert --pin-management --can-allowed --privileged --rid --verify-community --verify-age \
		&& $(ENV) $(builddir)/src/cvc-create --role=dv_domestic --chr=ZZATDVCA00001 --expires=`date --date="next month" "+%^y%^m%^d"` --sign-with=ZZATCVCA00001.pkcs8 --sign-as=ZZATCVCA00001.cvcert --scheme=ECDSA_SHA_256 --rid \
		&& $(ENV) $(builddir)/src/cvc-create --role=terminal --chr=ZZATTERM00001 --expires=`date --date="next week" "+%^y%^m%^d"` --sign-with=ZZATDVCA00001.pkcs8 --sign-as=ZZATDVCA00001.cvcert --scheme=ECDSA_SHA_1 --rid --cert-desc=ZZATTERM00001.txt --issuer-name=DVCA --issuer-url=http://dv.ca --subject-name=TERM --subject-url=http://term.ca \
		&& ln -fs ZZATCVCA00001.cvcert ZZATCVCA00001 \
		&& ln -fs ZZATDVCA00001.cvcert ZZATDVCA00001 \
		&& $(ENV) $(builddir)/src/cvc-print --cvc-dir=. --cvc ZZATCVCA00001.cvcert \
		&& $(ENV) $(builddir)/src/cvc-print --cvc-dir=. --cvc ZZATDVCA00001.cvcert \
		&& $(ENV) $(builddir)/src/cvc-print --cvc-dir=. --cvc ZZATTERM00001.cvcert --description ZZATTERM00001.desc
	rm -f ZZATTERM00001.txt ZZATCVCA00001 ZZATCVCA00001.pem ZZATCVCA00001.pkcs8 ZZATCVCA00001.cvcert ZZATDVCA00001 ZZATDVCA00001.cvcert ZZATDVCA00001.pkcs8 ZZATTERM00001.cvcert ZZATTERM00001.pkcs8 ZZATTERM00001.desc
	openssl genrsa -out ZZISCVCA00001.pem 2048 \
		&& openssl pkcs8 -topk8 -nocrypt -in ZZISCVCA00001.pem -outform DER -out ZZISCVCA00001.pkcs8 \
		&& $(ENV) $(builddir)/src/cvc-create --role=cvca --type=is --chr=ZZISCVCA00001 --issued=170101 --expires=`date --date="next year" "+%^y%^m%^d"` --sign-with=ZZISCVCA00001.pkcs8 --scheme=RSA_v1_5_SHA_512 --read-eid --is-rfu4 --is-rfu3 --is-rfu2 --read-iris --read-finger \
		&& $(ENV) $(builddir)/src/cvc-create --role=dv_foreign --chr=ZZISDVCA00001 --expires=`date --date="next month" "+%^y%^m%^d"` --sign-with=ZZISCVCA00001.pkcs8 --sign-as=ZZISCVCA00001.cvcert --scheme=RSA_v1_5_SHA_256 --read-eid \
		&& $(ENV) $(builddir)/src/cvc-create --role=terminal --chr=ZZISTERM00001 --expires=`date --date="next week" "+%^y%^m%^d"` --sign-with=ZZISDVCA00001.pkcs8 --sign-as=ZZISDVCA00001.cvcert --scheme=RSA_v1_5_SHA_1 --read-eid \
		&& ln -fs ZZISCVCA00001.cvcert ZZISCVCA00001 \
		&& ln -fs ZZISDVCA00001.cvcert ZZISDVCA00001 \
		&& $(ENV) $(builddir)/src/cvc-print --cvc-dir=. --cvc ZZISCVCA00001.cvcert \
		&& $(ENV) $(builddir)/src/cvc-print --cvc-dir=. --cvc ZZISDVCA00001.cvcert \
		&& $(ENV) $(builddir)/src/cvc-print --cvc-dir=. --cvc ZZISTERM00001.cvcert \
		|| (rm -f ZZISCVCA00001 ZZISCVCA00001.pem ZZISCVCA00001.pkcs8 ZZISCVCA00001.cvcert ZZISDVCA00001 ZZISDVCA00001.cvcert ZZISDVCA00001.pkcs8 ZZISTERM00001.cvcert ZZISTERM00001.pkcs8 && false)
	rm -f ZZISCVCA00001 ZZISCVCA00001.pem ZZISCVCA00001.pkcs8 ZZISCVCA00001.cvcert ZZISDVCA00001 ZZISDVCA00001.cvcert ZZISDVCA00001.pkcs8 ZZISTERM00001.cvcert ZZISTERM00001.pkcs8
	openssl genrsa -out ZZSTCVCA00001.pem 4096 \
		&& openssl pkcs8 -topk8 -nocrypt -in ZZSTCVCA00001.pem -outform DER -out ZZSTCVCA00001.pkcs8 \
		&& $(ENV) $(builddir)/src/cvc-create --role=cvca --type=st --chr=ZZSTCVCA00001 --issued=170101 --expires=`date --date="next year" "+%^y%^m%^d"` --sign-with=ZZSTCVCA00001.pkcs8 --scheme=RSA_PSS_SHA_512 --st-rfu5 --st-rfu4 --st-rfu3 --st-rfu2 --gen-qualified-sig --gen-sig \
		&& $(ENV) $(builddir)/src/cvc-create --role=dv_domestic --chr=ZZSTDVCA00001 --expires=`date --date="next month" "+%^y%^m%^d"` --sign-with=ZZSTCVCA00001.pkcs8 --sign-as=ZZSTCVCA00001.cvcert --scheme=RSA_PSS_SHA_256 --gen-sig \
		&& $(ENV) $(builddir)/src/cvc-create --role=terminal --chr=ZZSTTERM00001 --expires=`date --date="next week" "+%^y%^m%^d"` --sign-with=ZZSTDVCA00001.pkcs8 --sign-as=ZZSTDVCA00001.cvcert --scheme=RSA_PSS_SHA_1 --gen-sig \
		&& ln -fs ZZSTCVCA00001.cvcert ZZSTCVCA00001 \
		&& ln -fs ZZSTDVCA00001.cvcert ZZSTDVCA00001 \
		&& $(ENV) $(builddir)/src/cvc-print --cvc-dir=. --cvc ZZSTCVCA00001.cvcert \
		&& $(ENV) $(builddir)/src/cvc-print --cvc-dir=. --cvc ZZSTDVCA00001.cvcert \
		&& $(ENV) $(builddir)/src/cvc-print --cvc-dir=. --cvc ZZSTTERM00001.cvcert \
		|| (rm -f ZZSTCVCA00001 ZZSTCVCA00001.pem ZZSTCVCA00001.pkcs8 ZZSTCVCA00001.cvcert ZZSTDVCA00001 ZZSTDVCA00001.cvcert ZZSTDVCA00001.pkcs8 ZZSTTERM00001.cvcert ZZSTTERM00001.pkcs8 && false)
	rm -f ZZSTCVCA00001 ZZSTCVCA00001.pem ZZSTCVCA00001.pkcs8 ZZSTCVCA00001.cvcert ZZSTDVCA00001 ZZSTDVCA00001.cvcert ZZSTDVCA00001.pkcs8 ZZSTTERM00001.cvcert ZZSTTERM00001.pkcs8

test-python:
	cp $(builddir)/bindings/python/build/*/_eac.*so $(builddir)/bindings/python
	$(ENV) $(PYTHON) $(srcdir)/bindings/python/test.py \
		&& $(ENV) $(PYTHON) $(srcdir)/bindings/python/example.py \
		|| (rm $(builddir)/bindings/python/_eac.*so && false)
	rm $(builddir)/bindings/python/_eac.*so

test-go:
	$(ENV) $(builddir)/bindings/go/example

test-java:
	cd $(builddir)/bindings/java \
		&& $(ENV) java EAC_Example

test-ruby:
	$(ENV) $(RUBY) $(srcdir)/bindings/ruby/example.rb

install-data-local:
	$(INSTALL) -d $(DESTDIR)$(htmldir)
	find $(srcdir)/docs -type d -exec sh -c 'for f in $$@; do $(MKDIR_P)            "$(DESTDIR)$(htmldir)/$${f##$(srcdir)/docs/}"; done' {} +
	find $(srcdir)/docs -type f -exec sh -c 'for f in $$@; do $(INSTALL_DATA) "$$f" "$(DESTDIR)$(htmldir)/$${f##$(srcdir)/docs/}"; done' {} +

uninstall-local:
	rm -rf $(DESTDIR)$(htmldir)

# Check whether regular files were deleted except in the docs directory
distcleancheck_listfiles = find . -path ./docs -prune -o -type f -print
