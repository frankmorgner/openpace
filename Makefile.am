ACLOCAL_AMFLAGS = -I m4
SUBDIRS = src cross bindings doc

EXTRA_DIST = libeac.pc.in bootstrap oids.patch
DISTCHECK_CONFIGURE_FLAGS = --enable-java --enable-go --enable-ruby --enable-python --enable-openssl-install

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
	$(do_subst) < $(srcdir)/libeac.pc.in > libeac.pc

win:
	$(MAKE) -C cross $@

android:
	$(MAKE) -C cross $@

emscripten:
	$(MAKE) -C cross $@

.PHONY: doc
doc:
	$(MAKE) -C doc $@

clean-local:
	rm -f libeac.pc

LOCAL_TESTS = test-eactest
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
	  LD_LIBRARY_PATH=$${LD_LIBRARY_PATH}:$(abs_builddir)/bindings/ruby/ext:$(abs_builddir)/bindings/java/.libs:$(abs_builddir)/bindings/python:$(abs_builddir)/src/.libs:$(abs_builddir)/src/openssl \
	  DYLD_LIBRARY_PATH=$${DYLD_LIBRARY_PATH}:$(abs_builddir)/bindings/ruby/ext:$(abs_builddir)/bindings/java/.libs:$(abs_builddir)/bindings/python:$(abs_builddir)/src/.libs:$(abs_builddir)/src/openssl \
	  SHLIB_PATH=$${SHLIB_PATH}:$(abs_builddir)/bindings/ruby/ext:$(abs_builddir)/bindings/java/.libs:$(abs_builddir)/bindings/python:$(abs_builddir)/src/.libs:$(abs_builddir)/src/openssl \
	  LIBPATH=$${LIBPATH}:$(abs_builddir)/bindings/ruby/ext:$(abs_builddir)/bindings/java/.libs:$(abs_builddir)/bindings/python:$(abs_builddir)/src/.libs:$(abs_builddir)/src/openssl \
	  PYTHONPATH=$(abs_builddir)/bindings/python \
	  RUBYLIB=$(abs_builddir)/bindings/ruby/ext

test-eactest:
	$(ENV) \
		$(builddir)/src/eactest

test-python:
	cp $(builddir)/bindings/python/build/*/_eac.*so $(builddir)/bindings/python
	$(ENV) \
		$(PYTHON) $(srcdir)/bindings/python/test.py \
		&& $(ENV) $(PYTHON) $(srcdir)/bindings/python/example.py \
		|| (rm $(builddir)/bindings/python/_eac.*so && false)
	rm $(builddir)/bindings/python/_eac.*so

test-go:
	$(ENV) \
		$(builddir)/bindings/go/example

test-java:
	cd $(builddir)/bindings/java \
		$(ENV) \
		&& java Example \
		&& $(ENV) java JPace

test-ruby:
	$(ENV) \
		$(RUBY) $(srcdir)/bindings/ruby/example.rb

install-data-local:
	$(INSTALL) -d $(DESTDIR)$(CVCDIR)
	$(INSTALL) -d $(DESTDIR)$(X509DIR)

distcheck-hook:
	test -d .svn \
		&& svn2cl --group-by-day --reparagraph --separate-daylogs --include-actions --include-rev \
		|| true
	test -d .git \
		&& git2cl > ChangeLog \
		|| true
