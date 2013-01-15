INTERFACES = $(srcdir)/../ca.i \
			 $(srcdir)/../cvc.i \
			 $(srcdir)/../eac.i \
			 $(srcdir)/../pace.i \
			 $(srcdir)/../ta.i \
			 $(srcdir)/../util.i

BUILT_SOURCES = pace_wrap.c pace.py

EXTRA_DIST = setup.py.in cvc_rehash.in test.py
CLEANFILES = $(BUILT_SOURCES) installed_files.txt setup.py
bin_SCRIPTS = cvc_rehash

do_subst=$(SED)\
	-e's,[@]CFLAGS[@],$(CFLAGS),g'\
	-e's,[@]CPPFLAGS[@],$(CPPFLAGS),g'\
	-e's,[@]CRYPTO_CFLAGS[@],$(CRYPTO_CFLAGS),g'\
	-e's,[@]CRYPTO_LIBS[@],'"$(CRYPTO_LIBS)"',g'\
	-e's,[@]LIBS[@],$(LIBS),g'\
	-e's,[@]OPENPACE_CFLAGS[@],-I$(top_srcdir)/src,g'\
	-e's,[@]OPENPACE_LIBS[@],$(top_builddir)/src/.libs/libeac.so,g'\
	-e's,[@]PACKAGE_NAME[@],$(PACKAGE_NAME),g'\
	-e's,[@]PACKAGE_NAME[@],$(PACKAGE_NAME),g'\
	-e's,[@]PACKAGE_URL[@],$(PACKAGE_URL),g'\
	-e's,[@]PACKAGE_VERSION[@],$(PACKAGE_VERSION),g'\
	-e's,[@]PYTHON[@],$(PYTHON),g'\
	-e's,[@]builddir[@],$(builddir),g'\
	-e's,[@]sysconfdir[@],$(sysconfdir),g'\
	-e's,[@]srcdir[@],$(srcdir),g'


all-local: pace.py

$(top_builddir)/src/libeac.la:
	$(MAKE) -C $(top_builddir)/src libeac.la

setup.py: setup.py.in $(top_builddir)/src/libeac.la
	$(do_subst) < $(srcdir)/setup.py.in > setup.py

cvc_rehash: cvc_rehash.in
	$(do_subst) < $(srcdir)/cvc_rehash.in > cvc_rehash

$(BUILT_SOURCES): $(INTERFACES) setup.py
	python setup.py build_ext

install-exec-local:
	python setup.py install --prefix=$(prefix) --exec-prefix=$(exec_prefix) --record installed_files.txt

uninstall-local:
	cat installed_files.txt | xargs rm -rf

clean-local:
	rm -rf build
