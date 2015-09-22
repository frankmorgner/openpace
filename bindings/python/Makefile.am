INTERFACES = $(srcdir)/../ca.i \
			 $(srcdir)/../cvc.i \
			 $(srcdir)/../eac.i \
			 $(srcdir)/../pace.i \
			 $(srcdir)/../ta.i \
			 $(srcdir)/../objects.i \
			 $(srcdir)/../util.i

BUILT_SOURCES = eac_wrap.c eac.py

EXTRA_DIST = setup.py.in cvc_rehash.in test.py chat.py example.py
CLEANFILES = installed_files.txt setup.py $(BUILT_SOURCES)
bin_SCRIPTS = cvc_rehash

do_subst=$(SED)\
	-e's,[@]CFLAGS[@],$(CFLAGS),g'\
	-e's,[@]CPPFLAGS[@],$(CPPFLAGS),g'\
	-e's,[@]CRYPTO_CFLAGS[@],$(CRYPTO_CFLAGS),g'\
	-e's,[@]CRYPTO_LIBS[@],'"$(CRYPTO_LIBS)"',g'\
	-e's,[@]LIBS[@],$(LIBS),g'\
	-e's,[@]OPENPACE_CFLAGS[@],-I$(top_srcdir)/src,g'\
	-e's,[@]OPENPACE_LIBS[@],-L$(top_builddir)/src/.libs -leac,g'\
	-e's,[@]PACKAGE_NAME[@],$(PACKAGE_NAME),g'\
	-e's,[@]PACKAGE_NAME[@],$(PACKAGE_NAME),g'\
	-e's,[@]PACKAGE_URL[@],$(PACKAGE_URL),g'\
	-e's,[@]PACKAGE_VERSION[@],$(PACKAGE_VERSION),g'\
	-e's,[@]PYTHON[@],$(PYTHON),g'\
	-e's,[@]builddir[@],$(builddir),g'\
	-e's,[@]sysconfdir[@],$(sysconfdir),g'\
	-e's,[@]srcdir[@],$(srcdir),g'


all-local: eac.py

$(top_builddir)/src/libeac.la:
	$(MAKE) -C $(top_builddir)/src libeac.la

setup.py: setup.py.in $(top_builddir)/src/libeac.la
	@$(do_subst) < $(srcdir)/setup.py.in > setup.py

cvc_rehash: cvc_rehash.in
	@$(do_subst) < $(srcdir)/cvc_rehash.in > cvc_rehash

$(BUILT_SOURCES): $(INTERFACES) setup.py
	env CC="$(CC)" $(PYTHON) setup.py build_ext --swig=$(SWIG)

# Androids implementation does not honour --root=$(DESTDIR) so we change the prefix
install-exec-local:
	env CC="$(CC)" $(PYTHON) setup.py install --prefix=$(DESTDIR)$(prefix) --exec-prefix=$(DESTDIR)$(exec_prefix) --record installed_files.txt

uninstall-local:
	cat installed_files.txt | xargs rm -rf

clean-local:
	rm -rf build
	rm -f *.pyc setup.inc

distclean-local:
	rm -f cvc_rehash setup
