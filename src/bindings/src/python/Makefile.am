EXTRA_DIST = setup.py.in

do_subst=$(SED)\
	-e's,[@]CFLAGS[@],$(CFLAGS),g'\
	-e's,[@]CPPFLAGS[@],$(CPPFLAGS),g'\
	-e's,[@]OPENPACE_CFLAGS[@],$(OPENPACE_CFLAGS),g'\
	-e's,[@]OPENPACE_LIBS[@],$(OPENPACE_LIBS),g'\
	-e's,[@]LIBS[@],$(LIBS),g'\
	-e's,[@]OPENSSL_CFLAGS[@],$(OPENSSL_CFLAGS),g'\
	-e's,[@]OPENSSL_LIBS[@],$(OPENSSL_LIBS),g'\
	-e's,[@]PACKAGE_BUGREPORT[@],$(PACKAGE_BUGREPORT),g'\
	-e's,[@]PACKAGE_NAME[@],$(PACKAGE_NAME),g'\
	-e's,[@]PACKAGE_TARNAME[@],$(PACKAGE_TARNAME),g'\
	-e's,[@]PACKAGE_URL[@],$(PACKAGE_URL),g'\
	-e's,[@]PACKAGE_VERSION[@],$(PACKAGE_VERSION),g'\
	-e's,[@]builddir[@],$(builddir),g'\
	-e's,[@]top_srcdir[@],$(top_srcdir),g'

all-local: pace.py

setup.py: setup.py.in
	$(do_subst) < $(srcdir)/setup.py.in > setup.py

pace.py: setup.py
	python setup.py build_ext

install-exec-local:
	python setup.py install --prefix=$(prefix) --exec-prefix=$(exec_prefix) --record installed_files.txt

uninstall-local:
	cat installed_files.txt | xargs rm -rf

clean-local:
	rm -rf build
	rm -f pace_wrap.c installed_files.txt setup.py pace.py
