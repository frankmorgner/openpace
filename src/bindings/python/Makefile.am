EXTRA_DIST = setup.py.in

do_subst=$(SED)\
	-e's,[@]CFLAGS[@],$(CFLAGS),g'\
	-e's,[@]CPPFLAGS[@],$(CPPFLAGS),g'\
	-e's,[@]CRYPTO_CFLAGS[@],$(CRYPTO_CFLAGS),g'\
	-e's,[@]CRYPTO_LIBS[@],$(CRYPTO_LIBS),g'\
	-e's,[@]LIBS[@],$(LIBS),g'\
	-e's,[@]OPENPACE_CFLAGS[@],-I$(srcdir)/../..,g'\
	-e's,[@]OPENPACE_LIBS[@],$(builddir)/../../.libs/libeac.so,g'\
	-e's,[@]PACKAGE_NAME[@],$(PACKAGE_NAME),g'\
	-e's,[@]PACKAGE_NAME[@],$(PACKAGE_NAME),g'\
	-e's,[@]PACKAGE_URL[@],$(PACKAGE_URL),g'\
	-e's,[@]PACKAGE_VERSION[@],$(PACKAGE_VERSION),g'\
	-e's,[@]PYTHON[@],$(PYTHON),g'\
	-e's,[@]builddir[@],$(builddir),g'\
	-e's,[@]srcdir[@],$(srcdir),g'

all-local: pace.py

setup.py: setup.py.in
	$(do_subst) < $(srcdir)/setup.py.in > setup.py

pace.py: setup.py
	make -C $(srcdir)/../.. libeac.la
	python setup.py build_ext

install-exec-local:
	python setup.py install --prefix=$(prefix) --exec-prefix=$(exec_prefix) --record installed_files.txt

uninstall-local:
	cat installed_files.txt | xargs rm -rf

clean-local:
	rm -rf build
	rm -f pace_wrap.c installed_files.txt setup.py pace.py
