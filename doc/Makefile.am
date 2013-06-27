SUBDIRS = _static

EXTRA_DIST = Doxyfile.in conf.py.in index.txt.in index.txt protocols.txt protocols.txt Makefile.sphinx

do_subst = $(SED) \
	   -e 's,[@]PACKAGE_BUGREPORT[@],$(PACKAGE_BUGREPORT),g' \
	   -e 's,[@]PACKAGE_NAME[@],$(PACKAGE_NAME),g' \
	   -e 's,[@]PACKAGE_TARNAME[@],$(PACKAGE_TARNAME),g' \
	   -e 's,[@]PACKAGE_SUMMARY[@],$(PACKAGE_SUMMARY),g' \
	   -e 's,[@]PACKAGE_VERSION[@],$(PACKAGE_VERSION),g'

DOXYGEN_HTML = doxygen/html/index.html


doc: $(DOXYGEN_HTML) *.in *.txt *.txt.in
	$(do_subst) < conf.py.in > conf.py
	$(do_subst) < index.txt.in > index.txt
	env LD_LIBRARY_PATH=`pwd`/../bindings/python:`pwd`/../src/.libs:`pwd`/../src/openssl \
		DYLD_LIBRARY_PATH=$${LD_LIBRARY_PATH} SHLIB_PATH=$${LD_LIBRARY_PATH} LIBPATH=$${LD_LIBRARY_PATH} \
		$(MAKE) -f Makefile.sphinx html
	touch doc

$(DOXYGEN_HTML): $(top_srcdir)/src/eac/*.h Doxyfile.in
	$(do_subst) < Doxyfile.in > Doxyfile
	doxygen Doxyfile
