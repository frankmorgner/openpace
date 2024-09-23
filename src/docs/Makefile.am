SUBDIRS = _static

EXTRA_DIST = Doxyfile.in conf.py.in index.txt.in index.txt protocols.txt.in protocols.txt programming.txt.in programming.txt install.txt install.txt.in usage.txt.in efcardaccess_asn1.conf efcardsecurity_templ_asn1.conf Makefile.sphinx requirements.txt

do_subst = $(SED) \
	   -e 's,[@]PACKAGE_BUGREPORT[@],$(PACKAGE_BUGREPORT),g' \
	   -e 's,[@]PACKAGE_NAME[@],$(PACKAGE_NAME),g' \
	   -e 's,[@]PACKAGE_TARNAME[@],$(PACKAGE_TARNAME),g' \
	   -e 's,[@]PACKAGE_SUMMARY[@],$(PACKAGE_SUMMARY),g' \
	   -e 's,[@]PACKAGE_VERSION[@],$(PACKAGE_VERSION),g' \
	   -e 's,[@]srcdir[@],$(srcdir),g' \
	   -e 's,[@]builddir[@],$(srcdir),g'

DOXYGEN_HTML = doxygen/index.html

docs: $(DOXYGEN_HTML) $(srcdir)/*.in $(srcdir)/*.txt.in
	@$(do_subst) < $(srcdir)/conf.py.in > conf.py
	@$(do_subst) < $(srcdir)/index.txt.in > index.txt
	@$(do_subst) < $(srcdir)/programming.txt.in > programming.txt
	@$(do_subst) < $(srcdir)/install.txt.in > install.txt
	@$(do_subst) < $(srcdir)/usage.txt.in > usage.txt
	@$(do_subst) < $(srcdir)/protocols.txt.in > protocols.txt
	env LD_LIBRARY_PATH=${abs_top_builddir}/bindings/python:$(abs_top_builddir)/src/.libs:$(abs_top_builddir)/src/openssl \
		DYLD_LIBRARY_PATH=$${LD_LIBRARY_PATH} SHLIB_PATH=$${LD_LIBRARY_PATH} LIBPATH=$${LD_LIBRARY_PATH} \
		$(MAKE) -f $(srcdir)/Makefile.sphinx html
	mkdir -p $(top_builddir)/docs
	rm -rf $(top_builddir)/docs/*
	mv _build/html/* $(top_builddir)/docs
	mv doxygen $(top_builddir)/docs/_static

$(DOXYGEN_HTML): $(top_srcdir)/src/eac/*.h $(srcdir)/Doxyfile.in
	@$(do_subst) < $(srcdir)/Doxyfile.in > Doxyfile
	doxygen Doxyfile


clean-local:
	rm -rf _build doxygen conf.py index.txt programming.txt install.txt usage.txt protocols.txt Doxyfile
