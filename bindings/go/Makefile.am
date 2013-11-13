INTERFACES = $(srcdir)/../ca.i \
			 $(srcdir)/../cvc.i \
			 $(srcdir)/../eac.i \
			 $(srcdir)/../pace.i \
			 $(srcdir)/../ta.i \
			 $(srcdir)/../objects.i \
			 $(srcdir)/../util.i

BUILT_SOURCES = eac_wrap.c

EXTRA_DIST = example.go
CLEANFILES = $(BUILT_SOURCES) eac.go

lib_LTLIBRARIES = libgeac.la

libgeac_la_SOURCES = eac_wrap.c
libgeac_la_CFLAGS  = -I$(top_srcdir)/src $(CRYPTO_CFLAGS)
libgeac_la_LDFLAGS = $(top_builddir)/src/libeac.la $(CRYPTO_LIBS)

$(BUILT_SOURCES): $(INTERFACES)
	$(SWIG) -go -gccgo -intgosize 32 -outdir $(builddir) -I$(srcdir)/.. eac.i

eac.o: $(BUILT_SOURCES)
	$(GCCGO) -c eac.go

example.o: example.go
	$(GCCGO) -c example.go

example: example.o eac.o
	$(GCCGO) example.o eac.o libgeac_la-eac_wrap.o $(top_builddir)/src/.libs/libeac.a $(CRYPTO_LIBS) -o example

all-local: eac.o example

clean-local:
	rm -f example example.o
	rm -f eac.o

distclean-local:
	rm -f $(BUILT_SOURCES)
