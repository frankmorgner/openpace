INTERFACES = $(srcdir)/../ca.i \
			 $(srcdir)/../cvc.i \
			 $(srcdir)/../eac.i \
			 $(srcdir)/../pace.i \
			 $(srcdir)/../ta.i \
			 $(srcdir)/../objects.i \
			 $(srcdir)/../util.i

EXTRA_DIST = example.go

lib_LTLIBRARIES = libgeac.la

nodist_libgeac_la_SOURCES = eac_wrap.c
libgeac_la_CFLAGS  = -I$(top_srcdir)/src $(CRYPTO_CFLAGS)
libgeac_la_LDFLAGS = $(top_builddir)/src/libeac.la $(CRYPTO_LIBS)

eac_wrap.c: $(INTERFACES)
	$(SWIG) $(SWIGGOPARAMS) -go -no-cgo -gccgo -outdir $(builddir) -o eac_wrap.c -I$(srcdir)/.. $(srcdir)/../eac.i

eac.o: eac_wrap.c
	$(GCCGO) -c eac.go $(GCCGOFLAGS)

example.o: libgeac.la $(srcdir)/example.go
	$(GCCGO) -c $(srcdir)/example.go $(GCCGOFLAGS)

example: example.o eac.o
	$(GCCGO) example.o eac.o libgeac_la-eac_wrap.o $(top_builddir)/src/.libs/libeac.a $(CRYPTO_LIBS) $(GCCGOFLAGS) -o example

libgeac_la-local: eac_wrap.c

all-local: eac.o example

clean-local:
	rm -f eac_wrap.c eac.go
	rm -f example example.o
	rm -f eac.o
