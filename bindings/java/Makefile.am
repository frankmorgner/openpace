INTERFACES = $(srcdir)/../ca.i \
			 $(srcdir)/../cvc.i \
			 $(srcdir)/../eac.i \
			 $(srcdir)/../pace.i \
			 $(srcdir)/../ta.i \
			 $(srcdir)/../objects.i \
			 $(srcdir)/../util.i

BUILT_SOURCES = SWIGTYPE_p_BIO.java \
				SWIGTYPE_p_BUF_MEM.java \
				SWIGTYPE_p_CVC_CERT.java \
				SWIGTYPE_p_CVC_CERTIFICATE_DESCRIPTION.java \
				SWIGTYPE_p_CVC_CHAT.java \
				SWIGTYPE_p_EAC_CTX.java \
				SWIGTYPE_p_PACE_SEC.java \
				SWIGTYPE_p_int.java \
				SWIGTYPE_p_p_BUF_MEM.java \
				SWIGTYPE_p_p_CVC_CERT.java \
				SWIGTYPE_p_p_CVC_CERTIFICATE_DESCRIPTION.java \
				SWIGTYPE_p_p_CVC_CHAT.java \
				SWIGTYPE_p_p_char.java \
				SWIGTYPE_p_p_unsigned_char.java \
				SWIGTYPE_p_unsigned_char.java \
				pace.java \
				paceConstants.java \
				paceJNI.java \
				pace_wrap.c \
				s_type.java

EXTRA_DIST = JPace.java
CLEANFILES = $(BUILT_SOURCES)

lib_LTLIBRARIES = libjpace.la

libjpace_la_SOURCES = pace_wrap.c
libjpace_la_CFLAGS  = -I$(top_srcdir)/src $(CRYPTO_CFLAGS) $(JAVA_CFLAGS)
libjpace_la_LDFLAGS = $(top_builddir)/src/libeac.la $(CRYPTO_LIBS)

$(BUILT_SOURCES): $(INTERFACES)
	$(SWIG) -java -outdir $(builddir) -I$(srcdir)/.. pace.i


all-local: JPace.class

JPace.class: JPace.java $(BUILT_SOURCES)
	$(JAVAC) $(JAVACFLAGS) -d $(builddir) -sourcepath $(builddir) $(srcdir)/JPace.java
