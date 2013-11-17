INTERFACES = $(srcdir)/../ca.i \
			 $(srcdir)/../cvc.i \
			 $(srcdir)/../eac.i \
			 $(srcdir)/../pace.i \
			 $(srcdir)/../ta.i \
			 $(srcdir)/../objects.i \
			 $(srcdir)/../util.i

BUILT_SOURCES_SWIG = eacConstants.java \
					 eac.java \
					 eacJNI.java \
					 s_type.java \
					 SWIGTYPE_p_BUF_MEM.java \
					 SWIGTYPE_p_CVC_CERTIFICATE_DESCRIPTION.java \
					 SWIGTYPE_p_CVC_CERT.java \
					 SWIGTYPE_p_CVC_CHAT.java \
					 SWIGTYPE_p_EAC_CTX.java \
					 SWIGTYPE_p_PACE_SEC.java \
					 SWIGTYPE_p_p_BUF_MEM.java \
					 SWIGTYPE_p_p_char.java \
					 SWIGTYPE_p_size_t.java \
					 SWIGTYPE_p_unsigned_char.java \
					 eac_wrap.c

CLASSES_JPACE = eac.class \
				eacConstants.class \
				eacJNI.class \
				JPace.class \
				PACEEntity.class \
				PCD.class \
				PICC.class \
				s_type.class \
				SWIGTYPE_p_BUF_MEM.class \
				SWIGTYPE_p_CVC_CERT.class \
				SWIGTYPE_p_CVC_CERTIFICATE_DESCRIPTION.class \
				SWIGTYPE_p_CVC_CHAT.class \
				SWIGTYPE_p_EAC_CTX.class \
				SWIGTYPE_p_PACE_SEC.class \
				SWIGTYPE_p_p_BUF_MEM.class \
				SWIGTYPE_p_p_char.class \
				SWIGTYPE_p_size_t.class \
				SWIGTYPE_p_unsigned_char.class

EXTRA_DIST = JPace.java
CLEANFILES = $(BUILT_SOURCES_SWIG) $(CLASSES_JPACE)

lib_LTLIBRARIES = libjeac.la

libjeac_la_SOURCES = eac_wrap.c
libjeac_la_CFLAGS  = -I$(top_srcdir)/src $(CRYPTO_CFLAGS) $(JAVA_CFLAGS)
libjeac_la_LDFLAGS = $(top_builddir)/src/libeac.la $(CRYPTO_LIBS)

$(BUILT_SOURCES_SWIG): $(INTERFACES)
	$(SWIG) -java -outdir $(builddir) -I$(srcdir)/.. eac.i


all-local: $(BUILT_SOURCES) $(CLASSES_JPACE)

$(CLASSES_JPACE): JPace.java $(BUILT_SOURCES_SWIG)
	$(JAVAC) $(JAVACFLAGS) -d $(builddir) -sourcepath $(builddir) $(srcdir)/JPace.java
