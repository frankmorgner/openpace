INTERFACES = $(srcdir)/../ca.i \
			 $(srcdir)/../cvc.i \
			 $(srcdir)/../eac.i \
			 $(srcdir)/../pace.i \
			 $(srcdir)/../ta.i \
			 $(srcdir)/../objects.i \
			 $(srcdir)/../util.i

BUILT_SOURCES_SWIG = SWIGTYPE_p_BIO.java \
					 SWIGTYPE_p_BUF_MEM.java \
					 SWIGTYPE_p_CVC_CERT.java \
					 SWIGTYPE_p_CVC_CERTIFICATE_DESCRIPTION.java \
					 SWIGTYPE_p_CVC_CHAT.java \
					 SWIGTYPE_p_EAC_CTX.java \
					 SWIGTYPE_p_PACE_SEC.java \
					 SWIGTYPE_p_p_BUF_MEM.java \
					 SWIGTYPE_p_p_CVC_CERT.java \
					 SWIGTYPE_p_p_CVC_CERTIFICATE_DESCRIPTION.java \
					 SWIGTYPE_p_p_CVC_CHAT.java \
					 SWIGTYPE_p_p_unsigned_char.java \
					 SWIGTYPE_p_unsigned_char.java \
					 eac.java \
					 eacConstants.java \
					 eacJNI.java \
					 eac_wrap.c \
					 s_type.java

CLASSES_JPACE = JPace.class \
				PACEEntity.class \
				PCD.class \
				PICC.class \
				SWIGTYPE_p_BIO.class \
				SWIGTYPE_p_BUF_MEM.class \
				SWIGTYPE_p_CVC_CERT.class \
				SWIGTYPE_p_CVC_CERTIFICATE_DESCRIPTION.class \
				SWIGTYPE_p_CVC_CHAT.class \
				SWIGTYPE_p_EAC_CTX.class \
				SWIGTYPE_p_PACE_SEC.class \
				SWIGTYPE_p_p_BUF_MEM.class \
				SWIGTYPE_p_p_CVC_CERT.class \
				SWIGTYPE_p_p_CVC_CERTIFICATE_DESCRIPTION.class \
				SWIGTYPE_p_p_CVC_CHAT.class \
				SWIGTYPE_p_p_unsigned_char.class \
				SWIGTYPE_p_unsigned_char.class \
				eacConstants.class \
				eacJNI.class \
				s_type.class \
				eac.class

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
