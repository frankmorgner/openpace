#MAKEFLAGS         += -rR --no-print-directory

# workaround for old patch versions on Solaris
PATCH := $(shell [ -x /bin/gpatch ] && echo /bin/gpatch || echo patch)
# On Solaris you might also want to put the directories of the gnu-utils first
# in the path (see http://www.cozmanova.com/node/10)
# export PATH=/usr/local/bin:/usr/local/sbin:/usr/local/ssl/bin:/usr/sfw/sbin/:/usr/sfw/bin:/usr/sbin:/usr/bin:/usr/ccs/bin

all: patch
	$(MAKE) Makefile -C openssl-1.0.0-beta4 || \
	    (cd openssl-1.0.0-beta4 && sleep 1 && ./config experimental-pace -g)
	$(MAKE) -C openssl-1.0.0-beta4

patch: openssl-1.0.0-beta4
	# see http://rt.openssl.org/Ticket/Display.html?id=2092&user=guest&pass=guest
	[ ! -r openssl-1.0.0-beta4/crypto/cmac/cmac.h ] && \
	    ($(PATCH) -d openssl-1.0.0-beta4 -p1 < ibm4.patch || true) && \
	    ln -s ../../crypto/cmac/cmac.h openssl-1.0.0-beta4/include/openssl || \
	    echo Never mind.
	grep brainpool openssl-1.0.0-beta4/crypto/ec/ec_curve.c > /dev/null || \
	    patch -d openssl-1.0.0-beta4 -p1 < BP.patch
	[ ! -r openssl-1.0.0-beta4/crypto/pace/pace.h ] && \
	    $(PATCH) -d openssl-1.0.0-beta4 -p1 < OpenPACE.patch && \
	    ln -s ../../crypto/pace/pace.h openssl-1.0.0-beta4/include/openssl || \
	    echo Never mind.

openssl-1.0.0-beta4: openssl-1.0.0-beta4.tar.gz
	gunzip -c openssl-1.0.0-beta4.tar.gz | tar xvf -

openssl-1.0.0-beta4.tar.gz:
	wget http://www.openssl.org/source/openssl-1.0.0-beta4.tar.gz

clean:
	rm -rf openssl-1.0.0-beta4

veryclean:  clean
	rm -rf openssl-1.0.0-beta4.tar.gz
