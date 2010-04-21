#MAKEFLAGS         += -rR --no-print-directory

# workaround for old patch versions on Solaris
PATCH := $(shell [ -x /bin/gpatch ] && echo /bin/gpatch || echo patch)
# On Solaris you might also want to put the directories of the gnu-utils first
# in the path (see http://www.cozmanova.com/node/10)
# export PATH=/usr/local/bin:/usr/local/sbin:/usr/local/ssl/bin:/usr/sfw/sbin/:/usr/sfw/bin:/usr/sbin:/usr/bin:/usr/ccs/bin

all: patch
	$(MAKE) Makefile -C openssl-1.0.0 || \
	    (cd openssl-1.0.0 && sleep 1 && ./config experimental-pace)
	$(MAKE) -C openssl-1.0.0

patch: openssl-1.0.0
	# see http://rt.openssl.org/Ticket/Display.html?id=2092&user=guest&pass=guest
	# This patch is modified to be compliant with OpenSSL 1.0.0 
	[ ! -r openssl-1.0.0/crypto/cmac/cmac.h ] && \
	    ($(PATCH) -d openssl-1.0.0 -p1 < ibm4_2.patch || true) && \
	    ln -s ../../crypto/cmac/cmac.h openssl-1.0.0/include/openssl || \
	    echo Never mind.
	grep brainpool openssl-1.0.0/crypto/ec/ec_curve.c > /dev/null || \
	    patch -d openssl-1.0.0 -p1 < BP.patch
	[ ! -r openssl-1.0.0/crypto/pace/pace.h ] && \
	    $(PATCH) -d openssl-1.0.0 -p1 < OpenPACE.patch && \
	    ln -s ../../crypto/pace/pace.h openssl-1.0.0/include/openssl || \
	    echo Never mind.

test: all
	openssl-1.0.0/test/pacetest

openssl-1.0.0: openssl-1.0.0.tar.gz
	gunzip -c openssl-1.0.0.tar.gz | tar xf -

openssl-1.0.0.tar.gz:
	wget http://www.openssl.org/source/openssl-1.0.0.tar.gz

clean:
	rm -rf openssl-1.0.0

dist-clean: clean
	rm -rf openssl-1.0.0.tar.gz
