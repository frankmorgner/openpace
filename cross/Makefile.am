EXTRA_DIST = gentoo.config-1.0.0 MacOSX_install/postinstall MacOSX_uninstall/postinstall
all-local:
	@echo Use \`$(MAKE) win\` to cross compile for Windows
	@echo Use \`$(MAKE) android\` to cross compile for Android
	@echo Use \`$(MAKE) emscripten\` to cross compile for Javascript
	@echo Use \`$(MAKE) osx\` to compile a mulit arch package on Mac OS X



OSX_TOOLS_DIR = "$(shell xcode-select -p)/Platforms/MacOSX.platform/Developer/SDKs"
OSX_TOOL_DIR ?= "$(OSX_TOOLS_DIR)/$(shell ls -1 $(OSX_TOOLS_DIR) | sort -n -k2 -t. -r | head -1)/usr"
OSX_TARGETDIR = $(abs_top_builddir)/$(PACKAGE_TARNAME)-$(PACKAGE_VERSION)_osx
osx:
	(cd $(top_builddir)/src/openssl && git clean -xfd && git reset --hard HEAD) || true
	cd $(top_builddir) && ./configure --enable-openssl-install
	$(MAKE) -C $(top_builddir)/src patch_openssl
	cd $(top_builddir)/src/openssl && KERNEL_BITS=32 ./config --prefix=/Library/OpenPACE
	$(MAKE) -C $(top_builddir)/src/openssl
	$(MAKE) -C $(top_builddir)/src/openssl INSTALL_PREFIX=$(OSX_TARGETDIR)_32 install_sw clean
	cd $(top_builddir)/src/openssl && KERNEL_BITS=64 ./config --prefix=/Library/OpenPACE
	$(MAKE) -C $(top_builddir)/src/openssl
	$(MAKE) -C $(top_builddir)/src/openssl INSTALL_PREFIX=$(OSX_TARGETDIR)_64 install_sw
	rm -rf $(OSX_TARGETDIR) OpenPACE-install.pkg dmg $(top_builddir)/$(PACKAGE_TARNAME)-$(PACKAGE_VERSION)_osx.dmg
	cp -r $(OSX_TARGETDIR)_64 $(OSX_TARGETDIR)
	rm -f $(OSX_TARGETDIR)/Library/OpenPACE/lib/libcrypto.a $(OSX_TARGETDIR)/Library/OpenPACE/lib/libssl.a $(OSX_TARGETDIR)/Library/OpenPACE/bin/openssl
	lipo -create $(OSX_TARGETDIR)_64/Library/OpenPACE/lib/libcrypto.a $(OSX_TARGETDIR)_32/Library/OpenPACE/lib/libcrypto.a -output $(OSX_TARGETDIR)/Library/OpenPACE/lib/libcrypto.a
	lipo -create $(OSX_TARGETDIR)_64/Library/OpenPACE/lib/libssl.a $(OSX_TARGETDIR)_32/Library/OpenPACE/lib/libssl.a -output $(OSX_TARGETDIR)/Library/OpenPACE/lib/libssl.a
	lipo -create $(OSX_TARGETDIR)_64/Library/OpenPACE/bin/openssl $(OSX_TARGETDIR)_32/Library/OpenPACE/bin/openssl -output $(OSX_TARGETDIR)/Library/OpenPACE/bin/openssl
	cd $(top_builddir) && ./configure --prefix=/Library/OpenPACE \
		PKG_CONFIG_SYSROOT_DIR=$(OSX_TARGETDIR) \
		PKG_CONFIG_PATH=$(OSX_TARGETDIR)/Library/OpenPACE/lib/pkgconfig \
		--enable-python \
		CFLAGS="-arch i386 -arch x86_64" LIBS="-arch i386 -arch x86_64"
	make -C $(top_builddir) install DESTDIR=$(OSX_TARGETDIR)
	pkgbuild --root $(OSX_TARGETDIR) --scripts MacOSX_install --identifier com.openpace.mac --version $(PACKAGE_VERSION) --install-location / OpenPACE-$(PACKAGE_VERSION)_install.pkg
	pkgbuild --nopayload --identifier com.openpace.mac.uninstall --scripts MacOSX_uninstall Uninstall_OpenPACE.pkg
	mkdir dmg
	cp Uninstall_OpenPACE.pkg dmg
	cp OpenPACE-$(PACKAGE_VERSION)_install.pkg dmg
	hdiutil create -srcfolder dmg -volname "$(PACKAGE_STRING) for Mac OS X" $(top_builddir)/$(PACKAGE_TARNAME)-$(PACKAGE_VERSION)_osx.dmg



EMSCRIPTEN ?= ${HOME}/.local/src/emscripten
EMSCRIPTEN_TARGETDIR = $(abs_top_builddir)/$(PACKAGE_TARNAME)-$(PACKAGE_VERSION)_js

emscripten:
	touch $(top_builddir)/src/cvc-create.1 $(top_builddir)/src/cvc-print.1
	cd $(top_builddir) && emconfigure ./configure \
		--prefix=/ \
		--enable-openssl-install --disable-shared \
		CFLAGS=-O3 LDFLAGS=-O3 \
		OPENSSL_CONFIGURE_FLAGS="no-asm no-shared no-hw no-threads no-dso --prefix=/ BSD-x86 -I$(EMSCRIPTEN)/system/include/libc -O3"
	emmake $(MAKE) -C $(top_builddir) install DESTDIR=$(EMSCRIPTEN_TARGETDIR)
	for i in $(EMSCRIPTEN_TARGETDIR)/lib/*.a	; do mv $$i $${i%.a}.bc	; done
	for i in $(EMSCRIPTEN_TARGETDIR)/bin/*		; do mv $$i $$i.bc		; done
	mv $(EMSCRIPTEN_TARGETDIR)/bin/c_rehash.bc $(EMSCRIPTEN_TARGETDIR)/bin/c_rehash
	for i in $(EMSCRIPTEN_TARGETDIR)/bin/*.bc $(EMSCRIPTEN_TARGETDIR)/lib/*.bc; do \
		emcc -O3 $$i $(EMSCRIPTEN_TARGETDIR)/lib/libeac.bc $(EMSCRIPTEN_TARGETDIR)/lib/libcrypto.bc -o $${i%.*}.js; done
	emcc --proxy-to-worker -O3 $(EMSCRIPTEN_TARGETDIR)/bin/eactest.bc $(EMSCRIPTEN_TARGETDIR)/lib/libeac.bc $(EMSCRIPTEN_TARGETDIR)/lib/libcrypto.bc -o $(EMSCRIPTEN_TARGETDIR)/eactest.html



WIN_TOOL ?= i686-w64-mingw32
WIN_TOOL_DIR ?= /usr/$(WIN_TOOL)
WIN_TARGETDIR = $(abs_top_builddir)/$(PACKAGE_TARNAME)-$(PACKAGE_VERSION)_win32

win:
	env ac_cv_func_malloc_0_nonnull=yes $(MAKE) cross \
		TOOL=$(WIN_TOOL) \
		TOOL_DIR=$(WIN_TOOL_DIR) \
		TARGETDIR=$(WIN_TARGETDIR) \
		ENABLE_PYTHON="" \
		LDFLAGS="-static-libgcc" \
		LIBEAC=$(WIN_TARGETDIR)/bin/libeac-2.dll
	cd $(WIN_TARGETDIR)/lib && gendef $(WIN_TARGETDIR)/bin/*.dll



ANDROID_ARCH ?= arm
ANDROID_TOOL ?= $(ANDROID_ARCH)-linux-androideabi
ANDROID_TOOL_DIR ?= $(abs_builddir)/ndk
ANDROID_TARGETDIR = $(abs_top_builddir)/$(PACKAGE_TARNAME)-$(PACKAGE_VERSION)_$(ANDROID_ARCH)-androideabi
MAKE_STANDALONE_TOOLCHAIN ?= $${HOME}/.local/opt/android-ndk-r10e/build/tools/make-standalone-toolchain.sh

android:
	test -d $(ANDROID_TOOL_DIR) \
		|| $(MAKE_STANDALONE_TOOLCHAIN) --install-dir=$(ANDROID_TOOL_DIR) --arch=$(ANDROID_ARCH) --platform=android-16
	env ac_cv_func_malloc_0_nonnull=yes PATH=$(ANDROID_TOOL_DIR)/bin:$${PATH} $(MAKE) cross \
		TOOL=$(ANDROID_TOOL) \
		TOOL_DIR=$(ANDROID_TOOL_DIR) \
		TARGETDIR=$(ANDROID_TARGETDIR) \
		ENABLE_PYTHON=--enable-java \
		CROSS_CFLAGS=-fPIE \
		CROSS_LDFLAGS="-fPIE -pie" \
		LIBEAC=$(ANDROID_TARGETDIR)/lib/libeac.so



clean-local:
	rm -rf $(TARGETDIR) $(OSX_TARGETDIR)_64 $(OSX_TARGETDIR)_32 $(OSX_TARGETDIR)



CROSS_COMPILE = $(TOOL)-

cross: $(LIBEAC)

$(LIBEAC):
	touch $(top_builddir)/src/cvc-create.1 $(top_builddir)/src/cvc-print.1
	cd $(top_builddir) && unset CC && ./configure \
		--prefix=/ \
		--host=$(TOOL) --target=$(TOOL) \
		--enable-openssl-install \
		$(ENABLE_PYTHON) \
		CFLAGS="-I$(TOOL_DIR)/include -I$(TOOL_DIR)/include/python2.7 $(CROSS_CFLAGS)" \
		LDFLAGS="$${LDFLAGS} -L$(TOOL_DIR)/lib $(CROSS_LDFLAGS)"
	env CROSS_COMPILE=$(CROSS_COMPILE) WINDRES=$(TOOL)-windres \
		$(MAKE) -C $(top_builddir) install DESTDIR=$(TARGETDIR)
