EXTRA_DIST = gentoo.config-1.0.0
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
	cd $(top_builddir)/src/openssl && KERNEL_BITS=32 ./config --prefix=/usr/local
	$(MAKE) -C $(top_builddir)/src/openssl
	$(MAKE) -C $(top_builddir)/src/openssl INSTALL_PREFIX=$(OSX_TARGETDIR)_32 install_sw clean
	cd $(top_builddir)/src/openssl && KERNEL_BITS=64 ./config --prefix=/usr/local
	$(MAKE) -C $(top_builddir)/src/openssl
	$(MAKE) -C $(top_builddir)/src/openssl INSTALL_PREFIX=$(OSX_TARGETDIR)_64 install_sw
	rm -rf $(OSX_TARGETDIR)
	cp -r $(OSX_TARGETDIR)_64 $(OSX_TARGETDIR)
	rm -f $(OSX_TARGETDIR)/usr/local/lib/libcrypto.a $(OSX_TARGETDIR)/usr/local/lib/libssl.a $(OSX_TARGETDIR)/usr/local/bin/openssl
	lipo -create $(OSX_TARGETDIR)_64/usr/local/lib/libcrypto.a $(OSX_TARGETDIR)_32/usr/local/lib/libcrypto.a -output $(OSX_TARGETDIR)/usr/local/lib/libcrypto.a
	lipo -create $(OSX_TARGETDIR)_64/usr/local/lib/libssl.a $(OSX_TARGETDIR)_32/usr/local/lib/libssl.a -output $(OSX_TARGETDIR)/usr/local/lib/libssl.a
	lipo -create $(OSX_TARGETDIR)_64/usr/local/bin/openssl $(OSX_TARGETDIR)_32/usr/local/bin/openssl -output $(OSX_TARGETDIR)/usr/local/bin/openssl
	cd $(top_builddir) && ./configure --prefix=/usr/local \
		PKG_CONFIG_SYSROOT_DIR=$(OSX_TARGETDIR) \
		PKG_CONFIG_LIBDIR=$(OSX_TARGETDIR)/usr/local/lib/pkgconfig \
		PKG_CONFIG_PATH=$(OSX_TARGETDIR)/usr/local/lib/pkgconfig \
		CFLAGS="-arch i386 -arch x86_64"
	make -C $(top_builddir) install DESTDIR=$(OSX_TARGETDIR)
	rm -f $(PACKAGE_TARNAME)-$(PACKAGE_VERSION)_osx.dmg
	hdiutil create -srcfolder $(OSX_TARGETDIR) -volname "$(PACKAGE_STRING) for Mac OS X" $(PACKAGE_TARNAME)-$(PACKAGE_VERSION)_osx.dmg



EMSCRIPTEN_DIR ?= ${HOME}/.local/src/emscripten
EMSCRIPTEN_TARGETDIR = $(abs_top_builddir)/$(PACKAGE_TARNAME)-$(PACKAGE_VERSION)_bc

emscripten:
	cd $(top_builddir) && emconfigure ./configure \
		--prefix=/ \
		--enable-openssl-install \
		CFLAGS="-O2 -Wno-warn-absolute-paths" \
		OPENSSL_CONFIGURE_FLAGS="no-asm no-shared no-hw no-threads no-dso --prefix=/ BSD-x86 -I$(EMSCRIPTEN_DIR)/system/include/libc -O2 -Wno-warn-absolute-paths"
	emmake $(MAKE) -C $(top_builddir) install DESTDIR=$(EMSCRIPTEN_TARGETDIR)
	emcc -O2 $(top_builddir)/src/eactest-eactest.o $(EMSCRIPTEN_TARGETDIR)/lib/libeac.a $(EMSCRIPTEN_TARGETDIR)/lib/libcrypto.a -o $(EMSCRIPTEN_TARGETDIR)/eactest.html
	emcc -O2 $(top_builddir)/src/eactest-eactest.o $(EMSCRIPTEN_TARGETDIR)/lib/libeac.a $(EMSCRIPTEN_TARGETDIR)/lib/libcrypto.a -o $(EMSCRIPTEN_TARGETDIR)/eactest.js
	emcc -O2 $(top_builddir)/src/cvcprint-cvcprint.o $(EMSCRIPTEN_TARGETDIR)/lib/libeac.a $(EMSCRIPTEN_TARGETDIR)/lib/libcrypto.a -o $(EMSCRIPTEN_TARGETDIR)/cvcprint.html
	emcc -O2 $(top_builddir)/src/cvcprint-cvcprint.o $(EMSCRIPTEN_TARGETDIR)/lib/libeac.a $(EMSCRIPTEN_TARGETDIR)/lib/libcrypto.a -o $(EMSCRIPTEN_TARGETDIR)/cvcprint.js



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
		LIBEAC=$(WIN_TARGETDIR)/bin/libeac-0.dll
	cd $(WIN_TARGETDIR)/lib && gendef $(WIN_TARGETDIR)/bin/*.dll



ANDROID_ARCH ?= arm
ANDROID_TOOL ?= $(ANDROID_ARCH)-linux-androideabi
ANDROID_TOOL_DIR ?= $(abs_builddir)/ndk
ANDROID_TARGETDIR = $(abs_top_builddir)/$(PACKAGE_TARNAME)-$(PACKAGE_VERSION)_$(ANDROID_ARCH)
MAKE_STANDALONE_TOOLCHAIN ?= $${HOME}/.local/opt/android-ndk-r9/build/tools/make-standalone-toolchain.sh

android:
	test -d $(ANDROID_TOOL_DIR) \
		|| $(MAKE_STANDALONE_TOOLCHAIN) --install-dir=$(ANDROID_TOOL_DIR) --arch=$(ANDROID_ARCH)
	env PATH=$(ANDROID_TOOL_DIR)/bin:$${PATH} $(MAKE) cross \
		TOOL=$(ANDROID_TOOL) \
		TOOL_DIR=$(ANDROID_TOOL_DIR) \
		TARGETDIR=$(ANDROID_TARGETDIR) \
		ENABLE_PYTHON=--enable-python \
		LIBEAC=$(ANDROID_TARGETDIR)/lib/libeac.so



clean-local:
	rm -rf $(TARGETDIR) $(OSX_TARGETDIR)_64 $(OSX_TARGETDIR)_32 $(OSX_TARGETDIR)



CROSS_COMPILE = $(TOOL)-

cross: $(LIBEAC)

$(LIBEAC):
	cd $(top_builddir) && ./configure \
		--prefix=/ \
		--host=$(TOOL) --target=$(TOOL) \
		--enable-openssl-install \
		$(ENABLE_PYTHON) \
		CFLAGS="-I$(TOOL_DIR)/include -I$(TOOL_DIR)/include/python2.7" \
		LDFLAGS="$${LDFLAGS} -L$(TOOL_DIR)/lib"
	touch $(top_builddir)/src/cvc-create.1 $(top_builddir)/src/cvc-print.1
	env CROSS_COMPILE=$(CROSS_COMPILE) \
		$(MAKE) -C $(top_builddir) install DESTDIR=$(TARGETDIR)
