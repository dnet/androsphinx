#!/bin/sh

set -e

SPHINX=libsphinx
SODIUM=libsodium
OUTDIR=app/src/main/jniLibs

compile_libsphinx_arch() {
	ANDROID_ARCH=$1
	TARGET=../../$OUTDIR/$ANDROID_ARCH
	SODIUM_ARCH=$3

	cd $SODIUM
	LIBSODIUM_FULL_BUILD=1 dist-build/android-$SODIUM_ARCH.sh
	cd src
	mkdir -p $TARGET
	cp libsodium/.libs/libsodium.so $TARGET

	cd ../../$SPHINX/src
	cp $TARGET/libsodium.so .
	make clean
	make CC=$2 SODIUM=../../$SODIUM/src/libsodium/include android
	cp libsphinx.so $TARGET
	cd ../..
}

git submodule update --init --recursive --remote

cd $SODIUM
./autogen.sh
cd ..

compile_libsphinx_arch "x86_64"          "x86_64-linux-android21-clang" "x86_64"
compile_libsphinx_arch "x86"               "i686-linux-android21-clang" "x86"
compile_libsphinx_arch "arm64-v8a"      "aarch64-linux-android21-clang" "armv8-a"
compile_libsphinx_arch "armeabi-v7a" "armv7a-linux-androideabi21-clang" "armv7-a"
