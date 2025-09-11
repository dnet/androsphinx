#!/bin/sh

export HOST_ARCH=$(python3 -c 'import os, sys; print(sys.platform + "-" + os.uname().machine)')
export ANDROID_NDK_TOOLCHAIN=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$HOST_ARCH
export PATH=$PATH:$ANDROID_NDK_TOOLCHAIN/bin
export NDK_LEVEL=21
export NDK_PLATFORM="android-$NDK_LEVEL"

set -e

SPHINX=libsphinx
SODIUM=libsodium
OUTDIR=app/src/main/jniLibs

compile_libsphinx_arch() {
	ANDROID_ARCH=$1
	TARGET_EQUIHASH=../$OUTDIR/$ANDROID_ARCH
	TARGET=../$TARGET_EQUIHASH
	SODIUM_ARCH=$3
	NDK_ARCH=$4

	cd $SODIUM
	LIBSODIUM_FULL_BUILD=1 dist-build/android-$SODIUM_ARCH.sh
	cd src
	mkdir -p $TARGET
	cp libsodium/.libs/libsodium.so $TARGET

	cd ../../equihash
	cp $TARGET_EQUIHASH/libsodium.so .
	make clean
	make CXX=$2++ SODIUM=../$SODIUM/src/libsodium/include android
	cp libequihash.so $ANDROID_NDK_TOOLCHAIN/sysroot/usr/lib/$NDK_ARCH/libc++_shared.so $TARGET_EQUIHASH

	cd ../$SPHINX/src
	cp $TARGET/libsodium.so .
	make clean
	make CC=$2 SODIUM=../../$SODIUM/src/libsodium/include android
	cp libsphinx.so $TARGET
	cd ../..
}

git submodule update --init --recursive

cd $SODIUM
./autogen.sh
cd ..

compile_libsphinx_arch "x86_64"          "x86_64-linux-android$NDK_LEVEL-clang" "x86_64"  "x86_64-linux-android"
compile_libsphinx_arch "x86"               "i686-linux-android$NDK_LEVEL-clang" "x86"     "i686-linux-android"
compile_libsphinx_arch "arm64-v8a"      "aarch64-linux-android$NDK_LEVEL-clang" "armv8-a" "aarch64-linux-android"
compile_libsphinx_arch "armeabi-v7a" "armv7a-linux-androideabi$NDK_LEVEL-clang" "armv7-a" "arm-linux-androideabi"
