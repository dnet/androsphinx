#!/bin/sh

set -e

SPHINX=libsphinx
SODIUM=libsodium_headers
OUTDIR=app/src/main/jniLibs

git submodule update --init --recursive --remote

rm -rf $SODIUM
mkdir $SODIUM
ln -s /usr/include/sodium* $SODIUM

ARCH=x86_64
TARGET=../../$OUTDIR/$ARCH
cd $SPHINX/src/goldilocks
git submodule update --init --recursive --remote
make android_x86_64
cd ..
cp ../../app/build/intermediates/merged_native_libs/debug/out/lib/$ARCH/libsodiumjni.so .
make CC=x86_64-linux-android21-clang SODIUM=../../$SODIUM android
mkdir -p $TARGET
cp libsphinx.so $TARGET

ARCH=x86
TARGET=../../$OUTDIR/$ARCH
cd goldilocks
make clean
make FIELD_ARCH=arch_32 android_i686
cd ..
make clean
cp ../../app/build/intermediates/merged_native_libs/debug/out/lib/$ARCH/libsodiumjni.so .
make CC=i686-linux-android21-clang SODIUM=../../$SODIUM android
mkdir -p $TARGET
cp libsphinx.so $TARGET

ARCH=arm64-v8a
TARGET=../../$OUTDIR/$ARCH
cd goldilocks
make clean
make FIELD_ARCH=arch_ref64 android_aarch64
cd ..
make clean
cp ../../app/build/intermediates/merged_native_libs/debug/out/lib/$ARCH/libsodiumjni.so .
make CC=aarch64-linux-android21-clang SODIUM=../../$SODIUM android
mkdir -p $TARGET
cp libsphinx.so $TARGET

ARCH=armeabi-v7a
TARGET=../../$OUTDIR/$ARCH
cd goldilocks
make clean
make FIELD_ARCH=arch_32 android_armv7a
cd ..
make clean
cp ../../app/build/intermediates/merged_native_libs/debug/out/lib/$ARCH/libsodiumjni.so .
make CC=armv7a-linux-androideabi21-clang SODIUM=../../$SODIUM android
mkdir -p $TARGET
cp libsphinx.so $TARGET

cd ../..
rm -rf $SODIUM
