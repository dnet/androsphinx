SPHINX for Android
==================

**The code is not ready for average users, it's a proof of concept right now.**

Building
--------

Create a file called `local.properties` with a single line, editing the path
to match your file system layout:

	sdk.dir=/path/to/android/sdk

Then execute Gradle:

	./gradlew build

If this is the first build, `libsphinx.so` also needs to be built. To do this,
update `PATH` to include the NDK toolchain commands such as `clang` and run:

	sh build-libsphinx.sh

After a successful build of `libsphinx.so`, Gradle must be executed again to
include these files in the APK.

The resulting debug APK will be here:

	app/build/outputs/apk/debug/app-debug.apk

License
-------

The whole project is licensed under MIT license, see `LICENSE.txt`

Dependencies
------------

 - Android SDK
 - Android NDK
 - Gradle (included)
 - libsodium headers (only needed for building `libsphinx.so`, Debian/Ubuntu package: `libsodium-dev`)
 - libsodium-jni https://github.com/joshjdevl/libsodium-jni (referenced via Gradle dependency)
