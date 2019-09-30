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

QR code format
--------------

Server details can be configured using a simple QR code with the following format:

 - Server public key (32 bytes, "raw" without any encoding)
 - Server port (big endian, 2 bytes, "raw" without any encoding)
 - Server hostname (UTF-8)

This could be generated this way using qrencode (Debian/Ubuntu package: `qrencode`)

	(cat ~/.sphinx/server-key.pub ; printf '\x09\x33%s' "example.com") | qrencode -8 -t ANSI256

In the above case, 0x0933 is port 2355 (the default port). Extra care must be
taken so that the QR encoder also knows about the input being in 8-bit mode.
In the above example, without the `-8` switch, the output is truncated when
read by the application.
