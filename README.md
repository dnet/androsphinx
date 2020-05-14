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

The whole project is licensed under MIT license, see `LICENSE.txt` except for
the parts included from Google zxing which are under APACHE license.

As required by the Apache license, here are the modifications made in the zxing
library:

 - added methods to generate 8-bit QR codes from raw `byte[]` objects

Dependencies
------------

 - Android SDK
 - Android NDK
 - Gradle (included)
 - libsodium headers (only needed for building `libsphinx.so`, Debian/Ubuntu package: `libsodium-dev`)
 - libsodium-jni https://github.com/joshjdevl/libsodium-jni (referenced via Gradle dependency)
 - anything needed to build the Decaf elliptic curve library (Python, host C compiler)

QR code format
--------------

Server details can be configured using a simple QR code with the following format:

 - Format flags (1 byte, LSB: client credentials present, next bit: use TLS)
 - Client master key (32 bytes, "raw" without any encoding, only present when format type has LSB set)
 - Server port (big endian, 2 bytes, "raw" without any encoding)
 - Server hostname (UTF-8)

This could be generated this way using qrencode (Debian/Ubuntu package: `qrencode`)

	(printf '\x00' ;
		printf '\x09\x33%s' "example.com") | qrencode -8 -t ANSI256

	(printf '\x01' ; cat ~/.sphinx/masterkey ;
		printf '\x09\x33%s' "example.com") | qrencode -8 -t ANSI256

In the above case, 0x0933 is port 2355 (the default port). Extra care must be
taken so that the QR encoder also knows about the input being in 8-bit mode.
In the above example, without the `-8` switch, the output is truncated when
read by the application.

Testing
-------

Besides "regular" tests suites running on the host and instrumented ones running
on Android devices or emulators, there's also a test REPL that can be used to test
conformity to other implementations such as `pwdsphinx`. To launch this REPL,

 - (Optional) if you want the test suite to connect to a SPHINX server other
   than the default (host of an Android emulator, default port), modify the
   class `MockCredentialStore` accordingly.
 - Start `readEvalPrintLoopTest` from `ExampleInstrumentedTest`, this will
   listen on TCP port 2355 and wait for a single connection.
 - (Optional) if you want to tunnel over ADB (useful when using an emulator)
   set up port forward using `adb forward tcp:X tcp:2355` where `X` will be the
   port listening on the ADB host.
 - Now connect to TCP port 2355 on the device (or `X` on localhost if you use
   ADB port forwarding) and you can issue commands either manually or using an
   automated client, the protocol is easy to use by humans and programs alike.

There's a built in command list by using the `help` command:

	$ adb forward tcp:23555 tcp:2355
	23555
	$ nc localhost 23555
	ASREPL> help
	Available commands:

	create <master password> <user> <site> [u][l][d][s] [<size>]
	<get|change|commit|delete> <master password> <user> <site>
	list <site>
	ASREPL>

The `ASREPL>` is the prompt of the REPL and it signals that the REPL is ready
for the next command. The syntax is intentionally similar to that of
`pwdsphinx` except for the master password, which needs to be supplied as a
parameter for the relevant commands.

If you indend to check whether SPHINX entries created by one implementation
can be read by another, make sure that `key` also matches the one
defined in the class `MockCredentialStore`. For example, in `pwdsphinx`, this
can be found in the file `~/.sphinx/masterkey`.
